//! QUIC packet protection keys (RFC 9001 s5.1, s5.2).
//!
//! Initial keys come from a constant published in the RFC rather than from a
//! handshake, so the first packet on a connection is already protected.
//! HKDF-Expand-Label is TLS 1.3's, adopted unchanged (RFC 8446 s7.1).
const std = @import("std");

const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;

/// Published, so Initial packets are authenticated but not confidential.
/// Source: RFC 9001 s5.2.
pub const initial_salt = [_]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

const max_label = 16;
const label_prefix = "tls13 ";
const max_info = 2 + 1 + label_prefix.len + max_label + 1;

/// `HkdfLabel`: output length, then "tls13 "+label and a context, each length
/// prefixed. QUIC always passes an empty context. Split out because the RFC
/// publishes these bytes, so a structure bug stays distinguishable from an
/// HKDF one.
/// Source: RFC 8446 s7.1.
fn hkdfLabel(buf: *[max_info]u8, out_len: u16, comptime label: []const u8) []const u8 {
    comptime std.debug.assert(label.len <= max_label);

    std.mem.writeInt(u16, buf[0..2], out_len, .big);
    buf[2] = @intCast(label_prefix.len + label.len);
    @memcpy(buf[3..][0..label_prefix.len], label_prefix);
    @memcpy(buf[3 + label_prefix.len ..][0..label.len], label);

    const n = 3 + label_prefix.len + label.len;
    buf[n] = 0;
    return buf[0 .. n + 1];
}

fn expandLabel(out: []u8, prk: [Hkdf.prk_length]u8, comptime label: []const u8) void {
    var buf: [max_info]u8 = undefined;
    Hkdf.expand(out, hkdfLabel(&buf, @intCast(out.len), label), prk);
}

pub const Secrets = struct {
    client: [Hkdf.prk_length]u8,
    server: [Hkdf.prk_length]u8,
};

/// Both directions' secrets, from the client's *original* DCID. The server
/// issues its own connection id later, but Initial keys stay pinned to this one
/// so both ends keep agreeing.
/// Source: RFC 9001 s5.2.
pub fn initialSecrets(dcid: []const u8) Secrets {
    const initial = Hkdf.extract(&initial_salt, dcid);
    var s: Secrets = undefined;
    expandLabel(&s.client, initial, "client in");
    expandLabel(&s.server, initial, "server in");
    return s;
}

/// One direction's protection. `hp` is separate from `key` so header masking
/// cannot be derived from payload keys. Sized for AEAD_AES_128_GCM, which
/// Initial packets always use; becomes a union once TLS can negotiate another.
pub const Keys = struct {
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
};

/// Source: RFC 9001 s5.1.
pub fn keysFromSecret(secret: [Hkdf.prk_length]u8) Keys {
    var k: Keys = undefined;
    expandLabel(&k.key, secret, "quic key");
    expandLabel(&k.iv, secret, "quic iv");
    expandLabel(&k.hp, secret, "quic hp");
    return k;
}

pub const sample_len = 16;

/// One byte for the first byte, four for the longest packet number.
pub const mask_len = 5;

/// Header mask from a sample of the packet's own ciphertext. ECB is safe here
/// because exactly one block is encrypted per packet under a key that protects
/// nothing else. Entangles the layers: the header cannot change without
/// invalidating the payload.
/// Source: RFC 9001 s5.4.3.
pub fn headerMask(hp: [16]u8, sample: [sample_len]u8) [mask_len]u8 {
    var block: [16]u8 = undefined;
    std.crypto.core.aes.Aes128.initEnc(hp).encrypt(&block, &sample);
    return block[0..mask_len].*;
}

const testing = std.testing;
const testdata = @import("testdata.zig");
const hex = testdata.hex;

// The RFC publishes the encoded HkdfLabel for every label, which pins the
// structure independently of the HKDF consuming it.
test "RFC 9001 A.1 HkdfLabel encodings" {
    var buf: [max_info]u8 = undefined;
    inline for (.{
        .{ 32, "client in", "00200f746c73313320636c69656e7420696e00" },
        .{ 32, "server in", "00200f746c7331332073657276657220696e00" },
        .{ 16, "quic key", "00100e746c7331332071756963206b657900" },
        .{ 12, "quic iv", "000c0d746c733133207175696320697600" },
        .{ 16, "quic hp", "00100d746c733133207175696320687000" },
    }) |c| {
        try testing.expectEqualSlices(u8, &hex(c[2]), hkdfLabel(&buf, c[0], c[1]));
    }
}

// The whole chain, both directions. Matching key/iv/hp pins every step above
// them, since each is expanded from the one before.
test "RFC 9001 A.1 key schedule" {
    const dcid = hex(testdata.dcid);
    try testing.expectEqualSlices(
        u8,
        &hex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"),
        &Hkdf.extract(&initial_salt, &dcid),
    );

    const s = initialSecrets(&dcid);
    inline for (.{
        .{
            s.client,
            "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
            "1f369613dd76d5467730efcbe3b1a22d",
            "fa044b2f42a3fd3b46fb255c",
            "9f50449e04a0e810283a1e9933adedd2",
        },
        .{
            s.server,
            "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
            "cf3a5331653c364c88f0f379b6067e37",
            "0ac1493ca1905853b0bba03e",
            "c206b8d9b9f0f37644430b490eeaa314",
        },
    }) |c| {
        try testing.expectEqualSlices(u8, &hex(c[1]), &c[0]);
        const k = keysFromSecret(c[0]);
        try testing.expectEqualSlices(u8, &hex(c[2]), &k.key);
        try testing.expectEqualSlices(u8, &hex(c[3]), &k.iv);
        try testing.expectEqualSlices(u8, &hex(c[4]), &k.hp);
    }
}

test "RFC 9001 A.2 header protection mask" {
    const hp = keysFromSecret(initialSecrets(&hex(testdata.dcid)).client).hp;
    try testing.expectEqualSlices(u8, &hex("437b9aec36"), &headerMask(hp, hex("d1b1c98dd7689fb8ec11d242b123dc9b")));
}

// Keys must depend on the connection id and on the direction, or the salt is
// being used alone somewhere and every connection shares protection.
test "keys are bound to connection id and direction" {
    const a = initialSecrets(&hex(testdata.dcid));
    const b = initialSecrets(&hex("0000000000000000"));
    try testing.expect(!std.mem.eql(u8, &keysFromSecret(a.client).key, &keysFromSecret(b.client).key));
    try testing.expect(!std.mem.eql(u8, &keysFromSecret(a.client).key, &keysFromSecret(a.server).key));
}
