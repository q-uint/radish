//! QUIC packet protection keys (RFC 9001).
//!
//! Every QUIC packet is protected by an AEAD, and its header is separately
//! masked by "header protection". Both need keys. For Initial packets those
//! keys come from a constant published in the RFC rather than from a handshake,
//! which is what lets the very first packet on a connection already be
//! protected.
//!
//! Source: RFC 9001 s5.1 (packet protection keys), s5.2 (initial secrets),
//! and RFC 8446 s7.1 for HKDF-Expand-Label, which QUIC adopts unchanged.
const std = @import("std");

const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;

/// The salt every endpoint mixes with the client's Destination Connection ID
/// to derive Initial keys. It is published, so Initial packets are
/// authenticated but not confidential: anyone who observes the connection ID
/// can read them. That is deliberate. It keeps middleboxes from parsing fields
/// they were never given, without pretending to offer secrecy before any
/// handshake has happened.
/// Source: RFC 9001 s5.2.
pub const initial_salt = [_]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

/// Longest label we derive with ("client in", "server in", "quic key", ...),
/// so the HkdfLabel buffer can live on the stack.
const max_label = 16;
const label_prefix = "tls13 ";
const max_info = 2 + 1 + label_prefix.len + max_label + 1;

/// Builds the `HkdfLabel` structure TLS 1.3 feeds to HKDF-Expand: the output
/// length, then the label prefixed with "tls13 ", then a context. Both the
/// label and the context are length-prefixed, and QUIC always passes an empty
/// context.
///
/// Split out from `expandLabel` because the RFC publishes these encoded bytes,
/// so it can be checked on its own. A bug here and a bug in HKDF would
/// otherwise be indistinguishable from a wrong final key.
/// Source: RFC 8446 s7.1.
fn hkdfLabel(buf: *[max_info]u8, out_len: u16, comptime label: []const u8) []const u8 {
    comptime std.debug.assert(label.len <= max_label);

    std.mem.writeInt(u16, buf[0..2], out_len, .big);
    buf[2] = @intCast(label_prefix.len + label.len);
    @memcpy(buf[3..][0..label_prefix.len], label_prefix);
    @memcpy(buf[3 + label_prefix.len ..][0..label.len], label);

    const n = 3 + label_prefix.len + label.len;
    buf[n] = 0; // zero-length context
    return buf[0 .. n + 1];
}

fn expandLabel(out: []u8, prk: [Hkdf.prk_length]u8, comptime label: []const u8) void {
    var buf: [max_info]u8 = undefined;
    Hkdf.expand(out, hkdfLabel(&buf, @intCast(out.len), label), prk);
}

/// The per-direction secrets both endpoints derive from the connection ID
/// alone. Each is the root for one direction's key, IV, and header-protection
/// key.
pub const Secrets = struct {
    client: [Hkdf.prk_length]u8,
    server: [Hkdf.prk_length]u8,
};

/// Derives both Initial secrets from the Destination Connection ID in the
/// client's first packet. Note that this is the *original* DCID: the server
/// hands out a connection ID of its own during the handshake, but Initial keys
/// stay pinned to the client's first choice so both ends keep agreeing on them.
/// Source: RFC 9001 s5.2.
pub fn initialSecrets(dcid: []const u8) Secrets {
    const initial = Hkdf.extract(&initial_salt, dcid);
    var s: Secrets = undefined;
    expandLabel(&s.client, initial, "client in");
    expandLabel(&s.server, initial, "server in");
    return s;
}

/// What it takes to protect one direction's packets. `key` and `iv` drive the
/// AEAD over the payload; `hp` masks part of the header and is a separate key
/// precisely so that header masking cannot be derived from payload keys.
///
/// Sized for AEAD_AES_128_GCM, which Initial packets always use. Keys
/// negotiated later by TLS may select a different cipher, so this becomes a
/// tagged union once the handshake exists.
pub const Keys = struct {
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
};

/// Expands one direction's secret into its three protection keys.
/// Source: RFC 9001 s5.1.
pub fn keysFromSecret(secret: [Hkdf.prk_length]u8) Keys {
    var k: Keys = undefined;
    expandLabel(&k.key, secret, "quic key");
    expandLabel(&k.iv, secret, "quic iv");
    expandLabel(&k.hp, secret, "quic hp");
    return k;
}

/// Bytes of ciphertext sampled to derive a header mask.
pub const sample_len = 16;

/// Bytes of mask produced: one for the first byte, four for the longest
/// possible packet number encoding.
pub const mask_len = 5;

/// Derives the header protection mask by encrypting a sample of the packet's
/// own ciphertext under `hp`. This is a single AES block in ECB mode, which is
/// safe only because exactly one block is ever encrypted per packet, under a
/// key that protects nothing else.
///
/// The mask depends on the ciphertext, and the ciphertext depends on the
/// packet number in the header, so the two layers are deliberately entangled:
/// you cannot alter the header without invalidating the payload.
/// Source: RFC 9001 s5.4.3.
pub fn headerMask(hp: [16]u8, sample: [sample_len]u8) [mask_len]u8 {
    var block: [16]u8 = undefined;
    std.crypto.core.aes.Aes128.initEnc(hp).encrypt(&block, &sample);
    return block[0..mask_len].*;
}

const testing = std.testing;

/// Vectors read better as the hex the RFC prints them in.
fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

// RFC 9001 A.1 publishes the encoded HkdfLabel for each label it uses, which
// pins the structure independently of the HKDF that consumes it.
test "RFC 9001 A.1 HkdfLabel encodings" {
    var buf: [max_info]u8 = undefined;
    try testing.expectEqualSlices(u8, &hex("00200f746c73313320636c69656e7420696e00"), hkdfLabel(&buf, 32, "client in"));
    try testing.expectEqualSlices(u8, &hex("00200f746c7331332073657276657220696e00"), hkdfLabel(&buf, 32, "server in"));
    try testing.expectEqualSlices(u8, &hex("00100e746c7331332071756963206b657900"), hkdfLabel(&buf, 16, "quic key"));
    try testing.expectEqualSlices(u8, &hex("000c0d746c733133207175696320697600"), hkdfLabel(&buf, 12, "quic iv"));
    try testing.expectEqualSlices(u8, &hex("00100d746c733133207175696320687000"), hkdfLabel(&buf, 16, "quic hp"));
}

// The full chain from RFC 9001 A.1, using the sample 8-byte connection id.
test "RFC 9001 A.1 initial secret" {
    const dcid = hex("8394c8f03e515708");
    try testing.expectEqualSlices(
        u8,
        &hex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"),
        &Hkdf.extract(&initial_salt, &dcid),
    );
}

test "RFC 9001 A.1 client keys" {
    const s = initialSecrets(&hex("8394c8f03e515708"));
    try testing.expectEqualSlices(u8, &hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"), &s.client);

    const k = keysFromSecret(s.client);
    try testing.expectEqualSlices(u8, &hex("1f369613dd76d5467730efcbe3b1a22d"), &k.key);
    try testing.expectEqualSlices(u8, &hex("fa044b2f42a3fd3b46fb255c"), &k.iv);
    try testing.expectEqualSlices(u8, &hex("9f50449e04a0e810283a1e9933adedd2"), &k.hp);
}

test "RFC 9001 A.1 server keys" {
    const s = initialSecrets(&hex("8394c8f03e515708"));
    try testing.expectEqualSlices(u8, &hex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"), &s.server);

    const k = keysFromSecret(s.server);
    try testing.expectEqualSlices(u8, &hex("cf3a5331653c364c88f0f379b6067e37"), &k.key);
    try testing.expectEqualSlices(u8, &hex("0ac1493ca1905853b0bba03e"), &k.iv);
    try testing.expectEqualSlices(u8, &hex("c206b8d9b9f0f37644430b490eeaa314"), &k.hp);
}

// RFC 9001 A.2 publishes the sample taken from the client Initial packet and
// the mask it produces, so the AES step can be checked without a parser.
test "RFC 9001 A.2 header protection mask" {
    const hp = keysFromSecret(initialSecrets(&hex("8394c8f03e515708")).client).hp;
    const mask = headerMask(hp, hex("d1b1c98dd7689fb8ec11d242b123dc9b"));
    try testing.expectEqualSlices(u8, &hex("437b9aec36"), &mask);
}

// A different connection id must give different keys, or the salt is being
// used on its own somewhere and every connection shares protection.
test "keys are bound to the connection id" {
    const a = keysFromSecret(initialSecrets(&hex("8394c8f03e515708")).client);
    const b = keysFromSecret(initialSecrets(&hex("0000000000000000")).client);
    try testing.expect(!std.mem.eql(u8, &a.key, &b.key));
}
