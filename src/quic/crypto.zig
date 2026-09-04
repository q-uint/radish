//! QUIC packet protection keys (RFC 9001 s5.1, s5.2).
//!
//! Initial keys come from a constant published in the RFC rather than from a
//! handshake, so the first packet on a connection is already protected.
//! HKDF-Expand-Label is TLS 1.3's, adopted unchanged (RFC 8446 s7.1).
const std = @import("std");

const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const expandLabel = std.crypto.tls.hkdfExpandLabel;

/// Published, so Initial packets are authenticated but not confidential.
/// Source: RFC 9001 s5.2.
pub const initial_salt = [_]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

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
    return .{
        .client = expandLabel(Hkdf, initial, "client in", "", Hkdf.prk_length),
        .server = expandLabel(Hkdf, initial, "server in", "", Hkdf.prk_length),
    };
}

const Aead = std.crypto.aead.aes_gcm.Aes128Gcm;

pub const Key = [Aead.key_length]u8;
pub const Iv = [Aead.nonce_length]u8;

/// One direction's protection. `hp` is separate from `key` so header masking
/// cannot be derived from payload keys. Sized for AEAD_AES_128_GCM, which
/// Initial packets always use; becomes a union once TLS can negotiate another.
pub const Keys = struct {
    key: Key,
    iv: Iv,
    hp: Key,
};

/// Source: RFC 9001 s5.1.
pub fn keysFromSecret(secret: [Hkdf.prk_length]u8) Keys {
    return .{
        .key = expandLabel(Hkdf, secret, "quic key", "", @sizeOf(Key)),
        .iv = expandLabel(Hkdf, secret, "quic iv", "", @sizeOf(Iv)),
        .hp = expandLabel(Hkdf, secret, "quic hp", "", @sizeOf(Key)),
    };
}

pub const sample_len = 16;

/// One byte for the first byte, four for the longest packet number.
pub const mask_len = 5;

/// Header mask from a sample of the packet's own ciphertext. ECB is safe here
/// because exactly one block is encrypted per packet under a key that protects
/// nothing else. Entangles the layers: the header cannot change without
/// invalidating the payload.
/// Source: RFC 9001 s5.4.3.
pub fn headerMask(hp: Key, sample: [sample_len]u8) [mask_len]u8 {
    var block: [16]u8 = undefined;
    std.crypto.core.aes.Aes128.initEnc(hp).encrypt(&block, &sample);
    return block[0..mask_len].*;
}

const testing = std.testing;
const testdata = @import("testdata.zig");
const hex = testdata.hex;

// The whole chain, both directions. Matching key/iv/hp pins every step above
// them, since each is expanded from the one before.
test "RFC 9001 A.1 key schedule" {
    const dcid = hex(testdata.rfc9001_dcid);
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

    // A.2's header protection mask, from the client hp key above.
    try testing.expectEqualSlices(
        u8,
        &hex("437b9aec36"),
        &headerMask(keysFromSecret(s.client).hp, hex("d1b1c98dd7689fb8ec11d242b123dc9b")),
    );
}

// Keys must depend on the connection id and on the direction, or the salt is
// being used alone somewhere and every connection shares protection.
test "keys are bound to connection id and direction" {
    const a = initialSecrets(&hex(testdata.rfc9001_dcid));
    const b = initialSecrets(&hex("0000000000000000"));
    try testing.expect(!std.mem.eql(u8, &keysFromSecret(a.client).key, &keysFromSecret(b.client).key));
    try testing.expect(!std.mem.eql(u8, &keysFromSecret(a.client).key, &keysFromSecret(a.server).key));
}
