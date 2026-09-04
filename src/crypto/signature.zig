//! Ed25519 signing for Radicle.
//!
//! A Signature is 64 bytes; its human form is multibase base58btc (`z...`),
//! with NO multicodec prefix (unlike a NodeId/public key).
//! Source: heartwood crates/radicle-crypto/src/lib.rs (Signature Display/FromStr).
const std = @import("std");
const base58 = @import("base58.zig");
const node_id = @import("../identity/node_id.zig");

const Ed = std.crypto.sign.Ed25519;
const SIG_LEN = Ed.Signature.encoded_length; // 64
const SEED_LEN = Ed.KeyPair.seed_length; // 32
const MULTIBASE_BTC = 'z';

pub const Error = error{ InvalidMultibase, InvalidLength } || base58.Error;

pub const Signature = struct {
    bytes: [SIG_LEN]u8,

    /// Renders as multibase base58btc (`z...`). Caller owns the result.
    pub fn encode(self: Signature, allocator: std.mem.Allocator) base58.Error![]u8 {
        const b58 = try base58.encode(allocator, &self.bytes);
        defer allocator.free(b58);
        var out = try allocator.alloc(u8, 1 + b58.len);
        out[0] = MULTIBASE_BTC;
        @memcpy(out[1..], b58);
        return out;
    }

    const max_encoded = base58.encodedLenMax(SIG_LEN);

    pub fn parse(s: []const u8) Error!Signature {
        if (s.len == 0 or s[0] != MULTIBASE_BTC) return error.InvalidMultibase;
        if (s.len - 1 > max_encoded) return error.InvalidLength;

        // An all-'1' input maps every character to a zero byte, so that, not
        // the base58 ratio, is the worst case this has to hold.
        var buf: [max_encoded + 1]u8 = undefined;
        const decoded = try base58.decodeBuf(&buf, s[1..]);
        if (decoded.len != SIG_LEN) return error.InvalidLength;
        var sig: Signature = undefined;
        @memcpy(&sig.bytes, decoded);
        return sig;
    }
};

pub const SecretKey = struct {
    pair: Ed.KeyPair,

    /// Derives a key pair from a 32-byte seed (the RFC 8032 secret key).
    pub fn fromSeed(seed: [SEED_LEN]u8) !SecretKey {
        return .{ .pair = try Ed.KeyPair.generateDeterministic(seed) };
    }

    pub fn nodeId(self: SecretKey) node_id.NodeId {
        return node_id.NodeId.fromPublicKey(self.pair.public_key.toBytes());
    }

    pub fn sign(self: SecretKey, msg: []const u8) !Signature {
        const s = try self.pair.sign(msg, null);
        return .{ .bytes = s.toBytes() };
    }
};

/// Verifies `sig` over `msg` under the public key in `nid`.
pub fn verify(nid: node_id.NodeId, msg: []const u8, sig: Signature) !void {
    const pk = try Ed.PublicKey.fromBytes(nid.key);
    const s = Ed.Signature.fromBytes(sig.bytes);
    try s.verify(msg, pk);
}

const testing = std.testing;

// RFC 8032 Section 7.1, TEST 2.
// https://www.rfc-editor.org/rfc/rfc8032#section-7.1
const RFC_SEED = [_]u8{
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46,
    0xec, 0x11, 0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
    0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
};
const RFC_MSG = [_]u8{0x72};
const RFC_SIG = [_]u8{
    0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8, 0x72, 0x0e, 0x82, 0x0b,
    0x5f, 0x64, 0x25, 0x40, 0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f,
    0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb, 0x69, 0xda, 0x08, 0x5a, 0xc1, 0xe4,
    0x3e, 0x15, 0x99, 0x6e, 0x45, 0x8f, 0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c,
    0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee, 0xb0, 0x0d, 0x29, 0x16,
    0x12, 0xbb, 0x0c, 0x00,
};

test "sign matches RFC 8032 TEST 2, and verify accepts only that message" {
    const sk = try SecretKey.fromSeed(RFC_SEED);
    const sig = try sk.sign(&RFC_MSG);
    try testing.expectEqualSlices(u8, &RFC_SIG, &sig.bytes);
    try verify(sk.nodeId(), &RFC_MSG, sig);
    try testing.expectError(error.SignatureVerificationFailed, verify(sk.nodeId(), "wrong", sig));
}

test "signature string round trips" {
    const sk = try SecretKey.fromSeed(RFC_SEED);
    const sig = try sk.sign(&RFC_MSG);
    const s = try sig.encode(testing.allocator);
    defer testing.allocator.free(s);
    try testing.expect(s[0] == 'z');

    const back = try Signature.parse(s);
    try testing.expectEqualSlices(u8, &sig.bytes, &back.bytes);
}
