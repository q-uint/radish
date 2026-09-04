//! Radicle Node ID: an Ed25519 public key encoded as a did:key-style
//! multibase string, e.g. `z6Mk...`.
//!
//! Wire format of the decoded payload:
//!   [0xed, 0x01] ++ <32-byte ed25519 public key>
//! multibase-wrapped with a leading 'z' (base58btc).
const std = @import("std");
const base58 = @import("../crypto/base58.zig");

const MULTICODEC_ED25519 = [2]u8{ 0xed, 0x01 };
const KEY_LEN = 32;
const MULTIBASE_BTC = 'z';

pub const Error = error{
    InvalidMultibase,
    InvalidMulticodec,
    InvalidLength,
} || base58.Error;

pub const NodeId = struct {
    key: [KEY_LEN]u8,

    pub fn fromPublicKey(key: [KEY_LEN]u8) NodeId {
        return .{ .key = key };
    }

    /// Longest `z6Mk...` string that can hold a valid NodeId, and the buffer a
    /// decode of one needs. Both are comptime, so parsing needs no allocator.
    const payload_len = MULTICODEC_ED25519.len + KEY_LEN;
    const max_encoded = base58.encodedLenMax(payload_len);

    /// Parses a `z6Mk...` human-encoding into a NodeId.
    pub fn parse(s: []const u8) Error!NodeId {
        if (s.len == 0 or s[0] != MULTIBASE_BTC) return error.InvalidMultibase;
        if (s.len - 1 > max_encoded) return error.InvalidLength;

        // An all-'1' input maps every character to a zero byte, so that, not
        // the base58 ratio, is the worst case this has to hold.
        var buf: [max_encoded + 1]u8 = undefined;
        const decoded = try base58.decodeBuf(&buf, s[1..]);

        if (decoded.len != payload_len) return error.InvalidLength;
        if (!std.mem.eql(u8, decoded[0..2], &MULTICODEC_ED25519)) return error.InvalidMulticodec;

        var nid: NodeId = undefined;
        @memcpy(&nid.key, decoded[2..]);
        return nid;
    }

    /// Renders the NodeId as a `z6Mk...` string. Caller owns the result.
    pub fn encode(self: NodeId, allocator: std.mem.Allocator) base58.Error![]u8 {
        var payload: [MULTICODEC_ED25519.len + KEY_LEN]u8 = undefined;
        @memcpy(payload[0..2], &MULTICODEC_ED25519);
        @memcpy(payload[2..], &self.key);

        const b58 = try base58.encode(allocator, &payload);
        defer allocator.free(b58);

        var out = try allocator.alloc(u8, 1 + b58.len);
        out[0] = MULTIBASE_BTC;
        @memcpy(out[1..], b58);
        return out;
    }
};

const testing = std.testing;

test "round trip, always through a z6Mk prefix" {
    var key: [KEY_LEN]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xc0ffee);
    prng.random().bytes(&key);

    const nid = NodeId.fromPublicKey(key);
    const s = try nid.encode(testing.allocator);
    defer testing.allocator.free(s);
    // Multicodec 0xed01 in front of a 32-byte key always yields a `z6Mk` prefix.
    try testing.expect(std.mem.startsWith(u8, s, "z6Mk"));

    const back = try NodeId.parse(s);
    try testing.expectEqualSlices(u8, &key, &back.key);
}

test "heartwood did vectors re-encode to themselves" {
    // Source: heartwood crates/radicle/src/identity/did.rs test_did_vectors.
    const vectors = [_][]const u8{
        "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
        "z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG",
        "z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf",
        "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    };
    for (vectors) |v| {
        const s = try (try NodeId.parse(v)).encode(testing.allocator);
        defer testing.allocator.free(s);
        try testing.expectEqualStrings(v, s);
    }
}

test "parse rejects a bad multibase, or a legal-length string that decodes short" {
    try testing.expectError(error.InvalidMultibase, NodeId.parse("x6Mk"));

    // Leading '1's decode 1:1 to zero bytes, so this is the longest decoding a
    // valid-length input can produce: the wrong length, not a buffer overrun.
    var ones: [1 + NodeId.max_encoded]u8 = @splat('1');
    ones[0] = MULTIBASE_BTC;
    try testing.expectError(error.InvalidLength, NodeId.parse(&ones));
}
