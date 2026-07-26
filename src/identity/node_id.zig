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

    /// Parses a `z6Mk...` human-encoding into a NodeId.
    pub fn parse(allocator: std.mem.Allocator, s: []const u8) Error!NodeId {
        if (s.len == 0 or s[0] != MULTIBASE_BTC) return error.InvalidMultibase;
        const decoded = try base58.decode(allocator, s[1..]);
        defer allocator.free(decoded);

        if (decoded.len != MULTICODEC_ED25519.len + KEY_LEN) return error.InvalidLength;
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

test "encode has z6Mk structure" {
    // Multicodec 0xed01 in front of a 32-byte key always yields a `z6Mk` prefix.
    const nid = NodeId.fromPublicKey(@splat(0));
    const s = try nid.encode(testing.allocator);
    defer testing.allocator.free(s);
    try testing.expect(std.mem.startsWith(u8, s, "z6Mk"));
}

test "round trip" {
    var key: [KEY_LEN]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xc0ffee);
    prng.random().bytes(&key);

    const nid = NodeId.fromPublicKey(key);
    const s = try nid.encode(testing.allocator);
    defer testing.allocator.free(s);

    const back = try NodeId.parse(testing.allocator, s);
    try testing.expectEqualSlices(u8, &key, &back.key);
}

test "heartwood vectors decode" {
    // Source: heartwood crates/radicle/src/identity/did.rs test_did_vectors.
    // https://codeberg.org/radicle/heartwood/blob/master/crates/radicle/src/identity/did.rs
    const vectors = [_][]const u8{
        "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
        "z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG",
        "z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf",
    };
    for (vectors) |v| {
        _ = try NodeId.parse(testing.allocator, v);
    }
}

test "heartwood encode-decode round trip" {
    // Source: heartwood did.rs test_did_encode_decode: decode then re-encode
    // must reproduce the input string exactly.
    const input = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    const nid = try NodeId.parse(testing.allocator, input);
    const s = try nid.encode(testing.allocator);
    defer testing.allocator.free(s);
    try testing.expectEqualStrings(input, s);
}

test "parse rejects bad multibase" {
    try testing.expectError(error.InvalidMultibase, NodeId.parse(testing.allocator, "x6Mk"));
}
