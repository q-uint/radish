//! Radicle Repository Identifier (RID): `rad:z<base58btc(oid)>` where `oid`
//! is the 20-byte git SHA-1 of the canonical identity document blob.
//!
//! The character after `rad:` is a multibase tag. Radicle only permits
//! base58btc (`z`); any other base decodes but is rejected.
const std = @import("std");
const base58 = @import("base58.zig");
const git = @import("git.zig");

const RAD_PREFIX = "rad:";
const MULTIBASE_BTC = 'z';
const OID_LEN = 20;

pub const Error = error{
    MissingPrefix,
    MismatchedBaseEncoding,
    InvalidLength,
} || base58.Error;

pub const RepoId = struct {
    oid: git.Oid,

    pub fn fromOid(oid: git.Oid) RepoId {
        return .{ .oid = oid };
    }

    /// Derives the RID from the canonical identity-document bytes.
    pub fn fromDoc(doc: []const u8) git.Error!RepoId {
        return .{ .oid = try git.hashBlob(doc) };
    }

    /// Parses `rad:z...` (the `rad:` prefix is optional, matching Heartwood's
    /// from_urn convenience).
    pub fn parse(allocator: std.mem.Allocator, input: []const u8) Error!RepoId {
        const s = if (std.mem.startsWith(u8, input, RAD_PREFIX))
            input[RAD_PREFIX.len..]
        else
            input;

        if (s.len == 0) return error.MissingPrefix;
        if (s[0] != MULTIBASE_BTC) return error.MismatchedBaseEncoding;

        const bytes = try base58.decode(allocator, s[1..]);
        defer allocator.free(bytes);
        if (bytes.len != OID_LEN) return error.InvalidLength;

        var rid: RepoId = undefined;
        @memcpy(&rid.oid, bytes);
        return rid;
    }

    /// Renders the RID as `rad:z...`. Caller owns the result.
    pub fn encode(self: RepoId, allocator: std.mem.Allocator) base58.Error![]u8 {
        const b58 = try base58.encode(allocator, &self.oid);
        defer allocator.free(b58);

        var out = try allocator.alloc(u8, RAD_PREFIX.len + 1 + b58.len);
        @memcpy(out[0..RAD_PREFIX.len], RAD_PREFIX);
        out[RAD_PREFIX.len] = MULTIBASE_BTC;
        @memcpy(out[RAD_PREFIX.len + 1 ..], b58);
        return out;
    }
};

const testing = std.testing;

test "round trip" {
    var oid: git.Oid = undefined;
    var prng = std.Random.DefaultPrng.init(0xc0ffee);
    prng.random().bytes(&oid);

    const rid = RepoId.fromOid(oid);
    const s = try rid.encode(testing.allocator);
    defer testing.allocator.free(s);
    try testing.expect(std.mem.startsWith(u8, s, "rad:z"));

    const back = try RepoId.parse(testing.allocator, s);
    try testing.expectEqualSlices(u8, &oid, &back.oid);
}

test "heartwood vector parse round trip" {
    // Source: heartwood examples (e.g. crates/radicle-cli/examples/rad-node.md).
    // https://codeberg.org/radicle/heartwood
    const input = "rad:z42hL2jL4XNk6K8oHQaSWfMgCL7ji";
    const rid = try RepoId.parse(testing.allocator, input);
    const s = try rid.encode(testing.allocator);
    defer testing.allocator.free(s);
    try testing.expectEqualStrings(input, s);
}

test "parse accepts missing rad prefix" {
    const rid = try RepoId.parse(testing.allocator, "z42hL2jL4XNk6K8oHQaSWfMgCL7ji");
    const s = try rid.encode(testing.allocator);
    defer testing.allocator.free(s);
    try testing.expectEqualStrings("rad:z42hL2jL4XNk6K8oHQaSWfMgCL7ji", s);
}

test "parse rejects non-base58btc multibase" {
    // 'f' is the multibase tag for base16; must be rejected, not decoded.
    try testing.expectError(error.MismatchedBaseEncoding, RepoId.parse(testing.allocator, "rad:fdeadbeef"));
}

test "fromDoc matches git hash-object" {
    // `printf '%s' '{"payload":{},"delegates":[],"threshold":1}' | git hash-object --stdin`
    //   -> cf486bcaca813b85095310f78385dd17a2a930f1
    // (Placeholder doc bytes: exercises the derivation pipeline, not the real
    // canonical-JSON doc schema, which is a later slice.)
    const doc = "{\"payload\":{},\"delegates\":[],\"threshold\":1}";
    const rid = try RepoId.fromDoc(doc);

    const expected_oid = [_]u8{
        0xcf, 0x48, 0x6b, 0xca, 0xca, 0x81, 0x3b, 0x85, 0x09, 0x53,
        0x10, 0xf7, 0x83, 0x85, 0xdd, 0x17, 0xa2, 0xa9, 0x30, 0xf1,
    };
    try testing.expectEqualSlices(u8, &expected_oid, &rid.oid);

    const s = try rid.encode(testing.allocator);
    defer testing.allocator.free(s);
    const back = try RepoId.parse(testing.allocator, s);
    try testing.expectEqualSlices(u8, &rid.oid, &back.oid);
}

test "parse rejects wrong length" {
    // Valid base58btc but decodes to != 20 bytes.
    try testing.expectError(error.InvalidLength, RepoId.parse(testing.allocator, "rad:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"));
}
