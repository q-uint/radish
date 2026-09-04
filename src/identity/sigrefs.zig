//! Signed refs (`refs/rad/sigrefs`).
//!
//! A node publishes the tips of its refs, signed with its key. The signed
//! message is the canonical encoding of the ref set: for each (name, oid) in
//! name-sorted order,
//!     <40-hex-oid> <refname>\n
//! excluding the sigrefs branch itself and zero oids.
//! Source: radicle/src/storage/refs.rs (Refs::canonical, SignedRefs).
const std = @import("std");
const git = @import("../git/git.zig");
const node_id = @import("node_id.zig");
const signature = @import("../crypto/signature.zig");

pub const SIGREFS_BRANCH = "refs/rad/sigrefs";

pub const Ref = struct { name: []const u8, oid: git.Oid };

pub const Refs = struct {
    entries: []const Ref,

    /// Canonical signed-message bytes. Caller owns the result.
    /// Entries are sorted by name; the sigrefs branch and zero oids are skipped.
    pub fn canonical(self: Refs, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        const sorted = try allocator.dupe(Ref, self.entries);
        defer allocator.free(sorted);
        std.mem.sort(Ref, sorted, {}, struct {
            fn lt(_: void, a: Ref, b: Ref) bool {
                return std.mem.lessThan(u8, a.name, b.name);
            }
        }.lt);

        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        for (sorted) |r| {
            if (std.mem.eql(u8, r.name, SIGREFS_BRANCH)) continue;
            if (isZero(r.oid)) continue;
            var hex: [40]u8 = undefined;
            _ = std.fmt.bufPrint(&hex, "{x}", .{r.oid}) catch unreachable;
            try out.appendSlice(allocator, &hex);
            try out.append(allocator, ' ');
            try out.appendSlice(allocator, r.name);
            try out.append(allocator, '\n');
        }
        return out.toOwnedSlice(allocator);
    }

    /// Signs the canonical refs with `key`.
    pub fn sign(self: Refs, allocator: std.mem.Allocator, key: signature.SecretKey) !SignedRefs {
        const msg = try self.canonical(allocator);
        defer allocator.free(msg);
        return .{ .refs = self, .id = key.nodeId(), .sig = try key.sign(msg) };
    }
};

pub const SignedRefs = struct {
    refs: Refs,
    id: node_id.NodeId,
    sig: signature.Signature,

    /// Verifies the signature over the canonical refs.
    pub fn verify(self: SignedRefs, allocator: std.mem.Allocator) !void {
        const msg = try self.refs.canonical(allocator);
        defer allocator.free(msg);
        try signature.verify(self.id, msg, self.sig);
    }
};

fn isZero(oid: git.Oid) bool {
    return std.mem.allEqual(u8, &oid, 0);
}

const testing = std.testing;

fn oidFromHex(comptime hex: *const [40]u8) git.Oid {
    var oid: git.Oid = undefined;
    _ = std.fmt.hexToBytes(&oid, hex) catch unreachable;
    return oid;
}

test "canonical is sorted by name, skipping the sigrefs branch and zero oids" {
    const a = oidFromHex("1111111111111111111111111111111111111111");
    const b = oidFromHex("2222222222222222222222222222222222222222");
    const refs = Refs{ .entries = &.{
        .{ .name = "refs/heads/master", .oid = b },
        .{ .name = "refs/rad/sigrefs", .oid = a },
        .{ .name = "refs/heads/gone", .oid = @splat(0) },
        .{ .name = "refs/heads/dev", .oid = a },
    } };
    const c = try refs.canonical(testing.allocator);
    defer testing.allocator.free(c);
    try testing.expectEqualStrings(
        \\1111111111111111111111111111111111111111 refs/heads/dev
        \\2222222222222222222222222222222222222222 refs/heads/master
        \\
    , c);
}

test "verify accepts a signed ref set, and rejects a tampered one" {
    const key = try signature.SecretKey.fromSeed(@splat(7));
    const a = oidFromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    const b = oidFromHex("0000000000000000000000000000000000000001");
    const refs = Refs{ .entries = &.{.{ .name = "refs/heads/master", .oid = a }} };

    var signed = try refs.sign(testing.allocator, key);
    try signed.verify(testing.allocator);

    // Swap the refs out from under the signature.
    signed.refs = Refs{ .entries = &.{.{ .name = "refs/heads/master", .oid = b }} };
    try testing.expectError(error.SignatureVerificationFailed, signed.verify(testing.allocator));
}
