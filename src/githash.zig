//! Git's object id and the hash that produces one. A blob's oid is the SHA-1
//! of "blob <len>\0" ++ content, so hashing an identity document yields its
//! RID.
const std = @import("std");

pub const Oid = [20]u8;

/// Computes the git blob object id of `content`.
pub fn blob(content: []const u8) Oid {
    var h = std.crypto.hash.Sha1.init(.{});
    var hdr: [32]u8 = undefined;
    h.update(std.fmt.bufPrint(&hdr, "blob {d}\x00", .{content.len}) catch unreachable);
    h.update(content);
    return h.finalResult();
}

const testing = std.testing;

fn expectOid(comptime hex: []const u8, content: []const u8) !void {
    const oid = blob(content);
    var buf: [40]u8 = undefined;
    _ = std.fmt.bufPrint(&buf, "{x}", .{oid}) catch unreachable;
    try testing.expectEqualStrings(hex, &buf);
}

test "blob oids match git hash-object" {
    // printf '' | git hash-object --stdin
    try expectOid("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391", "");
    // printf 'hello\n' | git hash-object --stdin
    try expectOid("ce013625030ba8dba906f756967f9e9ca394464a", "hello\n");
}
