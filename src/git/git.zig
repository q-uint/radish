//! Git object types and operations, backed by libgit2. A blob's object id is
//! the SHA-1 of "blob <len>\0" ++ content; hashing a doc yields its RID.
const std = @import("std");
const git2 = @import("git2.zig");

pub const Oid = [20]u8;
pub const Error = git2.Error;

/// Computes the git blob object id of `content`.
pub fn hashBlob(content: []const u8) Error!Oid {
    var oid: git2.c.git_oid = undefined;
    try git2.check(git2.c.git_odb_hash(&oid, content.ptr, content.len, git2.c.GIT_OBJECT_BLOB));
    return oid.id;
}

const testing = std.testing;

fn expectOid(comptime hex: []const u8, content: []const u8) !void {
    const oid = try hashBlob(content);
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
