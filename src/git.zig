//! Minimal git object hashing. A git blob's object id is the SHA-1 of
//! "blob <len>\0" ++ content. Used to derive the RID from the identity doc.
const std = @import("std");

pub const Oid = [20]u8;

/// Computes the git blob object id (SHA-1) of `content`.
pub fn hashBlob(content: []const u8) Oid {
    var h = std.crypto.hash.Sha1.init(.{});
    var header: [32]u8 = undefined;
    const prefix = std.fmt.bufPrint(&header, "blob {d}\x00", .{content.len}) catch unreachable;
    h.update(prefix);
    h.update(content);
    return h.finalResult();
}

const testing = std.testing;

test "empty blob matches git hash-object" {
    // `printf '' | git hash-object --stdin` -> e69de29bb2d1d6434b8b29ae775ad8c2e48c5391
    const oid = hashBlob("");
    var hex: [40]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{oid}) catch unreachable;
    try testing.expectEqualStrings("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391", &hex);
}

test "hello blob matches git hash-object" {
    // `printf 'hello\n' | git hash-object --stdin` -> ce013625030ba8dba906f756967f9e9ca394464a
    const oid = hashBlob("hello\n");
    var hex: [40]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{oid}) catch unreachable;
    try testing.expectEqualStrings("ce013625030ba8dba906f756967f9e9ca394464a", &hex);
}
