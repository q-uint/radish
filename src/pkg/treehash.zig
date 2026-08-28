//! Hashing a resolved dependency tree.
//!
//! This is radish's own hash, not Zig's. Zig's `.hash` is computed by its
//! package hasher over its own format, an implementation detail that moves
//! between nightlies, so matching it would be brittle. `.rad_hash` is a field
//! Zig ignores and radish checks.
//!
//! Path and content both feed the digest, in sorted path order, so the hash is
//! stable regardless of readdir order. Directories contribute nothing on their
//! own: an empty one is invisible, exactly as in git.

const std = @import("std");

pub const PREFIX = "radtree-1-";
/// Hex of a 32-byte digest, after the prefix.
pub const LEN = PREFIX.len + 64;

/// Hashes every file under `dir`. Caller owns the returned string.
pub fn hashDir(gpa: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) ![]u8 {
    var paths: std.ArrayList([]u8) = .empty;
    defer {
        for (paths.items) |p| gpa.free(p);
        paths.deinit(gpa);
    }

    var walker = try dir.walk(gpa);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        try paths.append(gpa, try gpa.dupe(u8, entry.path));
    }

    std.mem.sort([]u8, paths.items, {}, struct {
        fn lt(_: void, a: []u8, b: []u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);

    var h = std.crypto.hash.sha2.Sha256.init(.{});
    for (paths.items) |path| {
        const content = try dir.readFileAlloc(io, path, gpa, .unlimited);
        defer gpa.free(content);

        // Length-prefix both, so no path/content boundary can be forged by a
        // file whose name contains the separator.
        var len_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &len_buf, path.len, .big);
        h.update(&len_buf);
        h.update(path);
        std.mem.writeInt(u64, &len_buf, content.len, .big);
        h.update(&len_buf);
        h.update(content);
    }

    var digest: [32]u8 = undefined;
    h.final(&digest);
    return std.fmt.allocPrint(gpa, "{s}{x}", .{ PREFIX, &digest });
}

const testing = std.testing;

fn scratchDir(io: std.Io, name: []const u8) !std.Io.Dir {
    var tmp = try std.Io.Dir.openDirAbsolute(io, @import("build_options").tmp_dir, .{});
    defer tmp.close(io);
    tmp.deleteTree(io, name) catch {};
    return tmp.createDirPathOpen(io, name, .{});
}

test "hash is stable and covers content" {
    const io = testing.io;
    var dir = try scratchDir(io, "radish-treehash-a");
    defer dir.close(io);

    try dir.writeFile(io, .{ .sub_path = "a.txt", .data = "hello" });
    try dir.writeFile(io, .{ .sub_path = "b.txt", .data = "world" });

    const first = try hashDir(testing.allocator, io, dir);
    defer testing.allocator.free(first);
    const again = try hashDir(testing.allocator, io, dir);
    defer testing.allocator.free(again);
    try testing.expectEqualStrings(first, again);
    try testing.expectEqual(@as(usize, LEN), first.len);

    // Same paths, different bytes.
    try dir.writeFile(io, .{ .sub_path = "b.txt", .data = "WORLD" });
    const changed = try hashDir(testing.allocator, io, dir);
    defer testing.allocator.free(changed);
    try testing.expect(!std.mem.eql(u8, first, changed));
}

// Content alone is not enough: renaming a file changes the tree, so the path
// has to be in the digest too.
test "hash covers paths, not just content" {
    const io = testing.io;
    var dir = try scratchDir(io, "radish-treehash-b");
    defer dir.close(io);

    try dir.writeFile(io, .{ .sub_path = "one", .data = "x" });
    const before = try hashDir(testing.allocator, io, dir);
    defer testing.allocator.free(before);

    try dir.deleteFile(io, "one");
    try dir.writeFile(io, .{ .sub_path = "two", .data = "x" });
    const after = try hashDir(testing.allocator, io, dir);
    defer testing.allocator.free(after);

    try testing.expect(!std.mem.eql(u8, before, after));
}
