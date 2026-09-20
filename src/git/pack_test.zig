//! Integration tests for `pack.zig`. What we write is handed to real `git`,
//! since a pack only counts as valid if the peer's git accepts it.
const std = @import("std");
const gitpack = @import("gitpack");
const pack = @import("pack.zig");
const storage = @import("storage.zig");
const walk = @import("walk.zig");
const fixture = @import("testfixture.zig");

const testing = std.testing;
const alloc = testing.allocator;

/// Writes `oids` out of `repo` to `<root>/<name>` and has git index it.
/// Returns how many objects git found.
fn indexed(
    root: []const u8,
    name: []const u8,
    repo: *storage.Repository,
    oids: []const gitpack.Oid,
) !usize {
    const path = try std.fmt.allocPrint(alloc, "{s}/{s}", .{ root, name });
    defer alloc.free(path);

    {
        var buf: [4096]u8 = undefined;
        const file = try std.Io.Dir.cwd().createFile(testing.io, path, .{});
        defer file.close(testing.io);
        var fw = file.writer(testing.io, &buf);

        try pack.write(alloc, &fw.interface, &repo.odb, oids);
        try fw.interface.flush();
    }
    return fixture.indexPack(alloc, path);
}

// git rejects a malformed pack outright, so reaching a count at all is most of
// what this proves.
test "git indexes a pack we wrote, whole, partial or empty" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);

    const base = try s.repo.commit("main", "a.txt", "one\n");
    const head = try s.repo.commit("main", "b.txt", "two\n");
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();

    const tip = try gitpack.Oid.parse(.sha1, head);
    const whole = try walk.missing(alloc, &repo.odb, &.{tip}, &.{});
    defer alloc.free(whole);

    // A pack carrying only part of a history is the normal case once a peer
    // says what it already has, and it has to stand on its own as a pack.
    const partial = try walk.missing(
        alloc,
        &repo.odb,
        &.{tip},
        &.{try gitpack.Oid.parse(.sha1, base)},
    );
    defer alloc.free(partial);
    try testing.expect(partial.len > 0 and partial.len < whole.len);

    try testing.expectEqual(whole.len, try indexed(s.repo.root, "whole.pack", repo, whole));
    try testing.expectEqual(partial.len, try indexed(s.repo.root, "partial.pack", repo, partial));
    // Nothing to send is still a pack.
    try testing.expectEqual(@as(usize, 0), try indexed(s.repo.root, "empty.pack", repo, &.{}));
}
