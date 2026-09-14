//! Integration tests for `walk.zig`, over packs built by real `git` (see
//! testfixture.zig).
const std = @import("std");
const gitpack = @import("gitpack");
const storage = @import("storage.zig");
const walk = @import("walk.zig");
const fixture = @import("testfixture.zig");

const testing = std.testing;
const alloc = testing.allocator;

fn has(oids: []const gitpack.Oid, want: gitpack.Oid) bool {
    for (oids) |o| {
        if (std.mem.eql(u8, o.slice(), want.slice())) return true;
    }
    return false;
}

test "the closure of a tip is the whole pack, and a have prunes it" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);

    const first = try s.repo.commit("main", "a.txt", "one\n");
    const second = try s.repo.commit("main", "b.txt", "two\n");
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();

    const head = try gitpack.Oid.parse(.sha1, second);
    const base = try gitpack.Oid.parse(.sha1, first);

    const all = try walk.missing(alloc, &repo.odb, &.{head}, &.{});
    defer alloc.free(all);

    // Everything the pack holds is reachable from the head, and the walk finds
    // exactly that: git's own answer is the expectation.
    const packed_oids = try fixture.packOids(alloc, bare);
    defer alloc.free(packed_oids);
    try testing.expectEqual(packed_oids.len, all.len);
    for (packed_oids) |o| try testing.expect(has(all, o));

    // Told the peer already has the first commit, we owe strictly less, and
    // nothing from behind that commit.
    const rest = try walk.missing(alloc, &repo.odb, &.{head}, &.{base});
    defer alloc.free(rest);
    try testing.expect(rest.len < all.len);
    try testing.expect(has(rest, head));
    try testing.expect(!has(rest, base));
}

test "a want we do not hold is refused, but a have we do not hold only prunes nothing" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);
    const only = try s.repo.commit("main", "a.txt", "one\n");
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();

    const head = try gitpack.Oid.parse(.sha1, only);
    const absent = try gitpack.Oid.parse(.sha1, "0123456789abcdef0123456789abcdef01234567");

    // A pack missing what was asked for would look complete, so this is fatal.
    try testing.expectError(
        error.ObjectMissing,
        walk.missing(alloc, &repo.odb, &.{absent}, &.{}),
    );

    // A have out of a history we never stored costs us only a larger pack.
    const all = try walk.missing(alloc, &repo.odb, &.{head}, &.{});
    defer alloc.free(all);
    const with_have = try walk.missing(alloc, &repo.odb, &.{head}, &.{absent});
    defer alloc.free(with_have);
    try testing.expectEqual(all.len, with_have.len);
}

// A merge reaches both sides, and a walk that followed only the first parent
// would quietly leave one branch out of the pack.
test "a merge commit reaches both of its parents" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);

    _ = try s.repo.commit("main", "base.txt", "base\n");
    const side = try s.repo.commit("side", "side.txt", "side\n");
    const merged = try s.repo.merge("main", "side");
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();

    const all = try walk.missing(
        alloc,
        &repo.odb,
        &.{try gitpack.Oid.parse(.sha1, merged)},
        &.{},
    );
    defer alloc.free(all);
    try testing.expect(has(all, try gitpack.Oid.parse(.sha1, side)));
}
