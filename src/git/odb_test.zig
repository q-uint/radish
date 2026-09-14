//! Integration tests for `odb.zig`, over packs built by real `git` (see
//! testfixture.zig).
const std = @import("std");
const gitpack = @import("gitpack");
const storage = @import("storage.zig");
const fixture = @import("testfixture.zig");

const testing = std.testing;
const alloc = testing.allocator;

/// The oid an object has by definition: SHA-1 over "<type> <len>\x00" and the
/// content. Recomputing it is what proves we read the right bytes with the
/// right type, deltas and all. Source: gitformat-pack.
fn oidOf(obj: anytype) gitpack.Oid {
    var h = std.crypto.hash.Sha1.init(.{});
    var hdr: [32]u8 = undefined;
    h.update(std.fmt.bufPrint(&hdr, "{s} {d}\x00", .{ obj.type.name(), obj.data.len }) catch unreachable);
    h.update(obj.data);
    return gitpack.Oid.fromBytes(.sha1, &h.finalResult());
}

/// `s` over and over, long enough that git bothers to delta it.
fn repeat(gpa: std.mem.Allocator, s: []const u8, times: usize) ![]u8 {
    const out = try gpa.alloc(u8, s.len * times);
    for (0..times) |i| @memcpy(out[i * s.len ..][0..s.len], s);
    return out;
}

test "every object in a pack reads back as itself" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);

    // Two revisions of one long file, which is what gives git a reason to
    // store the second as a delta against the first.
    const first = try repeat(alloc, "line one\n", 400);
    defer alloc.free(first);
    const second = try repeat(alloc, "line one\n", 400);
    defer alloc.free(second);
    @memcpy(second[1800..][0..9], "line two\n");

    _ = try s.repo.commit("main", "big.txt", first);
    _ = try s.repo.commit("main", "big.txt", second);
    _ = try s.repo.commit("main", "other.txt", "hi");
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();

    const oids = try fixture.packOids(alloc, bare);
    defer alloc.free(oids);
    try testing.expect(oids.len >= 6);

    var blobs: usize = 0;
    var commits: usize = 0;
    var trees: usize = 0;
    for (oids) |oid| {
        const obj = try repo.odb.read(alloc, oid);
        defer obj.deinit(alloc);
        try testing.expectEqualSlices(u8, oid.slice(), oidOf(obj).slice());
        switch (obj.type) {
            .blob => blobs += 1,
            .commit => commits += 1,
            .tree => trees += 1,
            .tag => {},
        }
    }
    try testing.expectEqual(@as(usize, 3), commits);
    try testing.expect(blobs >= 3);
    try testing.expect(trees >= 3);

    // One of those blobs is the file as first committed, byte for byte.
    var found = false;
    for (oids) |oid| {
        const obj = try repo.odb.read(alloc, oid);
        defer obj.deinit(alloc);
        if (obj.type == .blob and std.mem.eql(u8, obj.data, first)) found = true;
    }
    try testing.expect(found);
}

test "an oid the pack does not hold is missing rather than wrong" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);
    _ = try s.repo.commit("main", "f", "hi");
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();

    const absent = try gitpack.Oid.parse(.sha1, "0123456789abcdef0123456789abcdef01234567");
    try testing.expectEqual(@as(?u64, null), try repo.odb.offsetOf(absent));
    try testing.expectError(error.ObjectMissing, repo.odb.read(alloc, absent));
}
