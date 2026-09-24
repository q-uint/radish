//! Integration tests for `odb.zig`, over packs built by real `git` (see
//! testfixture.zig).
const std = @import("std");
const gitpack = @import("gitpack");
const odb = @import("odb.zig");
const storage = @import("storage.zig");
const fixture = @import("../testfixture.zig");

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

// `rad init` writes every object loose and packs none of them: `git gc` is
// heartwood's only packing, and it does nothing until thousands have piled up.
// A repository like that is most of what a node is asked to serve.
test "a repository with nothing packed reads its objects loose" {
    const s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);

    const first = try s.repo.commit("main", "a.txt", "one\n");
    const tip = try s.repo.commit("main", "b.txt", "two\n");
    const bare = try s.repo.looseOnly(tip);

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();
    try testing.expectEqual(@as(usize, 0), repo.packs.len);

    for ([_][]const u8{ first, tip }) |hex| {
        const oid = try storage.parseOid(hex);
        try testing.expect(try repo.odb.has(oid));
        try testing.expectEqual(@as(odb.Type, .commit), try repo.odb.typeOf(oid));

        const obj = try repo.odb.read(alloc, oid);
        defer obj.deinit(alloc);
        try testing.expectEqualSlices(u8, oid.slice(), oidOf(obj).slice());
    }
}

// What a repository looks like once it has been fetched into and collected at
// least once: some of it packed, whatever arrived since still loose.
test "objects are read across every pack and the loose ones" {
    const s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);

    const first = try s.repo.commit("main", "a.txt", "one\n");
    const second = try s.repo.commit("main", "b.txt", "two\n");
    const third = try s.repo.commit("main", "c.txt", "three\n");
    const since_first = try std.fmt.allocPrint(alloc, "{s} ^{s}", .{ second, first });
    defer alloc.free(since_first);
    const since_second = try std.fmt.allocPrint(alloc, "{s} ^{s}", .{ third, second });
    defer alloc.free(since_second);

    _ = try s.repo.packOnly(first);
    _ = try s.repo.packOnly(since_first);
    const bare = try s.repo.looseOnly(since_second);

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();
    try testing.expectEqual(@as(usize, 2), repo.packs.len);

    // One from each pack and one that was never packed.
    for ([_][]const u8{ first, second, third }) |hex| {
        const oid = try storage.parseOid(hex);
        const obj = try repo.odb.read(alloc, oid);
        defer obj.deinit(alloc);
        try testing.expectEqualSlices(u8, oid.slice(), oidOf(obj).slice());
    }
}

// Which source a lookup spends its work on. A packed object is found without
// opening a loose file, and a loose one is opened exactly once. How many packs
// get searched is not pinned: the fan-out gates them on the oid's first byte,
// so it depends on the hashes git happened to produce.
test "a packed read opens no loose file, and a loose read opens exactly one" {
    const s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);

    const packed_commit = try s.repo.commit("main", "a.txt", "one\n");
    const loose_commit = try s.repo.commit("main", "b.txt", "two\n");
    const since = try std.fmt.allocPrint(alloc, "{s} ^{s}", .{ loose_commit, packed_commit });
    defer alloc.free(since);

    _ = try s.repo.packOnly(packed_commit);
    const bare = try s.repo.looseOnly(since);

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();
    try testing.expectEqual(@as(usize, 1), repo.packs.len);

    {
        const obj = try repo.odb.read(alloc, try storage.parseOid(loose_commit));
        defer obj.deinit(alloc);
    }
    try testing.expectEqual(@as(usize, 1), repo.odb.stats.loose_opens);
    try testing.expectEqual(@as(usize, 1), repo.odb.stats.loose_hits);
    try testing.expect(repo.odb.stats.pack_searches <= repo.packs.len);

    repo.odb.stats = .{};
    {
        const obj = try repo.odb.read(alloc, try storage.parseOid(packed_commit));
        defer obj.deinit(alloc);
    }
    try testing.expectEqual(@as(usize, 1), repo.odb.stats.pack_searches);
    try testing.expectEqual(@as(usize, 0), repo.odb.stats.loose_opens);
}

// A damaged index costs whatever only that pack held, not the repository: the
// loose objects and any other pack still read, and the damage is counted so it
// is visible rather than silent. `git` degrades the same way.
test "a pack whose index will not parse is skipped and counted" {
    const s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);

    const packed_commit = try s.repo.commit("main", "a.txt", "one\n");
    const loose_commit = try s.repo.commit("main", "b.txt", "two\n");
    const since = try std.fmt.allocPrint(alloc, "{s} ^{s}", .{ loose_commit, packed_commit });
    defer alloc.free(since);

    _ = try s.repo.packOnly(packed_commit);
    const bare = try s.repo.looseOnly(since);

    // Replace the index git just wrote with garbage, which is what a damaged
    // one looks like to anything reading it. git writes packs read-only, so
    // the old file goes before the new one lands.
    {
        var dir = try std.Io.Dir.cwd().openDir(testing.io, bare, .{});
        defer dir.close(testing.io);
        var pack_dir = try dir.openDir(testing.io, "objects/pack", .{ .iterate = true });
        defer pack_dir.close(testing.io);

        var name_buf: [std.fs.max_name_bytes]u8 = undefined;
        var idx_name: ?[]const u8 = null;
        var it = pack_dir.iterate();
        while (try it.next(testing.io)) |entry| {
            if (!std.mem.endsWith(u8, entry.name, ".idx")) continue;
            @memcpy(name_buf[0..entry.name.len], entry.name);
            idx_name = name_buf[0..entry.name.len];
            break;
        }

        const name = idx_name orelse return error.NoIndexToDamage;
        try pack_dir.deleteFile(testing.io, name);
        try pack_dir.writeFile(testing.io, .{ .sub_path = name, .data = "XXXXXXXX" });
    }

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();
    try testing.expectEqual(@as(usize, 1), repo.damaged_packs);
    try testing.expectEqual(@as(usize, 0), repo.odb.packs.len);

    // What the broken pack held is gone.
    try testing.expect(!try repo.hasObject(try storage.parseOid(packed_commit)));
    // What it did not hold still reads.
    const obj = try repo.odb.read(alloc, try storage.parseOid(loose_commit));
    defer obj.deinit(alloc);
    try testing.expectEqual(@as(odb.Type, .commit), obj.type);
}

test "an oid the repository does not hold is missing rather than wrong" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);
    _ = try s.repo.commit("main", "f", "hi");
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();

    const absent = try gitpack.Oid.parse(.sha1, "0123456789abcdef0123456789abcdef01234567");
    try testing.expect(!try repo.odb.has(absent));
    try testing.expectError(error.ObjectMissing, repo.odb.read(alloc, absent));
}
