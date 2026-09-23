//! Integration tests for `checkout.zig`, against trees real `git` wrote.
const std = @import("std");
const fixture = @import("testfixture.zig");
const storage = @import("storage.zig");

const testing = std.testing;
const alloc = testing.allocator;

/// A directory beside the fixture's repo to check out into.
fn destination(s: *fixture.Scratch, name: []const u8) !std.Io.Dir {
    try s.tmp.dir.createDirPath(testing.io, name);
    return s.tmp.dir.openDir(testing.io, name, .{});
}

// Everything a tree can hold that is not a plain file: git records the
// executable bit in the entry's mode, keeps a symlink as a blob of its target,
// and nests trees inside trees.
test "a checkout writes files, the executable bit, symlinks and nested trees" {
    const s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);

    const tip = try s.repo.commitShell("main",
        \\printf 'one' > a.txt
        \\mkdir -p sub/deep && printf 'two' > sub/deep/b.txt
        \\printf '#!/bin/sh\n' > run.sh && chmod +x run.sh
        \\ln -sf a.txt link
    );
    // Loose, so this is also the checkout gitpack could not do at all.
    const bare = try s.repo.looseOnly(tip);

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();

    var dest = try destination(s, "out");
    defer dest.close(testing.io);
    try repo.checkoutTo(alloc, dest, try storage.parseOid(tip));

    const top = try dest.readFileAlloc(testing.io, "a.txt", alloc, .limited(64));
    defer alloc.free(top);
    try testing.expectEqualStrings("one", top);

    const nested = try dest.readFileAlloc(testing.io, "sub/deep/b.txt", alloc, .limited(64));
    defer alloc.free(nested);
    try testing.expectEqualStrings("two", nested);

    // The mode carries the file type as well, so the bit is what to look at,
    // and only the entry whose tree mode had it may have it.
    const script = try dest.statFile(testing.io, "run.sh", .{});
    try testing.expect(@backingInt(script.permissions) & 0o111 != 0);
    const plain = try dest.statFile(testing.io, "a.txt", .{});
    try testing.expect(@backingInt(plain.permissions) & 0o111 == 0);

    var target: [64]u8 = undefined;
    const n = try dest.readLink(testing.io, "link", &target);
    try testing.expectEqualStrings("a.txt", target[0..n]);
}

// A tree comes from whoever we fetched it from, and a checkout runs before
// anything has verified it: `readSigrefs` checks a remote's commit out and
// only then tests the signature. An entry naming a path rather than a
// component would write wherever it liked.
test "a tree entry that escapes its directory is refused" {
    const s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);

    const evil = try s.repo.craft(
        \\printf 'one' > a.txt
        \\blob=$(git hash-object -w a.txt)
        \\{ printf '100644 ../escaped.txt\0'; printf '%s' "$blob" | xxd -r -p; } > raw
        \\tree=$(git hash-object -w -t tree --literally --stdin < raw)
        \\rm raw
        \\git commit-tree "$tree" -m evil
    );
    const bare = try s.repo.looseOnly(evil);

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();

    var dest = try destination(s, "out");
    defer dest.close(testing.io);

    try testing.expectError(
        error.UnsafeName,
        repo.checkoutTo(alloc, dest, try storage.parseOid(evil)),
    );
    try testing.expectError(error.FileNotFound, s.tmp.dir.access(testing.io, "escaped.txt", .{}));
}

// Reading a file by path means checking its commit out, so an oid we do not
// hold has to fail rather than leave an empty directory that looks checked out.
test "a checkout of an object we do not hold fails" {
    const s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);

    _ = try s.repo.commit("main", "a.txt", "one\n");
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();

    var dest = try destination(s, "out");
    defer dest.close(testing.io);

    const absent = try storage.parseOid("0123456789abcdef0123456789abcdef01234567");
    try testing.expectError(error.ObjectMissing, repo.checkoutTo(alloc, dest, absent));
}
