//! Integration tests for `storage.zig`, over repositories built by real `git`
//! (see testfixture.zig). Unit tests for the file's private helpers stay in
//! storage.zig itself.
const std = @import("std");
const gitpack = @import("gitpack");
const storage = @import("storage.zig");
const fixture = @import("testfixture.zig");
const sigrefs = @import("../identity/sigrefs.zig");

const testing = std.testing;
const alloc = testing.allocator;

// Byte-for-byte a sigrefs pair produced by rad 1.9.1, so the reader is pinned
// to real output: `REAL_SIGREFS` is the canonical signed message and the
// signature below is the raw 64 bytes over exactly those bytes.
const REAL_SIGREFS =
    "23f4650fa29fc4134658a0bb7d7270f1a5922c82 refs/cobs/xyz.radicle.id/23f4650fa29fc4134658a0bb7d7270f1a5922c82\n" ++
    "9fe8d9621c7e778f7ef60fc2c302c968afba1541 refs/heads/main\n" ++
    "23f4650fa29fc4134658a0bb7d7270f1a5922c82 refs/rad/id\n" ++
    "23f4650fa29fc4134658a0bb7d7270f1a5922c82 refs/rad/root\n";
const REAL_SIGREFS_NID = "z6Mkrqyt3CCmZxNWAa4ZLm6esfuNqiCRyX6paGVMdvP14J7a";
const REAL_SIGREFS_SIG = hex(
    "7b7d16d6fd934484568e64b105758f8e30c97ad8bb18ce9aa4a2487ac7d20c7c" ++
        "70b1dc3745209991432cc5aa8156904052c8565f09667f1722fafdd9416f230d",
);

fn hex(comptime s: *const [128:0]u8) [64]u8 {
    var out: [64]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

/// A valid key that did not sign anything in these fixtures.
const OTHER_NID = "z6MkkfM3tPXNPrPevKr3uSiQtHPuwnNhu2yUVjgd2jXVsVz5";

test "reads and verifies a namespace's sigrefs" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);
    try s.repo.sigrefs(REAL_SIGREFS_NID, REAL_SIGREFS, &REAL_SIGREFS_SIG);
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();

    var signed = try repo.readSigrefs(alloc, alloc, REAL_SIGREFS_NID);
    defer signed.deinit(alloc);
    try testing.expectEqualStrings(REAL_SIGREFS, signed.message);
    try testing.expectEqualSlices(u8, &REAL_SIGREFS_SIG, &signed.signed.sig.bytes);
    try signed.signed.verify(alloc);
}

// The namespace name is the only thing binding a ref set to its signer, so a
// genuine signature filed under the wrong namespace must be rejected.
test "sigrefs signed by another node are rejected" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);
    try s.repo.sigrefs(OTHER_NID, REAL_SIGREFS, &REAL_SIGREFS_SIG);
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();
    try testing.expectError(
        error.SignatureVerificationFailed,
        repo.readSigrefs(alloc, alloc, OTHER_NID),
    );
}

test "a namespace with no sigrefs reports SigrefsMissing" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);
    try s.repo.sigrefs(REAL_SIGREFS_NID, REAL_SIGREFS, &REAL_SIGREFS_SIG);
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();
    try testing.expectError(
        error.SigrefsMissing,
        repo.readSigrefs(alloc, alloc, OTHER_NID),
    );
}

test "hasObject finds exactly the oids in the pack" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);
    _ = try s.repo.commit("main", "f", "hi");
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();

    const present = try fixture.packOids(alloc, bare);
    defer alloc.free(present);
    try testing.expect(present.len > 0);
    for (present) |oid| try testing.expect(try repo.hasObject(oid));

    const absent = try gitpack.Oid.parse(.sha1, "0123456789abcdef0123456789abcdef01234567");
    try testing.expect(!try repo.hasObject(absent));
}

// The signature is genuine, so only the pack check can catch this.
test "verifyRemote rejects signed refs whose objects are absent" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);
    try s.repo.sigrefs(REAL_SIGREFS_NID, REAL_SIGREFS, &REAL_SIGREFS_SIG);
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();

    // readSigrefs is satisfied: the signature is real.
    var signed = try repo.readSigrefs(alloc, alloc, REAL_SIGREFS_NID);
    signed.deinit(alloc);

    // verifyRemote is not: nothing packed the objects those refs name.
    try testing.expectError(
        error.MissingObject,
        repo.verifyRemote(alloc, alloc, REAL_SIGREFS_NID),
    );
}

test "verifyRemote accepts a remote whose objects are all present" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);
    const head = try s.repo.commit("main", "f", "hi");
    const nid = try s.repo.signedRefs(3, &.{.{ .oid = head, .name = "refs/heads/main" }});
    defer alloc.free(nid);
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();

    var signed = try repo.verifyRemote(alloc, alloc, nid);
    defer signed.deinit(alloc);
    try testing.expectEqual(@as(usize, 1), signed.signed.refs.entries.len);
    try testing.expectEqualStrings("refs/heads/main", signed.signed.refs.entries[0].name);
}

test "verifyAll reports each remote independently" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);
    const head = try s.repo.commit("main", "f", "hi");
    const good = try s.repo.signedRefs(3, &.{.{ .oid = head, .name = "refs/heads/main" }});
    defer alloc.free(good);
    // A second namespace whose signed objects were never committed.
    try s.repo.sigrefs(REAL_SIGREFS_NID, REAL_SIGREFS, &REAL_SIGREFS_SIG);
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();

    var report = try repo.verifyAll(alloc, alloc);
    defer report.deinit(alloc);
    try testing.expectEqual(@as(usize, 1), report.verified.len);
    try testing.expectEqualStrings(good, report.verified[0]);
    try testing.expectEqual(@as(usize, 1), report.failed.len);
    try testing.expectEqualStrings(REAL_SIGREFS_NID, report.failed[0].nid);
    try testing.expectEqual(error.MissingObject, report.failed[0].err);
}

test "verifyAll on a repo with no remotes reports nothing" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);
    _ = try s.repo.commit("main", "f", "hi");
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();
    var report = try repo.verifyAll(alloc, alloc);
    defer report.deinit(alloc);
    try testing.expectEqual(@as(usize, 0), report.verified.len);
    try testing.expectEqual(@as(usize, 0), report.failed.len);
}

test "remotes lists the namespaces on disk" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);
    try s.repo.sigrefs(REAL_SIGREFS_NID, REAL_SIGREFS, &REAL_SIGREFS_SIG);
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();
    const found = try repo.remotes(alloc);
    defer {
        for (found) |n| alloc.free(n);
        alloc.free(found);
    }
    try testing.expectEqual(@as(usize, 1), found.len);
    try testing.expectEqualStrings(REAL_SIGREFS_NID, found[0]);
}

test "reads the identity doc from a clone-layout repo" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);
    const doc_bytes = "{\"radish\":\"hello\"}";
    const id = try s.repo.commit("main", "embeds/radicle.json", doc_bytes);
    try s.repo.radId(id);
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();
    const got = try repo.readDocBytes(alloc, alloc);
    defer alloc.free(got);
    try testing.expectEqualStrings(doc_bytes, got);
}
