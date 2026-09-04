//! Integration tests for `storage.zig`, over repositories built by real `git`
//! (see testfixture.zig). Unit tests for the file's private helpers stay in
//! storage.zig itself.
const std = @import("std");
const gitpack = @import("gitpack");
const storage = @import("storage.zig");
const fixture = @import("testfixture.zig");
const rid = @import("../identity/rid.zig");
const signature = @import("../crypto/signature.zig");

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

test "reads a namespace's sigrefs, and the namespaces on disk" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);
    try s.repo.sigrefs(REAL_SIGREFS_NID, REAL_SIGREFS, &REAL_SIGREFS_SIG);
    // The same genuine signature, filed under a namespace that did not sign it.
    const foreign = try nidForSeed(SEED_SORTS_FIRST);
    defer alloc.free(foreign);
    try s.repo.sigrefs(foreign, REAL_SIGREFS, &REAL_SIGREFS_SIG);
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();

    var signed = try repo.readSigrefs(alloc, alloc, REAL_SIGREFS_NID);
    defer signed.deinit(alloc);
    try testing.expectEqualStrings(REAL_SIGREFS, signed.message);
    try testing.expectEqualSlices(u8, &REAL_SIGREFS_SIG, &signed.signed.sig.bytes);
    try signed.signed.verify(alloc);

    // The namespace name is the only thing binding a ref set to its signer.
    try testing.expectError(
        error.SignatureVerificationFailed,
        repo.readSigrefs(alloc, alloc, foreign),
    );
    try testing.expectError(
        error.SigrefsMissing,
        repo.readSigrefs(alloc, alloc, OTHER_NID),
    );

    const found = try repo.remotes(alloc);
    defer {
        for (found) |n| alloc.free(n);
        alloc.free(found);
    }
    try testing.expectEqual(@as(usize, 2), found.len);
    var saw_real = false;
    for (found) |n| saw_real = saw_real or std.mem.eql(u8, n, REAL_SIGREFS_NID);
    try testing.expect(saw_real);
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

test "verification turns on whether the signed objects are in the pack" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);
    const head = try s.repo.commit("main", "f", "hi");
    const good = try s.repo.signedRefs(3, &.{.{ .oid = head, .name = "refs/heads/main" }});
    defer alloc.free(good);
    // A second namespace whose signed objects were never committed.
    try s.repo.sigrefs(REAL_SIGREFS_NID, REAL_SIGREFS, &REAL_SIGREFS_SIG);
    // Both are delegates, so only the missing objects distinguish them.
    const doc_bytes = try docDelegating(&.{ good, REAL_SIGREFS_NID });
    defer alloc.free(doc_bytes);
    const id = try s.repo.commit("main", "embeds/radicle.json", doc_bytes);
    try s.repo.radId(id);
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();

    var ok = try repo.verifyRemote(alloc, alloc, good);
    defer ok.deinit(alloc);
    try testing.expectEqual(@as(usize, 1), ok.signed.refs.entries.len);
    try testing.expectEqualStrings("refs/heads/main", ok.signed.refs.entries[0].name);

    // readSigrefs is satisfied by the other one: the signature is real, so only
    // the pack check can catch it.
    var signed = try repo.readSigrefs(alloc, alloc, REAL_SIGREFS_NID);
    signed.deinit(alloc);
    try testing.expectError(
        error.MissingObject,
        repo.verifyRemote(alloc, alloc, REAL_SIGREFS_NID),
    );

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

// Delegates are `did:key:z6Mk...` in the doc but namespaces on disk are bare
// `z6Mk...`, so a raw string compare would never match and authorize nobody.
fn docWithDelegates(comptime delegates: []const u8) []const u8 {
    return "{\"payload\":{\"xyz.radicle.project\":{\"name\":\"t\",\"description\":\"\",\"defaultBranch\":\"main\"}}," ++
        "\"delegates\":[" ++ delegates ++ "],\"threshold\":1}";
}

/// Same, for node ids only known at runtime. Caller frees.
fn docDelegating(nids: []const []const u8) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(alloc);
    try list.appendSlice(alloc, "{\"payload\":{\"xyz.radicle.project\":{\"name\":\"t\",\"description\":\"\",\"defaultBranch\":\"main\"}},\"delegates\":[");
    for (nids, 0..) |n, i| {
        if (i > 0) try list.append(alloc, ',');
        try list.appendSlice(alloc, "\"did:key:");
        try list.appendSlice(alloc, n);
        try list.append(alloc, '"');
    }
    try list.appendSlice(alloc, "],\"threshold\":1}");
    return list.toOwnedSlice(alloc);
}

// Non-delegate remotes are legitimate contributors: heartwood's validate_remote
// checks signing, not authority (storage/git.rs). Verification must not reject
// them just for being absent from the delegate list.
test "a verified remote need not be a delegate" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);
    const head = try s.repo.commit("main", "f", "hi");
    const nid = try s.repo.signedRefs(3, &.{.{ .oid = head, .name = "refs/heads/main" }});
    defer alloc.free(nid);

    // A delegate elsewhere signs the root, so the doc is readable.
    const owner = try nidForSeed(SEED_SORTS_FIRST);
    defer alloc.free(owner);
    const doc_bytes = try docDelegating(&.{owner});
    defer alloc.free(doc_bytes);
    const id = try s.repo.commit("main", "embeds/radicle.json", doc_bytes);
    alloc.free(try s.repo.signedRefs(SEED_SORTS_FIRST, &.{.{ .oid = id, .name = "refs/rad/root" }}));
    try s.repo.radRoot(owner, id);
    try s.repo.radId(id);
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();
    try testing.expect(!try repo.isDelegate(alloc, nid));
    try testing.expect(try repo.isDelegate(alloc, owner));

    var report = try repo.verifyAll(alloc, alloc);
    defer report.deinit(alloc);
    try testing.expectEqual(@as(usize, 2), report.verified.len);
    try testing.expectEqual(@as(usize, 0), report.failed.len);
}

// The RID is the git-blob hash of the doc at the identity root, not at the head.
// The zine repo on rad.0x51.dev has an amended doc: refs/rad/id points at a
// revision that added an `xyz.radicle.crefs` payload, while the RID is still
// the hash of the root revision. Hashing the head would break every such repo.
test "repoId follows the root, not an amended identity head, and checkRepoId agrees" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);
    const signer = try nidForSeed(SEED_SORTS_SECOND);
    defer alloc.free(signer);
    const root_doc = try docDelegating(&.{signer});
    defer alloc.free(root_doc);
    const root = try s.repo.commit("main", "embeds/radicle.json", root_doc);
    // A later revision of the same document, with an extra payload.
    const head = try s.repo.commit("main", "embeds/radicle.json", "{\"payload\":{\"xyz.radicle.crefs\":{}},\"delegates\":[\"did:key:" ++ REAL_SIGREFS_NID ++ "\"],\"threshold\":1}");
    try s.repo.radId(head);
    alloc.free(try s.repo.signedRefs(SEED_SORTS_SECOND, &.{.{ .oid = root, .name = "refs/rad/root" }}));
    try s.repo.radRoot(signer, root);
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();

    const got = try repo.repoId(alloc);
    const want = try rid.RepoId.fromDoc(root_doc);
    try testing.expectEqualSlices(u8, &want.oid, &got.oid);

    try repo.checkRepoId(alloc, want);
    const wrong = try rid.RepoId.parse("rad:z3WukSjzicL8WaZHFALbBwb2r8W52");
    try testing.expectError(error.RepoIdMismatch, repo.checkRepoId(alloc, wrong));
}

// heartwood walks the refs actually present under the namespace and requires
// each to appear in sigrefs at the same oid (storage/git.rs validate_remote).
// Checking only the signed->disk direction misses refs the peer smuggled in.
test "verifyRemote rejects an on-disk ref sigrefs does not cover, or covers at another oid" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);
    const head = try s.repo.commit("main", "f", "hi");
    const other = try s.repo.commit("side", "g", "bye");

    const smuggler = try s.repo.signedRefs(SEED_SORTS_FIRST, &.{.{ .oid = head, .name = "refs/heads/main" }});
    defer alloc.free(smuggler);
    try s.repo.namespaceRef(smuggler, "refs/heads/main", head);
    // Signed by nobody: present on disk, absent from the signed set.
    try s.repo.namespaceRef(smuggler, "refs/heads/smuggled", head);

    const mismatcher = try s.repo.signedRefs(SEED_SORTS_SECOND, &.{.{ .oid = head, .name = "refs/heads/main" }});
    defer alloc.free(mismatcher);
    // Signed at `head`, but on disk it points at `other`.
    try s.repo.namespaceRef(mismatcher, "refs/heads/main", other);
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();
    try testing.expectError(error.UnsignedRef, repo.verifyRemote(alloc, alloc, smuggler));
    try testing.expectError(error.MismatchedRef, repo.verifyRemote(alloc, alloc, mismatcher));
}

// `refs/rad/id` is written from whatever the peer sent, so reading the doc there
// lets a seed pick the delegate list. isDelegate is an authorization answer, so
// it has to come from the doc at the signed root instead.
test "isDelegate ignores a peer-supplied refs/rad/id" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);

    const signer = try nidForSeed(SEED_SORTS_SECOND);
    defer alloc.free(signer);
    const attacker = try nidForSeed(SEED_SORTS_FIRST);
    defer alloc.free(attacker);

    const root_doc = try docDelegating(&.{signer});
    defer alloc.free(root_doc);
    const root = try s.repo.commit("main", "embeds/radicle.json", root_doc);
    alloc.free(try s.repo.signedRefs(SEED_SORTS_SECOND, &.{.{ .oid = root, .name = "refs/rad/root" }}));
    try s.repo.radRoot(signer, root);

    // The peer points refs/rad/id at a doc naming itself as the only delegate.
    const forged = try docDelegating(&.{attacker});
    defer alloc.free(forged);
    try s.repo.radId(try s.repo.commit("main", "embeds/radicle.json", forged));
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();

    try testing.expect(try repo.isDelegate(alloc, signer));
    try testing.expect(!try repo.isDelegate(alloc, attacker));
}

// Seeds 8 and 3 derive nids that straddle in readdir order:
// z6Mkfmm5... (8) sorts before z6MkvRXN... (3), so a namespace keyed on 8 is
// reached first by any first-match-wins scan.
const SEED_SORTS_FIRST = 8;
const SEED_SORTS_SECOND = 3;

// Publishing refs/rad/root without signing it is not a state any honest remote
// reaches: rad writes the ref and its sigrefs entry together. Skipping such a
// namespace would leave its refs in the clone, so the whole repository is
// rejected instead. Neither a valid delegate signature elsewhere nor a RID that
// matches excuses it.
test "an unsigned refs/rad/root rejects the repository" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);

    const honest_nid = try nidForSeed(SEED_SORTS_SECOND);
    defer alloc.free(honest_nid);
    const honest_doc = try docDelegating(&.{honest_nid});
    defer alloc.free(honest_doc);
    const root = try s.repo.commit("main", "embeds/radicle.json", honest_doc);

    const honest = try s.repo.signedRefs(SEED_SORTS_SECOND, &.{.{ .oid = root, .name = "refs/rad/root" }});
    defer alloc.free(honest);
    try s.repo.radRoot(honest, root);

    const attacker = try nidForSeed(SEED_SORTS_FIRST);
    defer alloc.free(attacker);
    try s.repo.radRoot(attacker, root);

    try s.repo.radId(root);
    const bare = try s.repo.finish();
    try testing.expect(std.mem.order(u8, attacker, honest) == .lt);

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();
    // SigrefsMissing rather than IdRootUnsigned: the attacker published a root
    // with no sigrefs at all, and saying which is missing is the diagnosis.
    try testing.expectError(error.SigrefsMissing, repo.identityRootOid(alloc));

    // The RID the honest root hashes to would have matched, and does not help.
    const want = try rid.RepoId.fromDoc(honest_doc);
    try testing.expectError(error.SigrefsMissing, repo.checkRepoId(alloc, want));
}

// Signature verification alone is not enough: an attacker signs their own
// namespace perfectly well. The binding is that the doc at the root hashes to
// the requested RID *and* the remote signing it is a delegate of that doc.
test "checkRepoId rejects a signed root from a non-delegate remote" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);

    // A doc delegating to somebody else entirely.
    const doc_bytes = docWithDelegates("\"did:key:" ++ OTHER_NID ++ "\"");
    const root = try s.repo.commit("main", "embeds/radicle.json", doc_bytes);

    // The attacker signs the root correctly, but is not a delegate of the doc.
    const attacker = try s.repo.signedRefs(SEED_SORTS_FIRST, &.{.{ .oid = root, .name = "refs/rad/root" }});
    defer alloc.free(attacker);
    try s.repo.radRoot(attacker, root);
    try s.repo.radId(root);
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();

    const want = try rid.RepoId.fromDoc(doc_bytes);
    try testing.expectError(error.IdRootUnauthorized, repo.checkRepoId(alloc, want));
}

// Two delegates publishing different roots is a fork, not a race to be won by
// whichever namespace readdir happens to yield first.
test "identityRoot rejects delegates that disagree on the root" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);

    const a_nid = try nidForSeed(SEED_SORTS_FIRST);
    defer alloc.free(a_nid);
    const b_nid = try nidForSeed(SEED_SORTS_SECOND);
    defer alloc.free(b_nid);
    const doc_bytes = try docDelegating(&.{ a_nid, b_nid });
    defer alloc.free(doc_bytes);

    const root_a = try s.repo.commit("main", "embeds/radicle.json", doc_bytes);
    const root_b = try s.repo.commit("main", "other", "divergent");

    const a = try s.repo.signedRefs(SEED_SORTS_FIRST, &.{.{ .oid = root_a, .name = "refs/rad/root" }});
    defer alloc.free(a);
    try s.repo.radRoot(a, root_a);
    const b = try s.repo.signedRefs(SEED_SORTS_SECOND, &.{.{ .oid = root_b, .name = "refs/rad/root" }});
    defer alloc.free(b);
    try s.repo.radRoot(b, root_b);

    try s.repo.radId(root_a);
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();

    try testing.expectError(error.IdRootDiverged, repo.identityRootOid(alloc));
}

// A dependency has to resolve to one commit, but every remote has its own
// namespace. The doc's defaultBranch names the branch and delegate status says
// whose namespace to read it from, so a contributor cannot steer the result.
test "canonicalHead reads defaultBranch, and the doc, from a delegate namespace" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);

    const signer = try nidForSeed(SEED_SORTS_SECOND);
    defer alloc.free(signer);
    const doc_bytes = try docDelegating(&.{signer});
    defer alloc.free(doc_bytes);
    const root = try s.repo.commit("main", "embeds/radicle.json", doc_bytes);
    const head = try s.repo.commit("main", "f", "hi");

    alloc.free(try s.repo.signedRefs(SEED_SORTS_SECOND, &.{
        .{ .oid = root, .name = "refs/rad/root" },
        .{ .oid = head, .name = "refs/heads/main" },
    }));
    try s.repo.radRoot(signer, root);
    try s.repo.radId(root);
    try s.repo.namespaceRef(signer, "refs/heads/main", head);

    // A non-delegate publishing the same branch must not be consulted. It signs
    // the same root and its own branch correctly, so only its lack of delegate
    // status rules it out.
    const decoy = try s.repo.commit("side", "f", "bye");
    const other = try s.repo.signedRefs(SEED_SORTS_FIRST, &.{
        .{ .oid = decoy, .name = "refs/heads/main" },
        .{ .oid = root, .name = "refs/rad/root" },
    });
    defer alloc.free(other);
    try s.repo.radRoot(other, root);
    try s.repo.namespaceRef(other, "refs/heads/main", decoy);
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();

    const got = try repo.canonicalHead(alloc);
    const want = try gitpack.Oid.parse(.sha1, head);
    try testing.expectEqualSlices(u8, want.slice(), got.slice());

    const doc = try repo.readDocBytes(alloc, alloc);
    defer alloc.free(doc);
    try testing.expectEqualStrings(doc_bytes, doc);
}

test "canonicalHead rejects delegates that disagree" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);

    const a_nid = try nidForSeed(SEED_SORTS_FIRST);
    defer alloc.free(a_nid);
    const b_nid = try nidForSeed(SEED_SORTS_SECOND);
    defer alloc.free(b_nid);
    const doc_bytes = try docDelegating(&.{ a_nid, b_nid });
    defer alloc.free(doc_bytes);

    const root = try s.repo.commit("main", "embeds/radicle.json", doc_bytes);
    const head_a = try s.repo.commit("main", "f", "hi");
    const head_b = try s.repo.commit("side", "f", "bye");

    // Both delegates sign a root and their own branch, so only the branch
    // disagreement is left to fail on.
    alloc.free(try s.repo.signedRefs(SEED_SORTS_FIRST, &.{
        .{ .oid = head_a, .name = "refs/heads/main" },
        .{ .oid = root, .name = "refs/rad/root" },
    }));
    alloc.free(try s.repo.signedRefs(SEED_SORTS_SECOND, &.{
        .{ .oid = head_b, .name = "refs/heads/main" },
        .{ .oid = root, .name = "refs/rad/root" },
    }));
    try s.repo.radRoot(a_nid, root);
    try s.repo.radRoot(b_nid, root);
    try s.repo.radId(root);

    try s.repo.namespaceRef(a_nid, "refs/heads/main", head_a);
    try s.repo.namespaceRef(b_nid, "refs/heads/main", head_b);
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();
    try testing.expectError(error.DelegatesDiverged, repo.canonicalHead(alloc));
}

// A pinned rev is usually an ancestor of the branch head, not the tip itself.
// The pack holds exactly what the fetched tips reach, and every tip is signed,
// so presence in the pack is the ancestry proof.
test "revPublishedByDelegate accepts an ancestor of a signed tip" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);

    const signer = try nidForSeed(SEED_SORTS_SECOND);
    defer alloc.free(signer);
    const doc_bytes = try docDelegating(&.{signer});
    defer alloc.free(doc_bytes);
    const root = try s.repo.commit("main", "embeds/radicle.json", doc_bytes);

    const older = try s.repo.commit("main", "f", "v1");
    const head = try s.repo.commit("main", "f", "v2");

    alloc.free(try s.repo.signedRefs(SEED_SORTS_SECOND, &.{
        .{ .oid = head, .name = "refs/heads/main" },
        .{ .oid = root, .name = "refs/rad/root" },
    }));
    try s.repo.radRoot(signer, root);
    try s.repo.radId(root);
    try s.repo.namespaceRef(signer, "refs/heads/main", head);
    const bare = try s.repo.finish();

    var repo = try storage.Repository.open(testing.io, alloc, bare);
    defer repo.deinit();

    const tip = try gitpack.Oid.parse(.sha1, head);
    try testing.expect(try repo.revPublishedByDelegate(alloc, tip));

    const ancestor = try gitpack.Oid.parse(.sha1, older);
    try testing.expect(try repo.revPublishedByDelegate(alloc, ancestor));

    // A commit that is not in the pack at all is not reachable from any tip.
    const absent = try gitpack.Oid.parse(.sha1, "0123456789abcdef0123456789abcdef01234567");
    try testing.expect(!try repo.revPublishedByDelegate(alloc, absent));
}

/// The node id for a fixture seed byte, matching what `signedRefs` derives.
fn nidForSeed(seed_byte: u8) ![]u8 {
    const seed: [32]u8 = @splat(seed_byte);
    const key = try signature.SecretKey.fromSeed(seed);
    return key.nodeId().encode(alloc);
}
