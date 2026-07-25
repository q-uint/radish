//! Reading a Radicle repository's git storage via libgit2.
//! The identity document lives at `refs/rad/id:embeds/radicle.json`.
//! Source: heartwood crates/radicle/src/identity/doc.rs (Doc::load_at).
const std = @import("std");
const git2 = @import("git2.zig");
const doc = @import("doc.zig");

const c = git2.c;

const DOC_PATH = "embeds/radicle.json";
const ID_REF = "refs/rad/id";

pub const Error = git2.Error || doc.ParseError;

// libgit2 init is ref-counted and idempotent, so calling it per-open is safe.
// Returns the init count (>= 0) on success, negative on error.
fn initLibgit2() git2.Error!void {
    try git2.check(c.git_libgit2_init());
}

pub const Repository = struct {
    repo: *c.git_repository,

    /// Opens a Radicle storage repository (a bare git repo) at `path`.
    pub fn open(path: [:0]const u8) git2.Error!Repository {
        try initLibgit2();
        var repo: ?*c.git_repository = null;
        try git2.check(c.git_repository_open(&repo, path.ptr));
        return .{ .repo = repo.? };
    }

    pub fn deinit(self: *Repository) void {
        c.git_repository_free(self.repo);
    }

    /// Reads and parses the identity document from `refs/rad/id`.
    /// Caller owns the returned `Parsed` (call `deinit`).
    pub fn identityDoc(self: *Repository, allocator: std.mem.Allocator) Error!doc.Parsed {
        var commit_oid: c.git_oid = undefined;
        try git2.check(c.git_reference_name_to_id(&commit_oid, self.repo, ID_REF));

        var commit: ?*c.git_commit = null;
        try git2.check(c.git_commit_lookup(&commit, self.repo, &commit_oid));
        defer c.git_commit_free(commit);

        var tree: ?*c.git_tree = null;
        try git2.check(c.git_commit_tree(&tree, commit));
        defer c.git_tree_free(tree);

        var entry: ?*c.git_tree_entry = null;
        try git2.check(c.git_tree_entry_bypath(&entry, tree, DOC_PATH));
        defer c.git_tree_entry_free(entry);

        var blob: ?*c.git_object = null;
        try git2.check(c.git_tree_entry_to_object(&blob, self.repo, entry));
        defer c.git_object_free(blob);

        const blob_ptr: *c.git_blob = @ptrCast(blob.?);
        const raw = c.git_blob_rawcontent(blob_ptr);
        const size = c.git_blob_rawsize(blob_ptr);
        const bytes = @as([*]const u8, @ptrCast(raw))[0..@intCast(size)];

        return doc.parse(allocator, bytes);
    }
};

const testing = std.testing;

// End-to-end: create a real repo with `rad` (radicle-node 1.9.1), open its
// storage with our Repository, and confirm the doc we read parses, verifies,
// and re-derives the same RID the reference produced. Skipped when `rad` is
// absent (non-dev-shell builds).
test "reads a real rad-init repo's identity doc" {
    const alloc = testing.allocator;

    // Native testing tmp dir for RAD_HOME; cleaned up automatically.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const rad_home_len = try tmp.dir.realPath(testing.io, &path_buf);
    const rad_home = path_buf[0..rad_home_len];

    const rid = radInit(alloc, rad_home) catch |e| switch (e) {
        error.RadUnavailable => return error.SkipZigTest,
        else => return e,
    };
    defer alloc.free(rid);

    const storage_path = try std.fmt.allocPrintSentinel(alloc, "{s}/storage/{s}", .{ rad_home, rid["rad:".len..] }, 0);
    defer alloc.free(storage_path);

    var repo = try Repository.open(storage_path);
    defer repo.deinit();

    const parsed = try repo.identityDoc(alloc);
    defer parsed.deinit();
    try parsed.doc.verify();

    const derived = try parsed.doc.repoId(alloc);
    const s = try derived.encode(alloc);
    defer alloc.free(s);
    try testing.expectEqualStrings(rid, s);
}

/// Creates a real repo in `rad_home` via the `rad` CLI; returns its RID
/// (caller frees). Errors with RadUnavailable if `rad` isn't on PATH.
fn radInit(alloc: std.mem.Allocator, rad_home: []const u8) ![]const u8 {
    const script = try std.fmt.allocPrint(alloc,
        \\set -e
        \\command -v rad >/dev/null || {{ exit 42; }}
        \\export RAD_HOME={s}
        \\export RAD_PASSPHRASE=""
        \\rad auth --alias radishtest >/dev/null 2>&1
        \\W=$(mktemp -d); cd "$W"
        \\git init -q -b master; git config user.email a@b.c; git config user.name t
        \\echo hi > r.md; git add .; git commit -qm i
        \\rad init --name testrepo --description "a test" --default-branch master --no-confirm --public >/dev/null 2>&1
        \\rad . 2>/dev/null
    , .{rad_home});
    defer alloc.free(script);

    const result = try std.process.run(alloc, testing.io, .{
        .argv = &.{ "bash", "-c", script },
    });
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    if (result.term == .exited and result.term.exited == 42) return error.RadUnavailable;
    if (!result.term.success()) return error.RadFailed;

    const rid = std.mem.trim(u8, result.stdout, " \n\r\t");
    if (!std.mem.startsWith(u8, rid, "rad:")) return error.RadFailed;
    return alloc.dupe(u8, rid);
}
