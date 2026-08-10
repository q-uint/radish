//! Builds repositories in radish's clone layout (one content-named pack plus
//! loose ref files) using `git`, for tests that need real git objects.
//!
//! `git` is the oracle here: fixtures are produced by the real tool so our
//! pure-Zig readers are checked against its output rather than against
//! themselves. Nothing in this file is reachable from the shipped binary.
//!
//! The clone layout is not a valid git repository - it has no HEAD or config -
//! so objects cannot be written into it directly. Everything is built in a
//! scratch `src` repo and packed across into `bare`.
const std = @import("std");
const gitpack = @import("gitpack");
const signature = @import("../crypto/signature.zig");
const testing = std.testing;

pub const Error = error{ GitUnavailable, GitFailed };

/// A repository under construction. `deinit` frees the owned paths; the files
/// themselves live in the caller's tmp dir.
pub const Repo = struct {
    alloc: std.mem.Allocator,
    root: []const u8,
    bare: []const u8,
    /// Oids that must end up in the pack, accumulated as content is added.
    packed_oids: std.ArrayList([]const u8) = .empty,

    pub fn deinit(self: *Repo) void {
        for (self.packed_oids.items) |o| self.alloc.free(o);
        self.packed_oids.deinit(self.alloc);
        self.alloc.free(self.bare);
        self.* = undefined;
    }

    /// Commits `content` at `path` on `branch` and returns the commit oid
    /// (owned by the Repo).
    pub fn commit(self: *Repo, branch: []const u8, path: []const u8, content: []const u8) ![]const u8 {
        const out = try run(self.alloc, try std.fmt.allocPrint(self.alloc,
            \\set -e
            \\cd {s}/src
            \\git checkout -q -B {s}
            \\mkdir -p "$(dirname '{s}')" && printf '%s' '{s}' > '{s}'
            \\git add -A && git commit -qm {s}
            \\git rev-parse HEAD
        , .{ self.root, branch, path, content, path, branch }));
        defer self.alloc.free(out);

        const oid = try self.alloc.dupe(u8, std.mem.trim(u8, out, " \t\r\n"));
        errdefer self.alloc.free(oid);
        try self.packed_oids.append(self.alloc, oid);
        return oid;
    }

    /// Writes a sigrefs commit for `nid`: a tree of {refs, signature} where
    /// `message` is the canonical ref lines and `sig` signs exactly those
    /// bytes. The sigrefs commit is always packed (otherwise it could not be
    /// read at all); whether the refs it *points at* are packed depends on
    /// whether the caller also committed them.
    pub fn sigrefs(
        self: *Repo,
        nid: []const u8,
        message: []const u8,
        sig: *const [64]u8,
    ) !void {
        var sig_hex: [128]u8 = undefined;
        _ = std.fmt.bufPrint(&sig_hex, "{x}", .{sig}) catch unreachable;

        const out = try run(self.alloc, try std.fmt.allocPrint(self.alloc,
            \\set -e
            \\cd {s}/src
            \\printf '%s' '{s}' > .sr_refs
            \\printf '%s' '{s}' | xxd -r -p > .sr_sig
            \\rb=$(git hash-object -w .sr_refs)
            \\sb=$(git hash-object -w .sr_sig)
            \\rm -f .sr_refs .sr_sig
            \\tree=$(printf '100644 blob %s\trefs\n100644 blob %s\tsignature\n' "$rb" "$sb" | git mktree)
            \\sc=$(git commit-tree "$tree" -m "Update signed refs")
            \\mkdir -p "{s}/bare/refs/namespaces/{s}/refs/rad"
            \\printf '%s\n' "$sc" > "{s}/bare/refs/namespaces/{s}/refs/rad/sigrefs"
            \\printf '%s' "$sc"
        , .{ self.root, message, &sig_hex, self.root, nid, self.root, nid }));
        defer self.alloc.free(out);

        // The sigrefs commit itself must always be readable, or readSigrefs
        // cannot even reach the signature check.
        try self.packed_oids.append(self.alloc, try self.alloc.dupe(u8, std.mem.trim(u8, out, " \t\r\n")));
    }

    /// Signs `refs` with a key derived from `seed_byte` and files them as that
    /// key's namespace. Returns the node id (caller frees).
    pub fn signedRefs(self: *Repo, seed_byte: u8, refs: []const Ref) ![]u8 {
        var message: std.ArrayList(u8) = .empty;
        defer message.deinit(self.alloc);
        for (refs) |r| {
            try message.appendSlice(self.alloc, r.oid);
            try message.append(self.alloc, ' ');
            try message.appendSlice(self.alloc, r.name);
            try message.append(self.alloc, '\n');
        }

        const seed: [32]u8 = @splat(seed_byte);
        const key = try signature.SecretKey.fromSeed(seed);
        const sig = try key.sign(message.items);
        const nid = try key.nodeId().encode(self.alloc);
        errdefer self.alloc.free(nid);

        try self.sigrefs(nid, message.items, &sig.bytes);
        return nid;
    }

    /// Writes `refs/rad/id` pointing at `commit_oid`.
    pub fn radId(self: *Repo, commit_oid: []const u8) !void {
        const out = try run(self.alloc, try std.fmt.allocPrint(self.alloc,
            \\set -e
            \\mkdir -p {s}/bare/refs/rad
            \\printf '%s\n' '{s}' > {s}/bare/refs/rad/id
        , .{ self.root, commit_oid, self.root }));
        self.alloc.free(out);
    }

    /// Packs everything accumulated so far into the bare repo. Call once, last.
    pub fn finish(self: *Repo) ![]const u8 {
        var oids: std.ArrayList(u8) = .empty;
        defer oids.deinit(self.alloc);
        for (self.packed_oids.items) |o| {
            try oids.appendSlice(self.alloc, o);
            try oids.append(self.alloc, ' ');
        }

        const out = try run(self.alloc, try std.fmt.allocPrint(self.alloc,
            \\set -e
            \\cd {s}
            \\mkdir -p bare/objects/pack
            \\rm -f bare/objects/pack/*
            \\git -C src rev-list --objects {s} \
            \\  | git -C src pack-objects "$PWD/bare/objects/pack/pack" >/dev/null 2>&1
        , .{ self.root, oids.items }));
        self.alloc.free(out);
        return self.bare;
    }
};

pub const Ref = struct { oid: []const u8, name: []const u8 };

/// A tmp dir plus the fixture repo inside it, so a test needs one line of
/// setup instead of six. `deinit` removes the whole tree.
pub const Scratch = struct {
    tmp: testing.TmpDir,
    repo: Repo,
    path_buf: [std.fs.max_path_bytes]u8 = undefined,

    pub fn deinit(self: *Scratch) void {
        self.repo.deinit();
        self.tmp.cleanup();
    }
};

/// Creates a tmp dir and starts a fixture repo in it. Returns
/// `error.SkipZigTest` directly when `git`/`xxd` are missing, so callers can
/// `try` it. Must be heap-allocated or returned by pointer: `Scratch` holds
/// the buffer its own `root` points into.
pub fn scratch(alloc: std.mem.Allocator) !*Scratch {
    const self = try alloc.create(Scratch);
    errdefer alloc.destroy(self);
    self.tmp = testing.tmpDir(.{});
    errdefer self.tmp.cleanup();

    const root = self.path_buf[0..try self.tmp.dir.realPath(testing.io, &self.path_buf)];
    self.repo = init(alloc, root) catch |e| switch (e) {
        error.GitUnavailable => return error.SkipZigTest,
        else => return e,
    };
    return self;
}

/// Frees a `scratch` and its tmp dir.
pub fn destroy(alloc: std.mem.Allocator, s: *Scratch) void {
    s.deinit();
    alloc.destroy(s);
}

/// Starts a fixture repo under `root` (typically a testing tmpDir realPath).
/// Returns `error.GitUnavailable` when `git` or `xxd` is missing, which tests
/// translate into a skip.
pub fn init(alloc: std.mem.Allocator, root: []const u8) !Repo {
    const out = try run(alloc, try std.fmt.allocPrint(alloc,
        \\set -e
        \\command -v git >/dev/null || exit 42
        \\command -v xxd >/dev/null || exit 42
        \\cd {s}
        \\git init -q -b main src
        \\cd src && git config user.email a@b.c && git config user.name t
    , .{root}));
    alloc.free(out);

    return .{
        .alloc = alloc,
        .root = root,
        .bare = try std.fmt.allocPrint(alloc, "{s}/bare", .{root}),
    };
}

/// Asks `git verify-pack` which oids the pack holds, so expectations come from
/// git rather than from our own index reader. Caller owns the slice.
pub fn packOids(alloc: std.mem.Allocator, bare: []const u8) ![]gitpack.Oid {
    const out = try run(alloc, try std.fmt.allocPrint(alloc,
        \\set -e
        \\cd {s}
        \\git verify-pack -v objects/pack/*.idx | grep -E '^[0-9a-f]{{40}} ' | cut -d' ' -f1
    , .{bare}));
    defer alloc.free(out);

    var list: std.ArrayList(gitpack.Oid) = .empty;
    errdefer list.deinit(alloc);
    var lines = std.mem.tokenizeAny(u8, out, "\r\n");
    while (lines.next()) |line| {
        const hex = std.mem.trim(u8, line, " \t");
        if (hex.len != 40) continue;
        try list.append(alloc, try gitpack.Oid.parse(.sha1, hex));
    }
    return list.toOwnedSlice(alloc);
}

/// Runs `script` under bash and returns stdout. Takes ownership of `script`.
fn run(alloc: std.mem.Allocator, script: []const u8) ![]u8 {
    defer alloc.free(script);
    const result = try std.process.run(alloc, testing.io, .{ .argv = &.{ "bash", "-c", script } });
    errdefer alloc.free(result.stdout);
    defer alloc.free(result.stderr);
    if (result.term == .exited and result.term.exited == 42) return error.GitUnavailable;
    if (!result.term.success()) return error.GitFailed;
    return result.stdout;
}
