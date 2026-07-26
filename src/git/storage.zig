//! Reading a repository radish has cloned into storage, pure Zig via the
//! toolchain's git plumbing. Our clone layout is a single pack (objects/pack/
//! pkg.{pack,idx}) plus loose ref files. The identity document lives at
//! `refs/rad/id:embeds/radicle.json`.
//! Source: heartwood crates/radicle/src/identity/doc.rs (Doc::load_at).
const std = @import("std");
const gitpack = @import("gitpack");
const doc = @import("../identity/doc.zig");

const DOC_PATH = "embeds/radicle.json";
const ID_REF = "refs/rad/id";

pub const Error = error{ IdRefMissing, DocMissing } || doc.ParseError;

pub const Repository = struct {
    io: std.Io,
    dir: std.Io.Dir,
    pack_file: std.Io.File,
    idx_file: std.Io.File,
    pack_reader: std.Io.File.Reader,
    idx_reader: std.Io.File.Reader,
    repo: gitpack.Repository,
    pbuf: []u8,
    ibuf: []u8,
    allocator: std.mem.Allocator,

    /// Opens a radish-cloned bare repo at `path` (dir containing objects/pack
    /// and refs/). Caller owns it; call `deinit`.
    pub fn open(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !*Repository {
        const self = try allocator.create(Repository);
        errdefer allocator.destroy(self);
        self.allocator = allocator;
        self.io = io;
        self.dir = try std.Io.Dir.cwd().openDir(io, path, .{});
        errdefer self.dir.close(io);

        self.pack_file = try self.dir.openFile(io, "objects/pack/pkg.pack", .{});
        errdefer self.pack_file.close(io);
        self.idx_file = try self.dir.openFile(io, "objects/pack/pkg.idx", .{});
        errdefer self.idx_file.close(io);

        self.pbuf = try allocator.alloc(u8, 4096);
        errdefer allocator.free(self.pbuf);
        self.ibuf = try allocator.alloc(u8, 4096);
        errdefer allocator.free(self.ibuf);
        self.pack_reader = self.pack_file.reader(io, self.pbuf);
        self.idx_reader = self.idx_file.reader(io, self.ibuf);

        try self.repo.init(allocator, .sha1, &self.pack_reader, &self.idx_reader);
        return self;
    }

    pub fn deinit(self: *Repository) void {
        self.repo.deinit();
        self.allocator.free(self.pbuf);
        self.allocator.free(self.ibuf);
        self.idx_file.close(self.io);
        self.pack_file.close(self.io);
        self.dir.close(self.io);
        self.allocator.destroy(self);
    }

    /// Reads and parses the identity document from `refs/rad/id`.
    /// Caller owns the returned `Parsed`.
    pub fn identityDoc(self: *Repository, allocator: std.mem.Allocator) !doc.Parsed {
        const bytes = try self.readDocBytes(allocator, allocator);
        defer allocator.free(bytes);
        return doc.parse(allocator, bytes);
    }

    /// Returns the raw bytes of `refs/rad/id:embeds/radicle.json`. gitpack
    /// exposes no blob-by-path read, so we check the commit out to a temp dir
    /// and read the file. Caller owns the returned bytes (freed via `gpa`);
    /// `scratch` backs the checkout diagnostics.
    pub fn readDocBytes(self: *Repository, gpa: std.mem.Allocator, scratch: std.mem.Allocator) ![]u8 {
        const oid = try self.readRef(ID_REF);

        var tmp = std.testing.tmpDir(.{}); // TODO: a non-test tmp dir helper
        defer tmp.cleanup();
        var diags: gitpack.Diagnostics = .{ .allocator = scratch };
        defer diags.deinit();
        try self.repo.checkout(self.io, tmp.dir, oid, &diags);

        return tmp.dir.readFileAlloc(self.io, DOC_PATH, gpa, .limited(1 << 20)) catch
            error.DocMissing;
    }

    fn readRef(self: *Repository, name: []const u8) !gitpack.Oid {
        const raw = self.dir.readFileAlloc(self.io, name, self.allocator, .limited(64)) catch
            return error.IdRefMissing;
        defer self.allocator.free(raw);
        const hex = std.mem.trimEnd(u8, raw, "\n");
        return gitpack.Oid.parse(.sha1, hex) catch error.IdRefMissing;
    }
};

const testing = std.testing;

// Builds a repo in radish's clone layout (one pack + loose refs) via `git`,
// then reads embeds/radicle.json back through our gitpack-backed Repository.
// Skipped when `git` is absent.
test "reads the identity doc from a clone-layout repo" {
    const alloc = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const root = pb[0..try tmp.dir.realPath(testing.io, &pb)];

    const doc_bytes = "{\"radish\":\"hello\"}";
    const bare = buildCloneLayout(alloc, root, doc_bytes) catch |e| switch (e) {
        error.GitUnavailable => return error.SkipZigTest,
        else => return e,
    };
    defer alloc.free(bare);

    var repo = try Repository.open(testing.io, alloc, bare);
    defer repo.deinit();
    const got = try repo.readDocBytes(alloc, alloc);
    defer alloc.free(got);
    try testing.expectEqualStrings(doc_bytes, got);
}

/// Uses `git` to create a repo with `doc_bytes` at embeds/radicle.json under
/// refs/rad/id, packed into `<root>/bare` in radish's clone layout. Returns the
/// bare path (caller frees). Errors GitUnavailable if `git` isn't on PATH.
fn buildCloneLayout(alloc: std.mem.Allocator, root: []const u8, doc_bytes: []const u8) ![]const u8 {
    const script = try std.fmt.allocPrint(alloc,
        \\set -e
        \\command -v git >/dev/null || exit 42
        \\cd {s}
        \\git init -q -b master src && cd src
        \\git config user.email a@b.c && git config user.name t
        \\mkdir -p embeds && printf '%s' '{s}' > embeds/radicle.json
        \\git add . && git commit -qm id
        \\cid=$(git rev-parse HEAD)
        \\cd .. && mkdir -p bare/objects/pack bare/refs/rad
        \\git -C src rev-list --objects --all | git -C src pack-objects --stdout > bare/objects/pack/pkg.pack 2>/dev/null
        \\git -C bare index-pack objects/pack/pkg.pack >/dev/null 2>&1
        \\printf '%s\n' "$cid" > bare/refs/rad/id
    , .{ root, doc_bytes });
    defer alloc.free(script);

    const result = try std.process.run(alloc, testing.io, .{ .argv = &.{ "bash", "-c", script } });
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);
    if (result.term == .exited and result.term.exited == 42) return error.GitUnavailable;
    if (!result.term.success()) return error.GitFailed;

    return std.fmt.allocPrint(alloc, "{s}/bare", .{root});
}
