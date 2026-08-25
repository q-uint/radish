//! Reading a repository radish has cloned into storage, pure Zig via the
//! toolchain's git plumbing. Our clone layout is a single content-named pack
//! (objects/pack/pack-<sha1>.{pack,idx}) plus loose ref files. The identity
//! document lives at `refs/rad/id:embeds/radicle.json`, and each remote's
//! signed refs at `refs/namespaces/<nid>/refs/rad/sigrefs`.
//! Source: heartwood crates/radicle/src/identity/doc.rs (Doc::load_at),
//! storage/refs.rs (SignedRefs); layout confirmed against rad 1.9.1.
const std = @import("std");
const gitpack = @import("gitpack");
const doc = @import("../identity/doc.zig");
const rid = @import("../identity/rid.zig");
const sigrefs = @import("../identity/sigrefs.zig");
const node_id = @import("../identity/node_id.zig");
const signature = @import("../crypto/signature.zig");
const git = @import("git.zig");

const DOC_PATH = "embeds/radicle.json";
const ID_REF = "refs/rad/id";
// Namespace-relative, as sigrefs names it.
const ROOT_REF = "refs/rad/root";
const MAX_DOC = 1 << 20;
const MAX_SIGREFS = 1 << 22;
const DID_KEY_PREFIX = "did:key:";

// v2 pack index: magic, u32 version, then a 256-entry u32 fan-out table,
// then the sorted oid table. (gitformat-pack)
const IDX_MAGIC = "\xFFtOc";
const IDX_FANOUT_OFF = 8;
const IDX_OIDS_OFF = IDX_FANOUT_OFF + 256 * 4;

pub const Error = error{
    IdRefMissing,
    DocMissing,
    PackMissing,
    SigrefsMissing,
    SigrefsMalformed,
    BadPackIndex,
    MissingObject,
    UnsignedRef,
    MismatchedRef,
    RepoIdMismatch,
    IdRootMissing,
    IdRootDiverged,
    IdRootUnsigned,
    IdRootUnauthorized,
} || doc.ParseError;

/// Per-remote outcome of verifying a whole repository. Remotes are trusted
/// independently, so one bad remote does not invalidate the others.
pub const VerifyReport = struct {
    verified: [][]u8,
    failed: []Failure,

    pub const Failure = struct { nid: []u8, err: anyerror };

    pub fn deinit(self: *VerifyReport, gpa: std.mem.Allocator) void {
        for (self.verified) |n| gpa.free(n);
        gpa.free(self.verified);
        for (self.failed) |f| gpa.free(f.nid);
        gpa.free(self.failed);
        self.* = undefined;
    }
};

/// A namespace's verified sigrefs. `message` is the canonical signed bytes as
/// they were on disk; `signed.refs.entries` borrows it, so both live until
/// `deinit`.
pub const Sigrefs = struct {
    message: []u8,
    signed: sigrefs.SignedRefs,

    pub fn deinit(self: *Sigrefs, gpa: std.mem.Allocator) void {
        gpa.free(self.signed.refs.entries);
        gpa.free(self.message);
        self.* = undefined;
    }
};

/// Parses canonical sigrefs lines: `<40-hex-oid> <refname>\n`, one per line.
/// Names borrow `message`. Caller owns the returned slice.
fn parseSigrefs(gpa: std.mem.Allocator, message: []const u8) ![]sigrefs.Ref {
    var list: std.ArrayList(sigrefs.Ref) = .empty;
    errdefer list.deinit(gpa);

    var lines = std.mem.splitScalar(u8, message, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (line.len < 42 or line[40] != ' ') return error.SigrefsMalformed;
        var oid: git.Oid = undefined;
        _ = std.fmt.hexToBytes(&oid, line[0..40]) catch return error.SigrefsMalformed;
        try list.append(gpa, .{ .name = line[41..], .oid = oid });
    }
    return list.toOwnedSlice(gpa);
}

/// Parses a 40-hex commit id.
pub fn parseOid(hex: []const u8) !gitpack.Oid {
    return gitpack.Oid.parse(.sha1, hex);
}

/// A uniquely-named directory under the system temp dir, removed on `deinit`.
/// `std.testing.tmpDir` is test-only (it asserts `is_test` and writes into
/// .zig-cache), so checkouts on the normal path need this instead.
const TmpDir = struct {
    dir: std.Io.Dir,
    parent: std.Io.Dir,
    name: [24]u8,

    fn create(io: std.Io) !TmpDir {
        var random_bytes: [18]u8 = undefined;
        io.random(&random_bytes);
        var name: [24]u8 = undefined;
        _ = std.base64.url_safe.Encoder.encode(&name, &random_bytes);

        // /tmp rather than $TMPDIR: reading the environment would mean
        // threading process.Init through every caller of Repository.open.
        var parent = try std.Io.Dir.openDirAbsolute(io, "/tmp", .{});
        errdefer parent.close(io);
        const dir = try parent.createDirPathOpen(io, &name, .{});
        return .{ .dir = dir, .parent = parent, .name = name };
    }

    fn deinit(self: *TmpDir, io: std.Io) void {
        self.dir.close(io);
        self.parent.deleteTree(io, &self.name) catch {};
        self.parent.close(io);
    }
};

/// Finds the single packfile under objects/pack and returns its basename
/// (no extension), copied into `buf`. Packs are named for their content, so
/// the name is not known ahead of time.
fn findPack(io: std.Io, dir: std.Io.Dir, buf: []u8) ![]const u8 {
    var pack_dir = dir.openDir(io, "objects/pack", .{ .iterate = true }) catch
        return error.PackMissing;
    defer pack_dir.close(io);

    var it = pack_dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".pack")) continue;
        const base = entry.name[0 .. entry.name.len - ".pack".len];
        if (base.len > buf.len) return error.PackMissing;
        @memcpy(buf[0..base.len], base);
        return buf[0..base.len];
    }
    return error.PackMissing;
}

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

        var base_buf: [std.fs.max_name_bytes]u8 = undefined;
        const base = try findPack(io, self.dir, &base_buf);
        var name_buf: [std.fs.max_name_bytes]u8 = undefined;

        self.pack_file = try self.dir.openFile(io, try std.fmt.bufPrint(&name_buf, "objects/pack/{s}.pack", .{base}), .{});
        errdefer self.pack_file.close(io);
        self.idx_file = try self.dir.openFile(io, try std.fmt.bufPrint(&name_buf, "objects/pack/{s}.idx", .{base}), .{});
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

    /// Reads and parses the identity document at the signed identity root.
    /// Nothing signs `refs/rad/id`, so authority questions must not read it.
    /// Caller owns the returned `Parsed`.
    pub fn identityDoc(self: *Repository, allocator: std.mem.Allocator) !doc.Parsed {
        const root = try self.identityRootOid(allocator);
        const bytes = self.readFileAt(allocator, allocator, root, DOC_PATH, MAX_DOC) catch
            return error.DocMissing;
        defer allocator.free(bytes);
        return doc.parse(allocator, bytes);
    }

    /// Raw bytes of `refs/rad/id:embeds/radicle.json`, unverified. Use
    /// `identityDoc` when the answer has to be trustworthy. gitpack exposes no
    /// blob-by-path read, so we check the commit out to a temp dir and read the
    /// file. Caller owns the returned bytes (freed via `gpa`); `scratch` backs
    /// the checkout diagnostics.
    pub fn readDocBytes(self: *Repository, gpa: std.mem.Allocator, scratch: std.mem.Allocator) ![]u8 {
        const oid = try self.readRef(ID_REF, error.IdRefMissing);
        return self.readFileAt(gpa, scratch, oid, DOC_PATH, MAX_DOC) catch error.DocMissing;
    }

    /// Reads `refs/namespaces/<nid>/refs/rad/sigrefs` and returns the signed
    /// ref set. The signature is checked against `nid` before returning, so a
    /// success means the bytes really came from that node. Caller owns the
    /// result; call `deinit`.
    pub fn readSigrefs(
        self: *Repository,
        gpa: std.mem.Allocator,
        scratch: std.mem.Allocator,
        nid: []const u8,
    ) !Sigrefs {
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const ref = try std.fmt.bufPrint(&path_buf, "refs/namespaces/{s}/refs/rad/sigrefs", .{nid});
        const oid = try self.readRef(ref, error.SigrefsMissing);

        // rad writes sigrefs as a commit whose tree is {refs, signature}; both
        // blobs are small, so a checkout costs two tiny files.
        var tmp = try TmpDir.create(self.io);
        defer tmp.deinit(self.io);
        var diags: gitpack.Diagnostics = .{ .allocator = scratch };
        defer diags.deinit();
        self.repo.checkout(self.io, tmp.dir, oid, &diags) catch return error.SigrefsMissing;

        const message = tmp.dir.readFileAlloc(self.io, "refs", gpa, .limited(MAX_SIGREFS)) catch
            return error.SigrefsMissing;
        errdefer gpa.free(message);
        // limited() errors when the limit is *reached*, so allow one extra byte
        // and reject anything that is not exactly a 64-byte signature.
        const raw = tmp.dir.readFileAlloc(self.io, "signature", scratch, .limited(65)) catch
            return error.SigrefsMissing;
        defer scratch.free(raw);
        if (raw.len != 64) return error.SigrefsMalformed;

        const id = node_id.NodeId.parse(nid) catch return error.SigrefsMalformed;
        var sig: signature.Signature = undefined;
        @memcpy(&sig.bytes, raw);

        const entries = try parseSigrefs(gpa, message);
        errdefer gpa.free(entries);
        const signed: sigrefs.SignedRefs = .{ .refs = .{ .entries = entries }, .id = id, .sig = sig };
        try signed.verify(scratch);
        return .{ .message = message, .signed = signed };
    }

    /// The RID of this repository: the git-blob hash of the identity document
    /// at the *root* of the identity COB, not at its head. The doc is amendable
    /// (a delegate can add payloads), so hashing `refs/rad/id` would give a
    /// value that changes with every identity update; only the root is stable.
    /// Source: heartwood storage/git.rs identity_root / identity_root_of.
    pub fn repoId(self: *Repository, scratch: std.mem.Allocator) !rid.RepoId {
        const root = try self.identityRootOid(scratch);
        const bytes = self.readFileAt(scratch, scratch, root, DOC_PATH, MAX_DOC) catch
            return error.DocMissing;
        defer scratch.free(bytes);
        return rid.RepoId.fromDoc(bytes);
    }

    /// The identity COB's root commit, read from `refs/rad/root` since the
    /// toolchain's git exposes no commit parents to revwalk with. Only remotes
    /// that signed the root count, and every one of them must agree: a
    /// disagreement is a fork, not a first-match-wins race over readdir order.
    /// Source: heartwood storage/git.rs identity_root_of.
    pub fn identityRootOid(self: *Repository, scratch: std.mem.Allocator) !gitpack.Oid {
        const nids = try self.remotes(scratch);
        defer {
            for (nids) |n| scratch.free(n);
            scratch.free(nids);
        }

        var found: ?gitpack.Oid = null;
        for (nids) |nid| {
            const oid = try self.signedRoot(scratch, nid) orelse continue;
            if (found) |prev| {
                if (!std.mem.eql(u8, prev.slice(), oid.slice())) return error.IdRootDiverged;
            } else found = oid;
        }
        return found orelse error.IdRootMissing;
    }

    /// `nid`'s `refs/rad/root`, or null when it publishes none, as contributors
    /// do. Once the ref exists it must verify: skipping a namespace that fails
    /// would leave its refs in the clone while another remote supplied the RID.
    fn signedRoot(self: *Repository, scratch: std.mem.Allocator, nid: []const u8) !?gitpack.Oid {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const ref = try std.fmt.bufPrint(&buf, "refs/namespaces/{s}/{s}", .{ nid, ROOT_REF });
        const on_disk = self.readRef(ref, error.IdRefMissing) catch return null;

        // verifyRemote already requires every on-disk ref to be signed at its
        // real oid; the explicit match below keeps this honest if that changes.
        var signed = self.verifyRemote(scratch, scratch, nid) catch return error.IdRootUnsigned;
        defer signed.deinit(scratch);
        for (signed.signed.refs.entries) |entry| {
            if (!std.mem.eql(u8, entry.name, ROOT_REF)) continue;
            const signed_oid = gitpack.Oid.fromBytes(.sha1, &entry.oid);
            if (!std.mem.eql(u8, signed_oid.slice(), on_disk.slice())) return error.IdRootUnsigned;
            return on_disk;
        }
        return error.IdRootUnsigned;
    }

    /// Confirms this repository really is `want`. A seed is only the transport:
    /// it can serve any internally-consistent repo, and per-remote signatures
    /// prove nothing about *which* repo came back, so the RID is the only
    /// binding. Establishing the RID is only half of it; a remote can sign a
    /// root it has no authority over. Once the doc's hash matches `want` its
    /// contents are pinned by the caller's own RID, so the delegate list inside
    /// it can be trusted to say who was allowed to publish that root.
    pub fn checkRepoId(self: *Repository, scratch: std.mem.Allocator, want: rid.RepoId) !void {
        const root = try self.identityRootOid(scratch);
        const bytes = self.readFileAt(scratch, scratch, root, DOC_PATH, MAX_DOC) catch
            return error.DocMissing;
        defer scratch.free(bytes);

        const got = try rid.RepoId.fromDoc(bytes);
        if (!std.mem.eql(u8, &got.oid, &want.oid)) return error.RepoIdMismatch;

        var parsed = try doc.parse(scratch, bytes);
        defer parsed.deinit();
        if (!try self.rootSignedByDelegate(scratch, root, parsed.doc.delegates))
            return error.IdRootUnauthorized;
    }

    /// Whether some delegate of `delegates` signed `root` in its own namespace.
    fn rootSignedByDelegate(
        self: *Repository,
        scratch: std.mem.Allocator,
        root: gitpack.Oid,
        delegates: []const []const u8,
    ) !bool {
        for (delegates) |d| {
            const bare = if (std.mem.startsWith(u8, d, DID_KEY_PREFIX)) d[DID_KEY_PREFIX.len..] else d;
            const oid = self.signedRoot(scratch, bare) catch continue orelse continue;
            if (std.mem.eql(u8, oid.slice(), root.slice())) return true;
        }
        return false;
    }

    /// Whether `nid` is a delegate in the identity document. Delegates are
    /// stored as `did:key:z6Mk...` while namespaces on disk are bare `z6Mk...`,
    /// so the prefix is stripped before comparing.
    pub fn isDelegate(self: *Repository, scratch: std.mem.Allocator, nid: []const u8) !bool {
        var parsed = try self.identityDoc(scratch);
        defer parsed.deinit();
        for (parsed.doc.delegates) |d| {
            const bare = if (std.mem.startsWith(u8, d, DID_KEY_PREFIX)) d[DID_KEY_PREFIX.len..] else d;
            if (std.mem.eql(u8, bare, nid)) return true;
        }
        return false;
    }

    /// The commit a dependency resolves to. There is no single `main` in a
    /// radicle repo, since every remote has its own namespace. The identity
    /// document names the branch in `defaultBranch`, and delegate status says
    /// whose copy of it counts. Delegates must agree. A disagreement is a fork
    /// for the caller to settle, not something to resolve by readdir order.
    pub fn canonicalHead(self: *Repository, scratch: std.mem.Allocator) !gitpack.Oid {
        var parsed = try self.identityDoc(scratch);
        defer parsed.deinit();

        var buf: [std.fs.max_path_bytes]u8 = undefined;
        var found: ?gitpack.Oid = null;
        for (parsed.doc.delegates) |d| {
            const bare = if (std.mem.startsWith(u8, d, DID_KEY_PREFIX)) d[DID_KEY_PREFIX.len..] else d;
            const ref = try std.fmt.bufPrint(&buf, "refs/namespaces/{s}/refs/heads/{s}", .{
                bare, parsed.doc.project.default_branch,
            });
            const oid = self.readRef(ref, error.BranchMissing) catch continue;
            if (found) |prev| {
                if (!std.mem.eql(u8, prev.slice(), oid.slice())) return error.DelegatesDiverged;
            } else found = oid;
        }
        return found orelse error.BranchMissing;
    }

    /// Whether `want` is a commit a delegate published, either as a signed ref
    /// tip or somewhere in the history behind one.
    ///
    /// Ancestry is established by the pack rather than by walking parents,
    /// which gitpack exposes no way to do: the clone asks for whole refs, so
    /// the pack holds exactly the objects reachable from the tips it fetched.
    /// A commit is in it only if some fetched tip reaches it, and every tip is
    /// checked against a delegate's sigrefs before this returns true. A
    /// contributor's unreferenced commit is therefore not in the pack at all.
    ///
    /// Requires that the caller verified the remotes first, since the argument
    /// rests on every tip in the pack being signed.
    pub fn revPublishedByDelegate(
        self: *Repository,
        scratch: std.mem.Allocator,
        want: gitpack.Oid,
    ) !bool {
        if (!try self.hasObject(want)) return false;

        var parsed = try self.identityDoc(scratch);
        defer parsed.deinit();

        // An exact tip match needs no further argument.
        for (parsed.doc.delegates) |d| {
            const bare = if (std.mem.startsWith(u8, d, DID_KEY_PREFIX)) d[DID_KEY_PREFIX.len..] else d;
            var signed = self.verifyRemote(scratch, scratch, bare) catch continue;
            defer signed.deinit(scratch);
            for (signed.signed.refs.entries) |entry| {
                const oid = gitpack.Oid.fromBytes(.sha1, &entry.oid);
                if (std.mem.eql(u8, oid.slice(), want.slice())) return true;
            }
        }

        // Otherwise it is an ancestor: present in a pack whose every tip a
        // delegate signed. Confirm at least one delegate contributed tips,
        // so an empty delegate set cannot vacuously authorize anything.
        for (parsed.doc.delegates) |d| {
            const bare = if (std.mem.startsWith(u8, d, DID_KEY_PREFIX)) d[DID_KEY_PREFIX.len..] else d;
            var signed = self.verifyRemote(scratch, scratch, bare) catch continue;
            defer signed.deinit(scratch);
            if (signed.signed.refs.entries.len > 0) return true;
        }
        return false;
    }

    /// Checks `commit` out into `dest`, which must already exist.
    pub fn checkoutTo(
        self: *Repository,
        scratch: std.mem.Allocator,
        dest: std.Io.Dir,
        commit: gitpack.Oid,
    ) !void {
        var diags: gitpack.Diagnostics = .{ .allocator = scratch };
        defer diags.deinit();
        try self.repo.checkout(self.io, dest, commit, &diags);
    }

    /// Verifies one remote: its sigrefs signature must check out against `nid`,
    /// every oid it signs must be in the pack, and every ref on disk under the
    /// namespace must be signed at the oid it actually points to.
    /// Non-delegates are legitimate remotes (contributors), so delegate status
    /// is deliberately not checked here; see `isDelegate`.
    /// Source: heartwood crates/radicle/src/storage/git.rs (Validation).
    /// Caller owns the result; call `deinit`.
    pub fn verifyRemote(
        self: *Repository,
        gpa: std.mem.Allocator,
        scratch: std.mem.Allocator,
        nid: []const u8,
    ) !Sigrefs {
        var signed = try self.readSigrefs(gpa, scratch, nid);
        errdefer signed.deinit(gpa);
        for (signed.signed.refs.entries) |ref| {
            const oid = gitpack.Oid.fromBytes(.sha1, &ref.oid);
            if (!try self.hasObject(oid)) return error.MissingObject;
        }
        try self.checkNamespaceRefs(scratch, nid, signed.signed.refs.entries);
        return signed;
    }

    /// Walks the refs actually on disk under `nid`'s namespace and requires each
    /// to appear in `entries` at the same oid. The signed-set direction alone
    /// would miss a ref the peer wrote but never signed.
    /// `refs/rad/sigrefs` is skipped: it carries the signature, so it can never
    /// be listed inside its own signed set.
    fn checkNamespaceRefs(
        self: *Repository,
        scratch: std.mem.Allocator,
        nid: []const u8,
        entries: []const sigrefs.Ref,
    ) !void {
        var prefix_buf: [std.fs.max_path_bytes]u8 = undefined;
        const prefix = try std.fmt.bufPrint(&prefix_buf, "refs/namespaces/{s}", .{nid});

        var ns = self.dir.openDir(self.io, prefix, .{ .iterate = true }) catch return;
        defer ns.close(self.io);

        var walker = try ns.walk(scratch);
        defer walker.deinit();
        while (try walker.next(self.io)) |entry| {
            if (entry.kind != .file) continue;
            if (std.mem.eql(u8, entry.path, sigrefs.SIGREFS_BRANCH)) continue;

            var full_buf: [std.fs.max_path_bytes]u8 = undefined;
            const full = try std.fmt.bufPrint(&full_buf, "{s}/{s}", .{ prefix, entry.path });
            const on_disk = try self.readRef(full, error.SigrefsMalformed);

            const signed_oid = for (entries) |ref| {
                if (std.mem.eql(u8, ref.name, entry.path)) break gitpack.Oid.fromBytes(.sha1, &ref.oid);
            } else return error.UnsignedRef;
            if (!std.mem.eql(u8, on_disk.slice(), signed_oid.slice())) return error.MismatchedRef;
        }
    }

    /// Verifies every remote in the repository, collecting per-remote results
    /// rather than failing on the first bad one. Caller owns the report.
    pub fn verifyAll(
        self: *Repository,
        gpa: std.mem.Allocator,
        scratch: std.mem.Allocator,
    ) !VerifyReport {
        const nids = try self.remotes(gpa);
        defer {
            for (nids) |n| gpa.free(n);
            gpa.free(nids);
        }

        var ok: std.ArrayList([]u8) = .empty;
        errdefer {
            for (ok.items) |n| gpa.free(n);
            ok.deinit(gpa);
        }
        var bad: std.ArrayList(VerifyReport.Failure) = .empty;
        errdefer {
            for (bad.items) |f| gpa.free(f.nid);
            bad.deinit(gpa);
        }

        for (nids) |nid| {
            if (self.verifyRemote(gpa, scratch, nid)) |*signed| {
                var s = signed.*;
                s.deinit(gpa);
                try ok.append(gpa, try gpa.dupe(u8, nid));
            } else |err| {
                try bad.append(gpa, .{ .nid = try gpa.dupe(u8, nid), .err = err });
            }
        }
        return .{
            .verified = try ok.toOwnedSlice(gpa),
            .failed = try bad.toOwnedSlice(gpa),
        };
    }

    /// Lists the node ids under refs/namespaces. Caller owns the slice and
    /// each name.
    pub fn remotes(self: *Repository, gpa: std.mem.Allocator) ![][]u8 {
        var ns = self.dir.openDir(self.io, "refs/namespaces", .{ .iterate = true }) catch
            return gpa.alloc([]u8, 0);
        defer ns.close(self.io);

        var list: std.ArrayList([]u8) = .empty;
        errdefer {
            for (list.items) |n| gpa.free(n);
            list.deinit(gpa);
        }
        var it = ns.iterate();
        while (try it.next(self.io)) |entry| {
            if (entry.kind != .directory) continue;
            try list.append(gpa, try gpa.dupe(u8, entry.name));
        }
        return list.toOwnedSlice(gpa);
    }

    /// Whether `oid` is present in the pack, by binary-searching the v2 index
    /// (`\xFFtOc`, 256-entry fan-out, then sorted oids). Reading the index
    /// directly avoids decoding any pack data; gitpack's own object database
    /// is private, so it cannot answer this.
    /// Source: gitformat-pack, "Version 2 pack-*.idx files".
    pub fn hasObject(self: *Repository, oid: gitpack.Oid) !bool {
        const r = &self.idx_reader;
        try r.seekTo(0);
        const magic = try r.interface.take(4);
        if (!std.mem.eql(u8, magic, IDX_MAGIC)) return error.BadPackIndex;
        if (try r.interface.takeInt(u32, .big) != 2) return error.BadPackIndex;

        // fan_out[b] is the number of oids whose first byte is <= b, so the
        // candidates for this oid sit in [fan_out[b-1], fan_out[b]).
        const key = oid.slice()[0];
        var lo: u32 = 0;
        if (key > 0) {
            try r.seekTo(IDX_FANOUT_OFF + (@as(u64, key) - 1) * 4);
            lo = try r.interface.takeInt(u32, .big);
        }
        try r.seekTo(IDX_FANOUT_OFF + @as(u64, key) * 4);
        var hi = try r.interface.takeInt(u32, .big);

        const oid_len = oid.slice().len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            try r.seekTo(IDX_OIDS_OFF + @as(u64, mid) * oid_len);
            const candidate = try r.interface.take(oid_len);
            switch (std.mem.order(u8, candidate, oid.slice())) {
                .lt => lo = mid + 1,
                .gt => hi = mid,
                .eq => return true,
            }
        }
        return false;
    }

    /// Checks `commit` out to a temp dir and returns the bytes of `path`
    /// within it. Caller owns the result (freed via `gpa`).
    fn readFileAt(
        self: *Repository,
        gpa: std.mem.Allocator,
        scratch: std.mem.Allocator,
        commit: gitpack.Oid,
        path: []const u8,
        max: usize,
    ) ![]u8 {
        var tmp = try TmpDir.create(self.io);
        defer tmp.deinit(self.io);
        var diags: gitpack.Diagnostics = .{ .allocator = scratch };
        defer diags.deinit();
        try self.repo.checkout(self.io, tmp.dir, commit, &diags);
        return tmp.dir.readFileAlloc(self.io, path, gpa, .limited(max));
    }

    fn readRef(self: *Repository, name: []const u8, missing: anyerror) !gitpack.Oid {
        const raw = self.dir.readFileAlloc(self.io, name, self.allocator, .limited(64)) catch
            return missing;
        defer self.allocator.free(raw);
        const hex = std.mem.trimEnd(u8, raw, "\n");
        return gitpack.Oid.parse(.sha1, hex) catch missing;
    }
};

const testing = std.testing;

// Integration tests over real git repositories live in storage_test.zig; these
// cover helpers that are private to this file.

const SAMPLE_SIGREFS =
    "23f4650fa29fc4134658a0bb7d7270f1a5922c82 refs/cobs/xyz.radicle.id/23f4650fa29fc4134658a0bb7d7270f1a5922c82\n" ++
    "9fe8d9621c7e778f7ef60fc2c302c968afba1541 refs/heads/main\n" ++
    "23f4650fa29fc4134658a0bb7d7270f1a5922c82 refs/rad/id\n" ++
    "23f4650fa29fc4134658a0bb7d7270f1a5922c82 refs/rad/root\n";

test "parseSigrefs round-trips the canonical encoding" {
    const alloc = testing.allocator;
    const entries = try parseSigrefs(alloc, SAMPLE_SIGREFS);
    defer alloc.free(entries);
    try testing.expectEqual(@as(usize, 4), entries.len);
    try testing.expectEqualStrings("refs/heads/main", entries[1].name);

    const canon = try (sigrefs.Refs{ .entries = entries }).canonical(alloc);
    defer alloc.free(canon);
    try testing.expectEqualStrings(SAMPLE_SIGREFS, canon);
}

test "parseSigrefs rejects malformed lines" {
    const alloc = testing.allocator;
    try testing.expectError(error.SigrefsMalformed, parseSigrefs(alloc, "too short\n"));
    try testing.expectError(error.SigrefsMalformed, parseSigrefs(alloc, "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz refs/heads/main\n"));
}
