//! Reading a repository radish has cloned into storage, pure Zig via the
//! toolchain's git plumbing. Our clone layout is a single content-named pack
//! (objects/pack/pack-<sha1>.{pack,idx}) plus loose ref files. The identity
//! document lives at `refs/rad/id:embeds/radicle.json`, and each remote's
//! signed refs at `refs/namespaces/<nid>/refs/rad/sigrefs`.
//! Source: heartwood crates/radicle/src/identity/doc.rs (Doc::load_at),
//! storage/refs.rs (SignedRefs); layout confirmed against rad 1.9.1.
const std = @import("std");
const build_options = @import("build_options");
const gitpack = @import("gitpack");
const doc = @import("../identity/doc.zig");
const rid = @import("../identity/rid.zig");
const sigrefs = @import("../identity/sigrefs.zig");
const node_id = @import("../identity/node_id.zig");
const signature = @import("../crypto/signature.zig");
const git = @import("git.zig");
const checkout = @import("checkout.zig");
const odb = @import("odb.zig");

const DOC_PATH = "embeds/radicle.json";
const ID_REF = "refs/rad/id";
// Namespace-relative, as sigrefs names it.
const ROOT_REF = "refs/rad/root";
const MAX_DOC = 1 << 20;
const MAX_PACKED_REFS = 1 << 24;
/// What each of a pack's two readers buffers. Paid per pack, and a repository
/// git has not collected holds dozens.
const PACK_BUF = 4096;
const MAX_SIGREFS = 1 << 22;
const DID_KEY_PREFIX = "did:key:";

pub const Error = error{
    IdRefMissing,
    DocMissing,
    PackMissing,
    SigrefsMissing,
    SigrefsMalformed,
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

        // Resolved at build time: reading the environment here would mean
        // threading process.Init through every caller of Repository.open.
        var parent = try std.Io.Dir.openDirAbsolute(io, build_options.tmp_dir, .{});
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

/// Where `HEAD` points. `target` is null on a detached HEAD; caller owns it.
pub const Head = struct {
    target: ?[]u8,
    oid: gitpack.Oid,

    pub fn deinit(self: Head, gpa: std.mem.Allocator) void {
        if (self.target) |t| gpa.free(t);
    }
};

/// A ref and what it points at, as ls-refs advertises the pair.
pub const Ref = struct {
    /// The full name, `refs/...`. Caller-owned.
    name: []u8,
    oid: gitpack.Oid,
};

fn lessByName(_: void, a: Ref, b: Ref) bool {
    return std.mem.order(u8, a.name, b.name) == .lt;
}

/// Whether `name` is under any of `prefixes`. No prefixes means everything,
/// which is what a peer asking for no `ref-prefix` wants.
fn matches(name: []const u8, prefixes: []const []const u8) bool {
    if (prefixes.len == 0) return true;
    for (prefixes) |p| {
        if (std.mem.startsWith(u8, name, p)) return true;
    }
    return false;
}

/// Every repository we hold, one bare git repo per RID directly under a root
/// directory, named by the RID's bare multibase form.
/// Source: RIP-0003 Layout; confirmed against rad 1.9.1 storage on disk.
pub const Storage = struct {
    io: std.Io,
    dir: std.Io.Dir,
    root: []const u8,
    allocator: std.mem.Allocator,

    pub fn open(io: std.Io, allocator: std.mem.Allocator, root: []const u8) !Storage {
        var dir = try std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true });
        errdefer dir.close(io);
        return .{
            .io = io,
            .dir = dir,
            .root = try allocator.dupe(u8, root),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Storage) void {
        self.dir.close(self.io);
        self.allocator.free(self.root);
    }

    /// The RIDs on disk, which is what a node announces as its inventory. Only
    /// repositories `repository` would open are counted: announcing one we
    /// cannot read objects out of promises a fetch we would then fail.
    /// Caller owns the result.
    pub fn inventory(self: *Storage, gpa: std.mem.Allocator) ![]rid.RepoId {
        var list: std.ArrayList(rid.RepoId) = .empty;
        errdefer list.deinit(gpa);

        var it = self.dir.iterate();
        while (try it.next(self.io)) |entry| {
            if (entry.kind != .directory) continue;
            // A directory that is not named for a RID is not ours to announce,
            // whatever else it might be.
            const id = rid.RepoId.parse(entry.name) catch continue;
            if (!self.readable(entry.name)) continue;
            try list.append(gpa, id);
        }
        return list.toOwnedSlice(gpa);
    }

    /// Whether `name` holds objects we could serve. A repository is its
    /// `objects` directory: packed or loose is git's business, and a
    /// repository that has only just been written has nothing packed at all.
    fn readable(self: *Storage, name: []const u8) bool {
        var dir = self.dir.openDir(self.io, name, .{}) catch return false;
        defer dir.close(self.io);
        dir.access(self.io, "objects", .{}) catch return false;
        return true;
    }

    /// Opens one repository by RID. Caller owns it; call `deinit`.
    pub fn repository(self: *Storage, gpa: std.mem.Allocator, id: rid.RepoId) !*Repository {
        const name = try id.encodeBare(gpa);
        defer gpa.free(name);

        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const path = try std.fmt.bufPrint(&buf, "{s}/{s}", .{ self.root, name });
        return Repository.open(self.io, gpa, path);
    }
};

/// One pack's open files and the buffers its readers borrow. An `odb.Pack` is
/// only two borrowed readers, so what they read from lives here.
const OpenPack = struct {
    pack_file: std.Io.File,
    idx_file: std.Io.File,
    pack_reader: std.Io.File.Reader,
    idx_reader: std.Io.File.Reader,
    pbuf: []u8,
    ibuf: []u8,

    fn open(
        io: std.Io,
        gpa: std.mem.Allocator,
        dir: std.Io.Dir,
        base: []const u8,
    ) !OpenPack {
        var name: [std.fs.max_name_bytes]u8 = undefined;
        var self: OpenPack = undefined;

        self.pack_file = try dir.openFile(
            io,
            try std.fmt.bufPrint(&name, "objects/pack/{s}.pack", .{base}),
            .{},
        );
        errdefer self.pack_file.close(io);
        self.idx_file = try dir.openFile(
            io,
            try std.fmt.bufPrint(&name, "objects/pack/{s}.idx", .{base}),
            .{},
        );
        errdefer self.idx_file.close(io);

        self.pbuf = try gpa.alloc(u8, PACK_BUF);
        errdefer gpa.free(self.pbuf);
        self.ibuf = try gpa.alloc(u8, PACK_BUF);
        errdefer gpa.free(self.ibuf);

        self.pack_reader = self.pack_file.reader(io, self.pbuf);
        self.idx_reader = self.idx_file.reader(io, self.ibuf);
        return self;
    }

    fn close(self: *OpenPack, io: std.Io, gpa: std.mem.Allocator) void {
        gpa.free(self.pbuf);
        gpa.free(self.ibuf);
        self.idx_file.close(io);
        self.pack_file.close(io);
    }
};

pub const Repository = struct {
    io: std.Io,
    dir: std.Io.Dir,
    /// Every pack the repository has. None is a repository whose objects are
    /// all still loose, which is what `rad init` leaves behind.
    packs: []OpenPack,
    /// What `odb` reads through, pointing into `packs`.
    views: []odb.Pack,
    /// The decompressor history a loose read borrows.
    window: []u8,
    /// Reads objects wherever they are, which gitpack will not do for us.
    odb: odb.Odb,
    allocator: std.mem.Allocator,

    /// Opens a bare repo at `path` (a dir holding `objects/` and `refs/`).
    /// Caller owns it; call `deinit`.
    pub fn open(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !*Repository {
        const self = try allocator.create(Repository);
        errdefer allocator.destroy(self);
        self.allocator = allocator;
        self.io = io;
        self.dir = try std.Io.Dir.cwd().openDir(io, path, .{});
        errdefer self.dir.close(io);

        try self.openPacks();
        errdefer self.closePacks();

        self.window = try allocator.alloc(u8, std.compress.flate.max_window_len);
        errdefer allocator.free(self.window);

        self.odb = .{
            .format = .sha1,
            .packs = self.views,
            .loose = .{ .io = io, .dir = self.dir, .window = self.window },
        };

        return self;
    }

    /// Opens every pack under `objects/pack`, which is as many as git left
    /// there: one per fetch until `git gc --auto` folds them together.
    fn openPacks(self: *Repository) !void {
        const gpa = self.allocator;
        var opened: std.ArrayList(OpenPack) = .empty;
        errdefer {
            for (opened.items) |*p| p.close(self.io, gpa);
            opened.deinit(gpa);
        }

        // No pack directory at all is a repository with nothing packed, not a
        // broken one.
        if (self.dir.openDir(self.io, "objects/pack", .{ .iterate = true })) |*found| {
            var dir = found.*;
            defer dir.close(self.io);

            var it = dir.iterate();
            while (try it.next(self.io)) |entry| {
                if (entry.kind != .file) continue;
                if (!std.mem.endsWith(u8, entry.name, ".pack")) continue;
                const base = entry.name[0 .. entry.name.len - ".pack".len];

                // A pack whose index we cannot open is one we cannot look
                // anything up in: git writes the index second, so this is a
                // fetch still in flight rather than a repository to refuse.
                const p = OpenPack.open(self.io, gpa, self.dir, base) catch continue;
                try opened.append(gpa, p);
            }
        } else |_| {}

        self.packs = try opened.toOwnedSlice(gpa);
        errdefer {
            for (self.packs) |*p| p.close(self.io, gpa);
            gpa.free(self.packs);
        }
        self.views = try gpa.alloc(odb.Pack, self.packs.len);
        for (self.packs, self.views) |*p, *v| {
            v.* = .{ .pack = &p.pack_reader, .idx = &p.idx_reader };
        }
    }

    fn closePacks(self: *Repository) void {
        for (self.packs) |*p| p.close(self.io, self.allocator);
        self.allocator.free(self.packs);
        self.allocator.free(self.views);
    }

    pub fn deinit(self: *Repository) void {
        self.allocator.free(self.window);
        self.closePacks();
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
        self.checkoutTo(scratch, tmp.dir, oid) catch return error.SigrefsMissing;

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
        // Its error propagates: IdRootUnsigned would say only that no root was
        // established, and not every cause is tampering.
        var signed = try self.verifyRemote(scratch, scratch, nid);
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

    /// Whether `want` is a commit a delegate published, as a signed ref tip or
    /// behind one. Ancestry is pack membership, not a parent walk: the pack
    /// holds exactly what the fetched tips reach.
    ///
    /// Requires verified remotes, since that argument rests on every tip in
    /// the pack being signed.
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
        return checkout.commit(scratch, self.io, &self.odb, dest, commit);
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

    /// Whether the repository holds `oid`, packed or loose.
    pub fn hasObject(self: *Repository, oid: gitpack.Oid) !bool {
        return self.odb.has(oid);
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
        try self.checkoutTo(scratch, tmp.dir, commit);
        return tmp.dir.readFileAlloc(self.io, path, gpa, .limited(max));
    }

    /// Writes the canonical branch and points `HEAD` at it, the pair `rad`
    /// leaves in its own storage. Neither half is carried on the wire: the
    /// name is the identity document's, the oid is the delegates' agreement.
    ///
    /// Both can move, so call this after every fetch, not only after a clone.
    /// Source: rad 1.9.1 storage on disk (`HEAD`, `refs/heads/<default>`).
    pub fn writeHead(self: *Repository, scratch: std.mem.Allocator) !void {
        var parsed = try self.identityDoc(scratch);
        defer parsed.deinit();
        const branch = parsed.doc.project.default_branch;
        const oid = try self.canonicalHead(scratch);

        var name: [std.fs.max_path_bytes]u8 = undefined;
        const ref = try std.fmt.bufPrint(&name, "refs/heads/{s}", .{branch});
        if (std.fs.path.dirnamePosix(ref)) |parent| {
            try self.dir.createDirPath(self.io, parent);
        }

        var line: [64]u8 = undefined;
        try self.dir.writeFile(self.io, .{
            .sub_path = ref,
            .data = try std.fmt.bufPrint(&line, "{x}\n", .{oid.slice()}),
        });

        var head: [std.fs.max_path_bytes]u8 = undefined;
        try self.dir.writeFile(self.io, .{
            .sub_path = "HEAD",
            .data = try std.fmt.bufPrint(&head, "ref: {s}\n", .{ref}),
        });
    }

    /// What `HEAD` points at: the ref and its oid, or just the oid when it is
    /// detached. Null when it names a ref we do not hold.
    ///
    /// Kept out of `listRefs` because a radicle peer never asks for it, but a
    /// git client asks on every clone and cannot check out without it.
    pub fn headRef(self: *Repository, gpa: std.mem.Allocator) !?Head {
        const raw = self.dir.readFileAlloc(self.io, "HEAD", gpa, .limited(1024)) catch return null;
        defer gpa.free(raw);
        const line = std.mem.trim(u8, raw, " \t\r\n");

        const prefix = "ref: ";
        if (!std.mem.startsWith(u8, line, prefix)) {
            const oid = parseOid(line) catch return null;
            return .{ .target = null, .oid = oid };
        }
        const target = line[prefix.len..];

        const refs = try self.listRefs(gpa, &.{target});
        defer {
            for (refs) |r| gpa.free(r.name);
            gpa.free(refs);
        }
        for (refs) |r| {
            if (!std.mem.eql(u8, r.name, target)) continue;
            return .{ .target = try gpa.dupe(u8, target), .oid = r.oid };
        }
        return null;
    }

    /// Every ref whose full name starts with one of `prefixes`, or all of them
    /// when `prefixes` is empty, sorted by name. This is what ls-refs
    /// advertises. Caller owns the names.
    ///
    /// Both halves of where git keeps refs: loose files under `refs/`, and
    /// `packed-refs`, which is where `git gc` moves them.
    ///
    /// `HEAD` is deliberately not among them. A peer never asks for it: the
    /// fetcher's only ref-prefixes are `refs/namespaces/<nid>/refs/rad/id`,
    /// the same remote's `refs/rad/sigrefs`, and `refs/namespaces`. HEAD is
    /// derived from the identity document instead of being fetched.
    /// Source: heartwood radicle-fetch/src/stage.rs (RefPrefix),
    /// radicle/src/storage/git.rs (head, canonical_head).
    pub fn listRefs(
        self: *Repository,
        gpa: std.mem.Allocator,
        prefixes: []const []const u8,
    ) ![]Ref {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();

        // Packed first, so a loose file of the same name replaces it: git
        // writes the loose one to move a ref that was packed.
        var by_name: std.StringHashMapUnmanaged(gitpack.Oid) = .empty;
        try self.readPackedRefs(arena.allocator(), prefixes, &by_name);
        try self.readLooseRefs(arena.allocator(), prefixes, &by_name);

        var found: std.ArrayList(Ref) = .empty;
        errdefer {
            for (found.items) |r| gpa.free(r.name);
            found.deinit(gpa);
        }
        try found.ensureTotalCapacity(gpa, by_name.count());

        var it = by_name.iterator();
        while (it.next()) |entry| {
            found.appendAssumeCapacity(.{
                .name = try gpa.dupe(u8, entry.key_ptr.*),
                .oid = entry.value_ptr.*,
            });
        }

        std.mem.sort(Ref, found.items, {}, lessByName);
        return found.toOwnedSlice(gpa);
    }

    fn readLooseRefs(
        self: *Repository,
        arena: std.mem.Allocator,
        prefixes: []const []const u8,
        out: *std.StringHashMapUnmanaged(gitpack.Oid),
    ) !void {
        var root = self.dir.openDir(self.io, "refs", .{ .iterate = true }) catch return;
        defer root.close(self.io);

        var walker = try root.walk(arena);
        defer walker.deinit();
        while (try walker.next(self.io)) |entry| {
            if (entry.kind != .file) continue;

            // A name too long to spell is one we cannot advertise, and no
            // reason to stop advertising the rest.
            var buf: [std.fs.max_path_bytes + "refs/".len]u8 = undefined;
            const name = std.fmt.bufPrint(&buf, "refs/{s}", .{entry.path}) catch continue;
            if (!matches(name, prefixes)) continue;
            // A ref file we cannot parse is not one we can advertise.
            const oid = self.readRef(name, error.IdRefMissing) catch continue;

            try out.put(arena, try arena.dupe(u8, name), oid);
        }
    }

    /// `packed-refs` is "<oid> <name>" a line, with `#` for its header and `^`
    /// for a tag's peeled target, which is not itself a ref.
    /// Source: gitrepository-layout, "packed-refs".
    fn readPackedRefs(
        self: *Repository,
        arena: std.mem.Allocator,
        prefixes: []const []const u8,
        out: *std.StringHashMapUnmanaged(gitpack.Oid),
    ) !void {
        const raw = self.dir.readFileAlloc(self.io, "packed-refs", arena, .limited(MAX_PACKED_REFS)) catch
            return;

        var lines = std.mem.tokenizeAny(u8, raw, "\r\n");
        while (lines.next()) |line| {
            if (line.len == 0 or line[0] == '#' or line[0] == '^') continue;
            const sp = std.mem.indexOfScalar(u8, line, ' ') orelse continue;
            const name = std.mem.trim(u8, line[sp + 1 ..], " \t");
            if (!matches(name, prefixes)) continue;
            const oid = gitpack.Oid.parse(.sha1, line[0..sp]) catch continue;

            try out.put(arena, name, oid);
        }
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

    try testing.expectError(error.SigrefsMalformed, parseSigrefs(alloc, "too short\n"));
    try testing.expectError(error.SigrefsMalformed, parseSigrefs(alloc, "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz refs/heads/main\n"));
}
