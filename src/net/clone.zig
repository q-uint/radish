//! Cloning a repo over a git session, which both transports arrive at: 1.x
//! wraps git bytes in radicle frames (`fetch.zig`), 2.x runs them straight down
//! a QUIC stream (`gitstream.zig`). Everything past the session is the same, so
//! it lives here rather than in either one.
const std = @import("std");

const gitproto = @import("../git/protocol.zig");
const gitstream = @import("gitstream.zig");
const fetch = @import("fetch.zig");
const node_id = @import("../identity/node_id.zig");
const quic = @import("../quic/mod.zig");
const repo_id = @import("../identity/rid.zig");
const storage = @import("../git/storage.zig");
const gitpack = @import("gitpack");

pub const CloneResult = struct {
    refs: usize,
    pack_bytes: usize,
    /// Per-remote verification of what was just written. Remotes are trusted
    /// independently, so a failure here does not invalidate the clone. The
    /// caller decides what to do with an unverified remote.
    report: storage.VerifyReport,

    pub fn deinit(self: *CloneResult, gpa: std.mem.Allocator) void {
        self.report.deinit(gpa);
    }
};

/// Clones `rid` into a fresh bare repo at `into_path` over an already connected
/// `session`: ls-refs all refs, fetch the packfile, index it, and write the
/// refs. Radicle stores every remote under refs/namespaces/<nid>/...; we fetch
/// refs/rad/* and refs/namespaces/*.
pub fn overSession(
    io: std.Io,
    allocator: std.mem.Allocator,
    session: anytype,
    rid: []const u8,
    into_path: []const u8,
) !CloneResult {
    const prefixes = [_][]const u8{ "refs/rad/", "refs/namespaces/" };
    var refs = try gitproto.lsRefs(allocator, session, &prefixes);
    defer refs.deinit();
    if (refs.refs.len == 0) return error.NoRefs;

    var wants = try allocator.alloc([40]u8, refs.refs.len);
    defer allocator.free(wants);
    for (refs.refs, 0..) |ref, i| wants[i] = ref.oid;

    var pack: std.ArrayList(u8) = .empty;
    defer pack.deinit(allocator);
    try gitproto.fetchPack(session, wants, &pack, allocator);
    if (pack.items.len == 0) return error.EmptyPack;

    try indexAndStore(io, allocator, into_path, pack.items, refs.refs);

    // Verify what the peer actually sent: each remote's sigrefs signature, and
    // that the objects behind those refs are really in the pack.
    var repo = try storage.Repository.open(io, allocator, into_path);
    defer repo.deinit();

    // Hard failure, unlike verifyAll below: a wrong repo is never acceptable.
    const want = try repo_id.RepoId.parse(rid);
    try repo.checkRepoId(allocator, want);

    const report = try repo.verifyAll(allocator, allocator);

    return .{ .refs = refs.refs.len, .pack_bytes = pack.items.len, .report = report };
}

/// Clones from a 1.x node: Noise over TCP, git bytes in radicle frames.
pub fn overNoise(
    io: std.Io,
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    nid: node_id.NodeId,
    rid: []const u8,
    into_path: []const u8,
) !CloneResult {
    const session = try fetch.Session.connect(io, allocator, host, port, nid, rid);
    defer session.deinit();
    return overSession(io, allocator, session, rid, into_path);
}

/// Clones from a 2.x node: the git ALPN on a QUIC stream. `conn` is the
/// caller's so that a failure can still be asked what the peer closed with.
pub fn overQuic(
    io: std.Io,
    allocator: std.mem.Allocator,
    conn: *quic.conn.Conn,
    opts: quic.conn.Options,
    rid: []const u8,
    into_path: []const u8,
) !CloneResult {
    var session = try gitstream.Session.connect(io, allocator, conn, opts, rid);
    defer session.deinit();
    return overSession(io, allocator, &session, rid, into_path);
}

/// Basenames git gives a packfile: `pack-<checksum>`, where the checksum is the
/// SHA-1 trailer in the pack's last 20 bytes. Naming by content keeps a second
/// fetch into the same repo from overwriting the first.
/// Source: gitformat-pack (the trailer), and `git index-pack` naming.
const PackName = ["pack-".len + 40]u8;

fn packName(pack: []const u8) !PackName {
    if (pack.len < 20) return error.ShortPack;
    var out: PackName = undefined;
    @memcpy(out[0..5], "pack-");
    _ = std.fmt.bufPrint(out[5..], "{x}", .{pack[pack.len - 20 ..]}) catch unreachable;
    return out;
}

/// Whether a name the peer advertised is safe to write as a path under the
/// repo. The peer chooses these and they land on disk verbatim, so anything
/// that is not a ref, or that could climb out of the repo, is refused.
fn safeRefName(name: []const u8) bool {
    if (!std.mem.startsWith(u8, name, "refs/")) return false;
    var it = std.mem.splitScalar(u8, name, '/');
    while (it.next()) |seg| {
        if (seg.len == 0 or std.mem.eql(u8, seg, ".") or std.mem.eql(u8, seg, "..")) return false;
        if (std.mem.indexOfAny(u8, seg, "\\\x00") != null) return false;
    }
    return true;
}

/// Writes a bare repo at `into_path`: the packfile plus its index (built by
/// the toolchain's `indexPack`) under objects/pack, and each ref as a loose
/// file.
fn indexAndStore(io: std.Io, allocator: std.mem.Allocator, into_path: []const u8, pack: []const u8, refs: []const gitproto.Ref) !void {
    const cwd = std.Io.Dir.cwd();
    var repo_dir = try cwd.createDirPathOpen(io, into_path, .{});
    defer repo_dir.close(io);
    var pack_dir = try repo_dir.createDirPathOpen(io, "objects/pack", .{});
    defer pack_dir.close(io);

    // Write the packfile, then index it into a sibling .idx.
    const base = try packName(pack);
    var name_buf: [@typeInfo(PackName).array.len + ".pack".len]u8 = undefined;
    var pack_file = try pack_dir.createFile(io, try std.fmt.bufPrint(&name_buf, "{s}.pack", .{base}), .{ .read = true });
    defer pack_file.close(io);
    var pfbuf: [4096]u8 = undefined;
    var pack_reader = blk: {
        var pw = pack_file.writer(io, &pfbuf);
        try pw.interface.writeAll(pack);
        try pw.interface.flush();
        break :blk pw.moveToReader();
    };

    var idx_file = try pack_dir.createFile(io, try std.fmt.bufPrint(&name_buf, "{s}.idx", .{base}), .{ .read = true });
    defer idx_file.close(io);
    var ibuf: [4096]u8 = undefined;
    var idx_writer = idx_file.writer(io, &ibuf);
    try gitpack.indexPack(allocator, .sha1, &pack_reader, &idx_writer, .{ .checksums = true });
    try idx_writer.interface.flush();

    // Write each advertised ref as a loose file: refs/... = "<oid>\n".
    for (refs) |ref| {
        if (!safeRefName(ref.name)) return error.BadRefName;
        if (std.fs.path.dirnamePosix(ref.name)) |parent| {
            var d = try repo_dir.createDirPathOpen(io, parent, .{});
            d.close(io);
        }
        var rf = try repo_dir.createFile(io, ref.name, .{});
        defer rf.close(io);
        var rbuf: [64]u8 = undefined;
        var rw = rf.writer(io, &rbuf);
        try rw.interface.writeAll(&ref.oid);
        try rw.interface.writeAll("\n");
        try rw.interface.flush();
    }
}

const testing = std.testing;

// Trailer and expected name taken from a pack `git pack-objects` produced, then
// cross-checked against the filename `git clone --no-local` wrote for it.
test "pack is named after its sha1 trailer" {
    var pack: [32]u8 = @splat(0);
    const trailer = [20]u8{
        0xdd, 0x58, 0xe7, 0xfd, 0x2a, 0x28, 0x04, 0x08, 0xd4, 0x41,
        0x4c, 0x3d, 0x72, 0x89, 0x0a, 0xc9, 0x73, 0xab, 0xb9, 0x59,
    };
    @memcpy(pack[12..], &trailer);
    const name = try packName(&pack);
    try testing.expectEqualStrings("pack-dd58e7fd2a280408d4414c3d72890ac973abb959", &name);

    const a: [20]u8 = @splat(0xaa);
    const b: [20]u8 = @splat(0xbb);
    try testing.expect(!std.mem.eql(u8, &try packName(&a), &try packName(&b)));
    try testing.expectError(error.ShortPack, packName("short"));
}

// ls-refs returns whatever the peer says it has, and those names become paths.
test "a ref name that could escape the repo is refused" {
    try testing.expect(safeRefName("refs/rad/id"));
    try testing.expect(safeRefName("refs/namespaces/z6Mk/refs/heads/main"));

    try testing.expect(!safeRefName("refs/rad/../../../../tmp/pwned"));
    try testing.expect(!safeRefName("refs/./rad/id"));
    try testing.expect(!safeRefName("refs//rad"));
    try testing.expect(!safeRefName("refs/"));
    // Not a ref at all: config and HEAD decide what the repo means.
    try testing.expect(!safeRefName("config"));
    try testing.expect(!safeRefName("/etc/passwd"));
    try testing.expect(!safeRefName("refs/rad\\..\\id"));
}
