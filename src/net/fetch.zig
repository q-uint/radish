//! Fetch transport to a radicle-node: after the Noise handshake, open a git
//! stream, send the git-upload-pack intro, and exchange raw git-protocol bytes
//! wrapped in Radicle Git frames. The git protocol v2 conversation on top of
//! this (ls-refs, want/have, packfile) is driven by the caller.
//!
//! radicle-node requires protocol v2, so the v2 client (git/protocol.zig) is
//! hand-rolled; this module provides the Session byte-bridge it runs over,
//! plus `clone`.
const std = @import("std");
const noise = @import("../crypto/noise.zig");
const node_id = @import("../identity/node_id.zig");
const protocol = @import("protocol.zig");
const gitproto = @import("../git/protocol.zig");
const gitpack = @import("gitpack");

const GIT_STREAM = protocol.StreamId.git_out.nth(1); // id 12, matches real fetch

/// Socket read/write buffering. Independent of the frame limit: frames are
/// reassembled in `frame_buf`, so this only trades syscalls for memory.
const STREAM_BUF = 64 * 1024;

/// A live, handshaked git-stream to a node. `read`/`write` deal in raw git
/// bytes; framing on/off the wire is handled here. Reads keep the leftover of
/// the current Git frame so callers can request arbitrary byte counts.
pub const Session = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: std.Io.net.Stream,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    rid: []const u8,
    intro_sent: bool = false,
    leftover: []const u8 = &.{},
    frame_buf: []u8,
    rbuf: []u8,
    wbuf: []u8,
    sr: std.Io.net.Stream.Reader,
    sw: std.Io.net.Stream.Writer,

    /// Connects, completes the Noise handshake, and returns a ready Session.
    /// Caller owns it; call `deinit` to close and free.
    pub fn connect(
        io: std.Io,
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
        nid: node_id.NodeId,
        rid: []const u8,
    ) !*Session {
        var seed: [32]u8 = undefined;
        io.random(&seed);
        const static = try noise.KeyPair.generateDeterministic(seed);
        io.random(&seed);
        const ephemeral = try noise.KeyPair.generateDeterministic(seed);
        var ini = noise.Initiator.init(static, ephemeral, nid.key);

        var addr = try std.Io.net.IpAddress.parseIp4(host, port);
        var stream = try addr.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);

        const self = try allocator.create(Session);
        errdefer allocator.destroy(self);
        self.* = .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .reader = undefined,
            .writer = undefined,
            .rid = rid,
            .frame_buf = try allocator.alloc(u8, protocol.MAX_FRAME_PAYLOAD),
            .rbuf = try allocator.alloc(u8, STREAM_BUF),
            .wbuf = try allocator.alloc(u8, STREAM_BUF),
            .sr = undefined,
            .sw = undefined,
        };
        self.sr = self.stream.reader(io, self.rbuf);
        self.sw = self.stream.writer(io, self.wbuf);
        self.reader = &self.sr.interface;
        self.writer = &self.sw.interface;

        try handshake(&ini, self.reader, self.writer);
        return self;
    }

    pub fn deinit(self: *Session) void {
        self.stream.close(self.io);
        self.allocator.free(self.frame_buf);
        self.allocator.free(self.rbuf);
        self.allocator.free(self.wbuf);
        self.allocator.destroy(self);
    }

    /// Opens the git stream and sends the upload-pack intro (once).
    pub fn sendIntro(self: *Session) !void {
        const open = try protocol.encodeControlFrame(self.allocator, .open, GIT_STREAM);
        defer self.allocator.free(open);
        try self.writer.writeAll(open);

        const intro = try protocol.gitUploadPackLine(self.allocator, self.rid);
        defer self.allocator.free(intro);
        const frame = try protocol.encodeGitFrame(self.allocator, GIT_STREAM, intro);
        defer self.allocator.free(frame);
        try self.writer.writeAll(frame);
        try self.writer.flush();
        self.intro_sent = true;
    }

    /// Wraps `data` as one Git frame and sends it.
    pub fn writeGit(self: *Session, data: []const u8) !void {
        const frame = try protocol.encodeGitFrame(self.allocator, GIT_STREAM, data);
        defer self.allocator.free(frame);
        try self.writer.writeAll(frame);
        try self.writer.flush();
    }

    /// Reads up to `buf.len` raw git bytes, refilling from the next Git frame
    /// when the current one is drained. Returns 0 at end of stream (git close).
    pub fn readGit(self: *Session, buf: []u8) !usize {
        if (self.leftover.len == 0) {
            self.fillFromNextGitFrame() catch |e| switch (e) {
                error.EndOfStream => return 0,
                else => return e,
            };
        }
        const n = @min(buf.len, self.leftover.len);
        @memcpy(buf[0..n], self.leftover[0..n]);
        self.leftover = self.leftover[n..];
        return n;
    }

    fn fillFromNextGitFrame(self: *Session) !void {
        while (true) {
            const f = try protocol.readRawFrame(self.reader, self.frame_buf);
            switch (f) {
                .git => |data| {
                    self.leftover = data;
                    return;
                },
                .control => |ctl| if (ctl.ctrl == .close or ctl.ctrl == .eof) return error.EndOfStream,
                else => {},
            }
        }
    }
};

fn handshake(ini: *noise.Initiator, r: *std.Io.Reader, w: *std.Io.Writer) !void {
    var msg: [128]u8 = undefined;
    const n1 = ini.writeMsg1(&msg);
    try w.writeAll(msg[0..n1]);
    try w.flush();
    const m2 = try r.takeArray(32);
    try ini.readMsg2(m2);
    const n3 = ini.writeMsg3(&msg);
    try w.writeAll(msg[0..n3]);
    try w.flush();
    _ = ini.split();
}

pub const CloneResult = struct { refs: usize, pack_bytes: usize };

/// Clones `rid` from `host:port` into a fresh bare repo at `into_path`:
/// connect + handshake, ls-refs all refs, fetch the packfile, index it, and
/// write the refs. Radicle stores every remote under refs/namespaces/<nid>/...;
/// we fetch refs/rad/* and refs/namespaces/*.
pub fn clone(
    io: std.Io,
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    nid: node_id.NodeId,
    rid: []const u8,
    into_path: []const u8,
) !CloneResult {
    const session = try Session.connect(io, allocator, host, port, nid, rid);
    defer session.deinit();

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
    return .{ .refs = refs.refs.len, .pack_bytes = pack.items.len };
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
    try gitpack.indexPack(allocator, .sha1, &pack_reader, &idx_writer);
    try idx_writer.interface.flush();

    // Write each advertised ref as a loose file: refs/... = "<oid>\n".
    for (refs) |ref| {
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
}

test "distinct packs get distinct names" {
    var a: [20]u8 = @splat(0xaa);
    var b: [20]u8 = @splat(0xbb);
    try testing.expect(!std.mem.eql(u8, &try packName(&a), &try packName(&b)));
    try testing.expectError(error.ShortPack, packName("short"));
}
