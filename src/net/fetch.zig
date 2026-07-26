//! Fetch transport to a radicle-node: after the Noise handshake, open a git
//! stream, send the git-upload-pack intro, and exchange raw git-protocol bytes
//! wrapped in Radicle Git frames. The git protocol v2 conversation on top of
//! this (ls-refs, want/have, packfile) is driven by the caller.
//!
//! libgit2 cannot drive it: it speaks only git protocol v1, while radicle-node
//! requires v2. So the v2 client (git/protocol.zig) is hand-rolled; this
//! module provides the Session byte-bridge it runs over, plus `clone`.
const std = @import("std");
const noise = @import("../crypto/noise.zig");
const node_id = @import("../identity/node_id.zig");
const protocol = @import("protocol.zig");
const gitproto = @import("../git/protocol.zig");
const git2 = @import("../git/git2.zig");
const c = git2.c;

const GIT_STREAM = protocol.StreamId.git_out.nth(1); // id 12, matches real fetch

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
            .frame_buf = try allocator.alloc(u8, 70 * 1024),
            .rbuf = try allocator.alloc(u8, 64 * 1024),
            .wbuf = try allocator.alloc(u8, 64 * 1024),
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
/// connect + handshake, ls-refs all refs, fetch the packfile, index it with
/// libgit2, and write the refs. Radicle stores every remote under
/// refs/namespaces/<nid>/...; we fetch refs/rad/* and refs/namespaces/*.
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

    try indexAndStore(allocator, into_path, pack.items, refs.refs);
    return .{ .refs = refs.refs.len, .pack_bytes = pack.items.len };
}

/// Initializes a bare repo, indexes `pack` into it, and writes `refs`.
fn indexAndStore(allocator: std.mem.Allocator, into_path: []const u8, pack: []const u8, refs: []const gitproto.Ref) !void {
    _ = c.git_libgit2_init();
    defer _ = c.git_libgit2_shutdown();

    const path_z = try std.fmt.allocPrintSentinel(allocator, "{s}", .{into_path}, 0);
    defer allocator.free(path_z);

    var repo: ?*c.git_repository = null;
    try git2.check(c.git_repository_init(&repo, path_z, 1));
    defer c.git_repository_free(repo);

    const pack_dir = try std.fmt.allocPrintSentinel(allocator, "{s}/objects/pack", .{into_path}, 0);
    defer allocator.free(pack_dir);

    var idx: ?*c.git_indexer = null;
    try git2.check(c.git_indexer_new(&idx, pack_dir, 0, null, null));
    defer c.git_indexer_free(idx);

    var stats: c.git_indexer_progress = std.mem.zeroes(c.git_indexer_progress);
    try git2.check(c.git_indexer_append(idx, pack.ptr, pack.len, &stats));
    try git2.check(c.git_indexer_commit(idx, &stats));

    for (refs) |ref| {
        var oid: c.git_oid = undefined;
        var namez: [256]u8 = undefined;
        if (ref.name.len >= namez.len) continue;
        @memcpy(namez[0..ref.name.len], ref.name);
        namez[ref.name.len] = 0;
        if (c.git_oid_fromstr(&oid, &ref.oid) != 0) continue;
        var out_ref: ?*c.git_reference = null;
        if (c.git_reference_create(&out_ref, repo, &namez, &oid, 1, null) == 0) {
            c.git_reference_free(out_ref);
        }
    }
}
