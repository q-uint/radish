//! Fetch transport to a radicle-node: after the Noise handshake, open a git
//! stream, send the git-upload-pack intro, and exchange raw git-protocol bytes
//! wrapped in Radicle Git frames. The git protocol v2 conversation on top of
//! this (ls-refs, want/have, packfile) is driven by the caller.
//!
//! libgit2 cannot drive it: it speaks only git protocol v1, while radicle-node
//! requires v2. So the v2 client is hand-rolled; this module provides the
//! Session byte-bridge it runs over.
const std = @import("std");
const noise = @import("noise.zig");
const node_id = @import("node_id.zig");
const protocol = @import("protocol.zig");

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
