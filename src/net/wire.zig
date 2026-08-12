//! Wire transport: dialing a radicle-node, completing the Noise handshake
//! over TCP, and exchanging framed gossip messages. After the handshake,
//! radicle sends protocol frames unencrypted over the connection.
const std = @import("std");
const noise = @import("../crypto/noise.zig");
const node_id = @import("../identity/node_id.zig");
const protocol = @import("protocol.zig");
const dial = @import("dial.zig");
const announce = @import("announce.zig");
const signature = @import("../crypto/signature.zig");

/// Connects to `host:port`, completes the Noise handshake, sends a gossip
/// Ping, and returns the number of zero-bytes in the node's Pong.
pub fn ping(
    io: std.Io,
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    nid: node_id.NodeId,
    ponglen: u16,
) !u16 {
    var session: Session = .{};
    try session.connect(io, host, port, nid);
    defer session.deinit(io);
    const w = session.w();

    const frame = try protocol.encodePingFrame(allocator, .{ .ponglen = ponglen, .zeroes = 0 });
    defer allocator.free(frame);
    try w.writeAll(frame);
    try w.flush();

    return readUntilPong(session.r());
}

/// Connects, handshakes, sends our signed NodeAnnouncement, then a Ping. A
/// Pong reply confirms the node accepted us (an invalid signature drops us).
/// Returns the pong's zero-byte count.
pub fn sendAnnouncement(
    io: std.Io,
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    nid: node_id.NodeId,
    key: signature.SecretKey,
    alias: []const u8,
) !u16 {
    var session: Session = .{};
    try session.connect(io, host, port, nid);
    defer session.deinit(io);
    const w = session.w();

    // Sign and send our NodeAnnouncement.
    const now_ms: u64 = @intCast(@divTrunc(std.Io.Clock.now(.real, io).nanoseconds, std.time.ns_per_ms));
    var msg_buf: std.ArrayList(u8) = .empty;
    defer msg_buf.deinit(allocator);
    const signed = try announce.sign(allocator, .{
        .timestamp = now_ms,
        .alias = alias,
    }, key, &msg_buf);
    const ann_frame = try signed.encodeFrame(allocator);
    defer allocator.free(ann_frame);
    try w.writeAll(ann_frame);
    try w.flush();

    // Ping afterwards: a Pong means we're still connected (announcement OK).
    const ping_frame = try protocol.encodePingFrame(allocator, .{ .ponglen = 4, .zeroes = 0 });
    defer allocator.free(ping_frame);
    try w.writeAll(ping_frame);
    try w.flush();

    return readUntilPong(session.r());
}

/// Connects, handshakes, sends Subscribe-all, and reads up to `max_frames`
/// gossip frames, invoking `handler.onMessage(msg)` for each. `handler` is any
/// value with an `onMessage(protocol.Message) void` method. Returns the number
/// of frames read.
pub fn subscribe(
    io: std.Io,
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    nid: node_id.NodeId,
    max_frames: usize,
    handler: anytype,
) !usize {
    var session: Session = .{};
    try session.connect(io, host, port, nid);
    defer session.deinit(io);
    return subscribeOver(allocator, session.r(), session.w(), max_frames, handler);
}

/// The subscribe conversation over an already-handshaked pair: send
/// Subscribe-all, then read frames until `max_frames` or end of stream.
/// Split from `subscribe` so it can be driven from in-memory buffers.
pub fn subscribeOver(
    allocator: std.mem.Allocator,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    max_frames: usize,
    handler: anytype,
) !usize {
    {
        const frame = try protocol.encodeSubscribeAllFrame(allocator);
        defer allocator.free(frame);
        try w.writeAll(frame);
        try w.flush();
    }

    var scratch: [protocol.MAX_FRAME_PAYLOAD]u8 = undefined;
    var oids: [protocol.INVENTORY_LIMIT][20]u8 = undefined;
    var frames: usize = 0;
    while (frames < max_frames) : (frames += 1) {
        const msg = protocol.decodeFrameStreaming(r, &scratch, &oids) catch |e| switch (e) {
            error.EndOfStream => break,
            else => return e,
        };
        handler.onMessage(msg);
    }
    return frames;
}

/// Opens a git stream and sends the git-upload-pack intro for `rid`, then
/// reads raw frames, passing each git payload to `handler.onGit([]const u8)`.
/// This is a probe of the fetch transport: it does not yet drive the git
/// protocol v2 conversation. Returns frames read.
pub fn fetchProbe(
    io: std.Io,
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    nid: node_id.NodeId,
    rid: []const u8,
    max_frames: usize,
    handler: anytype,
) !usize {
    var session: Session = .{};
    try session.connect(io, host, port, nid);
    defer session.deinit(io);
    return fetchProbeOver(allocator, session.r(), session.w(), rid, max_frames, handler);
}

/// The fetch-probe conversation over an already-handshaked pair. Split from
/// `fetchProbe` so it can be driven from in-memory buffers.
pub fn fetchProbeOver(
    allocator: std.mem.Allocator,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    rid: []const u8,
    max_frames: usize,
    handler: anytype,
) !usize {
    // Real radicle uses the first non-base git stream (n=1, id 12), not the
    // base git stream (id 4); matched against an on-wire capture.
    const git_stream = protocol.StreamId.git_out.nth(1);

    const open = try protocol.encodeControlFrame(allocator, .open, git_stream);
    defer allocator.free(open);
    try w.writeAll(open);

    const intro = try protocol.gitUploadPackLine(allocator, rid);
    defer allocator.free(intro);
    const git_frame = try protocol.encodeGitFrame(allocator, git_stream, intro);
    defer allocator.free(git_frame);
    try w.writeAll(git_frame);
    try w.flush();

    var scratch: [protocol.MAX_FRAME_PAYLOAD]u8 = undefined;
    var frames: usize = 0;
    while (frames < max_frames) : (frames += 1) {
        const f = protocol.readRawFrame(r, &scratch) catch |e| switch (e) {
            error.EndOfStream => break,
            else => return e,
        };
        switch (f) {
            .git => |data| handler.onGit(data),
            .control => |c| handler.onControl(c.ctrl, c.target),
            else => {},
        }
    }
    return frames;
}

/// A dialed, handshaked connection. Owns the stream and its buffers, which the
/// reader and writer borrow, so it must outlive any use of `r`/`w`; hence
/// `connect` taking the storage rather than returning it by value.
const Session = struct {
    stream: Stream = undefined,
    wbuf: [4096]u8 = undefined,
    rbuf: [4096]u8 = undefined,
    sw: Stream.Writer = undefined,
    sr: Stream.Reader = undefined,

    const Stream = std.Io.net.Stream;

    /// Dials `host:port` and completes the Noise_XK handshake against `nid`.
    /// Caller closes with `deinit`.
    fn connect(
        self: *Session,
        io: std.Io,
        host: []const u8,
        port: u16,
        nid: node_id.NodeId,
    ) !void {
        var seed: [32]u8 = undefined;
        io.random(&seed);
        const static = try noise.KeyPair.generateDeterministic(seed);
        io.random(&seed);
        const ephemeral = try noise.KeyPair.generateDeterministic(seed);
        // The responder static is the node's raw Ed25519 public key (its NID).
        var ini = noise.Initiator.init(static, ephemeral, nid.key);

        self.stream = try dial.connect(io, host, port);
        errdefer self.stream.close(io);
        self.sw = self.stream.writer(io, &self.wbuf);
        self.sr = self.stream.reader(io, &self.rbuf);
        try handshake(&ini, self.r(), self.w());
    }

    fn deinit(self: *Session, io: std.Io) void {
        self.stream.close(io);
    }

    fn r(self: *Session) *std.Io.Reader {
        return &self.sr.interface;
    }

    fn w(self: *Session) *std.Io.Writer {
        return &self.sw.interface;
    }
};

fn handshake(ini: *noise.Initiator, r: *std.Io.Reader, w: *std.Io.Writer) !void {
    var msg: [128]u8 = undefined;
    const n1 = ini.writeMsg1(&msg);
    try w.writeAll(msg[0..n1]);
    try w.flush();

    const m2 = try r.takeArray(32); // e + empty payload
    try ini.readMsg2(m2);

    const n3 = ini.writeMsg3(&msg);
    try w.writeAll(msg[0..n3]);
    try w.flush();

    // The handshake authenticates identity; radicle sends protocol frames
    // unencrypted over the connection (confirmed on the wire).
    _ = ini.split();
}

/// Reads frames (announcements etc.) until a Pong arrives; bounded so a
/// misbehaving peer can't loop us forever.
fn readUntilPong(r: *std.Io.Reader) !u16 {
    var scratch: [protocol.MAX_FRAME_PAYLOAD]u8 = undefined;
    var oids: [protocol.INVENTORY_LIMIT][20]u8 = undefined;
    var frames: usize = 0;
    while (frames < 64) : (frames += 1) {
        const decoded = try protocol.decodeFrameStreaming(r, &scratch, &oids);
        switch (decoded) {
            .pong => |p| return p.zeroes,
            else => {},
        }
    }
    return error.NoPong;
}

const testing = std.testing;

/// A handler that records what it was given, for driving the loops without a
/// socket.
const Recorder = struct {
    alloc: std.mem.Allocator,
    nodes: usize = 0,
    inventories: usize = 0,
    git_frames: usize = 0,
    git_bytes: usize = 0,
    controls: usize = 0,

    pub fn onMessage(self: *Recorder, msg: protocol.Message) void {
        switch (msg) {
            .node_announced => self.nodes += 1,
            .inventory_announced => self.inventories += 1,
            else => {},
        }
    }

    pub fn onGit(self: *Recorder, data: []const u8) void {
        self.git_frames += 1;
        self.git_bytes += data.len;
    }

    pub fn onControl(self: *Recorder, _: protocol.ControlType, _: u64) void {
        self.controls += 1;
    }
};

test "subscribe sends Subscribe-all before reading" {
    var out_buf: [8192]u8 = undefined;
    var w = std.Io.Writer.fixed(&out_buf);
    var r = std.Io.Reader.fixed(&.{});

    var rec = Recorder{ .alloc = testing.allocator };
    const frames = try subscribeOver(testing.allocator, &r, &w, 10, &rec);
    try testing.expectEqual(@as(usize, 0), frames);

    const want = try protocol.encodeSubscribeAllFrame(testing.allocator);
    defer testing.allocator.free(want);
    try testing.expectEqualSlices(u8, want, w.buffered());
}

// An empty stream is the common case against a node with nothing stored, and
// must end the loop rather than surface as an error.
test "subscribe stops at end of stream" {
    var out_buf: [8192]u8 = undefined;
    var w = std.Io.Writer.fixed(&out_buf);

    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    for (0..3) |_| {
        const f = try protocol.encodePingFrame(testing.allocator, .{ .ponglen = 0, .zeroes = 0 });
        defer testing.allocator.free(f);
        try frames.appendSlice(testing.allocator, f);
    }
    var r = std.Io.Reader.fixed(frames.items);

    var rec = Recorder{ .alloc = testing.allocator };
    // Asks for more than the stream holds: the short read ends it.
    const read = try subscribeOver(testing.allocator, &r, &w, 100, &rec);
    try testing.expectEqual(@as(usize, 3), read);
}

test "subscribe stops at max_frames with input left" {
    var out_buf: [8192]u8 = undefined;
    var w = std.Io.Writer.fixed(&out_buf);

    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    for (0..5) |_| {
        const f = try protocol.encodePingFrame(testing.allocator, .{ .ponglen = 0, .zeroes = 0 });
        defer testing.allocator.free(f);
        try frames.appendSlice(testing.allocator, f);
    }
    var r = std.Io.Reader.fixed(frames.items);

    var rec = Recorder{ .alloc = testing.allocator };
    const read = try subscribeOver(testing.allocator, &r, &w, 2, &rec);
    try testing.expectEqual(@as(usize, 2), read);
}

test "fetch-probe opens a git stream and sends the upload-pack intro" {
    var out_buf: [8192]u8 = undefined;
    var w = std.Io.Writer.fixed(&out_buf);
    var r = std.Io.Reader.fixed(&.{});

    var rec = Recorder{ .alloc = testing.allocator };
    _ = try fetchProbeOver(testing.allocator, &r, &w, "rad:z4VSyUhaBGUJQrFdS7nWULf1dJdos", 10, &rec);

    const git_stream = protocol.StreamId.git_out.nth(1);
    const open = try protocol.encodeControlFrame(testing.allocator, .open, git_stream);
    defer testing.allocator.free(open);
    const sent = w.buffered();
    try testing.expect(std.mem.startsWith(u8, sent, open));
    // The bare rid, no `rad:` prefix, is what the responder expects.
    try testing.expect(std.mem.indexOf(u8, sent, "git-upload-pack /z4VSyUhaBGUJQrFdS7nWULf1dJdos") != null);
    try testing.expect(std.mem.indexOf(u8, sent, "version=2") != null);
}
