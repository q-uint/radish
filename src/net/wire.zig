//! Wire transport: dialing a radicle-node, completing the Noise handshake
//! over TCP, and exchanging framed gossip messages. After the handshake,
//! radicle sends protocol frames unencrypted over the connection.
const std = @import("std");
const noise = @import("../crypto/noise.zig");
const node_id = @import("../identity/node_id.zig");
const protocol = @import("protocol.zig");
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
    // The responder static is the node's raw Ed25519 public key (its NID).
    var seed: [32]u8 = undefined;
    io.random(&seed);
    const static = try noise.KeyPair.generateDeterministic(seed);
    io.random(&seed);
    const ephemeral = try noise.KeyPair.generateDeterministic(seed);

    var ini = noise.Initiator.init(static, ephemeral, nid.key);

    var addr = try std.Io.net.IpAddress.parseIp4(host, port);
    var stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);

    var wbuf: [4096]u8 = undefined;
    var rbuf: [4096]u8 = undefined;
    var sw = stream.writer(io, &wbuf);
    var sr = stream.reader(io, &rbuf);
    const w = &sw.interface;
    const r = &sr.interface;

    try handshake(&ini, r, w);

    const frame = try protocol.encodePingFrame(allocator, .{ .ponglen = ponglen, .zeroes = 0 });
    defer allocator.free(frame);
    try w.writeAll(frame);
    try w.flush();

    return readUntilPong(r);
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
    var seed: [32]u8 = undefined;
    io.random(&seed);
    const static = try noise.KeyPair.generateDeterministic(seed);
    io.random(&seed);
    const ephemeral = try noise.KeyPair.generateDeterministic(seed);
    var ini = noise.Initiator.init(static, ephemeral, nid.key);

    var addr = try std.Io.net.IpAddress.parseIp4(host, port);
    var stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);

    var wbuf: [4096]u8 = undefined;
    var rbuf: [4096]u8 = undefined;
    var sw = stream.writer(io, &wbuf);
    var sr = stream.reader(io, &rbuf);
    const w = &sw.interface;
    const r = &sr.interface;

    try handshake(&ini, r, w);

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

    return readUntilPong(r);
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
    var seed: [32]u8 = undefined;
    io.random(&seed);
    const static = try noise.KeyPair.generateDeterministic(seed);
    io.random(&seed);
    const ephemeral = try noise.KeyPair.generateDeterministic(seed);
    var ini = noise.Initiator.init(static, ephemeral, nid.key);

    var addr = try std.Io.net.IpAddress.parseIp4(host, port);
    var stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);

    var wbuf: [4096]u8 = undefined;
    var rbuf: [4096]u8 = undefined;
    var sw = stream.writer(io, &wbuf);
    var sr = stream.reader(io, &rbuf);
    const w = &sw.interface;
    const r = &sr.interface;

    try handshake(&ini, r, w);

    const frame = try protocol.encodeSubscribeAllFrame(allocator);
    defer allocator.free(frame);
    try w.writeAll(frame);
    try w.flush();

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
    var seed: [32]u8 = undefined;
    io.random(&seed);
    const static = try noise.KeyPair.generateDeterministic(seed);
    io.random(&seed);
    const ephemeral = try noise.KeyPair.generateDeterministic(seed);
    var ini = noise.Initiator.init(static, ephemeral, nid.key);

    var addr = try std.Io.net.IpAddress.parseIp4(host, port);
    var stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);

    var wbuf: [4096]u8 = undefined;
    var rbuf: [4096]u8 = undefined;
    var sw = stream.writer(io, &wbuf);
    var sr = stream.reader(io, &rbuf);
    const w = &sw.interface;
    const r = &sr.interface;

    try handshake(&ini, r, w);

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
