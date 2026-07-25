//! Wire transport: dialing a radicle-node, completing the Noise handshake
//! over TCP, and exchanging framed messages over the encrypted channel.
//!
//! Each transport record is a u16-big-endian length prefix around the AEAD
//! ciphertext (the netservices framing radicle-node uses on the wire).
const std = @import("std");
const noise = @import("noise.zig");
const node_id = @import("node_id.zig");
const protocol = @import("protocol.zig");

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

    // Handshake: -> e,es  <- e,ee  -> s,se
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
    // unencrypted over TCP (confirmed on the wire).
    _ = ini.split();

    const frame = try protocol.encodePingFrame(allocator, .{ .ponglen = ponglen, .zeroes = 0 });
    defer allocator.free(frame);
    try w.writeAll(frame);
    try w.flush();

    // The node interleaves announcements with the Pong; read frames until we
    // see it (bounded so a misbehaving peer can't loop us forever).
    var scratch: [8192]u8 = undefined;
    var frames: usize = 0;
    while (frames < 64) : (frames += 1) {
        const decoded = try protocol.decodeFrameStreaming(r, &scratch);
        switch (decoded) {
            .pong => |p| return p.zeroes,
            else => {},
        }
    }
    return error.NoPong;
}
