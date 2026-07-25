//! Wire transport: dialing a radicle-node and completing the Noise_XK
//! handshake over TCP.
const std = @import("std");
const noise = @import("noise.zig");
const node_id = @import("node_id.zig");

pub const Session = struct {
    stream: std.Io.net.Stream,
    transport: noise.Transport,
    io: std.Io,

    pub fn close(self: *Session) void {
        self.stream.close(self.io);
    }
};

/// Connects to `host:port` and performs the Noise_XK handshake, using `nid`
/// (the node's Ed25519 identity) as the responder static key. Returns a
/// Session with derived transport keys on success.
pub fn connect(
    io: std.Io,
    host: []const u8,
    port: u16,
    nid: node_id.NodeId,
) !Session {
    // The responder static is the node's raw Ed25519 public key (its NID).
    const rs = nid.key;
    // Ephemeral and static keys for this connection. In XK the initiator
    // authenticates with its static key; for dialing we can use a fresh one.
    var seed: [32]u8 = undefined;
    io.random(&seed);
    const static = try noise.KeyPair.generateDeterministic(seed);
    io.random(&seed);
    const ephemeral = try noise.KeyPair.generateDeterministic(seed);

    var ini = noise.Initiator.init(static, ephemeral, rs);

    var addr = try std.Io.net.IpAddress.parseIp4(host, port);
    var stream = try addr.connect(io, .{ .mode = .stream });
    errdefer stream.close(io);

    var wbuf: [512]u8 = undefined;
    var rbuf: [512]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    var r = stream.reader(io, &rbuf);

    var msg: [128]u8 = undefined;

    const n1 = ini.writeMsg1(&msg);
    try w.interface.writeAll(msg[0..n1]);
    try w.interface.flush();

    // Message 2 is `e` (32) plus an empty payload (no tag) => 32 bytes.
    const m2 = try r.interface.takeArray(32);
    try ini.readMsg2(m2);

    const n3 = ini.writeMsg3(&msg);
    try w.interface.writeAll(msg[0..n3]);
    try w.interface.flush();

    return .{ .stream = stream, .transport = ini.split(), .io = io };
}
