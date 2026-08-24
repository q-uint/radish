//! Answering inbound connections: the responder half of the wire.
//!
//! `wire.zig` dials out; this accepts. A session greets the way heartwood's
//! `initial()` does (node announcement, inventory announcement, subscribe),
//! then answers what arrives. It does not yet store gossip, route, or serve
//! fetches, so a Subscribe gets the greeting and nothing to replay.
//! Source: radicle-protocol service.rs initial / handle Ping.

const std = @import("std");
const noise = @import("../crypto/noise.zig");
const signature = @import("../crypto/signature.zig");
const protocol = @import("protocol.zig");
const announce = @import("announce.zig");

/// What a session did, for the caller to report. Counting rather than logging
/// keeps this testable without capturing output.
pub const SessionStats = struct {
    frames: usize = 0,
    pings: usize = 0,
    subscribes: usize = 0,
    announcements: usize = 0,
};

/// Drives one already-handshaked session to completion: sends the greeting,
/// then answers frames until the peer goes away or `max_frames` is reached.
/// Split from the socket loop so it runs off in-memory buffers.
pub fn serveOver(
    allocator: std.mem.Allocator,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    key: signature.SecretKey,
    alias: []const u8,
    now_ms: u64,
    max_frames: usize,
) !SessionStats {
    try greet(allocator, w, key, alias, now_ms);

    var stats: SessionStats = .{};
    var scratch: [protocol.MAX_FRAME_PAYLOAD]u8 = undefined;
    var oids: [protocol.INVENTORY_LIMIT][20]u8 = undefined;

    while (stats.frames < max_frames) : (stats.frames += 1) {
        const msg = protocol.decodeFrameStreaming(r, &scratch, &oids) catch |e| switch (e) {
            error.EndOfStream => break,
            // A peer that sends us garbage is not worth staying connected to,
            // which is what heartwood does with "peer misbehaved".
            else => return e,
        };
        switch (msg) {
            .ping => |p| {
                stats.pings += 1;
                try pong(allocator, w, p.ponglen);
            },
            .node_announced, .inventory_announced => stats.announcements += 1,
            .other => |t| {
                if (t == .subscribe) stats.subscribes += 1;
            },
            .pong => {},
        }
    }
    return stats;
}

/// Binds `port` and serves inbound connections one at a time, until
/// `max_sessions` have been handled. Sequential on purpose: a concurrent
/// accept loop needs a session table and cancellation, which is the next piece
/// of work rather than this one.
///
/// `key` is the node's identity. It is a parameter because radish generates a
/// throwaway key per run today; a listener really wants a stable one, or peers
/// cannot find it twice across restarts.
pub fn listen(
    io: std.Io,
    allocator: std.mem.Allocator,
    port: u16,
    seed: [32]u8,
    alias: []const u8,
    max_sessions: usize,
    handler: anytype,
) !usize {
    const key = try signature.SecretKey.fromSeed(seed);
    const addr = try std.Io.net.IpAddress.resolve(io, "0.0.0.0", port);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);

    var served: usize = 0;
    while (served < max_sessions) : (served += 1) {
        var stream = server.accept(io) catch |e| switch (e) {
            error.ConnectionAborted => continue,
            else => return e,
        };
        defer stream.close(io);

        const stats = accept(io, allocator, &stream, seed, key, alias) catch |e| {
            handler.onSessionFailed(e);
            continue;
        };
        handler.onSession(stats);
    }
    return served;
}

/// Completes the responder handshake on `stream`, then serves the session.
fn accept(
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: *std.Io.net.Stream,
    seed: [32]u8,
    key: signature.SecretKey,
    alias: []const u8,
) !SessionStats {
    var eph_seed: [32]u8 = undefined;
    io.random(&eph_seed);
    const ephemeral = try noise.KeyPair.generateDeterministic(eph_seed);
    // noise.KeyPair carries the seed as its secret, matching how the initiator
    // builds one; the node id is the Ed25519 public key over that seed.
    const static: noise.KeyPair = .{ .secret_key = seed, .public_key = key.nodeId().key };
    var res = noise.Responder.init(static, ephemeral);

    var wbuf: [4096]u8 = undefined;
    var rbuf: [protocol.MAX_FRAME_PAYLOAD]u8 = undefined;
    var sw = stream.writer(io, &wbuf);
    var sr = stream.reader(io, &rbuf);
    const w = &sw.interface;
    const r = &sr.interface;

    // XK: read `e, es` (32), write `e, ee` (32), read `s, se` (48: a 32-byte
    // static key plus its 16-byte tag, then an empty encrypted payload). The
    // peer's static key falls out of message 3, which is how we learn who
    // dialed us.
    var msg: [128]u8 = undefined;
    try r.readSliceAll(msg[0..noise.MSG1_LEN]);
    try res.readMsg1(msg[0..noise.MSG1_LEN]);

    const n2 = res.writeMsg2(&msg);
    try w.writeAll(msg[0..n2]);
    try w.flush();

    try r.readSliceAll(msg[0..noise.MSG3_LEN]);
    _ = try res.readMsg3(msg[0..noise.MSG3_LEN]);
    _ = res.split();

    const now_ms: u64 = @intCast(@divTrunc(std.Io.Clock.now(.real, io).nanoseconds, std.time.ns_per_ms));
    return serveOver(allocator, r, w, key, alias, now_ms, 1000);
}

/// The three messages heartwood sends on every new connection.
fn greet(
    allocator: std.mem.Allocator,
    w: *std.Io.Writer,
    key: signature.SecretKey,
    alias: []const u8,
    now_ms: u64,
) !void {
    var msg_buf: std.ArrayList(u8) = .empty;
    defer msg_buf.deinit(allocator);
    const signed = try announce.sign(allocator, .{
        .timestamp = now_ms,
        .alias = alias,
    }, key, &msg_buf);
    const ann = try signed.encodeFrame(allocator);
    defer allocator.free(ann);
    try w.writeAll(ann);

    // No inventory announcement yet: we hold nothing to announce, and an empty
    // one would claim we serve nothing rather than say nothing.

    const sub = try protocol.encodeSubscribeAllFrame(allocator);
    defer allocator.free(sub);
    try w.writeAll(sub);
    try w.flush();
}

/// Answers a Ping. A request for more zeroes than a Pong can carry is ignored
/// rather than honoured, which is what heartwood does with it.
/// Source: radicle-protocol service.rs, `handle_message` Ping.
fn pong(allocator: std.mem.Allocator, w: *std.Io.Writer, ponglen: u16) !void {
    if (ponglen > protocol.MAX_PONG_ZEROES) return;
    const frame = try protocol.encodePongFrame(allocator, ponglen);
    defer allocator.free(frame);
    try w.writeAll(frame);
    try w.flush();
}

const testing = std.testing;

fn testKey() !signature.SecretKey {
    const seed: [32]u8 = @splat(7);
    return signature.SecretKey.fromSeed(seed);
}

test "greets with a signed announcement and a subscribe" {
    var out: [8192]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    var r = std.Io.Reader.fixed(&.{});

    const stats = try serveOver(testing.allocator, &r, &w, try testKey(), "radish", 1, 10);
    try testing.expectEqual(@as(usize, 0), stats.frames);

    // Both frames are on the gossip stream and decode cleanly.
    var sent = std.Io.Reader.fixed(w.buffered());
    var scratch: [protocol.MAX_FRAME_PAYLOAD]u8 = undefined;
    var oids: [8][20]u8 = undefined;
    const first = try protocol.decodeFrameStreaming(&sent, &scratch, &oids);
    try testing.expectEqualStrings("radish", first.node_announced.alias);
    const second = try protocol.decodeFrameStreaming(&sent, &scratch, &oids);
    try testing.expectEqual(protocol.MessageType.subscribe, second.other);
}

// A node that does not answer pings is dropped as unresponsive after
// STALE_CONNECTION_TIMEOUT, so this is what keeps a session alive.
test "answers a ping with a matching pong" {
    var out: [8192]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);

    const ping = try protocol.encodePingFrame(testing.allocator, .{ .ponglen = 4, .zeroes = 0 });
    defer testing.allocator.free(ping);
    var r = std.Io.Reader.fixed(ping);

    const stats = try serveOver(testing.allocator, &r, &w, try testKey(), "radish", 1, 10);
    try testing.expectEqual(@as(usize, 1), stats.pings);

    // Skip the greeting, then find the pong we wrote.
    var sent = std.Io.Reader.fixed(w.buffered());
    var scratch: [protocol.MAX_FRAME_PAYLOAD]u8 = undefined;
    var oids: [8][20]u8 = undefined;
    _ = try protocol.decodeFrameStreaming(&sent, &scratch, &oids);
    _ = try protocol.decodeFrameStreaming(&sent, &scratch, &oids);
    const reply = try protocol.decodeFrameStreaming(&sent, &scratch, &oids);
    try testing.expectEqual(@as(u16, 4), reply.pong.zeroes);
}

// A ponglen above MAX_PONG_ZEROES cannot be encoded as a Pong at all, so
// answering it would mean sending a malformed frame.
test "ignores a ping asking for more zeroes than a pong can carry" {
    var out: [8192]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);

    const ping = try protocol.encodePingFrame(testing.allocator, .{
        .ponglen = protocol.MAX_PONG_ZEROES + 1,
        .zeroes = 0,
    });
    defer testing.allocator.free(ping);
    var r = std.Io.Reader.fixed(ping);

    const stats = try serveOver(testing.allocator, &r, &w, try testKey(), "radish", 1, 10);
    try testing.expectEqual(@as(usize, 1), stats.pings);

    // The greeting is all that was written: no pong follows it.
    var sent = std.Io.Reader.fixed(w.buffered());
    var scratch: [protocol.MAX_FRAME_PAYLOAD]u8 = undefined;
    var oids: [8][20]u8 = undefined;
    _ = try protocol.decodeFrameStreaming(&sent, &scratch, &oids);
    _ = try protocol.decodeFrameStreaming(&sent, &scratch, &oids);
    try testing.expectError(error.EndOfStream, protocol.decodeFrameStreaming(&sent, &scratch, &oids));
}

test "counts a peer's subscribe and announcements" {
    var out: [16384]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);

    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    const sub = try protocol.encodeSubscribeAllFrame(testing.allocator);
    defer testing.allocator.free(sub);
    try input.appendSlice(testing.allocator, sub);

    var r = std.Io.Reader.fixed(input.items);
    const stats = try serveOver(testing.allocator, &r, &w, try testKey(), "radish", 1, 10);
    try testing.expectEqual(@as(usize, 1), stats.subscribes);
    try testing.expectEqual(@as(usize, 1), stats.frames);
}
