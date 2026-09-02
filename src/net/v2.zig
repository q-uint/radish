//! Radicle 2.x gossip, which is the same messages as 1.x on a different
//! transport: no Noise, no `rad` frame header, just a QUIC varint length and
//! the message, on one bidirectional stream.
//! Source: radicle-node/src/wire.rs `read_message`.
const std = @import("std");

const codec = @import("../codec.zig");
const protocol = @import("protocol.zig");
const quic = @import("../quic/mod.zig");

pub const Error = error{ MessageTooLong, NoAnswer, HandshakeUnconfirmed } ||
    quic.conn.Error;

/// The gossip ALPN. A connection carrying anything else is a different
/// protocol, and the node routes on this.
/// Source: radicle-node/src/runtime.rs.
pub const alpn_gossip = "radicle/gossip/1";
pub const alpn_git = "radicle/git/1";

/// A message plus what it cost to read, so a reader can drop those bytes.
pub const Framed = struct {
    message: protocol.Message,
    consumed: usize,
};

/// Writes `message` with its length in front. `out` needs room for both.
pub fn frame(out: []u8, message: []const u8) ![]u8 {
    var w = std.Io.Writer.fixed(out);
    try codec.writeVarint(&w, message.len);
    try w.writeAll(message);
    return w.buffered();
}

/// Reads the first whole message out of `buf`, or null while it is still
/// arriving. A length past what a message may be is fatal: the stream is
/// misframed from here on.
pub fn next(buf: []const u8) Error!?Framed {
    var r = codec.Reader{ .buf = buf };
    const len = r.varint() catch return null;
    if (len > protocol.MAX_MESSAGE_SIZE) return error.MessageTooLong;
    const payload = r.take(@intCast(len)) catch return null;
    return .{
        .message = protocol.decodeMessage(payload) catch return error.MessageTooLong,
        .consumed = r.pos,
    };
}

/// Sends a Ping on a fresh connection and waits for the Pong, which is the
/// smallest exchange that proves the stream works in both directions.
pub fn ping(
    io: std.Io,
    allocator: std.mem.Allocator,
    c: *quic.conn.Conn,
    opts: quic.conn.Options,
    zeroes: u16,
) !protocol.Pong {
    try c.open(io, opts);
    errdefer c.close();
    try c.handshake();
    if (!c.hs.confirmed) return error.HandshakeUnconfirmed;

    const message = try protocol.encodePing(allocator, .{ .ponglen = zeroes });
    defer allocator.free(message);
    var framed: [@as(usize, protocol.MAX_MESSAGE_SIZE) + codec.max_varint_len]u8 = undefined;
    try c.send(try frame(&framed, message), false);

    // The node answers on the same stream; anything else it sends first is
    // still gossip and gets skipped past.
    while (try c.service()) {
        while (try next(c.readable())) |got| {
            c.consume(got.consumed);
            switch (got.message) {
                .pong => |p| return p,
                else => {},
            }
        }
    }
    return error.NoAnswer;
}

const testing = std.testing;

test "a framed message reads back" {
    const message = try protocol.encodePing(testing.allocator, .{ .ponglen = 3 });
    defer testing.allocator.free(message);

    var buf: [64]u8 = undefined;
    const framed = try frame(&buf, message);
    // One length byte for a message this short, then the message itself.
    try testing.expectEqual(message.len + 1, framed.len);

    const got = (try next(framed)).?;
    try testing.expectEqual(framed.len, got.consumed);
    try testing.expectEqual(@as(u16, 3), got.message.ping.ponglen);
}

test "a message still arriving reads as nothing yet" {
    const message = try protocol.encodePong(testing.allocator, 2);
    defer testing.allocator.free(message);

    var buf: [64]u8 = undefined;
    const framed = try frame(&buf, message);

    // Every prefix of a whole message is incomplete, including an empty one.
    for (0..framed.len) |n| {
        try testing.expectEqual(@as(?Framed, null), try next(framed[0..n]));
    }
    try testing.expectEqual(@as(u16, 2), (try next(framed)).?.message.pong.zeroes);
}

test "a length no message could have is fatal" {
    // A four-byte varint holding 1 << 20, well past MAX_MESSAGE_SIZE.
    var buf: [8]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try codec.writeVarint(&w, 1 << 20);
    try testing.expectError(error.MessageTooLong, next(w.buffered()));
}
