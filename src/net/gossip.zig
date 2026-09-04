//! Radicle 2.x gossip, which is the same messages as 1.x on a different
//! transport: no Noise, no `rad` frame header, just a QUIC varint length and
//! the message, on one bidirectional stream.
//! Source: radicle-node/src/wire.rs `read_message`.
const std = @import("std");

const codec = @import("../codec.zig");
const protocol = @import("protocol.zig");
const quic = @import("../quic/mod.zig");

pub const Error = error{ MessageTooLong, NoAnswer } || quic.conn.Error;

/// The gossip ALPN. A connection carrying anything else is a different
/// protocol, and the node routes on this.
/// Source: radicle-node/src/runtime.rs.
pub const alpn_gossip = "radicle/gossip/1";
pub const alpn_git = "radicle/git/1";

/// A message plus what it cost to read, so a reader can drop those bytes.
///
/// The message borrows the buffer it was read from, so drop those bytes only
/// once done with it: on a stream, consuming slides what follows down over
/// them.
pub const Framed = struct {
    contents: union(enum) {
        message: protocol.Message,
        /// What decoding the frame failed with. `consumed` still says how to
        /// skip past it.
        undecodable: anyerror,
    },
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
/// misframed from here on. `oid_buf` receives an inventory's oids.
///
/// Contents that do not decode are not fatal, unlike a bad length: the prefix
/// says where the next message starts, so an address kind or a field we do not
/// know costs one message rather than the connection.
pub fn next(buf: []const u8, oid_buf: [][20]u8) Error!?Framed {
    var r = codec.Reader{ .buf = buf };
    const len = r.varint() catch return null;
    if (len > protocol.MAX_MESSAGE_SIZE) return error.MessageTooLong;
    const payload = r.take(@intCast(len)) catch return null;
    if (protocol.decodeMessage(payload, oid_buf)) |message| {
        return .{ .contents = .{ .message = message }, .consumed = r.pos };
    } else |e| {
        return .{ .contents = .{ .undecodable = e }, .consumed = r.pos };
    }
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
    try c.establish(io, opts);

    const message = try protocol.encodePing(allocator, .{ .ponglen = zeroes });
    defer allocator.free(message);
    var framed: [@as(usize, protocol.MAX_MESSAGE_SIZE) + codec.max_varint_len]u8 = undefined;
    try c.send(try frame(&framed, message), false);

    // The node answers on the same stream; anything else it sends first is
    // still gossip and gets skipped past.
    while (true) {
        // Whatever arrived comes first: the Pong can share a packet with a
        // close that follows it.
        while (try next(c.readable(), &.{})) |got| {
            c.consume(got.consumed);
            switch (got.contents) {
                .message => |m| switch (m) {
                    .pong => |p| return p,
                    else => {},
                },
                .undecodable => {},
            }
        }
        // Either leaves the answer we came for unaccounted for, however
        // politely it happened.
        if (c.peerClose() != null) return error.PeerClosed;
        if (c.streamDone()) return error.NoAnswer;
        switch (try c.service()) {
            .arrived, .closed => {},
            .silent => return error.NoAnswer,
        }
    }
}

/// Subscribes to everything and hands each message to `handler.onMessage`, or
/// to `handler.onUndecodable` when it does not decode, until `max_messages`
/// have arrived or the peer stops. Returns how many were read.
pub fn subscribe(
    io: std.Io,
    allocator: std.mem.Allocator,
    c: *quic.conn.Conn,
    opts: quic.conn.Options,
    max_messages: usize,
    handler: anytype,
) !usize {
    try c.establish(io, opts);
    return subscribeOn(allocator, c, max_messages, handler);
}

/// The subscription itself, on a connection that is already up.
pub fn subscribeOn(
    allocator: std.mem.Allocator,
    c: *quic.conn.Conn,
    max_messages: usize,
    handler: anytype,
) !usize {
    var framed: [protocol.subscribe_all_message.len + codec.max_varint_len]u8 = undefined;
    try c.send(try frame(&framed, &protocol.subscribe_all_message), false);

    // An inventory names every repo a node holds, so the oids need somewhere
    // to land that outlives each message.
    const oids = try allocator.alloc([20]u8, protocol.INVENTORY_LIMIT);
    defer allocator.free(oids);

    var seen: usize = 0;
    while (seen < max_messages) {
        // Whatever arrived comes first, however the connection ended: a close
        // travels in the same packet as the messages before it.
        while (seen < max_messages) {
            const got = try next(c.readable(), oids) orelse break;
            seen += 1;
            // Handled before consuming: a message's strings borrow the stream
            // buffer, and consuming slides the bytes after it down over them.
            switch (got.contents) {
                .message => |m| handler.onMessage(m),
                .undecodable => |e| handler.onUndecodable(e),
            }
            c.consume(got.consumed);
        }
        if (c.streamDone()) break;
        if (c.peerClose()) |close| {
            // A clean close ends the run; what was read still counts. An
            // error code is the peer saying the run did not go well.
            if (close.error_code != 0) return error.PeerClosed;
            break;
        }
        switch (try c.service()) {
            // Both re-test the loop above rather than ending the run here.
            .arrived, .closed => {},
            .silent => break,
        }
    }
    return seen;
}

const testing = std.testing;
const fakepeer = @import("../quic/fakepeer.zig");

/// Counts what a subscription hands it, which is all these tests ask about.
const Counter = struct {
    messages: usize = 0,
    undecodable: usize = 0,
    /// The last pong's length, which says which message we landed on.
    zeroes: ?u16 = null,

    pub fn onMessage(self: *Counter, msg: protocol.Message) void {
        self.messages += 1;
        switch (msg) {
            .pong => |p| self.zeroes = p.zeroes,
            else => {},
        }
    }

    pub fn onUndecodable(self: *Counter, _: anyerror) void {
        self.undecodable += 1;
    }
};

/// A pong framed the way it travels, appended to `w`.
fn appendPong(w: *std.Io.Writer, zeroes: u16) !void {
    const message = try protocol.encodePong(testing.allocator, zeroes);
    defer testing.allocator.free(message);
    try codec.writeVarint(w, message.len);
    try w.writeAll(message);
}

test "messages arriving with a close are read first, and one that does not decode costs only itself" {
    const d = try fakepeer.Dialed.init(testing.io, 1000);
    defer d.deinit();

    // Both messages and the close, all in the one packet. The first is a node
    // announcement with nothing behind its type id; the second we understand.
    var buf: [128]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try codec.writeVarint(&w, 2);
    try w.writeAll(&.{ 0x00, @backingInt(protocol.MessageType.node_announcement) });
    try appendPong(&w, 3);
    try d.peer.sendStreamAndClose(w.buffered(), false, 0, "done");

    var counter = Counter{};
    try testing.expectEqual(@as(usize, 2), try subscribeOn(testing.allocator, d.conn, 8, &counter));
    try testing.expectEqual(@as(usize, 1), counter.messages);
    try testing.expectEqual(@as(usize, 1), counter.undecodable);
    // The length prefix put the reader exactly on the message after it.
    try testing.expectEqual(@as(?u16, 3), counter.zeroes);
}

test "a close with an error code ends the run as a failure" {
    const d = try fakepeer.Dialed.init(testing.io, 1000);
    defer d.deinit();

    var buf: [128]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try appendPong(&w, 4);
    try d.peer.sendStreamAndClose(w.buffered(), false, 0x2, "internal error");

    var counter = Counter{};
    try testing.expectError(
        error.PeerClosed,
        subscribeOn(testing.allocator, d.conn, 8, &counter),
    );
    // Still handed over: the message arrived, whatever followed it.
    try testing.expectEqual(@as(usize, 1), counter.messages);
    try testing.expectEqualStrings("internal error", d.conn.peerClose().?.reason());
}

test "a message arriving in pieces reads once it is whole" {
    const message = try protocol.encodePong(testing.allocator, 2);
    defer testing.allocator.free(message);

    var buf: [64]u8 = undefined;
    const framed = try frame(&buf, message);
    // One length byte for a message this short, then the message itself.
    try testing.expectEqual(message.len + 1, framed.len);

    // Every prefix of a whole message is incomplete, including an empty one.
    for (0..framed.len) |n| {
        try testing.expectEqual(@as(?Framed, null), try next(framed[0..n], &.{}));
    }

    // Through the receiver a connection reads from, split the way two
    // datagrams would arrive.
    var stream_buf: [64]u8 = undefined;
    var r = quic.stream.Receiver.init(&stream_buf, stream_buf.len);
    const half = framed.len / 2;
    try r.push(.{ .id = 0, .offset = 0, .data = framed[0..half], .fin = false });
    try testing.expectEqual(@as(?Framed, null), try next(r.readable(), &.{}));

    try r.push(.{ .id = 0, .offset = half, .data = framed[half..], .fin = false });
    const got = (try next(r.readable(), &.{})).?;
    try testing.expectEqual(framed.len, got.consumed);
    try testing.expectEqual(@as(u16, 2), got.contents.message.pong.zeroes);

    // Consuming it leaves the stream empty, ready for the next one.
    r.consume(got.consumed);
    try testing.expectEqual(@as(?Framed, null), try next(r.readable(), &.{}));
}

test "a length no message could have is fatal" {
    // A four-byte varint holding 1 << 20, well past MAX_MESSAGE_SIZE.
    var buf: [8]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try codec.writeVarint(&w, 1 << 20);
    try testing.expectError(error.MessageTooLong, next(w.buffered(), &.{}));
}
