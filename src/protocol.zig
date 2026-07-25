//! Radicle wire frames and gossip messages, layered on the QUIC-varint codec.
//! A gossip frame is: version(4) ++ stream(varint) ++ varint(len) ++ message.
//! A message is: type_id(u16) ++ body.
//! Source: radicle-protocol/src/wire/{frame,message}.rs, service/message.rs.
const std = @import("std");
const codec = @import("codec.zig");

pub const PROTOCOL_VERSION: u8 = 1;
pub const VERSION_STRING = [4]u8{ 'r', 'a', 'd', PROTOCOL_VERSION };

/// Gossip message type ids (radicle-protocol wire/message.rs MessageType).
pub const MessageType = enum(u16) {
    node_announcement = 2,
    inventory_announcement = 4,
    refs_announcement = 6,
    subscribe = 8,
    ping = 10,
    pong = 12,
    info = 14,
    _,
};

/// Stream ids: the low 3 bits are the stream type/initiator. The gossip and
/// control streams are always open. (radicle-protocol wire/frame.rs StreamId)
pub const StreamType = enum(u64) {
    control = 0b000,
    gossip = 0b010,
};

pub const Ping = struct { ponglen: u16 = 0, zeroes: u16 = 0 };
pub const Pong = struct { zeroes: u16 };

/// Encodes a gossip `Ping` as a full frame. Caller owns the result.
pub fn encodePingFrame(allocator: std.mem.Allocator, ping: Ping) ![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(allocator);
    const mw = codec.Writer{ .out = &msg, .allocator = allocator };
    // Message: type_id ++ ponglen ++ zeroes(len ++ zero bytes).
    try mw.writeU16(@backingInt(MessageType.ping));
    try mw.writeU16(ping.ponglen);
    try mw.writeU16(ping.zeroes);
    var i: u16 = 0;
    while (i < ping.zeroes) : (i += 1) try mw.writeU8(0);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    const w = codec.Writer{ .out = &out, .allocator = allocator };
    try w.bytes(&VERSION_STRING);
    try w.varint(@backingInt(StreamType.gossip));
    try w.varint(msg.items.len); // gossip payload is varint-length-prefixed
    try w.bytes(msg.items);
    return out.toOwnedSlice(allocator);
}

/// A parsed gossip message (only the variants we handle).
pub const Message = union(enum) {
    ping: Ping,
    pong: Pong,
    other: MessageType,
};

pub const DecodedFrame = struct { message: Message, consumed: usize };

/// Decodes one frame from `buf`, returning the gossip message and the number
/// of bytes consumed.
pub fn decodeFrame(buf: []const u8) !DecodedFrame {
    var r = codec.Reader{ .buf = buf };
    const version = try r.take(4);
    if (!std.mem.eql(u8, version, &VERSION_STRING)) return error.BadVersion;
    _ = try r.varint(); // stream id
    const len = try r.varint();
    const payload = try r.take(@intCast(len));

    var mr = codec.Reader{ .buf = payload };
    const type_id: MessageType = @fromBackingInt(@intCast(try mr.readU16()));
    const message: Message = switch (type_id) {
        .ping => .{ .ping = .{
            .ponglen = try mr.readU16(),
            .zeroes = try readZeroBytes(&mr),
        } },
        .pong => .{ .pong = .{ .zeroes = try readZeroBytes(&mr) } },
        else => .{ .other = type_id },
    };
    return .{ .message = message, .consumed = r.pos };
}

fn readZeroBytes(r: *codec.Reader) !u16 {
    const n = try r.readU16();
    _ = try r.take(n);
    return n;
}

/// Reads exactly one frame from an Io.Reader stream and returns its gossip
/// message. `scratch` must be large enough for the payload.
pub fn decodeFrameStreaming(r: *std.Io.Reader, scratch: []u8) !Message {
    const version = try r.takeArray(4);
    if (!std.mem.eql(u8, version, &VERSION_STRING)) return error.BadVersion;
    _ = try readStreamVarint(r); // stream id
    const len = try readStreamVarint(r);
    const payload = scratch[0..@intCast(len)];
    try r.readSliceAll(payload);

    var mr = codec.Reader{ .buf = payload };
    const type_id: MessageType = @fromBackingInt(@intCast(try mr.readU16()));
    return switch (type_id) {
        .ping => .{ .ping = .{ .ponglen = try mr.readU16(), .zeroes = try readZeroBytes(&mr) } },
        .pong => .{ .pong = .{ .zeroes = try readZeroBytes(&mr) } },
        else => .{ .other = type_id },
    };
}

fn readStreamVarint(r: *std.Io.Reader) !u64 {
    const first = try r.takeByte();
    const tag = first >> 6;
    const n: usize = @as(usize, 1) << @intCast(tag);
    var v: u64 = first & 0x3f;
    for (1..n) |_| v = (v << 8) | try r.takeByte();
    return v;
}

const testing = std.testing;

test "encode ping frame layout" {
    const frame = try encodePingFrame(testing.allocator, .{ .ponglen = 0, .zeroes = 0 });
    defer testing.allocator.free(frame);
    // version(rad,1) ++ stream(varint 0x02) ++ len(varint 0x06) ++
    //   ping: type(00 0a) ponglen(00 00) zeroes-len(00 00)
    try testing.expectEqualSlices(u8, &[_]u8{
        'r',  'a',  'd',  1,
        0x02, 0x06, 0x00, 0x0a,
        0x00, 0x00, 0x00, 0x00,
    }, frame);
}

test "decode pong frame" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    const w = codec.Writer{ .out = &buf, .allocator = testing.allocator };
    try w.bytes(&VERSION_STRING);
    try w.varint(@backingInt(StreamType.gossip));
    try w.varint(7); // type(2) + zeroeslen(2) + 3 zero bytes
    try w.writeU16(@backingInt(MessageType.pong));
    try w.writeU16(3);
    try w.writeU8(0);
    try w.writeU8(0);
    try w.writeU8(0);

    const decoded = try decodeFrame(buf.items);
    try testing.expectEqual(@as(u16, 3), decoded.message.pong.zeroes);
    try testing.expectEqual(buf.items.len, decoded.consumed);
}

test "round trip ping via decode" {
    const frame = try encodePingFrame(testing.allocator, .{ .ponglen = 5, .zeroes = 2 });
    defer testing.allocator.free(frame);
    const decoded = try decodeFrame(frame);
    try testing.expectEqual(@as(u16, 5), decoded.message.ping.ponglen);
    try testing.expectEqual(@as(u16, 2), decoded.message.ping.zeroes);
}
