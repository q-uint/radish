//! Radicle wire frames and gossip messages, layered on the QUIC-varint codec.
//! A gossip frame is: version(4) ++ stream(varint) ++ varint(len) ++ message.
//! A message is: type_id(u16) ++ body.
//! Source: radicle-protocol/src/wire/{frame,message}.rs, service/message.rs.
const std = @import("std");
const codec = @import("../codec.zig");

pub const PROTOCOL_VERSION: u8 = 1;
pub const VERSION_STRING = [4]u8{ 'r', 'a', 'd', PROTOCOL_VERSION };

/// Largest frame payload we will buffer. A git frame carries at most one
/// max-size pkt-line (65516 + 4 header); inventory gossip frames observed from
/// a live node run to tens of KiB. Frames declaring more are rejected rather
/// than truncated.
pub const MAX_FRAME_PAYLOAD = 70 * 1024;

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

/// Stream kind, in bits [2:1] of a stream id. (wire/frame.rs StreamType)
pub const StreamType = enum(u2) {
    control = 0b00,
    gossip = 0b01,
    git = 0b10,
};

pub const Link = enum(u1) { outbound = 0, inbound = 1 };

/// A multiplexed stream id: varint `(n << 3) | (type << 1) | link`. We are
/// always the initiator (outbound), so link = 0. (wire/frame.rs StreamId)
pub const StreamId = struct {
    value: u64,

    pub fn base(kind: StreamType, link: Link) StreamId {
        return .{ .value = (@as(u64, @backingInt(kind)) << 1) | @backingInt(link) };
    }

    /// The nth stream of this type/initiator (adds n << 3).
    pub fn nth(self: StreamId, n: u64) StreamId {
        return .{ .value = self.value + (n << 3) };
    }

    pub const control_out = StreamId{ .value = 0b000 };
    pub const gossip_out = StreamId{ .value = 0b010 };
    pub const git_out = StreamId{ .value = 0b100 };
};

pub const Ping = struct { ponglen: u16 = 0, zeroes: u16 = 0 };
pub const Pong = struct { zeroes: u16 };

/// Largest message body a node will encode: the u16 size the transport allows,
/// less the type id that shares it.
/// Source: radicle-protocol wire/message.rs Message::MAX_SIZE.
pub const MAX_MESSAGE_SIZE: u16 = std.math.maxInt(u16) - @sizeOf(u16);

/// Max zero bytes a Pong may carry: the body, less the u16 length prefix the
/// zeroes themselves need. Note this is below u16::MAX, so a peer can ask for
/// a Pong that will not fit.
/// Source: radicle-protocol service/message.rs Ping::MAX_PONG_ZEROES.
pub const MAX_PONG_ZEROES: u16 = MAX_MESSAGE_SIZE - @sizeOf(u16);

/// Smallest gossip bloom-filter (radicle service/filter.rs FILTER_SIZE_S).
pub const FILTER_SIZE_S = 1024;

/// Max repos in an InventoryAnnouncement (radicle service/message.rs).
pub const INVENTORY_LIMIT = 2973;

/// Radicle timestamps are signed-64 milliseconds, so the largest value a node
/// accepts is i64::MAX. Sending u64::MAX instead is rejected as an invalid
/// timestamp and the session is dropped as "peer misbehaved".
/// Source: radicle node/timestamp.rs Timestamp::MAX.
pub const TIMESTAMP_MAX: u64 = std.math.maxInt(i64);

/// A Subscribe frame requesting all gossip: the "match everything" filter
/// (1 KiB of 0xff) over the full time range. It depends on nothing at runtime,
/// so it is built once at compile time rather than allocated per call.
/// Source: radicle-protocol service/message.rs Subscribe, filter.rs default().
pub const subscribe_all_frame = blk: {
    // message: type ++ filter(u16 len ++ bytes) ++ since ++ until
    const msg_len = 2 + 2 + FILTER_SIZE_S + 8 + 8;
    var msg: [msg_len]u8 = undefined;
    std.mem.writeInt(u16, msg[0..2], @backingInt(MessageType.subscribe), .big);
    std.mem.writeInt(u16, msg[2..4], FILTER_SIZE_S, .big);
    @memset(msg[4 .. 4 + FILTER_SIZE_S], 0xff);
    std.mem.writeInt(u64, msg[4 + FILTER_SIZE_S ..][0..8], 0, .big); // since
    std.mem.writeInt(u64, msg[12 + FILTER_SIZE_S ..][0..8], TIMESTAMP_MAX, .big); // until

    // frame: version ++ stream varint ++ length varint ++ message
    var frame: [VERSION_STRING.len + 1 + 2 + msg_len]u8 = undefined;
    @memcpy(frame[0..VERSION_STRING.len], &VERSION_STRING);
    frame[VERSION_STRING.len] = @intCast(StreamId.gossip_out.value);
    std.mem.writeInt(u16, frame[VERSION_STRING.len + 1 ..][0..2], (0b01 << 14) | @as(u16, msg_len), .big);
    @memcpy(frame[VERSION_STRING.len + 3 ..], &msg);
    break :blk frame;
};

/// Wraps a varint-payload frame: version ++ stream ++ varint(len) ++ body.
/// Used for gossip and git streams (both length-prefix their payload).
fn wrapFrame(allocator: std.mem.Allocator, stream: StreamId, body: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    const w = codec.Writer{ .out = &out, .allocator = allocator };
    try w.bytes(&VERSION_STRING);
    try w.varint(stream.value);
    try w.varint(body.len);
    try w.bytes(body);
    return out.toOwnedSlice(allocator);
}

fn wrapGossip(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    return wrapFrame(allocator, StreamId.gossip_out, body);
}

/// Control message types (wire/frame.rs ControlType).
pub const ControlType = enum(u8) { open = 0, close = 1, eof = 2 };

/// Encodes a control frame: version ++ control-stream ++ type ++ stream-id.
/// Control frames do NOT length-prefix their body. Caller owns the result.
pub fn encodeControlFrame(allocator: std.mem.Allocator, ctrl: ControlType, target: StreamId) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    const w = codec.Writer{ .out = &out, .allocator = allocator };
    try w.bytes(&VERSION_STRING);
    try w.varint(StreamId.control_out.value);
    try w.writeU8(@backingInt(ctrl));
    try w.varint(target.value);
    return out.toOwnedSlice(allocator);
}

/// Encodes a git frame carrying raw git-protocol bytes on `stream`.
/// Caller owns the result.
pub fn encodeGitFrame(allocator: std.mem.Allocator, stream: StreamId, data: []const u8) ![]u8 {
    return wrapFrame(allocator, stream, data);
}

/// Builds the git intro pkt-line: `git-upload-pack /<bare-rid>\0\0version=2\0`,
/// 4-hex length prefix counting itself and the NULs. `rid` is the bare base58
/// id (no `rad:`, no `.git`) - verified against a real radicle-node fetch.
/// `version=2` is required or the responder rejects the request.
pub fn gitUploadPackLine(allocator: std.mem.Allocator, rid: []const u8) ![]u8 {
    const bare = if (std.mem.startsWith(u8, rid, "rad:")) rid["rad:".len..] else rid;
    const payload = try std.fmt.allocPrint(allocator, "git-upload-pack /{s}\x00\x00version=2\x00", .{bare});
    defer allocator.free(payload);
    const total = payload.len + 4;
    return std.fmt.allocPrint(allocator, "{x:0>4}{s}", .{ total, payload });
}

/// Encodes a `Ping` message, with no transport framing around it. 1.x wraps
/// this in a gossip frame; 2.x length-prefixes it on a QUIC stream. Caller owns
/// the result.
pub fn encodePing(allocator: std.mem.Allocator, ping: Ping) ![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(allocator);
    const mw = codec.Writer{ .out = &msg, .allocator = allocator };
    // type_id ++ ponglen ++ zeroes(len ++ zero bytes).
    try mw.writeU16(@backingInt(MessageType.ping));
    try mw.writeU16(ping.ponglen);
    try mw.writeU16(ping.zeroes);
    var i: u16 = 0;
    while (i < ping.zeroes) : (i += 1) try mw.writeU8(0);
    return msg.toOwnedSlice(allocator);
}

/// Encodes a `Pong` message, with no transport framing. Caller owns the result.
pub fn encodePong(allocator: std.mem.Allocator, zeroes: u16) ![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    errdefer msg.deinit(allocator);
    const mw = codec.Writer{ .out = &msg, .allocator = allocator };
    try mw.writeU16(@backingInt(MessageType.pong));
    try mw.writeU16(zeroes);
    var i: u16 = 0;
    while (i < zeroes) : (i += 1) try mw.writeU8(0);
    return msg.toOwnedSlice(allocator);
}

/// Encodes a gossip `Ping` as a full frame. Caller owns the result.
pub fn encodePingFrame(allocator: std.mem.Allocator, ping: Ping) ![]u8 {
    const msg = try encodePing(allocator, ping);
    defer allocator.free(msg);
    return wrapGossip(allocator, msg);
}

/// Encodes a gossip `Pong` as a full frame. Caller owns the result.
pub fn encodePongFrame(allocator: std.mem.Allocator, zeroes: u16) ![]u8 {
    const msg = try encodePong(allocator, zeroes);
    defer allocator.free(msg);
    return wrapGossip(allocator, msg);
}

/// Max addresses in a NodeAnnouncement (radicle service/message.rs).
pub const ADDRESS_LIMIT = 16;

/// An address a node advertises for itself. `host` borrows the decode scratch
/// buffer: 4 or 16 octets for ip, the name for dns, 32 raw bytes for onion.
/// Source: radicle node/address.rs AddressType.
pub const Address = struct {
    kind: Kind,
    host: []const u8,
    port: u16,

    pub const Kind = enum(u8) { ipv4 = 1, ipv6 = 2, dns = 3, onion = 4, i2p = 5, _ };
};

/// A node announcing itself: identity, alias, and the addresses it can be
/// reached at. `alias`, `agent`, and each address host borrow the decode
/// scratch buffer; copy them out to retain past the next frame.
pub const NodeAnnounced = struct {
    node: [32]u8,
    alias: []const u8,
    agent: []const u8,
    timestamp: u64,
    /// Inline, since the protocol caps this at ADDRESS_LIMIT: no caller-owned
    /// buffer to thread through, unlike the unbounded inventory list.
    addr_storage: [ADDRESS_LIMIT]Address = undefined,
    addr_count: u8 = 0,

    pub fn addresses(self: *const NodeAnnounced) []const Address {
        return self.addr_storage[0..self.addr_count];
    }
};

/// A node announcing which repos it holds. `inventory` is a slice of raw
/// 20-byte git oids borrowing the decode scratch buffer.
pub const InventoryAnnounced = struct {
    node: [32]u8,
    inventory: []const [20]u8,
    timestamp: u64,
};

/// A parsed gossip message (only the variants we handle).
pub const Message = union(enum) {
    ping: Ping,
    pong: Pong,
    node_announced: NodeAnnounced,
    inventory_announced: InventoryAnnounced,
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
    return .{ .message = try decodeMessage(payload), .consumed = r.pos };
}

/// Decodes one message, with no transport framing around it. Shared by 1.x
/// frames and 2.x streams, which differ only in how they delimit this.
pub fn decodeMessage(payload: []const u8) !Message {
    var mr = codec.Reader{ .buf = payload };
    const type_id: MessageType = @fromBackingInt(@intCast(try mr.readU16()));
    return switch (type_id) {
        .ping => .{ .ping = .{
            .ponglen = try mr.readU16(),
            .zeroes = try readZeroBytes(&mr),
        } },
        .pong => .{ .pong = .{ .zeroes = try readZeroBytes(&mr) } },
        else => .{ .other = type_id },
    };
}

fn readZeroBytes(r: *codec.Reader) !u16 {
    const n = try r.readU16();
    _ = try r.take(n);
    return n;
}

/// Reads exactly one frame from an Io.Reader stream and returns its gossip
/// message. `scratch` must be large enough for the payload; `oid_buf` receives
/// decoded inventory oids (copied out of the length-prefixed wire form).
pub fn decodeFrameStreaming(r: *std.Io.Reader, scratch: []u8, oid_buf: [][20]u8) !Message {
    const version = try r.takeArray(4);
    if (!std.mem.eql(u8, version, &VERSION_STRING)) return error.BadVersion;
    _ = try readStreamVarint(r); // stream id
    const len = try readStreamVarint(r);
    if (len > scratch.len) return error.FrameTooLarge;
    const payload = scratch[0..@intCast(len)];
    try r.readSliceAll(payload);

    var mr = codec.Reader{ .buf = payload };
    const type_id: MessageType = @fromBackingInt(@intCast(try mr.readU16()));
    return switch (type_id) {
        .ping => .{ .ping = .{ .ponglen = try mr.readU16(), .zeroes = try readZeroBytes(&mr) } },
        .pong => .{ .pong = .{ .zeroes = try readZeroBytes(&mr) } },
        .node_announcement => .{ .node_announced = try parseNodeAnnounced(&mr) },
        .inventory_announcement => .{ .inventory_announced = try parseInventoryAnnounced(&mr, oid_buf) },
        else => .{ .other = type_id },
    };
}

/// A raw frame off the wire, tagged by stream kind. `payload` (gossip/git)
/// borrows `scratch`; control frames carry the target stream instead.
pub const RawFrame = union(enum) {
    control: struct { ctrl: ControlType, target: u64 },
    gossip: []const u8,
    git: []const u8,
    unknown: struct { stream: u64, payload: []const u8 },
};

/// Reads a varint-length-prefixed body into `scratch`, rejecting a declared
/// length that would overrun it.
fn readPayload(r: *std.Io.Reader, scratch: []u8) ![]const u8 {
    const len = try readStreamVarint(r);
    if (len > scratch.len) return error.FrameTooLarge;
    const payload = scratch[0..@intCast(len)];
    try r.readSliceAll(payload);
    return payload;
}

/// Reads one frame, dispatching on the stream id's type bits. Control bodies
/// are not length-prefixed; gossip/git bodies are varint-length-prefixed.
pub fn readRawFrame(r: *std.Io.Reader, scratch: []u8) !RawFrame {
    const version = try r.takeArray(4);
    if (!std.mem.eql(u8, version, &VERSION_STRING)) return error.BadVersion;
    const stream = try readStreamVarint(r);
    const kind: u2 = @intCast((stream >> 1) & 0b11);
    switch (kind) {
        @backingInt(StreamType.control) => {
            const ctrl: ControlType = @fromBackingInt(@intCast(try r.takeByte()));
            const target = try readStreamVarint(r);
            return .{ .control = .{ .ctrl = ctrl, .target = target } };
        },
        @backingInt(StreamType.gossip), @backingInt(StreamType.git) => {
            const payload = try readPayload(r, scratch);
            return if (kind == @backingInt(StreamType.git))
                .{ .git = payload }
            else
                .{ .gossip = payload };
        },
        else => {
            const payload = try readPayload(r, scratch);
            return .{ .unknown = .{ .stream = stream, .payload = payload } };
        },
    }
}

// Announcement wrapper: node(32) ++ signature(64) ++ message. We don't verify
// the relayed signature here (the origin node signed it, not our peer).
/// A node announcing more addresses than ADDRESS_LIMIT keeps the overflow
/// parsed-but-dropped: the fields after the address list still have to be read.
fn parseNodeAnnounced(r: *codec.Reader) !NodeAnnounced {
    const node = (try r.take(32))[0..32].*;
    _ = try r.take(64); // signature
    _ = try r.readU8(); // version
    _ = try r.readU64(); // features
    const timestamp = try r.readU64();
    const alias_len = try r.readU8();
    const alias = try r.take(alias_len);

    var storage: [ADDRESS_LIMIT]Address = undefined;
    const naddrs = try r.readU16();
    var found: u8 = 0;
    var i: u16 = 0;
    while (i < naddrs) : (i += 1) {
        const addr = try readAddress(r) orelse continue;
        if (found < storage.len) {
            storage[found] = addr;
            found += 1;
        }
    }

    _ = try r.readU64(); // nonce
    const agent_len = try r.readU8();
    const agent = try r.take(agent_len);
    return .{
        .node = node,
        .alias = alias,
        .agent = agent,
        .timestamp = timestamp,
        .addr_storage = storage,
        .addr_count = found,
    };
}

fn parseInventoryAnnounced(r: *codec.Reader, oid_buf: [][20]u8) !InventoryAnnounced {
    const node = (try r.take(32))[0..32].*;
    _ = try r.take(64); // signature
    // inventory: u16 count ++ [RepoId]. Each RepoId (git::Oid) is itself
    // u16-length-prefixed bytes, so oids are NOT contiguous - copy each out.
    const count = try r.readU16();
    if (count > oid_buf.len) return error.TooManyOids;
    var i: u16 = 0;
    while (i < count) : (i += 1) {
        const oid_len = try r.readU16();
        if (oid_len != 20) return error.UnexpectedOidLength;
        @memcpy(&oid_buf[i], try r.take(20));
    }
    const timestamp = try r.readU64();
    return .{ .node = node, .inventory = oid_buf[0..count], .timestamp = timestamp };
}

// Address wire form (radicle-protocol wire/message.rs Address): u8 kind ++
// host ++ u16 port. We skip past addresses we don't consume.
/// Decodes one address. Unknown kinds are skipped rather than rejected: i2p
/// (5) is behind a feature flag upstream and more may follow, and an address
/// we cannot use must not cost us the rest of the announcement. Every kind is
/// either fixed-width or length-prefixed, so an unknown one stays parseable.
/// Source: radicle wire.rs (OnionAddrV3 raw bytes, I2pAddr as String).
fn readAddress(r: *codec.Reader) !?Address {
    const kind: Address.Kind = @fromBackingInt(try r.readU8());
    const host: ?[]const u8 = switch (kind) {
        .ipv4 => try r.take(4),
        .ipv6 => try r.take(16),
        .dns, .i2p => try r.take(try r.readU8()),
        .onion => try r.take(32),
        _ => blk: {
            _ = try r.take(try r.readU8());
            break :blk null;
        },
    };
    const port = try r.readU16();
    return if (host) |h| .{ .kind = kind, .host = h, .port = port } else null;
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

test "encode subscribe-all frame layout" {
    const frame = &subscribe_all_frame;

    // Header: version(rad,1) ++ stream(0x02) ++ len(varint).
    // Message: type(00 08) ++ filter-len(04 00) ++ 1024*0xff ++ since(8) ++ until(8).
    const body_len = 2 + 2 + FILTER_SIZE_S + 8 + 8;
    try testing.expectEqualSlices(u8, &VERSION_STRING, frame[0..4]);
    try testing.expectEqual(@as(u8, 0x02), frame[4]);

    var r = codec.Reader{ .buf = frame[5..] };
    try testing.expectEqual(@as(u64, body_len), try r.varint());
    try testing.expectEqual(@backingInt(MessageType.subscribe), try r.readU16());
    try testing.expectEqual(@as(u16, FILTER_SIZE_S), try r.readU16());
    const filter = try r.take(FILTER_SIZE_S);
    try testing.expect(std.mem.allEqual(u8, filter, 0xff));
    try testing.expectEqual(@as(u64, 0), try r.readU64());
    try testing.expectEqual(TIMESTAMP_MAX, try r.readU64());
}

test "stream ids match the frame.rs table" {
    try testing.expectEqual(@as(u64, 0b000), StreamId.control_out.value);
    try testing.expectEqual(@as(u64, 0b010), StreamId.gossip_out.value);
    try testing.expectEqual(@as(u64, 0b100), StreamId.git_out.value);
    try testing.expectEqual(@as(u64, 0b100), StreamId.base(.git, .outbound).value);
    try testing.expectEqual(@as(u64, 0b101), StreamId.base(.git, .inbound).value);
    // nth preserves type+initiator, adding n<<3.
    try testing.expectEqual(@as(u64, 0b100 + 8), StreamId.git_out.nth(1).value);
}

test "control open frame layout" {
    const frame = try encodeControlFrame(testing.allocator, .open, StreamId.git_out);
    defer testing.allocator.free(frame);
    // version(rad,1) ++ control-stream(0x00) ++ type(open=0x00) ++ target(0x04)
    try testing.expectEqualSlices(u8, &[_]u8{ 'r', 'a', 'd', 1, 0x00, 0x00, 0x04 }, frame);
}

test "git-upload-pack pkt-line matches a captured radicle-node fetch" {
    // Golden bytes captured off the wire from a real radicle-node 1.9.1 fetch:
    // bare base58 id (no rad:, no .git), empty host, then version=2.
    const line = try gitUploadPackLine(testing.allocator, "rad:z3WukSjzicL8WaZHFALbBwb2r8W52");
    defer testing.allocator.free(line);
    const expected = "003egit-upload-pack /z3WukSjzicL8WaZHFALbBwb2r8W52\x00\x00version=2\x00";
    try testing.expectEqualSlices(u8, expected, line);
}

test "decode inventory announcement: each oid is u16-length-prefixed" {
    const node: [32]u8 = @splat(0xAB);
    const sig: [64]u8 = @splat(0xCD);
    var oid: [20]u8 = undefined;
    for (&oid, 0..) |*b, i| b.* = @intCast(i);

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    const w = codec.Writer{ .out = &buf, .allocator = testing.allocator };
    try w.bytes(&VERSION_STRING);
    try w.varint(StreamId.gossip_out.value);
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(testing.allocator);
    const bw = codec.Writer{ .out = &body, .allocator = testing.allocator };
    try bw.writeU16(@backingInt(MessageType.inventory_announcement));
    try bw.bytes(&node);
    try bw.bytes(&sig);
    try bw.writeU16(1); // inventory count
    try bw.writeU16(20); // oid length prefix (git::Oid uses &[u8] encode)
    try bw.bytes(&oid);
    try bw.writeU64(0x1122334455667788); // timestamp
    try w.varint(body.items.len);
    try w.bytes(body.items);

    var stream_reader = std.Io.Reader.fixed(buf.items);
    var scratch: [1024]u8 = undefined;
    var oids: [8][20]u8 = undefined;
    const msg = try decodeFrameStreaming(&stream_reader, &scratch, &oids);
    const inv = msg.inventory_announced;
    try testing.expectEqual(@as(usize, 1), inv.inventory.len);
    try testing.expectEqualSlices(u8, &oid, &inv.inventory[0]);
    try testing.expectEqual(@as(u64, 0x1122334455667788), inv.timestamp);
    try testing.expectEqualSlices(u8, &node, &inv.node);
}

// Peer discovery rides on NodeAnnouncement: the addresses field is the only
// place the wire says where another node can be reached.
test "decode node announcement addresses" {
    const node: [32]u8 = @splat(0xAB);
    const sig: [64]u8 = @splat(0xCD);

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    const w = codec.Writer{ .out = &buf, .allocator = testing.allocator };
    try w.bytes(&VERSION_STRING);
    try w.varint(StreamId.gossip_out.value);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(testing.allocator);
    const bw = codec.Writer{ .out = &body, .allocator = testing.allocator };
    try bw.writeU16(@backingInt(MessageType.node_announcement));
    try bw.bytes(&node);
    try bw.bytes(&sig);
    try bw.writeU8(1); // version
    try bw.writeU64(0); // features
    try bw.writeU64(0x1122334455667788); // timestamp
    try bw.writeU8(3);
    try bw.bytes("abc"); // alias
    try bw.writeU16(2); // address count
    try bw.writeU8(1); // ipv4
    try bw.bytes(&[_]u8{ 192, 168, 0, 1 });
    try bw.writeU16(8776);
    try bw.writeU8(3); // dns
    try bw.writeU8(11);
    try bw.bytes("example.com");
    try bw.writeU16(8777);
    try bw.writeU64(0); // nonce
    try bw.writeU8(5);
    try bw.bytes("agent");
    try w.varint(body.items.len);
    try w.bytes(body.items);

    var stream_reader = std.Io.Reader.fixed(buf.items);
    var scratch: [1024]u8 = undefined;
    var oids: [8][20]u8 = undefined;
    const msg = try decodeFrameStreaming(&stream_reader, &scratch, &oids);
    const n = msg.node_announced;

    try testing.expectEqualStrings("abc", n.alias);
    try testing.expectEqualStrings("agent", n.agent);
    const addrs = n.addresses();
    try testing.expectEqual(@as(usize, 2), addrs.len);
    try testing.expectEqual(Address.Kind.ipv4, addrs[0].kind);
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 0, 1 }, addrs[0].host);
    try testing.expectEqual(@as(u16, 8776), addrs[0].port);
    try testing.expectEqual(Address.Kind.dns, addrs[1].kind);
    try testing.expectEqualStrings("example.com", addrs[1].host);
    try testing.expectEqual(@as(u16, 8777), addrs[1].port);
}

// A node may advertise more than we have room for, and an address kind we do
// not know (heartwood has i2p behind a feature flag). Neither may abort the
// frame: the announcement's other fields are still usable.
test "node announcement with unknown address kind is not fatal" {
    const node: [32]u8 = @splat(0xAB);
    const sig: [64]u8 = @splat(0xCD);

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    const w = codec.Writer{ .out = &buf, .allocator = testing.allocator };
    try w.bytes(&VERSION_STRING);
    try w.varint(StreamId.gossip_out.value);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(testing.allocator);
    const bw = codec.Writer{ .out = &body, .allocator = testing.allocator };
    try bw.writeU16(@backingInt(MessageType.node_announcement));
    try bw.bytes(&node);
    try bw.bytes(&sig);
    try bw.writeU8(1);
    try bw.writeU64(0);
    try bw.writeU64(7);
    try bw.writeU8(1);
    try bw.bytes("a");
    try bw.writeU16(1);
    try bw.writeU8(5); // i2p: length-prefixed, skippable without knowing it
    try bw.writeU8(4);
    try bw.bytes("i2pa");
    try bw.writeU16(1234);
    try bw.writeU64(0);
    try bw.writeU8(1);
    try bw.bytes("x");
    try w.varint(body.items.len);
    try w.bytes(body.items);

    var stream_reader = std.Io.Reader.fixed(buf.items);
    var scratch: [1024]u8 = undefined;
    var oids: [8][20]u8 = undefined;
    const msg = try decodeFrameStreaming(&stream_reader, &scratch, &oids);
    const n = msg.node_announced;
    try testing.expectEqualStrings("a", n.alias);
    try testing.expectEqualStrings("x", n.agent);
    try testing.expectEqual(@as(u64, 7), n.timestamp);
}

test "decode pong frame" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    const w = codec.Writer{ .out = &buf, .allocator = testing.allocator };
    try w.bytes(&VERSION_STRING);
    try w.varint(StreamId.gossip_out.value);
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
