//! Radicle wire frames and gossip messages, layered on the QUIC-varint codec.
//! A gossip frame is: version(4) ++ stream(varint) ++ varint(len) ++ message.
//! A message is: type_id(u16) ++ body.
//! Source: radicle-protocol/src/wire/{frame,message}.rs, service/message.rs.
const std = @import("std");
const codec = @import("../codec.zig");
const node_id = @import("../identity/node_id.zig");
const pktline = @import("../git/pktline.zig");
const signature = @import("../crypto/signature.zig");

pub const PROTOCOL_VERSION: u8 = 1;
pub const VERSION_STRING = [4]u8{ 'r', 'a', 'd', PROTOCOL_VERSION };

/// Largest frame payload we will buffer, which is whichever of the two things a
/// frame carries is bigger: a gossip message, or one max-size pkt-line of git
/// data. Frames declaring more are rejected rather than truncated.
pub const MAX_FRAME_PAYLOAD = @max(@as(usize, MAX_MESSAGE_SIZE), pktline.MAX_LINE);

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

/// A Subscribe message requesting all gossip: the "match everything" filter
/// (1 KiB of 0xff) over the full time range. It depends on nothing at runtime,
/// so it is built once at compile time rather than allocated per call.
/// Source: radicle-protocol service/message.rs Subscribe, filter.rs default().
pub const subscribe_all_message = blk: {
    // type ++ filter(u16 len ++ bytes) ++ since ++ until
    var msg: [2 + 2 + FILTER_SIZE_S + 8 + 8]u8 = undefined;
    std.mem.writeInt(u16, msg[0..2], @backingInt(MessageType.subscribe), .big);
    std.mem.writeInt(u16, msg[2..4], FILTER_SIZE_S, .big);
    @memset(msg[4 .. 4 + FILTER_SIZE_S], 0xff);
    std.mem.writeInt(u64, msg[4 + FILTER_SIZE_S ..][0..8], 0, .big); // since
    std.mem.writeInt(u64, msg[12 + FILTER_SIZE_S ..][0..8], TIMESTAMP_MAX, .big); // until
    break :blk msg;
};

/// `subscribe_all_message` in a 1.x frame: version ++ stream varint ++ length
/// varint ++ message.
pub const subscribe_all_frame = blk: {
    const msg_len = subscribe_all_message.len;
    var frame: [VERSION_STRING.len + 1 + 2 + msg_len]u8 = undefined;
    @memcpy(frame[0..VERSION_STRING.len], &VERSION_STRING);
    frame[VERSION_STRING.len] = @intCast(StreamId.gossip_out.value);
    std.mem.writeInt(u16, frame[VERSION_STRING.len + 1 ..][0..2], (0b01 << 14) | @as(u16, msg_len), .big);
    @memcpy(frame[VERSION_STRING.len + 3 ..], &subscribe_all_message);
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

    /// `iroh` carries no host or port: a node id is the whole address there.
    /// Source: radicle/src/node.rs Address::IROH, wire/message.rs.
    pub const Kind = enum(u8) { ipv4 = 1, ipv6 = 2, dns = 3, onion = 4, i2p = 5, iroh = 6, _ };
};

/// Whether `node` signed `body`, which is the message body alone: not the type
/// id, not the wrapper carrying it.
/// Source: radicle-protocol service/message.rs Announcement::verify.
fn signedBy(node: [32]u8, body: []const u8, sig: [64]u8) bool {
    signature.verify(
        node_id.NodeId.fromPublicKey(node),
        body,
        .{ .bytes = sig },
    ) catch return false;
    return true;
}

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
    /// The signature and the bytes it covers, kept so a caller can decide
    /// whether to trust any of the above.
    sig: [64]u8 = @splat(0),
    signed: []const u8 = &.{},

    pub fn addresses(self: *const NodeAnnounced) []const Address {
        return self.addr_storage[0..self.addr_count];
    }

    pub fn verified(self: *const NodeAnnounced) bool {
        return signedBy(self.node, self.signed, self.sig);
    }
};

/// A node announcing which repos it holds. `inventory` is a slice of raw
/// 20-byte git oids borrowing the decode scratch buffer.
pub const InventoryAnnounced = struct {
    node: [32]u8,
    inventory: []const [20]u8,
    timestamp: u64,
    sig: [64]u8 = @splat(0),
    signed: []const u8 = &.{},

    pub fn verified(self: *const InventoryAnnounced) bool {
        return signedBy(self.node, self.signed, self.sig);
    }
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
    return .{ .message = try decodeMessage(payload, &.{}), .consumed = r.pos };
}

/// Decodes one message, with no transport framing around it. Shared by 1.x
/// frames and 2.x streams, which differ only in how they delimit this.
///
/// Announcements borrow from `payload`, except inventory oids, which are copied
/// into `oid_buf`; pass an empty one to report inventories as `.other`.
pub fn decodeMessage(payload: []const u8, oid_buf: [][20]u8) !Message {
    var mr = codec.Reader{ .buf = payload };
    const type_id: MessageType = @fromBackingInt(@intCast(try mr.readU16()));
    return switch (type_id) {
        .ping => .{ .ping = .{
            .ponglen = try mr.readU16(),
            .zeroes = try readZeroBytes(&mr),
        } },
        .pong => .{ .pong = .{ .zeroes = try readZeroBytes(&mr) } },
        .node_announcement => .{ .node_announced = try parseNodeAnnounced(&mr) },
        .inventory_announcement => if (oid_buf.len == 0)
            .{ .other = type_id }
        else
            .{ .inventory_announced = try parseInventoryAnnounced(&mr, oid_buf) },
        else => .{ .other = type_id },
    };
}

fn readZeroBytes(r: *codec.Reader) !u16 {
    const n = try r.readU16();
    _ = try r.take(n);
    return n;
}

/// One frame's gossip message, or what decoding it failed with.
pub const FramedMessage = union(enum) {
    message: Message,
    undecodable: anyerror,
};

/// Reads one frame off a stream. Contents that do not decode are not fatal,
/// unlike a bad version or length: the length prefix already put the reader on
/// the next frame, so an unknown field costs one frame, not the connection.
pub fn readFramedMessage(r: *std.Io.Reader, scratch: []u8, oid_buf: [][20]u8) !FramedMessage {
    const version = try r.takeArray(4);
    if (!std.mem.eql(u8, version, &VERSION_STRING)) return error.BadVersion;
    _ = try readStreamVarint(r); // stream id
    const len = try readStreamVarint(r);
    if (len > scratch.len) return error.FrameTooLarge;
    const payload = scratch[0..@intCast(len)];
    try r.readSliceAll(payload);
    if (decodeMessage(payload, oid_buf)) |message| {
        return .{ .message = message };
    } else |e| {
        return .{ .undecodable = e };
    }
}

/// As `readFramedMessage`, raising an undecodable payload instead. For the
/// readers that answer a peer rather than watch it.
pub fn decodeFrameStreaming(r: *std.Io.Reader, scratch: []u8, oid_buf: [][20]u8) !Message {
    return switch (try readFramedMessage(r, scratch, oid_buf)) {
        .message => |m| m,
        .undecodable => |e| e,
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
    const sig = (try r.take(64))[0..64].*;
    // What the signature covers: the body, which runs to the end of the
    // message.
    const signed = r.buf[r.pos..];
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
        const addr = try readAddress(r);
        if (found < storage.len) {
            storage[found] = addr;
            found += 1;
        }
    }

    _ = try r.readU64(); // nonce
    // A peer may cut the message off before the agent, which upstream tolerates
    // rather than rejecting the announcement.
    // Source: radicle-protocol service/message.rs NodeAnnouncement::decode.
    const agent = readAgent(r) catch "";
    return .{
        .node = node,
        .alias = alias,
        .agent = agent,
        .timestamp = timestamp,
        .addr_storage = storage,
        .addr_count = found,
        .sig = sig,
        .signed = signed,
    };
}

fn parseInventoryAnnounced(r: *codec.Reader, oid_buf: [][20]u8) !InventoryAnnounced {
    const node = (try r.take(32))[0..32].*;
    const sig = (try r.take(64))[0..64].*;
    const signed = r.buf[r.pos..];
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
    return .{
        .node = node,
        .inventory = oid_buf[0..count],
        .timestamp = timestamp,
        .sig = sig,
        .signed = signed,
    };
}

// Address wire form (radicle-protocol wire/message.rs Address): u8 kind ++
// host ++ u16 port, except iroh, which is the kind byte alone.
/// Decodes one address. An unknown kind is fatal: not every kind is framed, so
/// skipping one means guessing its length and misaligning every field after the
/// address list. Upstream rejects them too.
/// Source: radicle-protocol wire/message.rs Address::decode.
fn readAddress(r: *codec.Reader) !Address {
    const kind: Address.Kind = @fromBackingInt(try r.readU8());
    const host = switch (kind) {
        // Nothing follows the kind byte: a node id is the whole address.
        .iroh => return .{ .kind = kind, .host = &.{}, .port = 0 },
        .ipv4 => try r.take(4),
        .ipv6 => try r.take(16),
        .dns, .i2p => try r.take(try r.readU8()),
        .onion => try r.take(32),
        else => return error.UnknownAddressType,
    };
    return .{ .kind = kind, .host = host, .port = try r.readU16() };
}

/// The announcement's trailing user-agent string.
fn readAgent(r: *codec.Reader) ![]const u8 {
    return r.take(try r.readU8());
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

test "ping and control frame layouts, and a ping round trip" {
    const ping = try encodePingFrame(testing.allocator, .{ .ponglen = 0, .zeroes = 0 });
    defer testing.allocator.free(ping);
    // version(rad,1) ++ stream(varint 0x02) ++ len(varint 0x06) ++
    //   ping: type(00 0a) ponglen(00 00) zeroes-len(00 00)
    try testing.expectEqualSlices(u8, &[_]u8{
        'r',  'a',  'd',  1,
        0x02, 0x06, 0x00, 0x0a,
        0x00, 0x00, 0x00, 0x00,
    }, ping);

    const control = try encodeControlFrame(testing.allocator, .open, StreamId.git_out);
    defer testing.allocator.free(control);
    // version(rad,1) ++ control-stream(0x00) ++ type(open=0x00) ++ target(0x04)
    try testing.expectEqualSlices(u8, &[_]u8{ 'r', 'a', 'd', 1, 0x00, 0x00, 0x04 }, control);

    const round_trip = try encodePingFrame(testing.allocator, .{ .ponglen = 5, .zeroes = 2 });
    defer testing.allocator.free(round_trip);
    const decoded = try decodeFrame(round_trip);
    try testing.expectEqual(@as(u16, 5), decoded.message.ping.ponglen);
    try testing.expectEqual(@as(u16, 2), decoded.message.ping.zeroes);
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

test "git-upload-pack pkt-line matches a captured radicle-node fetch" {
    // Captured off the wire from radicle-node 1.9.1: bare base58 id (no rad:,
    // no .git), empty host, then version=2.
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
// place the wire says where another node can be reached. Every address kind
// has to be read exactly, unframed ones included, or the fields after the
// address list misalign.
test "decode node announcement addresses, and reject an unknown kind" {
    const key = try signature.SecretKey.fromSeed(@splat(7));

    // The signed part: version ++ features ++ timestamp ++ alias ++ addresses
    // ++ nonce ++ agent. iroh (which every 2.x node announces, and which
    // carries nothing) and i2p (behind a heartwood feature flag) sit between
    // the two ordinary kinds.
    var signed: std.ArrayList(u8) = .empty;
    defer signed.deinit(testing.allocator);
    const sw = codec.Writer{ .out = &signed, .allocator = testing.allocator };
    try sw.writeU8(1); // version
    try sw.writeU64(0); // features
    try sw.writeU64(7); // timestamp
    try sw.writeU8(1);
    try sw.bytes("a"); // alias
    try sw.writeU16(4); // address count
    const first_kind_at = signed.items.len;
    try sw.writeU8(@backingInt(Address.Kind.ipv4));
    try sw.bytes(&[_]u8{ 192, 168, 0, 1 });
    try sw.writeU16(8776);
    try sw.writeU8(@backingInt(Address.Kind.dns));
    try sw.writeU8(11);
    try sw.bytes("example.com");
    try sw.writeU16(8777);
    try sw.writeU8(@backingInt(Address.Kind.iroh));
    try sw.writeU8(@backingInt(Address.Kind.i2p));
    try sw.writeU8(4);
    try sw.bytes("i2pa");
    try sw.writeU16(1234);
    try sw.writeU64(0); // nonce
    try sw.writeU8(1);
    try sw.bytes("x"); // agent

    const sig = try key.sign(signed.items);

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    const w = codec.Writer{ .out = &buf, .allocator = testing.allocator };
    try w.bytes(&VERSION_STRING);
    try w.varint(StreamId.gossip_out.value);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(testing.allocator);
    const bw = codec.Writer{ .out = &body, .allocator = testing.allocator };
    try bw.writeU16(@backingInt(MessageType.node_announcement));
    try bw.bytes(&key.nodeId().key);
    try bw.bytes(&sig.bytes);
    const signed_at = body.items.len;
    try bw.bytes(signed.items);
    try w.varint(body.items.len);
    try w.bytes(body.items);

    var stream_reader = std.Io.Reader.fixed(buf.items);
    var scratch: [1024]u8 = undefined;
    var oids: [8][20]u8 = undefined;
    const msg = try decodeFrameStreaming(&stream_reader, &scratch, &oids);
    const n = msg.node_announced;
    // The fields after the address list line up, so no address ran long.
    try testing.expectEqualStrings("a", n.alias);
    try testing.expectEqualStrings("x", n.agent);
    try testing.expectEqual(@as(u64, 7), n.timestamp);
    try testing.expect(n.verified());

    const addrs = n.addresses();
    try testing.expectEqual(@as(usize, 4), addrs.len);
    try testing.expectEqual(Address.Kind.ipv4, addrs[0].kind);
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 0, 1 }, addrs[0].host);
    try testing.expectEqual(@as(u16, 8776), addrs[0].port);
    try testing.expectEqual(Address.Kind.dns, addrs[1].kind);
    try testing.expectEqualStrings("example.com", addrs[1].host);
    try testing.expectEqual(@as(u16, 8777), addrs[1].port);
    try testing.expectEqual(Address.Kind.iroh, addrs[2].kind);
    try testing.expectEqual(@as(u16, 0), addrs[2].port);
    try testing.expectEqual(@as(u16, 1234), addrs[3].port);

    // Editing what the announcer signed breaks the signature, whoever relays
    // it: the alias here, which a peer would love to rewrite.
    var tampered = try body.clone(testing.allocator);
    defer tampered.deinit(testing.allocator);
    tampered.items[signed_at + 1 + 8 + 8 + 1] = 'b';
    const edited = (try decodeMessage(tampered.items, &oids)).node_announced;
    try testing.expectEqualStrings("b", edited.alias);
    try testing.expect(!edited.verified());

    // A kind nothing frames cannot be skipped, so it fails the message.
    var unknown = try body.clone(testing.allocator);
    defer unknown.deinit(testing.allocator);
    unknown.items[signed_at + first_kind_at] = 0x7f;
    try testing.expectError(error.UnknownAddressType, decodeMessage(unknown.items, &oids));
}

test "decode pong frame, consuming exactly the frame" {
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
