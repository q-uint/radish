//! Gossip announcements. A NodeAnnouncement advertises a node's identity and
//! addresses; it is signed by the node's key and wrapped in an Announcement
//! (node ++ signature ++ message) inside a gossip frame.
//!
//! Wire encoding is bespoke big-endian: u8/u16/u64 big-endian, strings are
//! u8-length-prefixed, vectors are u16-length-prefixed.
//! Source: radicle-protocol service/message.rs (NodeAnnouncement, Announcement),
//! wire.rs (Encode for &str/slice), node.rs (MAX_ALIAS_LENGTH).
const std = @import("std");
const codec = @import("../codec.zig");
const signature = @import("../crypto/signature.zig");
const node_id = @import("../identity/node_id.zig");
const protocol = @import("protocol.zig");

pub const MAX_ALIAS_LEN = 32;
pub const ADDRESS_LIMIT = 16;

/// Radicle's user-agent convention is `/<name>:<version>/`.
pub const USER_AGENT = "/radish:0.0.0/";

pub const Error = error{ AliasTooLong, AgentTooLong, TooManyAddresses } || std.mem.Allocator.Error;

pub const Address = struct {
    pub const Kind = enum(u8) { ipv4 = 1, ipv6 = 2, dns = 3 };
    // Only the fields we need to emit; a bare node announcing itself may send none.
};

pub const NodeAnnouncement = struct {
    version: u8 = 1,
    features: u64 = 1,
    timestamp: u64, // unix millis
    alias: []const u8,
    // addresses omitted for now (empty vec)
    nonce: u64 = 0,
    agent: []const u8 = USER_AGENT,

    /// Encodes the signed message body (the bytes that get signed).
    pub fn encodeMessage(self: NodeAnnouncement, allocator: std.mem.Allocator, out: *std.ArrayList(u8)) Error!void {
        if (self.alias.len > MAX_ALIAS_LEN) return error.AliasTooLong;
        if (self.agent.len > std.math.maxInt(u8)) return error.AgentTooLong;
        const w = codec.Writer{ .out = out, .allocator = allocator };
        try w.writeU8(self.version);
        try writeU64(w, self.features);
        try writeU64(w, self.timestamp);
        try w.writeU8(@intCast(self.alias.len));
        try w.bytes(self.alias);
        try w.writeU16(0); // addresses: empty u16-prefixed vec
        try writeU64(w, self.nonce);
        try w.writeU8(@intCast(self.agent.len));
        try w.bytes(self.agent);
    }
};

/// A signed announcement, ready to wrap in a gossip frame.
pub const Announcement = struct {
    node: node_id.NodeId,
    sig: signature.Signature,
    message: []const u8, // the encoded NodeAnnouncement body

    /// Encodes a full gossip frame: version ++ stream ++ len ++
    ///   type(NodeAnnouncement) ++ node ++ signature ++ message.
    /// Caller owns the result.
    pub fn encodeFrame(self: Announcement, allocator: std.mem.Allocator) ![]u8 {
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(allocator);
        const pw = codec.Writer{ .out = &payload, .allocator = allocator };
        try pw.writeU16(@backingInt(protocol.MessageType.node_announcement));
        try pw.bytes(&self.node.key);
        try pw.bytes(&self.sig.bytes);
        try pw.bytes(self.message);

        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        const w = codec.Writer{ .out = &out, .allocator = allocator };
        try w.bytes(&protocol.VERSION_STRING);
        try w.varint(protocol.StreamId.gossip_out.value);
        try w.varint(payload.items.len);
        try w.bytes(payload.items);
        return out.toOwnedSlice(allocator);
    }
};

/// Signs a NodeAnnouncement with `key` and returns the wrapped Announcement.
/// The signature is over the encoded message body. `message` is owned by the
/// returned Announcement's caller via `allocator` (kept in `msg_buf`).
pub fn sign(
    allocator: std.mem.Allocator,
    ann: NodeAnnouncement,
    key: signature.SecretKey,
    msg_buf: *std.ArrayList(u8),
) !Announcement {
    try ann.encodeMessage(allocator, msg_buf);
    const sig = try key.sign(msg_buf.items);
    return .{ .node = key.nodeId(), .sig = sig, .message = msg_buf.items };
}

fn writeU64(w: codec.Writer, v: u64) !void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, .big);
    try w.bytes(&b);
}

const testing = std.testing;

// Golden vector: the NodeAnnouncement message body captured off the wire from
// radicle-node 1.9.1 (alias "fixnode"). CAPTURED_AGENT is the emitting node's
// user-agent, not ours (USER_AGENT) - it must match the captured bytes.
const CAPTURED_AGENT = "/radicle:1.9.1/";
const CAPTURED_MSG = [_]u8{
    0x01, // version
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // features = 1
    0x00, 0x00, 0x01, 0x9f, 0x9a, 0x1f, 0x98, 0xb4, // timestamp
    0x07, 'f', 'i', 'x', 'n', 'o', 'd', 'e', // alias
    0x00, 0x00, // addresses: empty
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // nonce
    0x0f, '/', 'r', 'a', 'd', 'i', 'c', 'l', 'e', ':', '1', '.', '9', '.', '1', '/', // agent
};

test "encodes the captured NodeAnnouncement message byte-for-byte" {
    const ann = NodeAnnouncement{
        .features = 1,
        .timestamp = 0x000001_9f9a1f98b4,
        .alias = "fixnode",
        .nonce = 1,
        .agent = CAPTURED_AGENT,
    };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try ann.encodeMessage(testing.allocator, &out);
    try testing.expectEqualSlices(u8, &CAPTURED_MSG, out.items);
}

test "accepts an alias at the length limit" {
    const alias = "radish-seed-node-abcdefghijklmno"; // exactly 32
    try testing.expectEqual(@as(usize, MAX_ALIAS_LEN), alias.len);
    const ann = NodeAnnouncement{ .timestamp = 0, .alias = alias };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try ann.encodeMessage(testing.allocator, &out);
    try testing.expectEqual(@as(u8, MAX_ALIAS_LEN), out.items[17]); // the alias length prefix
}

test "rejects an alias one byte over the limit" {
    const alias = "seed-node-with-a-33-char-name-abc"; // exactly 33, one over
    try testing.expectEqual(@as(usize, MAX_ALIAS_LEN + 1), alias.len);
    const ann = NodeAnnouncement{ .timestamp = 0, .alias = alias };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try testing.expectError(error.AliasTooLong, ann.encodeMessage(testing.allocator, &out));
}
