//! QUIC frames (RFC 9000 s12.4, s19).
//!
//! A decrypted packet payload is a sequence of frames with no length prefix
//! and no count: you parse until the buffer runs out. That works only because
//! every frame type has a self-describing length, which is also why an unknown
//! frame type is fatal rather than skippable. Without recognising the type,
//! there is no way to know how far to skip.
//!
//! QUIC v1 assigns 0x00 through 0x1e and nothing beyond, so every layout here
//! is known and an unknown code means a peer speaking something else.
const std = @import("std");
const codec = @import("../codec.zig");

pub const Error = error{ UnsupportedFrame, FrameEncoding, NothingToAck } || codec.Error;

/// Every frame type QUIC v1 defines.
/// Source: RFC 9000 s19, Table 3.
pub const Type = enum(u64) {
    padding = 0x00,
    ping = 0x01,
    ack = 0x02,
    ack_ecn = 0x03,
    reset_stream = 0x04,
    stop_sending = 0x05,
    crypto = 0x06,
    new_token = 0x07,
    /// 0x08 through 0x0f: the low three bits carry the OFF, LEN and FIN flags.
    stream = 0x08,
    stream_fin = 0x09,
    stream_len = 0x0a,
    stream_len_fin = 0x0b,
    stream_off = 0x0c,
    stream_off_fin = 0x0d,
    stream_off_len = 0x0e,
    stream_off_len_fin = 0x0f,
    max_data = 0x10,
    max_stream_data = 0x11,
    max_streams_bidi = 0x12,
    max_streams_uni = 0x13,
    data_blocked = 0x14,
    stream_data_blocked = 0x15,
    streams_blocked_bidi = 0x16,
    streams_blocked_uni = 0x17,
    new_connection_id = 0x18,
    retire_connection_id = 0x19,
    path_challenge = 0x1a,
    path_response = 0x1b,
    connection_close = 0x1c,
    connection_close_app = 0x1d,
    handshake_done = 0x1e,
    _,
};

/// The payload PATH_CHALLENGE carries and PATH_RESPONSE echoes back.
/// Source: RFC 9000 s19.17.
pub const path_challenge_len = 8;

/// The low three bits of a STREAM frame type. `off` and `len` say which fields
/// are present; without `len` the data runs to the end of the packet.
/// Source: RFC 9000 s19.8.
pub const StreamFlags = packed struct(u3) {
    fin: bool,
    len: bool,
    off: bool,

    pub fn of(t: Type) StreamFlags {
        return @bitCast(@as(u3, @truncate(@backingInt(t))));
    }
};

/// Why a peer is closing. `frame_type` is absent on an application close.
/// Source: RFC 9000 s19.19.
pub const ConnectionClose = struct {
    error_code: u64,
    frame_type: ?u64,
    reason: []const u8,
};

/// Transport error codes. QUIC v1 assigns 0x00 through 0x11, and reserves all
/// of 0x0100-0x01ff for CRYPTO_ERROR.
/// Source: RFC 9000 s20.1.
pub const TransportError = enum(u64) {
    no_error = 0x00,
    internal_error = 0x01,
    connection_refused = 0x02,
    flow_control_error = 0x03,
    stream_limit_error = 0x04,
    stream_state_error = 0x05,
    final_size_error = 0x06,
    frame_encoding_error = 0x07,
    transport_parameter_error = 0x08,
    connection_id_limit_error = 0x09,
    protocol_violation = 0x0a,
    invalid_token = 0x0b,
    application_error = 0x0c,
    crypto_buffer_exceeded = 0x0d,
    key_update_error = 0x0e,
    aead_limit_reached = 0x0f,
    no_viable_path = 0x10,
    version_negotiation_error = 0x11,
    _,
};

pub const crypto_error_base = 0x0100;

/// The TLS alert a CRYPTO_ERROR carries, or null for any other code. The alert
/// is the low byte, so the whole range maps one to one onto TLS's own.
/// Source: RFC 9000 s20.1, RFC 8446 s6.
pub fn cryptoAlert(error_code: u64) ?u8 {
    if (error_code < crypto_error_base or error_code > crypto_error_base + 0xff) return null;
    return @intCast(error_code - crypto_error_base);
}

/// A name for `error_code`, or null when it is outside what QUIC v1 assigns.
/// CRYPTO_ERROR is excluded: `cryptoAlert` carries the detail there.
pub fn transportErrorName(error_code: u64) ?[]const u8 {
    if (error_code > 0x11) return null;
    return @tagName(@as(TransportError, @fromBackingInt(@intCast(error_code))));
}

pub const Ecn = struct { ect0: u64, ect1: u64, ce: u64 };

/// A contiguous run of acknowledged packet numbers, inclusive at both ends.
pub const AckRange = struct { largest: u64, smallest: u64 };

/// Ranges are left encoded so the frame needs no allocation; walk them with
/// `ranges`.
pub const Ack = struct {
    largest: u64,
    /// Still scaled by the peer's ack_delay_exponent.
    delay: u64,
    first_range: u64,
    range_count: u64,
    encoded_ranges: []const u8,
    ecn: ?Ecn,

    /// The range containing `largest`.
    pub fn firstRange(self: Ack) Error!AckRange {
        if (self.largest < self.first_range) return error.FrameEncoding;
        return .{ .largest = self.largest, .smallest = self.largest - self.first_range };
    }

    pub fn ranges(self: Ack) Error!RangeIterator {
        return .{
            .r = .{ .buf = self.encoded_ranges },
            .remaining = self.range_count,
            .prev_smallest = (try self.firstRange()).smallest,
        };
    }
};

/// Walks the Gap/Length pairs, which run downward from `largest`.
/// Source: RFC 9000 s19.3.1.
pub const RangeIterator = struct {
    r: codec.Reader,
    remaining: u64,
    prev_smallest: u64,

    pub fn next(self: *RangeIterator) Error!?AckRange {
        if (self.remaining == 0) return null;
        self.remaining -= 1;

        const gap = try self.r.varint();
        const len = try self.r.varint();

        // largest = prev_smallest - gap - 2, in steps that cannot wrap. The
        // RFC requires a connection error if any of it would go negative.
        if (self.prev_smallest < 2) return error.FrameEncoding;
        const limit = self.prev_smallest - 2;
        if (gap > limit) return error.FrameEncoding;
        const largest = limit - gap;
        if (largest < len) return error.FrameEncoding;

        self.prev_smallest = largest - len;
        return .{ .largest = largest, .smallest = self.prev_smallest };
    }
};

/// A set of packet numbers, kept as descending disjoint ranges. Used for both
/// directions: what has arrived, and what the peer has acknowledged.
pub const NumberSet = struct {
    ranges: [max_ranges]AckRange = undefined,
    count: usize = 0,

    /// Older ranges are dropped once full: the peer only needs the recent ones
    /// to make progress, and an ACK has to fit in a packet.
    pub const max_ranges = 8;

    /// The largest number in the set, or null while it is empty. This is what
    /// `decodePacketNumber` expects.
    pub fn largest(self: *const NumberSet) ?u64 {
        return if (self.count == 0) null else self.ranges[0].largest;
    }

    pub fn contains(self: *const NumberSet, pn: u64) bool {
        for (self.ranges[0..self.count]) |r| {
            if (pn >= r.smallest and pn <= r.largest) return true;
        }
        return false;
    }

    pub fn record(self: *NumberSet, pn: u64) void {
        // Extend a range this touches, then merge any that meet as a result.
        for (self.ranges[0..self.count], 0..) |*r, i| {
            if (pn >= r.smallest and pn <= r.largest) return;
            if (pn == r.largest + 1) {
                r.largest = pn;
                return self.mergeDown(i);
            }
            if (r.smallest > 0 and pn == r.smallest - 1) {
                r.smallest = pn;
                return self.mergeDown(i + 1);
            }
        }
        self.insert(pn);
    }

    /// Joins range `i - 1` with range `i` when they have become adjacent.
    /// `i == count` means the extended range was already the lowest, so there
    /// is nothing under it to join.
    fn mergeDown(self: *NumberSet, i: usize) void {
        if (i == 0 or i >= self.count) return;
        const above = &self.ranges[i - 1];
        const below = self.ranges[i];
        if (above.smallest != below.largest + 1) return;
        above.smallest = below.smallest;
        for (i..self.count - 1) |j| self.ranges[j] = self.ranges[j + 1];
        self.count -= 1;
    }

    fn insert(self: *NumberSet, pn: u64) void {
        var at: usize = 0;
        while (at < self.count and self.ranges[at].largest > pn) at += 1;
        if (at == max_ranges) return; // older than everything kept

        const end = @min(self.count, max_ranges - 1);
        var j = end;
        while (j > at) : (j -= 1) self.ranges[j] = self.ranges[j - 1];
        self.ranges[at] = .{ .largest = pn, .smallest = pn };
        self.count = @min(self.count + 1, max_ranges);
    }

    /// Writes an ACK for everything in the set. `delay` is already scaled by
    /// the ack_delay_exponent we advertised.
    /// Source: RFC 9000 s19.3.
    pub fn writeAck(self: *const NumberSet, w: *std.Io.Writer, delay: u64) !void {
        if (self.count == 0) return error.NothingToAck;

        try codec.writeVarint(w, @backingInt(Type.ack));
        try codec.writeVarint(w, self.ranges[0].largest);
        try codec.writeVarint(w, delay);
        try codec.writeVarint(w, self.count - 1);
        try codec.writeVarint(w, self.ranges[0].largest - self.ranges[0].smallest);

        // Each later range is encoded as the distance down from the previous
        // one, which is why they have to be descending and disjoint.
        for (self.ranges[1..self.count], 0..) |r, i| {
            const prev = self.ranges[i];
            try codec.writeVarint(w, prev.smallest - r.largest - 2);
            try codec.writeVarint(w, r.largest - r.smallest);
        }
    }
};

/// What has arrived in one packet number space. Each space acknowledges
/// separately and numbers restart in each, so one of these belongs to each.
/// Source: RFC 9000 s13.2.
pub const Received = struct {
    numbers: NumberSet = .{},
    /// Set when a packet arrives that must be acknowledged. PADDING, ACK and
    /// CONNECTION_CLOSE alone do not elicit one.
    /// Source: RFC 9000 s13.2.1.
    ack_eliciting: bool = false,

    pub fn record(self: *Received, pn: u64) void {
        self.numbers.record(pn);
    }

    pub fn largest(self: *const Received) ?u64 {
        return self.numbers.largest();
    }

    pub fn writeAck(self: *const Received, w: *std.Io.Writer, delay: u64) !void {
        return self.numbers.writeAck(w, delay);
    }
};

pub const Crypto = struct {
    offset: u64,
    data: []const u8,
};

/// Application data. `fin` marks the last byte of the stream.
/// Source: RFC 9000 s19.8.
pub const Stream = struct {
    id: u64,
    offset: u64,
    data: []const u8,
    fin: bool,
};

pub const MaxStreamData = struct {
    id: u64,
    max: u64,
};

/// A connection id the peer is offering for future use, with the token that
/// would let us prove a stateless reset.
/// Source: RFC 9000 s19.15.
pub const NewConnectionId = struct {
    sequence: u64,
    retire_prior_to: u64,
    id: []const u8,
    stateless_reset_token: [16]u8,
};

pub const Frame = union(enum) {
    /// A run of padding, coalesced. Padding exists to inflate a datagram to
    /// the 1200 bytes an Initial must reach, which is how QUIC refuses to
    /// amplify traffic toward an unvalidated address.
    padding: usize,
    ping,
    ack: Ack,
    crypto: Crypto,
    connection_close: ConnectionClose,
    stream: Stream,
    new_connection_id: NewConnectionId,
    /// Must be echoed back as a PATH_RESPONSE carrying the same eight bytes, or
    /// the peer concludes the path is unusable.
    /// Source: RFC 9000 s8.2.
    path_challenge: [8]u8,
    path_response: [8]u8,
    /// The server confirming the handshake is complete.
    /// Source: RFC 9000 s19.20.
    handshake_done,
    /// A raised limit on everything we may send, across all streams.
    /// Source: RFC 9000 s19.9.
    max_data: u64,
    /// A raised limit on what we may send on one stream.
    /// Source: RFC 9000 s19.10.
    max_stream_data: MaxStreamData,
    /// Parsed so the payload can be walked, but carried no further. Flow
    /// control and stream resets land here.
    ignored: Type,
};

/// Writes a STREAM frame. The length is always explicit, so another frame can
/// follow it in the same packet.
/// Source: RFC 9000 s19.8.
pub fn writeStream(w: *std.Io.Writer, s: Stream) !void {
    const flags: StreamFlags = .{ .fin = s.fin, .len = true, .off = s.offset != 0 };
    try codec.writeVarint(w, @backingInt(Type.stream) | @as(u64, @as(u3, @bitCast(flags))));
    try codec.writeVarint(w, s.id);
    if (flags.off) try codec.writeVarint(w, s.offset);
    try codec.writeVarint(w, s.data.len);
    try w.writeAll(s.data);
}

/// Writes MAX_DATA, raising the limit on everything the peer may send.
/// Source: RFC 9000 s19.9.
pub fn writeMaxData(w: *std.Io.Writer, max: u64) !void {
    try codec.writeVarint(w, @backingInt(Type.max_data));
    try codec.writeVarint(w, max);
}

/// Writes MAX_STREAM_DATA, raising the limit on one stream.
/// Source: RFC 9000 s19.10.
pub fn writeMaxStreamData(w: *std.Io.Writer, m: MaxStreamData) !void {
    try codec.writeVarint(w, @backingInt(Type.max_stream_data));
    try codec.writeVarint(w, m.id);
    try codec.writeVarint(w, m.max);
}

/// Whether receiving `f` obliges us to acknowledge the packet carrying it.
/// Everything but ACK, PADDING and CONNECTION_CLOSE does, which is what stops
/// two peers acknowledging each other's acknowledgements forever.
/// Source: RFC 9000 s13.2.1.
pub fn isAckEliciting(f: Frame) bool {
    return switch (f) {
        .padding, .ack, .connection_close => false,
        else => true,
    };
}

/// Frames whose whole body is varints, and how many. Stream limits and resets
/// are consumed so the payload can be walked. Null means the type is not a QUIC
/// v1 frame.
/// Source: RFC 9000 s19.4-19.16.
fn ignoredVarints(t: Type) ?usize {
    return switch (t) {
        .max_streams_bidi,
        .max_streams_uni,
        .data_blocked,
        .streams_blocked_bidi,
        .streams_blocked_uni,
        .retire_connection_id,
        => 1,
        .stream_data_blocked, .stop_sending => 2,
        .reset_stream => 3,
        else => null,
    };
}

/// Iterates the frames in a decrypted payload. Slices borrow from it.
pub const Iterator = struct {
    r: codec.Reader,

    pub fn init(payload: []const u8) Iterator {
        return .{ .r = .{ .buf = payload } };
    }

    pub fn next(self: *Iterator) Error!?Frame {
        if (self.r.pos >= self.r.buf.len) return null;

        switch (@as(Type, @fromBackingInt(try self.r.varintCanonical()))) {
            .padding => {
                var n: usize = 1;
                while (self.r.pos < self.r.buf.len and self.r.buf[self.r.pos] == 0) : (self.r.pos += 1) {
                    n += 1;
                }
                return .{ .padding = n };
            },
            .ping => return .ping,
            .ack, .ack_ecn => |t| {
                const largest = try self.r.varint();
                const delay = try self.r.varint();
                const range_count = try self.r.varint();
                const first_range = try self.r.varint();

                const start = self.r.pos;
                var i: u64 = 0;
                while (i < range_count) : (i += 1) {
                    _ = try self.r.varint();
                    _ = try self.r.varint();
                }
                const encoded = self.r.buf[start..self.r.pos];

                return .{ .ack = .{
                    .largest = largest,
                    .delay = delay,
                    .range_count = range_count,
                    .first_range = first_range,
                    .encoded_ranges = encoded,
                    .ecn = if (t == .ack_ecn) .{
                        .ect0 = try self.r.varint(),
                        .ect1 = try self.r.varint(),
                        .ce = try self.r.varint(),
                    } else null,
                } };
            },
            .crypto => {
                const offset = try self.r.varint();
                const len = try self.r.varint();
                return .{ .crypto = .{ .offset = offset, .data = try self.r.take(@intCast(len)) } };
            },
            .connection_close, .connection_close_app => |t| {
                const code = try self.r.varint();
                const frame_type: ?u64 = if (t == .connection_close) try self.r.varint() else null;
                const len = try self.r.varint();
                return .{ .connection_close = .{
                    .error_code = code,
                    .frame_type = frame_type,
                    .reason = try self.r.take(@intCast(len)),
                } };
            },
            .stream,
            .stream_fin,
            .stream_len,
            .stream_len_fin,
            .stream_off,
            .stream_off_fin,
            .stream_off_len,
            .stream_off_len_fin,
            => |t| {
                const flags = StreamFlags.of(t);
                const id = try self.r.varint();
                const offset = if (flags.off) try self.r.varint() else 0;
                // Without an explicit length the frame owns the rest of the
                // packet, which is also why it has to be the last one.
                const len = if (flags.len)
                    @as(usize, @intCast(try self.r.varint()))
                else
                    self.r.buf.len - self.r.pos;
                return .{ .stream = .{
                    .id = id,
                    .offset = offset,
                    .data = try self.r.take(len),
                    .fin = flags.fin,
                } };
            },
            .handshake_done => return .handshake_done,
            .max_data => return .{ .max_data = try self.r.varint() },
            .max_stream_data => return .{ .max_stream_data = .{
                .id = try self.r.varint(),
                .max = try self.r.varint(),
            } },
            .path_challenge => return .{ .path_challenge = (try self.r.take(8))[0..8].* },
            .path_response => return .{ .path_response = (try self.r.take(8))[0..8].* },
            .new_connection_id => {
                const sequence = try self.r.varint();
                const retire_prior_to = try self.r.varint();
                if (retire_prior_to > sequence) return error.FrameEncoding;
                const id_len = try self.r.readU8();
                if (id_len == 0 or id_len > 20) return error.FrameEncoding;
                const id = try self.r.take(id_len);
                return .{ .new_connection_id = .{
                    .sequence = sequence,
                    .retire_prior_to = retire_prior_to,
                    .id = id,
                    .stateless_reset_token = (try self.r.take(16))[0..16].*,
                } };
            },
            .new_token => |t| {
                _ = try self.r.take(@intCast(try self.r.varint()));
                return .{ .ignored = t };
            },
            else => |t| {
                const n = ignoredVarints(t) orelse return error.UnsupportedFrame;
                for (0..n) |_| _ = try self.r.varint();
                return .{ .ignored = t };
            },
        }
    }
};

const testing = std.testing;

test "a written STREAM frame parses back" {
    var buf: [32]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeStream(&w, .{ .id = 4, .offset = 7, .data = &.{ 0xaa, 0xbb }, .fin = true });
    // OFF, LEN and FIN set, so the type is 0x0f.
    try testing.expectEqual(@as(u8, 0x0f), w.buffered()[0]);

    var it = Iterator.init(w.buffered());
    const s = (try it.next()).?.stream;
    try testing.expectEqual(@as(u64, 4), s.id);
    try testing.expectEqual(@as(u64, 7), s.offset);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, s.data);
    try testing.expect(s.fin);
    try testing.expectEqual(@as(?Frame, null), try it.next());
}

test "a STREAM frame at offset zero leaves the offset out" {
    var buf: [32]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeStream(&w, .{ .id = 0, .offset = 0, .data = &.{0xcc}, .fin = false });
    try testing.expectEqualSlices(u8, &.{ 0x0a, 0x00, 0x01, 0xcc }, w.buffered());
}

test "written limits parse back" {
    var buf: [32]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeMaxData(&w, 1 << 20);
    try writeMaxStreamData(&w, .{ .id = 0, .max = 4096 });

    var it = Iterator.init(w.buffered());
    try testing.expectEqual(@as(u64, 1 << 20), (try it.next()).?.max_data);
    const m = (try it.next()).?.max_stream_data;
    try testing.expectEqual(@as(u64, 0), m.id);
    try testing.expectEqual(@as(u64, 4096), m.max);
}

test "parses a CRYPTO frame followed by padding" {
    // type(06) offset(00) length(0403) then 3 bytes, then 2 padding bytes.
    var payload = [_]u8{ 0x06, 0x00, 0x03, 0xaa, 0xbb, 0xcc, 0x00, 0x00 };
    var it = Iterator.init(&payload);

    const f = (try it.next()).?;
    try testing.expectEqual(@as(u64, 0), f.crypto.offset);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc }, f.crypto.data);

    try testing.expectEqual(@as(usize, 2), (try it.next()).?.padding);
    try testing.expectEqual(@as(?Frame, null), try it.next());
}

// Every value here stays under 64 so it is a one-byte varint.
// largest=60 first=2 -> [58,60]; gap=1 len=3 -> 58-1-2=55, [52,55];
// gap=0 len=0 -> 52-0-2=50, [50,50].
test "walks ack ranges downward" {
    var payload = [_]u8{ 0x02, 60, 0x00, 0x02, 0x02, 0x01, 0x03, 0x00, 0x00 };
    var it = Iterator.init(&payload);
    const ack = (try it.next()).?.ack;

    try testing.expectEqual(@as(u64, 60), ack.largest);
    try testing.expectEqual(AckRange{ .largest = 60, .smallest = 58 }, try ack.firstRange());

    var r = try ack.ranges();
    try testing.expectEqual(AckRange{ .largest = 55, .smallest = 52 }, (try r.next()).?);
    try testing.expectEqual(AckRange{ .largest = 50, .smallest = 50 }, (try r.next()).?);
    try testing.expectEqual(@as(?AckRange, null), try r.next());
    try testing.expectEqual(@as(?Ecn, null), ack.ecn);
}

// Type 0x03 appends three counts after the ranges.
test "reads the ecn counts of an ack_ecn frame" {
    var payload = [_]u8{ 0x03, 10, 0x00, 0x00, 0x00, 0x05, 0x06, 0x07 };
    var it = Iterator.init(&payload);
    const ack = (try it.next()).?.ack;

    try testing.expectEqual(@as(u64, 10), ack.largest);
    try testing.expectEqual(Ecn{ .ect0 = 5, .ect1 = 6, .ce = 7 }, ack.ecn.?);
    try testing.expectEqual(@as(?Frame, null), try it.next());
}

// A peer can encode gaps that drive the computation below zero. The RFC
// requires rejecting that rather than wrapping.
test "ack ranges that would go negative are rejected" {
    // largest=1, first=0, then one range with gap=0: 1 - 0 - 2 underflows.
    var payload = [_]u8{ 0x02, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };
    var it = Iterator.init(&payload);
    var r = try (try it.next()).?.ack.ranges();
    try testing.expectError(error.FrameEncoding, r.next());

    // first_range larger than largest is the same class of error.
    var bad = [_]u8{ 0x02, 0x01, 0x00, 0x00, 0x05 };
    var it2 = Iterator.init(&bad);
    try testing.expectError(error.FrameEncoding, (try it2.next()).?.ack.firstRange());
}

// The flags live in the type code, so the same frame has eight spellings.
test "parses a STREAM frame with and without its optional fields" {
    // 0x0f is off|len|fin: id 4, offset 8, length 3.
    var full = [_]u8{ 0x0f, 0x04, 0x08, 0x03, 0xaa, 0xbb, 0xcc };
    var it = Iterator.init(&full);
    const a = (try it.next()).?.stream;
    try testing.expectEqual(@as(u64, 4), a.id);
    try testing.expectEqual(@as(u64, 8), a.offset);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc }, a.data);
    try testing.expect(a.fin);
    try testing.expectEqual(@as(?Frame, null), try it.next());

    // 0x08 is none of them: offset 0, and the data runs to the end.
    var bare = [_]u8{ 0x08, 0x04, 0xaa, 0xbb };
    var it2 = Iterator.init(&bare);
    const b = (try it2.next()).?.stream;
    try testing.expectEqual(@as(u64, 0), b.offset);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, b.data);
    try testing.expect(!b.fin);
    try testing.expectEqual(@as(?Frame, null), try it2.next());
}

test "parses the 1-RTT frames radish acts on" {
    var payload = [_]u8{0x1e} ++ // HANDSHAKE_DONE
        [_]u8{0x1a} ++ [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 } ++ // PATH_CHALLENGE
        [_]u8{0x1b} ++ [_]u8{ 8, 7, 6, 5, 4, 3, 2, 1 }; // PATH_RESPONSE
    var it = Iterator.init(&payload);

    try testing.expectEqual(Frame.handshake_done, (try it.next()).?);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, &(try it.next()).?.path_challenge);
    try testing.expectEqualSlices(u8, &.{ 8, 7, 6, 5, 4, 3, 2, 1 }, &(try it.next()).?.path_response);
    try testing.expectEqual(@as(?Frame, null), try it.next());
}

test "parses NEW_CONNECTION_ID and rejects a retire past its sequence" {
    // type, sequence, retire_prior_to, id length, the id, then a 16-byte token.
    var payload: [24]u8 = @splat(0x11);
    @memcpy(payload[0..8], &[_]u8{ 0x18, 0x02, 0x01, 0x04, 0xaa, 0xbb, 0xcc, 0xdd });
    var it = Iterator.init(&payload);
    const n = (try it.next()).?.new_connection_id;
    try testing.expectEqual(@as(u64, 2), n.sequence);
    try testing.expectEqual(@as(u64, 1), n.retire_prior_to);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc, 0xdd }, n.id);
    try testing.expectEqualSlices(u8, &@as([16]u8, @splat(0x11)), &n.stateless_reset_token);
    try testing.expectEqual(@as(?Frame, null), try it.next());

    // Retiring more than has been issued.
    var bad: [20]u8 = @splat(0);
    @memcpy(bad[0..4], &[_]u8{ 0x18, 0x01, 0x02, 0x00 });
    var it2 = Iterator.init(&bad);
    try testing.expectError(error.FrameEncoding, it2.next());
}

// The limits are read; the rest is consumed by shape so the walk reaches the
// frames that matter.
test "limit frames are read and the rest walked past" {
    var payload = [_]u8{
        0x10, 0x44, 0x00, // MAX_DATA, a two-byte varint
        0x11, 0x04, 0x20, // MAX_STREAM_DATA, two varints
        0x04, 0x04, 0x01, 0x08, // RESET_STREAM, three varints
        0x07, 0x02, 0xaa, 0xbb, // NEW_TOKEN, a length-prefixed blob
        0x01, // PING, to prove the walk arrived
    };
    var it = Iterator.init(&payload);
    try testing.expectEqual(@as(u64, 0x400), (try it.next()).?.max_data);
    try testing.expectEqual(@as(u64, 0x20), (try it.next()).?.max_stream_data.max);
    try testing.expectEqual(Type.reset_stream, (try it.next()).?.ignored);
    try testing.expectEqual(Type.new_token, (try it.next()).?.ignored);
    try testing.expectEqual(Frame.ping, (try it.next()).?);
    try testing.expectEqual(@as(?Frame, null), try it.next());
}

// QUIC v1 stops at 0x1e, so anything above it is another protocol's frame and
// skipping is impossible without knowing its length.
test "an unknown frame type is fatal" {
    var payload = [_]u8{0x1f};
    var it = Iterator.init(&payload);
    try testing.expectError(error.UnsupportedFrame, it.next());
}

// 0x4001 is a two-byte encoding of 1, which would otherwise read as PING.
test "an overlong frame type encoding is rejected" {
    var payload = [_]u8{ 0x40, 0x01 };
    var it = Iterator.init(&payload);
    try testing.expectError(error.VarIntNotCanonical, it.next());
}

test "records packet numbers into ranges regardless of arrival order" {
    var a: NumberSet = .{};
    for ([_]u64{ 0, 1, 2, 5, 6, 9 }) |pn| a.record(pn);

    var b: NumberSet = .{};
    for ([_]u64{ 9, 5, 1, 6, 0, 2 }) |pn| b.record(pn);

    try testing.expectEqual(@as(usize, 3), a.count);
    try testing.expectEqualSlices(AckRange, a.ranges[0..a.count], b.ranges[0..b.count]);
    try testing.expectEqual(@as(?u64, 9), a.largest());
    // Largest first, with the gaps at 3-4 and 7-8 keeping them apart.
    try testing.expectEqual(AckRange{ .largest = 9, .smallest = 9 }, a.ranges[0]);
    try testing.expectEqual(AckRange{ .largest = 6, .smallest = 5 }, a.ranges[1]);
    try testing.expectEqual(AckRange{ .largest = 2, .smallest = 0 }, a.ranges[2]);

    a.record(6);
    try testing.expectEqual(@as(usize, 3), a.count);
}

test "filling a gap merges the ranges around it" {
    var r: NumberSet = .{};
    for ([_]u64{ 0, 2 }) |pn| r.record(pn);
    try testing.expectEqual(@as(usize, 2), r.count);

    r.record(1);
    try testing.expectEqual(@as(usize, 1), r.count);
    try testing.expectEqual(AckRange{ .largest = 2, .smallest = 0 }, r.ranges[0]);
}

test "an ACK we write reads back as the ranges we recorded" {
    var r: NumberSet = .{};
    for ([_]u64{ 50, 52, 53, 54, 55, 58, 59, 60 }) |pn| r.record(pn);

    var buf: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try r.writeAck(&w, 0);

    var it = Iterator.init(w.buffered());
    const ack = (try it.next()).?.ack;
    try testing.expectEqual(@as(u64, 60), ack.largest);
    try testing.expectEqual(@as(u64, 2), ack.range_count);
    try testing.expectEqual(AckRange{ .largest = 60, .smallest = 58 }, try ack.firstRange());

    var ranges = try ack.ranges();
    try testing.expectEqual(AckRange{ .largest = 55, .smallest = 52 }, (try ranges.next()).?);
    try testing.expectEqual(AckRange{ .largest = 50, .smallest = 50 }, (try ranges.next()).?);
    try testing.expectEqual(@as(?AckRange, null), try ranges.next());
    try testing.expectEqual(@as(?Frame, null), try it.next());
}

// Extending the lowest range downward has nothing beneath it to merge with. On
// a full set that index is one past the array, not just one past the count.
test "extending the lowest of a full set of ranges" {
    var r: NumberSet = .{};
    for (0..NumberSet.max_ranges) |i| r.record((i + 1) * 4);
    try testing.expectEqual(NumberSet.max_ranges, r.count);

    r.record(3);
    try testing.expect(r.contains(3));
    try testing.expectEqual(AckRange{ .largest = 4, .smallest = 3 }, r.ranges[r.count - 1]);
}

test "acking nothing is refused" {
    const r: NumberSet = .{};
    var buf: [16]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try testing.expectError(error.NothingToAck, r.writeAck(&w, 0));
}
