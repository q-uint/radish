//! QUIC frames (RFC 9000 s12.4, s19).
//!
//! A decrypted packet payload is a sequence of frames with no length prefix
//! and no count: you parse until the buffer runs out. That works only because
//! every frame type has a self-describing length, which is also why an unknown
//! frame type is fatal rather than skippable. Without recognising the type,
//! there is no way to know how far to skip.
const std = @import("std");
const codec = @import("../codec.zig");

pub const Error = error{ UnsupportedFrame, FrameEncoding } || codec.Error;

/// Frame type codes. Only the ones an Initial packet can carry are handled so
/// far; the rest arrive with the handshake and the data phase.
/// Source: RFC 9000 s19, Table 3.
pub const Type = enum(u64) {
    padding = 0x00,
    ping = 0x01,
    ack = 0x02,
    ack_ecn = 0x03,
    crypto = 0x06,
    _,
};

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

pub const Crypto = struct {
    offset: u64,
    data: []const u8,
};

pub const Frame = union(enum) {
    /// A run of padding, coalesced. Padding exists to inflate a datagram to
    /// the 1200 bytes an Initial must reach, which is how QUIC refuses to
    /// amplify traffic toward an unvalidated address.
    padding: usize,
    ping,
    ack: Ack,
    crypto: Crypto,
};

/// Iterates the frames in a decrypted payload. Slices borrow from it.
pub const Iterator = struct {
    r: codec.Reader,

    pub fn init(payload: []const u8) Iterator {
        return .{ .r = .{ .buf = payload } };
    }

    pub fn next(self: *Iterator) Error!?Frame {
        if (self.r.pos >= self.r.buf.len) return null;

        switch (@as(Type, @fromBackingInt(@intCast(try self.r.varint())))) {
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
            else => return error.UnsupportedFrame,
        }
    }
};

const testing = std.testing;

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

// Skipping an unknown frame is impossible without knowing its length, so the
// only safe response is to stop.
test "an unknown frame type is fatal" {
    var payload = [_]u8{0x1f};
    var it = Iterator.init(&payload);
    try testing.expectError(error.UnsupportedFrame, it.next());
}
