//! QUIC frames (RFC 9000 s12.4, s19).
//!
//! A decrypted packet payload is a sequence of frames with no length prefix
//! and no count: you parse until the buffer runs out. That works only because
//! every frame type has a self-describing length, which is also why an unknown
//! frame type is fatal rather than skippable. Without recognising the type,
//! there is no way to know how far to skip.
const std = @import("std");
const codec = @import("../codec.zig");

pub const Error = error{UnsupportedFrame} || codec.Error;

/// Frame type codes. Only the ones an Initial packet can carry are handled so
/// far; the rest arrive with the handshake and the data phase.
/// Source: RFC 9000 s19, Table 3.
pub const Type = enum(u64) {
    padding = 0x00,
    ping = 0x01,
    crypto = 0x06,
    _,
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

// Skipping an unknown frame is impossible without knowing its length, so the
// only safe response is to stop.
test "an unknown frame type is fatal" {
    var payload = [_]u8{0x1f};
    var it = Iterator.init(&payload);
    try testing.expectError(error.UnsupportedFrame, it.next());
}
