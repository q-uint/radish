//! Wire codec primitives for the Radicle protocol: QUIC variable-length
//! integers (RFC 9000 s16) and big-endian fixed integers. Higher layers
//! (frames, messages) build on these.
//! Source: radicle-protocol/src/wire/varint.rs.
const std = @import("std");

pub const Error = error{ UnexpectedEnd, VarIntTooLarge, VarIntNotCanonical };

/// Bytes the canonical encoding of `v` occupies.
pub fn varintLen(v: u64) usize {
    if (v < (1 << 6)) return 1;
    if (v < (1 << 14)) return 2;
    if (v < (1 << 30)) return 4;
    return 8;
}

/// Reads bytes from a buffer, tracking position.
pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn take(self: *Reader, n: usize) Error![]const u8 {
        if (self.pos + n > self.buf.len) return error.UnexpectedEnd;
        defer self.pos += n;
        return self.buf[self.pos .. self.pos + n];
    }

    pub fn readU8(self: *Reader) Error!u8 {
        return (try self.take(1))[0];
    }

    pub fn readU16(self: *Reader) Error!u16 {
        return std.mem.readInt(u16, (try self.take(2))[0..2], .big);
    }

    pub fn readU64(self: *Reader) Error!u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .big);
    }

    /// Reads a QUIC varint: top 2 bits of the first byte select 1/2/4/8-byte
    /// length; the value is the remaining bits, big-endian.
    pub fn varint(self: *Reader) Error!u64 {
        const first = try self.readU8();
        const tag = first >> 6;
        const len: usize = @as(usize, 1) << @intCast(tag);
        var v: u64 = first & 0x3f;
        for (1..len) |_| {
            v = (v << 8) | try self.readU8();
        }
        return v;
    }

    /// A varint that must use the shortest encoding for its value. QUIC only
    /// requires this of frame types.
    /// Source: RFC 9000 s12.4.
    pub fn varintCanonical(self: *Reader) Error!u64 {
        const start = self.pos;
        const v = try self.varint();
        if (self.pos - start != varintLen(v)) return error.VarIntNotCanonical;
        return v;
    }
};

/// Writes the canonical (shortest) varint for `v`.
///
/// Takes a `std.Io.Writer` so one implementation serves both a fixed packet
/// buffer and a growing one.
pub fn writeVarint(w: *std.Io.Writer, v: u64) !void {
    if (v < (1 << 6)) return w.writeInt(u8, @intCast(v), .big);
    if (v < (1 << 14)) return w.writeInt(u16, @as(u16, 0b01 << 14) | @as(u16, @intCast(v)), .big);
    if (v < (1 << 30)) return w.writeInt(u32, @as(u32, 0b10 << 30) | @as(u32, @intCast(v)), .big);
    if (v < (1 << 62)) return w.writeInt(u64, (@as(u64, 0b11) << 62) | v, .big);
    return error.VarIntTooLarge;
}

/// Appends encoded values to an ArrayList.
pub const Writer = struct {
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,

    pub fn writeU8(self: Writer, v: u8) !void {
        try self.out.append(self.allocator, v);
    }

    pub fn writeU16(self: Writer, v: u16) !void {
        var b: [2]u8 = undefined;
        std.mem.writeInt(u16, &b, v, .big);
        try self.out.appendSlice(self.allocator, &b);
    }

    pub fn writeU64(self: Writer, v: u64) !void {
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, v, .big);
        try self.out.appendSlice(self.allocator, &b);
    }

    /// Writes a QUIC varint using the minimal length (canonical form).
    ///
    /// Defers to `writeVarint` so the encoding lives in one place. A varint is
    /// at most 8 bytes, so the detour through a stack buffer costs nothing.
    pub fn varint(self: Writer, v: u64) !void {
        var buf: [8]u8 = undefined;
        var w = std.Io.Writer.fixed(&buf);
        try writeVarint(&w, v);
        try self.out.appendSlice(self.allocator, w.buffered());
    }

    pub fn bytes(self: Writer, data: []const u8) !void {
        try self.out.appendSlice(self.allocator, data);
    }
};

const testing = std.testing;

test "varint RFC 9000 A.1 vectors" {
    const cases = .{
        .{ @as(u64, 37), &[_]u8{0x25} },
        .{ @as(u64, 15293), &[_]u8{ 0x7b, 0xbd } },
        .{ @as(u64, 494878333), &[_]u8{ 0x9d, 0x7f, 0x3e, 0x7d } },
        .{ @as(u64, 151288809941952652), &[_]u8{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c } },
    };
    inline for (cases) |c| {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(testing.allocator);
        try (Writer{ .out = &out, .allocator = testing.allocator }).varint(c[0]);
        try testing.expectEqualSlices(u8, c[1], out.items);

        // The same vectors through the allocation-free path, so both sinks are
        // pinned rather than one relying on the other.
        var buf: [8]u8 = undefined;
        var w = std.Io.Writer.fixed(&buf);
        try writeVarint(&w, c[0]);
        try testing.expectEqualSlices(u8, c[1], w.buffered());

        var r = Reader{ .buf = c[1] };
        try testing.expectEqual(c[0], try r.varint());
    }
}

// `writeVarint` picks widths from its own thresholds, so pin them together.
test "varintLen agrees with what writeVarint emits" {
    for ([_]u64{ 0, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, (1 << 62) - 1 }) |v| {
        var buf: [8]u8 = undefined;
        var w = std.Io.Writer.fixed(&buf);
        try writeVarint(&w, v);
        try testing.expectEqual(w.buffered().len, varintLen(v));

        var r = Reader{ .buf = w.buffered() };
        try testing.expectEqual(v, try r.varintCanonical());
    }
}

test "a value too large to encode is rejected" {
    var buf: [8]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try testing.expectError(error.VarIntTooLarge, writeVarint(&w, 1 << 62));
}

test "varint small values are 1 byte" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try (Writer{ .out = &out, .allocator = testing.allocator }).varint(0);
    try testing.expectEqualSlices(u8, &[_]u8{0}, out.items);
}

test "u16 big-endian round trip" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try (Writer{ .out = &out, .allocator = testing.allocator }).writeU16(10);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x0a }, out.items);
    var r = Reader{ .buf = out.items };
    try testing.expectEqual(@as(u16, 10), try r.readU16());
}
