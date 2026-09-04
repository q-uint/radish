//! Putting data that arrives by offset back in order: the CRYPTO stream during
//! a handshake, and STREAM frames after it.
//! Source: RFC 9000 s2.2.
const std = @import("std");

pub const Error = error{ StreamTooLong, StreamGaps };

pub const Reassembler = struct {
    buf: []u8,
    /// Relative to `base`, so a shift moves them all at once.
    ranges: [max_ranges]Range = undefined,
    count: usize = 0,
    /// The stream offset `buf[0]` holds.
    base: u64 = 0,
    /// Bytes at the front the reader is done with. They are not moved until a
    /// push needs the room, so what `contiguous` handed out stays valid until
    /// more data arrives.
    pending: usize = 0,

    /// A handshake needs a handful; more means the peer is fragmenting far
    /// beyond anything useful.
    pub const max_ranges = 8;

    const Range = struct {
        start: u64,
        end: u64,

        fn lessThan(_: void, a: Range, b: Range) bool {
            return a.start < b.start;
        }
    };

    pub fn init(buf: []u8) Reassembler {
        return .{ .buf = buf };
    }

    /// Copies one frame's data into place. A retransmit of bytes already read
    /// is skipped rather than refused.
    pub fn push(self: *Reassembler, offset: u64, data: []const u8) Error!void {
        var at = offset;
        var bytes = data;
        const unread_at = self.read();
        if (at < unread_at) {
            const old = unread_at - at;
            if (old >= bytes.len) return;
            bytes = bytes[@intCast(old)..];
            at = unread_at;
        }
        if (bytes.len == 0) return;

        // Reclaim what the reader is done with, now that the room is wanted.
        if (at - self.base + bytes.len > self.buf.len) self.compact();

        const start = at - self.base;
        const end = start + bytes.len;
        if (end > self.buf.len) return error.StreamTooLong;
        @memcpy(self.buf[@intCast(start)..][0..bytes.len], bytes);

        // Merge into the disjoint set, so `contiguous` can trust range 0.
        var new: Range = .{ .start = start, .end = end };
        var kept: usize = 0;
        for (self.ranges[0..self.count]) |e| {
            if (e.end < new.start or e.start > new.end) {
                self.ranges[kept] = e;
                kept += 1;
            } else {
                new.start = @min(new.start, e.start);
                new.end = @max(new.end, e.end);
            }
        }
        if (kept == max_ranges) return error.StreamGaps;
        self.ranges[kept] = new;
        self.count = kept + 1;
        std.mem.sort(Range, self.ranges[0..self.count], {}, Range.lessThan);
    }

    /// Bytes not yet read. A gap at the front yields nothing, since a parser
    /// cannot skip one.
    pub fn contiguous(self: *const Reassembler) []const u8 {
        if (self.count == 0 or self.ranges[0].start > self.pending) return &.{};
        return self.buf[self.pending..@intCast(self.ranges[0].end)];
    }

    /// The offset the next unread byte sits at.
    pub fn read(self: *const Reassembler) u64 {
        return self.base + self.pending;
    }

    /// Marks the first `n` unread bytes as read. Nothing moves, so slices
    /// taken from `contiguous` stay valid until the next `push`.
    pub fn drop(self: *Reassembler, n: usize) void {
        self.pending += n;
    }

    /// Slides the unread bytes to the front, making room at the end.
    fn compact(self: *Reassembler) void {
        if (self.pending == 0) return;
        const n = self.pending;
        std.mem.copyForwards(u8, self.buf, self.buf[n..]);
        self.base += n;
        self.pending = 0;

        var kept: usize = 0;
        for (self.ranges[0..self.count]) |e| {
            if (e.end <= n) continue;
            self.ranges[kept] = .{
                .start = if (e.start > n) e.start - n else 0,
                .end = e.end - n,
            };
            kept += 1;
        }
        self.count = kept;
    }
};

const testing = std.testing;

test "reassembles fragments in any order" {
    var buf: [16]u8 = @splat(0);
    var r = Reassembler.init(&buf);

    // The tail first: nothing is readable until the gap at the front closes.
    try r.push(4, &.{ 4, 5, 6, 7 });
    try testing.expectEqual(@as(usize, 0), r.contiguous().len);

    try r.push(0, &.{ 0, 1, 2, 3 });
    try testing.expectEqualSlices(u8, &.{ 0, 1, 2, 3, 4, 5, 6, 7 }, r.contiguous());

    // A retransmit overlapping what we have changes nothing.
    try r.push(2, &.{ 2, 3, 4 });
    try testing.expectEqual(@as(usize, 8), r.contiguous().len);
}

test "reading frees room, but only once a push needs it" {
    var buf: [8]u8 = @splat(0);
    var r = Reassembler.init(&buf);

    try r.push(0, &.{ 0, 1, 2, 3, 4, 5, 6, 7 });
    const borrowed = r.contiguous();
    r.drop(6);
    try testing.expectEqual(@as(u64, 6), r.read());
    try testing.expectEqualSlices(u8, &.{ 6, 7 }, r.contiguous());
    // Nothing has moved yet, so what a reader took is still what it read.
    try testing.expectEqualSlices(u8, &.{ 0, 1, 2, 3, 4, 5, 6, 7 }, borrowed);

    // This push wants room the read bytes hold, so now they go.
    try r.push(8, &.{ 8, 9 });
    try testing.expectEqualSlices(u8, &.{ 6, 7, 8, 9 }, r.contiguous());

    // A retransmit of read bytes carries what is still wanted.
    try r.push(4, &.{ 4, 5, 6, 7, 8, 9, 10 });
    try testing.expectEqualSlices(u8, &.{ 6, 7, 8, 9, 10 }, r.contiguous());
}

test "a stream past the buffer or too gappy is refused" {
    var small: [4]u8 = @splat(0);
    var r = Reassembler.init(&small);
    try testing.expectError(error.StreamTooLong, r.push(2, &.{ 1, 2, 3 }));

    var buf: [64]u8 = @splat(0);
    var g = Reassembler.init(&buf);
    for (0..Reassembler.max_ranges) |i| try g.push(i * 4, &.{0xaa});
    try testing.expectError(error.StreamGaps, g.push(Reassembler.max_ranges * 4, &.{0xaa}));
}
