//! QUIC streams: ordered byte sequences carried in STREAM frames.
//! Source: RFC 9000 s2, s19.8.
const std = @import("std");

const frame = @import("frame.zig");
const reassembly = @import("reassembly.zig");

pub const Error = error{
    FinalSizeError,
    FlowControlError,
    FlowControlBlocked,
    SendBufferFull,
} || reassembly.Error;

/// One direction of one limit: how many bytes may cross before the peer raises
/// it with a MAX_DATA or MAX_STREAM_DATA frame.
/// Source: RFC 9000 s4.1.
pub const Window = struct {
    limit: u64,
    used: u64 = 0,

    pub fn room(self: Window) u64 {
        return self.limit -| self.used;
    }

    /// Records `n` bytes crossing, or refuses when they do not fit.
    pub fn take(self: *Window, n: u64) Error!void {
        if (n > self.room()) return error.FlowControlBlocked;
        self.used += n;
    }

    /// A limit only ever moves up: a peer repeating an old MAX_DATA must not
    /// shrink the window we are already using.
    /// Source: RFC 9000 s4.1.
    pub fn extend(self: *Window, limit: u64) void {
        self.limit = @max(self.limit, limit);
    }
};

/// Stream ids encode who opened the stream in bit 0 and whether it is
/// unidirectional in bit 1, so a client's first bidirectional stream is 0.
/// Source: RFC 9000 s2.1.
pub const first_client_bidi: u64 = 0;

/// One direction of a stream: what the peer has sent us, in order. Consumed
/// bytes are dropped, so a stream longer than the buffer still runs, as long as
/// the reader keeps up.
pub const Receiver = struct {
    data: reassembly.Reassembler,
    /// The furthest byte the peer has sent, which is what its window limits.
    /// Source: RFC 9000 s4.1.
    highest: u64 = 0,
    /// What we have granted the peer, and how much of it it has used.
    window: Window,
    /// The offset a FIN put the end of the stream at, once one has arrived.
    final: ?u64 = null,
    /// Set by a RESET_STREAM: the peer has abandoned its half, so what has
    /// arrived is all there will be and it is not a whole stream.
    /// Source: RFC 9000 s19.4.
    reset: bool = false,

    pub fn init(buf: []u8, limit: u64) Receiver {
        return .{
            .data = reassembly.Reassembler.init(buf),
            .window = .{ .limit = limit },
        };
    }

    /// Takes one STREAM frame. A FIN fixes the stream's length, and anything
    /// contradicting it afterwards is fatal.
    /// Source: RFC 9000 s4.5.
    pub fn push(self: *Receiver, f: frame.Stream) Error!void {
        const end = f.offset + f.data.len;
        if (end > self.window.limit) return error.FlowControlError;
        if (self.final) |final| {
            if (end > final) return error.FinalSizeError;
            if (f.fin and end != final) return error.FinalSizeError;
        } else if (f.fin) {
            if (end < self.highest) return error.FinalSizeError;
            self.final = end;
        }

        try self.data.push(f.offset, f.data);
        self.highest = @max(self.highest, end);
        self.window.used = self.highest;
    }

    /// Bytes in order and not yet consumed.
    pub fn readable(self: *const Receiver) []const u8 {
        return self.data.contiguous();
    }

    /// Marks `n` bytes at the front as read. What `readable` handed back stays
    /// valid until the next `push`, which is when the room is reclaimed.
    pub fn consume(self: *Receiver, n: usize) void {
        self.data.drop(n);
    }

    /// How far the reader has got, which is where a new limit is measured from.
    pub fn read(self: *const Receiver) u64 {
        return self.data.read();
    }

    /// The limit to grant now: everything read, plus a full buffer again.
    pub fn grant(self: *const Receiver) u64 {
        return self.read() + self.data.buf.len;
    }

    /// Whether the peer is close enough to the limit to be worth raising it.
    /// Half the window is the usual point: often enough that a sender never
    /// stalls, rarely enough that we are not sending a frame per packet.
    pub fn wantsGrant(self: *const Receiver) bool {
        return self.grant() -| self.window.limit >= self.data.buf.len / 2;
    }

    /// Every byte the peer will send has arrived and been read.
    pub fn done(self: *const Receiver) bool {
        const final = self.final orelse return false;
        return self.read() == final;
    }
};

/// Bytes we have sent and not seen acknowledged, held so a lost packet can
/// carry them again. A resend goes out under a new packet number.
/// Source: RFC 9000 s13.3.
pub const Sender = struct {
    buf: []u8,
    /// Stream offset of `buf[0]`, the oldest byte still unacknowledged.
    base: u64 = 0,
    len: usize = 0,
    chunks: [max_chunks]Chunk = undefined,
    count: usize = 0,

    /// More outstanding packets than this and we wait for acknowledgements
    /// rather than adding to what may already be lost.
    pub const max_chunks = 8;

    /// One packet's worth of stream data, and where it went.
    pub const Chunk = struct {
        pn: u64,
        offset: u64,
        len: usize,
        fin: bool,
        acked: bool = false,
        /// Whether this chunk has gone out again since the last thing the peer
        /// acknowledged, so a burst of loss works through the chunks rather
        /// than repeating the oldest.
        resent: bool = false,
    };

    pub fn init(buf: []u8) Sender {
        return .{ .buf = buf };
    }

    /// The offset the next send starts at.
    pub fn next(self: *const Sender) u64 {
        return self.base + self.len;
    }

    /// Keeps `data` as sent in packet `pn`.
    pub fn sent(self: *Sender, pn: u64, data: []const u8, fin: bool) Error!void {
        if (self.count == max_chunks or self.len + data.len > self.buf.len) {
            return error.SendBufferFull;
        }
        const offset = self.next();
        @memcpy(self.buf[self.len..][0..data.len], data);
        self.len += data.len;
        self.chunks[self.count] = .{
            .pn = pn,
            .offset = offset,
            .len = data.len,
            .fin = fin,
        };
        self.count += 1;
    }

    /// Marks what the peer acknowledged and frees the run of it at the front.
    pub fn ack(self: *Sender, acked: *const frame.NumberSet) void {
        var news = false;
        for (self.chunks[0..self.count]) |*c| {
            if (c.acked or !acked.contains(c.pn)) continue;
            c.acked = true;
            news = true;
        }
        // Something got through, so whatever is still outstanding is worth
        // resending again rather than counting as already tried.
        if (news) for (self.chunks[0..self.count]) |*c| {
            c.resent = false;
        };

        var done: usize = 0;
        var freed: usize = 0;
        while (done < self.count and self.chunks[done].acked) : (done += 1) {
            freed += self.chunks[done].len;
        }
        if (done == 0) return;

        std.mem.copyForwards(u8, self.buf, self.buf[freed..self.len]);
        std.mem.copyForwards(Chunk, &self.chunks, self.chunks[done..self.count]);
        self.count -= done;
        self.len -= freed;
        self.base += freed;
    }

    /// Bytes that can still be held. Zero means waiting for acknowledgements,
    /// either for buffer space or for a chunk to track it with.
    pub fn room(self: *const Sender) usize {
        if (self.count == max_chunks) return 0;
        return self.buf.len - self.len;
    }

    /// The oldest chunk still outstanding that has not gone out again since
    /// the last acknowledgement, so successive repairs walk the outstanding
    /// data instead of resending the front of it over and over. Null once
    /// every outstanding chunk has been tried again.
    pub fn unacked(self: *Sender) ?*Chunk {
        for (self.chunks[0..self.count]) |*c| {
            if (!c.acked and !c.resent) return c;
        }
        return null;
    }

    /// The oldest chunk still outstanding, tried again or not: a probe has to
    /// carry something to be a probe.
    /// Source: RFC 9002 s6.2.4.
    pub fn oldestUnacked(self: *Sender) ?*Chunk {
        for (self.chunks[0..self.count]) |*c| {
            if (!c.acked) return c;
        }
        return null;
    }

    pub fn bytes(self: *const Sender, c: Chunk) []const u8 {
        return self.buf[@intCast(c.offset - self.base)..][0..c.len];
    }
};

const testing = std.testing;

test "sent data is held until acknowledged" {
    var buf: [16]u8 = @splat(0);
    var s = Sender.init(&buf);

    try s.sent(0, "abc", false);
    try s.sent(1, "de", false);
    try s.sent(2, "fg", true);
    try testing.expectEqual(@as(u64, 7), s.next());

    const first = s.unacked().?;
    try testing.expectEqual(@as(u64, 0), first.offset);
    try testing.expectEqualSlices(u8, "abc", s.bytes(first.*));

    // Acknowledging a later packet alone frees nothing: the first is still owed.
    var acked: frame.NumberSet = .{};
    acked.record(1);
    s.ack(&acked);
    try testing.expectEqual(@as(u64, 0), s.base);
    try testing.expectEqual(@as(u64, 0), s.unacked().?.offset);

    // With the front acknowledged the run at the front goes. The tail slides
    // down over the freed bytes; its stream offset does not.
    acked.record(0);
    s.ack(&acked);
    try testing.expectEqual(@as(u64, 5), s.base);
    const tail = s.unacked().?;
    try testing.expectEqual(@as(u64, 5), tail.offset);
    try testing.expect(tail.fin);
    try testing.expectEqualSlices(u8, "fg", s.bytes(tail.*));

    acked.record(2);
    s.ack(&acked);
    try testing.expectEqual(@as(u64, 7), s.base);
    try testing.expectEqual(@as(?*Sender.Chunk, null), s.unacked());

    // Sending past what is held has to wait for an acknowledgement.
    var small: [4]u8 = @splat(0);
    var t = Sender.init(&small);
    try t.sent(0, "abcd", false);
    try testing.expectError(error.SendBufferFull, t.sent(1, "e", false));
}

test "reads a stream that arrives out of order" {
    var buf: [16]u8 = @splat(0);
    var r = Receiver.init(&buf, 64);

    try r.push(.{ .id = 0, .offset = 3, .data = &.{ 3, 4, 5 }, .fin = true });
    // A gap at the front holds everything back, FIN or not.
    try testing.expectEqual(@as(usize, 0), r.readable().len);
    try testing.expect(!r.done());

    try r.push(.{ .id = 0, .offset = 0, .data = &.{ 0, 1, 2 }, .fin = false });
    try testing.expectEqualSlices(u8, &.{ 0, 1, 2, 3, 4, 5 }, r.readable());

    r.consume(4);
    try testing.expectEqualSlices(u8, &.{ 4, 5 }, r.readable());
    r.consume(2);
    try testing.expect(r.done());
}

test "a final size that disagrees with the stream is refused" {
    var buf: [16]u8 = @splat(0);
    var r = Receiver.init(&buf, 64);
    try r.push(.{ .id = 0, .offset = 0, .data = &.{ 0, 1 }, .fin = true });

    // Data past a FIN.
    try testing.expectError(error.FinalSizeError, r.push(.{
        .id = 0,
        .offset = 2,
        .data = &.{2},
        .fin = false,
    }));
    // A second FIN has to agree with the first.
    try testing.expectError(error.FinalSizeError, r.push(.{
        .id = 0,
        .offset = 0,
        .data = &.{0},
        .fin = true,
    }));

    // A FIN below what has already arrived.
    var other: [16]u8 = @splat(0);
    var s = Receiver.init(&other, 64);
    try s.push(.{ .id = 0, .offset = 0, .data = &.{ 0, 1, 2, 3 }, .fin = false });
    try testing.expectError(error.FinalSizeError, s.push(.{
        .id = 0,
        .offset = 0,
        .data = &.{0},
        .fin = true,
    }));
}

test "a window bounds what crosses and only ever grows" {
    var w: Window = .{ .limit = 4 };
    try w.take(3);
    try testing.expectEqual(@as(u64, 1), w.room());
    try testing.expectError(error.FlowControlBlocked, w.take(2));

    w.extend(8);
    try w.take(2);
    // An older limit arriving late cannot take back room already granted.
    w.extend(4);
    try testing.expectEqual(@as(u64, 8), w.limit);
}

test "consuming slides the buffer and earns a new limit" {
    var buf: [16]u8 = @splat(0);
    var r = Receiver.init(&buf, buf.len);
    try testing.expect(!r.wantsGrant());

    try r.push(.{ .id = 0, .offset = 0, .data = &@as([16]u8, @splat(0xaa)), .fin = false });
    // Full, and nothing read, so there is nothing to grant.
    try testing.expect(!r.wantsGrant());

    r.consume(8);
    try testing.expectEqual(@as(u64, 8), r.read());
    try testing.expect(r.wantsGrant());
    try testing.expectEqual(@as(u64, 24), r.grant());

    // The freed half takes the offsets the new limit covers.
    r.window.extend(r.grant());
    try r.push(.{ .id = 0, .offset = 16, .data = &.{ 1, 2 }, .fin = false });
    try testing.expectEqual(@as(usize, 10), r.readable().len);

    // Data past what we granted is a flow control violation, not a short read.
    var other: [16]u8 = @splat(0);
    var s = Receiver.init(&other, 4);
    try testing.expectError(error.FlowControlError, s.push(.{
        .id = 0,
        .offset = 2,
        .data = &.{ 2, 3, 4 },
        .fin = false,
    }));
}
