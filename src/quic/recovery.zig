//! RFC 9002: round trip estimation, loss detection, and NewReno congestion
//! control.
//!
//! Nothing here reads a clock. Every entry point takes the time it happens at,
//! in milliseconds, so `conn.zig` passes real time and a test passes its own.
const std = @import("std");

const packet = @import("packet.zig");

/// Timer granularity, and the floor under any delay derived from an RTT.
/// Source: RFC 9002 s6.1.2, A.2.
pub const granularity_ms: u64 = 1;

/// The RTT to assume before the first sample, which puts the first probe
/// timeout at about a second.
/// Source: RFC 9002 s6.2.2.
pub const initial_rtt_ms: u64 = 333;

/// How far behind the largest acknowledged packet a packet must fall before the
/// gap is loss rather than reordering.
/// Source: RFC 9002 s6.1.1.
pub const packet_threshold: u64 = 3;

/// The reordering window as a fraction of an RTT: 9/8.
/// Source: RFC 9002 s6.1.2.
pub const time_threshold_numerator: u64 = 9;
pub const time_threshold_denominator: u64 = 8;

/// Probe timeouts' worth of unbroken loss that means the path is gone rather
/// than merely congested.
/// Source: RFC 9002 s7.6.1.
pub const persistent_congestion_threshold: u64 = 3;

/// The round trip estimate. Sub-millisecond detail is dropped, since the timer
/// granularity is a millisecond anyway.
/// Source: RFC 9002 s5.
pub const Rtt = struct {
    latest_ms: u64 = 0,
    smoothed_ms: u64 = initial_rtt_ms,
    var_ms: u64 = initial_rtt_ms / 2,
    min_ms: u64 = 0,
    /// Whether any of the above came from a measurement. Until one does, the
    /// initial values stand in for one.
    sampled: bool = false,

    /// Folds in one measurement. `ack_delay_ms` is what the peer said it waited
    /// before acknowledging, which is not time spent on the path.
    /// Source: RFC 9002 s5.2, s5.3.
    pub fn sample(self: *Rtt, latest_ms: u64, ack_delay_ms: u64, max_ack_delay_ms: u64) void {
        self.latest_ms = latest_ms;
        if (!self.sampled) {
            self.sampled = true;
            self.min_ms = latest_ms;
            self.smoothed_ms = latest_ms;
            self.var_ms = latest_ms / 2;
            return;
        }
        self.min_ms = @min(self.min_ms, latest_ms);

        // The peer's delay comes off only if what is left still covers the
        // shortest trip seen: a sample below that is the delay being wrong.
        const delay = @min(ack_delay_ms, max_ack_delay_ms);
        const adjusted = if (latest_ms >= self.min_ms + delay) latest_ms - delay else latest_ms;

        const diff = if (self.smoothed_ms > adjusted)
            self.smoothed_ms - adjusted
        else
            adjusted - self.smoothed_ms;
        self.var_ms = (3 * self.var_ms + diff) / 4;
        self.smoothed_ms = (7 * self.smoothed_ms + adjusted) / 8;
    }

    /// How long past a packet a later acknowledgement has to arrive before that
    /// packet counts as lost rather than reordered.
    /// Source: RFC 9002 s6.1.2.
    pub fn lossDelayMs(self: *const Rtt) u64 {
        const base = @max(self.latest_ms, self.smoothed_ms);
        return @max(granularity_ms, base * time_threshold_numerator / time_threshold_denominator);
    }

    /// How long to wait for an acknowledgement before probing, doubled once per
    /// consecutive probe. `max_ack_delay_ms` is zero for the Initial and
    /// Handshake spaces, where the peer may not delay on purpose.
    /// Source: RFC 9002 s6.2.1.
    pub fn ptoMs(self: *const Rtt, backoff: u32, max_ack_delay_ms: u64) u64 {
        const base = self.smoothed_ms + @max(4 * self.var_ms, granularity_ms) + max_ack_delay_ms;
        var out = @max(granularity_ms, base);
        // Saturating, so a long run of probes cannot wrap the deadline around.
        for (0..backoff) |_| out = out *| 2;
        return out;
    }

    /// How long every packet in a row has to be lost before the path counts as
    /// gone. The unbacked-off probe timeout, three times over.
    /// Source: RFC 9002 s7.6.1.
    pub fn persistentCongestionMs(self: *const Rtt, max_ack_delay_ms: u64) u64 {
        return self.ptoMs(0, max_ack_delay_ms) * persistent_congestion_threshold;
    }
};

/// One packet we sent and have not seen acknowledged. Only ack-eliciting
/// packets are kept: an ACK on its own is neither retransmitted nor counted
/// against the congestion window.
/// Source: RFC 9002 s2, A.1.1.
pub const Sent = struct {
    pn: u64,
    time_ms: u64,
    size: u16,
};

/// What one pass of loss detection found.
pub const Lost = struct {
    count: usize = 0,
    bytes: u64 = 0,
    /// Send times of the first and last packet declared lost, which is the span
    /// persistent congestion is measured over.
    earliest_ms: u64 = 0,
    latest_ms: u64 = 0,

    pub fn any(self: Lost) bool {
        return self.count > 0;
    }
};

/// The outstanding packets of one space, oldest first.
pub const Tracker = struct {
    sent: [max_tracked]Sent = undefined,
    count: usize = 0,
    /// The largest number the peer has acknowledged here, which is what loss is
    /// measured against.
    largest_acked: ?u64 = null,
    /// When the oldest packet still outstanding crosses the reordering window,
    /// once one is old enough for that to be a question.
    loss_time_ms: ?u64 = null,
    /// When the last ack-eliciting packet went out, which is what the probe
    /// timeout counts from.
    last_sent_ms: ?u64 = null,

    /// The sender holds at most `stream.Sender.max_chunks` chunks outstanding
    /// and the rest of what we send is one packet at a time, so this is room to
    /// spare.
    pub const max_tracked = 32;

    /// Records a packet, returning whatever had to be forgotten to make room:
    /// its bytes are no longer accounted for here, so the caller has to take
    /// them out of flight.
    pub fn onSent(self: *Tracker, pn: u64, size: u16, now_ms: u64) ?Sent {
        self.last_sent_ms = now_ms;
        var dropped: ?Sent = null;
        if (self.count == max_tracked) {
            dropped = self.sent[0];
            std.mem.copyForwards(Sent, &self.sent, self.sent[1..]);
            self.count -= 1;
        }
        self.sent[self.count] = .{ .pn = pn, .time_ms = now_ms, .size = size };
        self.count += 1;
        return dropped;
    }

    pub fn inFlight(self: *const Tracker) u64 {
        var total: u64 = 0;
        for (self.sent[0..self.count]) |s| total += s.size;
        return total;
    }

    pub fn oldest(self: *const Tracker) ?Sent {
        return if (self.count == 0) null else self.sent[0];
    }

    /// Whether `pn` is still waiting on an acknowledgement here.
    pub fn outstanding(self: *const Tracker, pn: u64) bool {
        for (self.sent[0..self.count]) |s| {
            if (s.pn == pn) return true;
        }
        return false;
    }

    fn remove(self: *Tracker, i: usize) Sent {
        const out = self.sent[i];
        std.mem.copyForwards(Sent, self.sent[i..], self.sent[i + 1 .. self.count]);
        self.count -= 1;
        return out;
    }

    /// Drops `pn` from the outstanding set, returning what it was if it was
    /// still there. A repeated acknowledgement finds nothing, which is how
    /// "newly acknowledged" is decided.
    pub fn take(self: *Tracker, pn: u64) ?Sent {
        for (self.sent[0..self.count], 0..) |s, i| {
            if (s.pn == pn) return self.remove(i);
        }
        return null;
    }
};

/// NewReno, the controller RFC 9002 specifies in the absence of another. All
/// sizes are bytes, and the window is shared across spaces because the path is.
/// Source: RFC 9002 s7.
pub const Congestion = struct {
    /// The largest datagram we send. Every window is a multiple of it.
    max_datagram: u64,
    window: u64,
    in_flight: u64 = 0,
    /// Where slow start ended, so below it the window grows by every byte and
    /// above it by a packet per round trip. Null until loss sets it.
    /// Source: RFC 9002 s7.3.
    ssthresh: ?u64 = null,
    /// When the last congestion event was answered. Loss of anything sent
    /// before it is that same event.
    /// Source: RFC 9002 s7.3.2.
    recovery_from_ms: ?u64 = null,

    /// Ten packets, capped at the larger of 14720 bytes and two packets.
    /// Source: RFC 9002 s7.2.
    pub fn initialWindow(max_datagram: u64) u64 {
        return @min(10 * max_datagram, @max(14720, 2 * max_datagram));
    }

    /// The floor a congestion event may take the window to.
    /// Source: RFC 9002 s7.2.
    pub fn minimumWindow(max_datagram: u64) u64 {
        return 2 * max_datagram;
    }

    pub fn init(max_datagram: u64) Congestion {
        return .{ .max_datagram = max_datagram, .window = initialWindow(max_datagram) };
    }

    /// Whether `bytes` more may go out. A probe may ignore it.
    /// Source: RFC 9002 s7, s7.5.
    pub fn canSend(self: *const Congestion, bytes: u64) bool {
        return self.in_flight + bytes <= self.window;
    }

    pub fn onSent(self: *Congestion, bytes: u64) void {
        self.in_flight += bytes;
    }

    /// Grows the window by what was freed: every byte in slow start, about a
    /// packet per round trip after it.
    /// Source: RFC 9002 s7.3.1, s7.3.3.
    pub fn onAcked(self: *Congestion, bytes: u64, sent_ms: u64) void {
        self.in_flight -|= bytes;
        // Recovery ends only once something sent after it began gets through.
        if (self.recovery_from_ms) |from| {
            if (sent_ms <= from) return;
            self.recovery_from_ms = null;
        }
        if (self.ssthresh == null or self.window < self.ssthresh.?) {
            self.window += bytes;
            return;
        }
        self.window += self.max_datagram * bytes / self.window;
    }

    pub fn onLost(self: *Congestion, bytes: u64) void {
        self.in_flight -|= bytes;
    }

    /// Halves the window, unless this loss belongs to an event already
    /// answered.
    /// Source: RFC 9002 s7.3.2.
    pub fn onCongestion(self: *Congestion, sent_ms: u64, now_ms: u64) void {
        if (self.recovery_from_ms) |from| {
            if (sent_ms <= from) return;
        }
        self.recovery_from_ms = now_ms;
        const halved = self.window / 2;
        self.ssthresh = halved;
        self.window = @max(halved, minimumWindow(self.max_datagram));
    }

    /// Nothing got through for long enough that congestion is not the
    /// explanation: back to the minimum, and to slow start.
    /// Source: RFC 9002 s7.6.2.
    pub fn onPersistentCongestion(self: *Congestion) void {
        self.window = minimumWindow(self.max_datagram);
        self.recovery_from_ms = null;
    }
};

/// Which timer is next to fire, and for what.
pub const Timer = struct {
    at_ms: u64,
    space: packet.Space,
    kind: enum { loss, probe },

    /// Milliseconds from `now_ms` until it fires, floored at zero for a timer
    /// already due.
    pub fn afterMs(self: Timer, now_ms: u64) u64 {
        return self.at_ms -| now_ms;
    }
};

/// Everything one connection needs to decide what is lost, when to probe, and
/// how much may be in flight.
pub const Recovery = struct {
    rtt: Rtt = .{},
    cc: Congestion,
    /// Indexed by `packet.Space`: loss is per space, congestion is not.
    /// Source: RFC 9002 s6, s7.6.2.
    trackers: [3]Tracker = .{ .{}, .{}, .{} },
    /// Consecutive probe timeouts, which double the next one.
    /// Source: RFC 9002 s6.2.1.
    backoff: u32 = 0,
    /// The peer's max_ack_delay, allowed for in the application space's probe
    /// timeout. The default until its transport parameters say otherwise.
    /// Source: RFC 9000 s18.2.
    peer_max_ack_delay_ms: u64 = 25,
    /// HANDSHAKE_DONE has arrived. Until then the application space gets no
    /// probe timer, neither side being sure the other can read one.
    /// Source: RFC 9002 s6.2.1.
    confirmed: bool = false,
    pending: Pending = .{},

    /// Newly acknowledged packets, accumulated across one ACK frame's ranges.
    const Pending = struct {
        bytes: u64 = 0,
        count: usize = 0,
        /// The largest newly acknowledged, and when it went out: the only
        /// packet an RTT may be measured from.
        /// Source: RFC 9002 s5.1.
        largest: ?u64 = null,
        largest_sent_ms: u64 = 0,
        /// The send times acknowledged, which break a run of loss they fall
        /// inside.
        earliest_sent_ms: u64 = 0,
        latest_sent_ms: u64 = 0,
    };

    pub fn init(max_datagram: u64) Recovery {
        return .{ .cc = Congestion.init(max_datagram) };
    }

    pub fn tracker(self: *Recovery, space: packet.Space) *Tracker {
        return &self.trackers[@backingInt(space)];
    }

    /// Records an ack-eliciting packet going out. Anything else is untracked,
    /// being neither retransmitted nor in flight.
    /// Source: RFC 9002 s2, s7.
    pub fn onSent(self: *Recovery, space: packet.Space, pn: u64, size: usize, now_ms: u64) void {
        if (self.tracker(space).onSent(pn, @intCast(size), now_ms)) |dropped| {
            self.cc.onLost(dropped.size);
        }
        self.cc.onSent(size);
    }

    /// Marks `pn` acknowledged. Call once per number in the ACK's ranges, then
    /// `onAck` to finish the frame.
    pub fn acked(self: *Recovery, space: packet.Space, pn: u64) void {
        const t = self.tracker(space);
        t.largest_acked = if (t.largest_acked) |l| @max(l, pn) else pn;

        const s = t.take(pn) orelse return;
        const p = &self.pending;
        if (p.count == 0) {
            p.earliest_sent_ms = s.time_ms;
            p.latest_sent_ms = s.time_ms;
        } else {
            p.earliest_sent_ms = @min(p.earliest_sent_ms, s.time_ms);
            p.latest_sent_ms = @max(p.latest_sent_ms, s.time_ms);
        }
        p.count += 1;
        p.bytes += s.size;
        if (p.largest == null or pn > p.largest.?) {
            p.largest = pn;
            p.largest_sent_ms = s.time_ms;
        }
    }

    /// Finishes one ACK frame: takes a round trip sample, grows the window by
    /// what was freed, and returns what is now lost. `ack_delay_ms` is the
    /// peer's stated delay, already unscaled.
    /// Source: RFC 9002 s5.1, A.7.
    pub fn onAck(self: *Recovery, space: packet.Space, largest: u64, ack_delay_ms: u64, now_ms: u64) Lost {
        const p = self.pending;
        self.pending = .{};
        if (p.count == 0) return .{};

        // Only the largest acknowledged packet times the path, and only when
        // this ACK is what first acknowledged it.
        if (p.largest == largest) {
            const delay = if (space == .application) ack_delay_ms else 0;
            self.rtt.sample(now_ms -| p.largest_sent_ms, delay, self.peer_max_ack_delay_ms);
        }

        self.cc.onAcked(p.bytes, p.latest_sent_ms);

        // A client leaves the backoff alone for an Initial-space ACK: the
        // server may still be validating our address, and probes are what get
        // it there.
        // Source: RFC 9002 s6.2.1.
        if (space != .initial) self.backoff = 0;

        const lost = self.detect(space, now_ms);
        if (lost.any()) self.onLost(lost, p, now_ms);
        return lost;
    }

    /// The loss timer expired: what it was waiting on is gone, and the window
    /// answers for it as it would for loss an acknowledgement revealed.
    /// Source: RFC 9002 s6.1.2, A.10.
    pub fn onLossTimer(self: *Recovery, space: packet.Space, now_ms: u64) Lost {
        const lost = self.detect(space, now_ms);
        if (lost.any()) self.onLost(lost, .{}, now_ms);
        return lost;
    }

    /// Everything outstanding in `space` that a later acknowledgement or the
    /// reordering window has left behind, removed from the outstanding set.
    /// Detection only: `onAck` and `onLossTimer` are what answer for it.
    /// Source: RFC 9002 s6.1, A.10.
    fn detect(self: *Recovery, space: packet.Space, now_ms: u64) Lost {
        const t = self.tracker(space);
        const largest = t.largest_acked orelse return .{};
        const delay = self.rtt.lossDelayMs();

        t.loss_time_ms = null;
        var out: Lost = .{};
        var i: usize = 0;
        while (i < t.count) {
            const s = t.sent[i];
            if (s.pn > largest) {
                i += 1;
                continue;
            }
            const by_order = s.pn + packet_threshold <= largest;
            const by_time = now_ms >= s.time_ms + delay;
            if (!by_order and !by_time) {
                // Outstanding, behind the largest acknowledged, and not yet old
                // enough: the earliest such packet is when to look again.
                const at = s.time_ms + delay;
                t.loss_time_ms = if (t.loss_time_ms) |l| @min(l, at) else at;
                i += 1;
                continue;
            }
            if (out.count == 0) out.earliest_ms = s.time_ms;
            out.latest_ms = s.time_ms;
            out.count += 1;
            out.bytes += s.size;
            _ = t.remove(i);
        }
        return out;
    }

    /// Answers a loss: the window comes down once for the event, or all the way
    /// if nothing at all got through for long enough.
    /// Source: RFC 9002 s7.3.2, s7.6.2.
    fn onLost(self: *Recovery, lost: Lost, p: Pending, now_ms: u64) void {
        self.cc.onLost(lost.bytes);

        if (self.persistent(lost, p)) {
            self.cc.onPersistentCongestion();
            return;
        }
        self.cc.onCongestion(lost.latest_ms, now_ms);
    }

    /// Whether `lost` is a long enough unbroken run to mean the path is gone:
    /// two packets at least, nothing acknowledged between them, and an RTT
    /// already measured. Only this space counts, which the RFC allows.
    /// Source: RFC 9002 s7.6.2.
    fn persistent(self: *const Recovery, lost: Lost, p: Pending) bool {
        if (lost.count < 2 or !self.rtt.sampled) return false;
        const span = lost.latest_ms - lost.earliest_ms;
        if (span <= self.rtt.persistentCongestionMs(self.peer_max_ack_delay_ms)) return false;
        const acked_inside = p.count > 0 and
            p.earliest_sent_ms > lost.earliest_ms and
            p.latest_sent_ms < lost.latest_ms;
        return !acked_inside;
    }

    /// The probe timeout for `space`, or null when it has nothing outstanding
    /// or may not be probed yet.
    /// Source: RFC 9002 s6.2.1.
    fn probeAt(self: *const Recovery, space: packet.Space) ?u64 {
        if (space == .application and !self.confirmed) return null;
        const t = &self.trackers[@backingInt(space)];
        if (t.count == 0) return null;
        const last = t.last_sent_ms orelse return null;
        // The peer only delays acknowledgements once there is application data
        // to delay them for.
        const delay: u64 = if (space == .application) self.peer_max_ack_delay_ms else 0;
        return last + self.rtt.ptoMs(self.backoff, delay);
    }

    /// The next timer to fire, or null when nothing is outstanding. A loss
    /// timer always wins: it is both earlier and less likely to resend
    /// something that was only reordered.
    /// Source: RFC 9002 s6.2.1, A.8.
    pub fn timer(self: *const Recovery) ?Timer {
        var out: ?Timer = null;
        for ([_]packet.Space{ .initial, .handshake, .application }) |space| {
            if (self.trackers[@backingInt(space)].loss_time_ms) |at| {
                if (out == null or at < out.?.at_ms) {
                    out = .{ .at_ms = at, .space = space, .kind = .loss };
                }
            }
        }
        if (out != null) return out;

        for ([_]packet.Space{ .initial, .handshake, .application }) |space| {
            if (self.probeAt(space)) |at| {
                if (out == null or at < out.?.at_ms) {
                    out = .{ .at_ms = at, .space = space, .kind = .probe };
                }
            }
        }
        return out;
    }

    /// A probe timeout expired: the next one waits twice as long. What to send
    /// is the caller's, since only it knows what is worth repeating.
    /// Source: RFC 9002 s6.2.1, s6.2.4.
    pub fn onProbe(self: *Recovery) void {
        self.backoff += 1;
    }

    /// Forgets everything outstanding in `space`, which is what discarding its
    /// keys means here: those packets can never be acknowledged now, so they
    /// are neither in flight nor lost, and no timer should wait on them.
    /// Source: RFC 9002 s6.4.
    pub fn discard(self: *Recovery, space: packet.Space) void {
        const t = self.tracker(space);
        self.cc.onLost(t.inFlight());
        t.* = .{};
        self.backoff = 0;
    }

    /// Whether `pn` is still outstanding in `space`. Loss detection removes
    /// what it declares lost, so a packet neither here nor acknowledged is one
    /// the peer never got.
    pub fn outstanding(self: *const Recovery, space: packet.Space, pn: u64) bool {
        return self.trackers[@backingInt(space)].outstanding(pn);
    }

    /// Whether `bytes` may go out under the congestion window.
    pub fn canSend(self: *const Recovery, bytes: u64) bool {
        return self.cc.canSend(bytes);
    }
};

const testing = std.testing;

test "the first sample replaces the assumed round trip, and later ones smooth it" {
    var r: Rtt = .{};
    // Before a measurement, the assumption puts a probe at about a second.
    try testing.expectEqual(@as(u64, 333 + 4 * 166), r.ptoMs(0, 0));

    r.sample(100, 0, 25);
    try testing.expectEqual(@as(u64, 100), r.smoothed_ms);
    try testing.expectEqual(@as(u64, 50), r.var_ms);
    try testing.expectEqual(@as(u64, 100), r.min_ms);

    // 7/8 of 100 plus 1/8 of 200.
    r.sample(200, 0, 25);
    try testing.expectEqual(@as(u64, 112), r.smoothed_ms);
    // 3/4 of 50 plus 1/4 of |100 - 200|.
    try testing.expectEqual(@as(u64, 62), r.var_ms);
    try testing.expectEqual(@as(u64, 100), r.min_ms);
}

test "the peer's stated delay comes off, capped, and never below the path" {
    var r: Rtt = .{};
    r.sample(100, 0, 25);

    // 120 of which the peer delayed 20 is a 100ms path, so nothing moves.
    r.sample(120, 20, 25);
    try testing.expectEqual(@as(u64, 100), r.smoothed_ms);

    // Capped at the 25 it promised, so 25 comes off 200, not 100: 7/8 of 100
    // plus 1/8 of 175.
    r.sample(200, 100, 25);
    try testing.expectEqual(@as(u64, 109), r.smoothed_ms);

    // More delay than the sample has room for would put the trip under the
    // fastest ever seen, so it is ignored.
    var bare: Rtt = .{};
    bare.sample(100, 0, 25);
    bare.sample(100, 25, 25);
    try testing.expectEqual(@as(u64, 100), bare.smoothed_ms);
}

test "the probe timeout doubles per attempt and does not wrap" {
    var r: Rtt = .{};
    r.sample(100, 0, 0);
    const base = r.ptoMs(0, 0);
    try testing.expectEqual(base * 2, r.ptoMs(1, 0));
    try testing.expectEqual(base * 4, r.ptoMs(2, 0));
    // Saturating rather than wrapping to something in the past.
    try testing.expect(r.ptoMs(200, 0) > r.ptoMs(8, 0));
}

test "a packet three behind the largest acknowledged is lost, whatever the clock says" {
    var r = Recovery.init(1200);
    r.confirmed = true;
    // A measured trip, so the reordering window is wide enough that only the
    // ordering rule can fire here.
    r.rtt.sample(100, 0, 0);
    for (0..5) |i| r.onSent(.application, i, 100, 1000);

    // Only the newest acknowledged, one millisecond later: 0 and 1 are three or
    // more behind it, 2 and 3 are not.
    r.acked(.application, 4);
    const lost = r.onAck(.application, 4, 0, 1001);
    try testing.expectEqual(@as(usize, 2), lost.count);
    try testing.expectEqual(@as(u64, 200), lost.bytes);
    try testing.expectEqual(@as(usize, 2), r.tracker(.application).count);
}

test "a packet older than the reordering window is lost once the window passes" {
    var r = Recovery.init(1200);
    r.confirmed = true;
    r.rtt.sample(100, 0, 0);

    r.onSent(.application, 0, 100, 1000);
    r.onSent(.application, 1, 100, 1000);
    r.acked(.application, 1);

    // 112ms of window on a 100ms trip, so at 1100 the gap is still reordering
    // and the timer says when to look again.
    const none = r.onAck(.application, 1, 0, 1100);
    try testing.expect(!none.any());
    try testing.expectEqual(@as(?u64, 1000 + r.rtt.lossDelayMs()), r.tracker(.application).loss_time_ms);

    // The timer path has to answer for what it finds, or the bytes stay in
    // flight forever and the window never reopens.
    const before = r.cc.in_flight;
    const lost = r.onLossTimer(.application, 1000 + r.rtt.lossDelayMs());
    try testing.expectEqual(@as(usize, 1), lost.count);
    try testing.expectEqual(before - 100, r.cc.in_flight);
    try testing.expectEqual(@as(?u64, null), r.tracker(.application).loss_time_ms);
}

test "discarding a space takes its packets out of flight and disarms it" {
    var r = Recovery.init(1200);
    r.onSent(.initial, 0, 1200, 1000);
    r.onSent(.handshake, 0, 800, 1010);
    try testing.expectEqual(@as(u64, 2000), r.cc.in_flight);
    try testing.expect(r.timer() != null);

    r.discard(.initial);
    try testing.expectEqual(@as(u64, 800), r.cc.in_flight);
    r.discard(.handshake);
    try testing.expectEqual(@as(u64, 0), r.cc.in_flight);
    // Nothing can be acknowledged in either space now, so nothing waits on one.
    try testing.expectEqual(@as(?Timer, null), r.timer());
}

test "a forgotten packet does not stay in flight" {
    var r = Recovery.init(1200);
    // One more than the tracker holds, so the oldest is dropped rather than
    // counted against the window for good.
    for (0..Tracker.max_tracked + 1) |i| r.onSent(.application, i, 100, 1000 + i);
    try testing.expectEqual(@as(usize, Tracker.max_tracked), r.tracker(.application).count);
    try testing.expectEqual(r.tracker(.application).inFlight(), r.cc.in_flight);
}

test "an acknowledgement times the path only from the largest it newly covers" {
    var r = Recovery.init(1200);
    r.confirmed = true;
    r.onSent(.application, 0, 100, 1000);
    r.onSent(.application, 1, 100, 1050);

    // Acknowledging both: the sample comes from packet 1, sent at 1050.
    r.acked(.application, 0);
    r.acked(.application, 1);
    _ = r.onAck(.application, 1, 0, 1100);
    try testing.expectEqual(@as(u64, 50), r.rtt.latest_ms);

    // The same ACK again acknowledges nothing new, so nothing is measured.
    r.onSent(.application, 2, 100, 1200);
    r.acked(.application, 1);
    _ = r.onAck(.application, 1, 0, 1400);
    try testing.expectEqual(@as(u64, 50), r.rtt.latest_ms);
}

test "the window grows by every byte in slow start and by a packet a round trip after" {
    var r = Recovery.init(1200);
    r.confirmed = true;
    const start = r.cc.window;

    r.onSent(.application, 0, 1200, 1000);
    r.acked(.application, 0);
    _ = r.onAck(.application, 0, 0, 1010);
    // Slow start: the window took on everything acknowledged.
    try testing.expectEqual(start + 1200, r.cc.window);
    try testing.expectEqual(@as(u64, 0), r.cc.in_flight);

    // Past the threshold the same acknowledgement is worth a fraction of a
    // packet instead.
    r.cc.ssthresh = 1;
    const before = r.cc.window;
    r.onSent(.application, 1, 1200, 1100);
    r.acked(.application, 1);
    _ = r.onAck(.application, 1, 0, 1110);
    try testing.expectEqual(before + 1200 * 1200 / before, r.cc.window);
}

test "loss halves the window once per event, not once per packet" {
    var r = Recovery.init(1200);
    r.confirmed = true;
    r.rtt.sample(100, 0, 0);
    const start = r.cc.window;

    for (0..6) |i| r.onSent(.application, i, 1200, 1000);
    r.acked(.application, 5);
    const lost = r.onAck(.application, 5, 0, 1001);
    try testing.expect(lost.count >= 2);
    // The acknowledged packet grew the window before the loss halved it.
    const grown = start + 1200;
    try testing.expectEqual(grown / 2, r.cc.window);
    try testing.expectEqual(@as(?u64, grown / 2), r.cc.ssthresh);

    // More loss from packets sent before the event does not halve it again.
    const halved = r.cc.window;
    for (6..12) |i| r.onSent(.application, i, 1200, 1000);
    r.acked(.application, 11);
    _ = r.onAck(.application, 11, 0, 1002);
    try testing.expectEqual(halved, r.cc.window);
}

test "the window never falls below two packets" {
    var r = Recovery.init(1200);
    // Each event has to be newer than the recovery the last one started, or it
    // is the same event and does nothing.
    for (0..8) |i| {
        const at = 2000 + i * 10;
        r.cc.onCongestion(at, at);
    }
    try testing.expectEqual(Congestion.minimumWindow(1200), r.cc.window);
}

test "a long enough run of loss with nothing acknowledged collapses the window" {
    var r = Recovery.init(1200);
    r.confirmed = true;
    r.peer_max_ack_delay_ms = 0;
    r.rtt.sample(10, 0, 0);
    // Ten milliseconds of trip, so half a second of unbroken loss is well past
    // what congestion alone explains.
    const span: u64 = 500;

    r.onSent(.application, 0, 1200, 1000);
    r.onSent(.application, 1, 1200, 1000 + span);
    r.onSent(.application, 2, 1200, 1001 + span);
    r.onSent(.application, 3, 1200, 1002 + span);
    r.onSent(.application, 4, 1200, 1003 + span);

    // Only the newest gets through, and it was sent after the run, so nothing
    // inside the span was acknowledged.
    r.acked(.application, 4);
    const lost = r.onAck(.application, 4, 0, 1004 + span);
    try testing.expectEqual(@as(usize, 2), lost.count);
    try testing.expectEqual(span, lost.latest_ms - lost.earliest_ms);
    try testing.expectEqual(Congestion.minimumWindow(1200), r.cc.window);
}

test "the loss timer comes before a probe, and a probe waits on the last packet sent" {
    var r = Recovery.init(1200);
    r.confirmed = true;
    r.rtt.sample(100, 0, 0);

    // Nothing outstanding, nothing to time.
    try testing.expectEqual(@as(?Timer, null), r.timer());

    r.onSent(.application, 0, 100, 1000);
    const probe = r.timer().?;
    try testing.expectEqual(packet.Space.application, probe.space);
    try testing.expectEqual(@as(u64, 1000) + r.rtt.ptoMs(0, r.peer_max_ack_delay_ms), probe.at_ms);

    // A gap under the reordering window arms the loss timer, which takes over.
    r.onSent(.application, 1, 100, 1000);
    r.acked(.application, 1);
    _ = r.onAck(.application, 1, 0, 1010);
    const loss = r.timer().?;
    try testing.expectEqual(@as(u64, 1000) + r.rtt.lossDelayMs(), loss.at_ms);
    try testing.expect(loss.at_ms < probe.at_ms);
}

test "the application space is not probed before the handshake is confirmed" {
    var r = Recovery.init(1200);
    r.onSent(.application, 0, 100, 1000);
    try testing.expectEqual(@as(?Timer, null), r.timer());

    r.confirmed = true;
    try testing.expect(r.timer() != null);

    // The handshake spaces are probed from the start, and without allowing for
    // an acknowledgement delay the peer is not entitled to there.
    var r2 = Recovery.init(1200);
    r2.onSent(.initial, 0, 1200, 1000);
    const t = r2.timer().?;
    try testing.expectEqual(packet.Space.initial, t.space);
    try testing.expectEqual(@as(u64, 1000) + r2.rtt.ptoMs(0, 0), t.at_ms);
}

test "an acknowledgement clears the backoff, except in the Initial space" {
    var r = Recovery.init(1200);
    r.confirmed = true;

    r.onProbe();
    r.onProbe();
    try testing.expectEqual(@as(u32, 2), r.backoff);

    // A client keeps probing at the same rate while the server may still be
    // validating its address.
    r.onSent(.initial, 0, 1200, 1000);
    r.acked(.initial, 0);
    _ = r.onAck(.initial, 0, 0, 1100);
    try testing.expectEqual(@as(u32, 2), r.backoff);

    r.onSent(.handshake, 0, 1200, 1100);
    r.acked(.handshake, 0);
    _ = r.onAck(.handshake, 0, 0, 1200);
    try testing.expectEqual(@as(u32, 0), r.backoff);
}

test "outstanding packets are tracked in flight and released by an acknowledgement" {
    var r = Recovery.init(1200);
    r.confirmed = true;
    try testing.expect(r.canSend(1200));

    var pn: u64 = 0;
    while (r.canSend(1200)) : (pn += 1) r.onSent(.application, pn, 1200, 1000);
    try testing.expect(!r.canSend(1200));
    try testing.expectEqual(r.tracker(.application).inFlight(), r.cc.in_flight);

    r.acked(.application, 0);
    _ = r.onAck(.application, 0, 0, 1010);
    try testing.expect(r.canSend(1200));
}

test "the oldest goes when more is outstanding than the tracker holds" {
    var t: Tracker = .{};
    for (0..Tracker.max_tracked) |i| try testing.expectEqual(@as(?Sent, null), t.onSent(i, 100, 1000 + i));

    // Full, so each further packet reports the one it displaced.
    for (Tracker.max_tracked..Tracker.max_tracked + 4) |i| {
        const dropped = t.onSent(i, 100, 1000 + i);
        try testing.expectEqual(@as(u64, i - Tracker.max_tracked), dropped.?.pn);
    }
    try testing.expectEqual(Tracker.max_tracked, t.count);
    try testing.expectEqual(@as(u64, 4), t.oldest().?.pn);
    try testing.expectEqual(@as(?Sent, null), t.take(0));
    try testing.expect(t.take(4) != null);
}
