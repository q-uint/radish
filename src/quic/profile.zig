//! Counters for one connection: what arrived, what went out, and the shape of
//! the acknowledgements between them. Incremented per packet, so plain adds.
const std = @import("std");

pub const Profile = struct {
    datagrams_in: u64 = 0,
    datagrams_out: u64 = 0,
    bytes_in: u64 = 0,
    bytes_out: u64 = 0,
    /// Datagrams that no key would open, which are not the peer talking to us.
    unopened: u64 = 0,
    /// Turns that waited and got nothing.
    silent: u64 = 0,
    /// Time blocked waiting for a datagram. Near the elapsed time means the
    /// peer is not sending; near zero means we are the slow end and the socket
    /// buffer is backing up behind us. Nanoseconds, because at a millisecond
    /// a wait shorter than the per-packet cost rounds to nothing, which is the
    /// distinction this is here to make.
    waited_ns: u64 = 0,
    /// Datagrams that came back in under a microsecond, which is too fast to
    /// have involved the network.
    ready: u64 = 0,
    /// When the transfer finished, to separate it from whatever the caller
    /// does with the bytes afterwards.
    pack_ms: u64 = 0,

    /// 1-RTT packets accepted, and the highest number among them. The
    /// difference between the two is what never arrived.
    app_packets: u64 = 0,
    app_highest: u64 = 0,
    /// Packets that did not follow the one before them.
    app_gaps: u64 = 0,

    acks_sent: u64 = 0,
    /// Ranges across every ACK sent: one per ACK means the peer sees an
    /// unbroken run, more means we are reporting holes.
    ack_ranges: u64 = 0,
    ack_ranges_max: u64 = 0,
    grants_sent: u64 = 0,

    /// Round trip estimate and congestion window as they finished.
    rtt_ms: u64 = 0,
    cwnd: u64 = 0,

    /// Packets the peer got through per round trip, which is what its
    /// congestion window allowed. Zero until an RTT has been measured.
    pub fn packetsPerRtt(self: *const Profile, elapsed_ms: u64) u64 {
        if (self.rtt_ms == 0 or elapsed_ms == 0) return 0;
        const rtts = @max(1, elapsed_ms / self.rtt_ms);
        return self.app_packets / rtts;
    }

    /// What never arrived, by number rather than by loss detection.
    pub fn missing(self: *const Profile) u64 {
        if (self.app_packets == 0) return 0;
        return (self.app_highest + 1) -| self.app_packets;
    }

    /// Bytes a second over the transfer, or over `elapsed_ms` when nothing
    /// marked the transfer as finished.
    pub fn rate(self: *const Profile, elapsed_ms: u64) u64 {
        const span = if (self.pack_ms != 0) self.pack_ms else elapsed_ms;
        if (span == 0) return 0;
        return self.bytes_in * 1000 / span;
    }

    pub fn report(self: *const Profile, w: *std.Io.Writer, elapsed_ms: u64) !void {
        try w.print("profile: {d} ms, {d} ms transfer, {d} bytes/s\n", .{
            elapsed_ms,
            self.pack_ms,
            self.rate(elapsed_ms),
        });
        try w.print("  in       {d} datagrams, {d} bytes\n", .{ self.datagrams_in, self.bytes_in });
        try w.print("  out      {d} datagrams, {d} bytes\n", .{ self.datagrams_out, self.bytes_out });
        try w.print("  waiting  {d} ms blocked, {d} of {d} under a microsecond\n", .{
            self.waited_ns / std.time.ns_per_ms,
            self.ready,
            self.datagrams_in,
        });
        try w.print("  1-rtt    {d} packets, highest {d}, {d} missing, {d} gaps\n", .{
            self.app_packets,
            self.app_highest,
            self.missing(),
            self.app_gaps,
        });
        try w.print("  acks     {d} sent, {d} ranges, {d} widest\n", .{
            self.acks_sent,
            self.ack_ranges,
            self.ack_ranges_max,
        });
        try w.print("  grants   {d}\n", .{self.grants_sent});
        try w.print("  unopened {d}, silent {d}\n", .{ self.unopened, self.silent });
        try w.print("  rtt      {d} ms, our cwnd {d}\n", .{ self.rtt_ms, self.cwnd });
        try w.print("  peer     {d} packets per rtt\n", .{self.packetsPerRtt(elapsed_ms)});
    }
};

const testing = std.testing;

test "missing counts the numbers that never arrived" {
    var p: Profile = .{ .app_packets = 10, .app_highest = 11 };
    try testing.expectEqual(@as(u64, 2), p.missing());

    p = .{ .app_packets = 12, .app_highest = 11 };
    try testing.expectEqual(@as(u64, 0), p.missing());

    p = .{};
    try testing.expectEqual(@as(u64, 0), p.missing());
}

test "packets per rtt needs a measured rtt" {
    var p: Profile = .{ .app_packets = 1000, .rtt_ms = 0 };
    try testing.expectEqual(@as(u64, 0), p.packetsPerRtt(10_000));

    // 10 s at 20 ms is 500 round trips.
    p = .{ .app_packets = 1000, .rtt_ms = 20 };
    try testing.expectEqual(@as(u64, 2), p.packetsPerRtt(10_000));

    // Less than one round trip still counts as one.
    p = .{ .app_packets = 8, .rtt_ms = 20 };
    try testing.expectEqual(@as(u64, 8), p.packetsPerRtt(5));
}
