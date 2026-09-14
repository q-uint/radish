//! One endpoint: a UDP socket, the timers a connection runs on, and the
//! connection state it drives.
//!
//! Every buffer lives in the struct and is pointed at by the connection, so an
//! `Endpoint` must be initialized where it will stay, never returned by value.
const std = @import("std");

const dial = @import("../net/dial.zig");
const connection = @import("connection.zig");
const packet = @import("packet.zig");
const profile = @import("profile.zig");
const recovery = @import("recovery.zig");
const stream = @import("stream.zig");
const tls = @import("tls.zig");

const Ed25519 = std.crypto.sign.Ed25519;

pub const Error = error{
    NoReply,
    DatagramTooLarge,
    SendStalled,
    HandshakeUnconfirmed,
    /// A server's first datagram was something other than a client opening a
    /// connection.
    NotInitial,
} || connection.Error;

/// Where the connection reads time. A test supplies its own so a timer can be
/// driven to expiry without waiting for it.
pub const Clock = union(enum) {
    /// The monotonic system clock.
    awake,
    /// Milliseconds, moved by whoever owns the value.
    fixed: *const u64,

    pub fn nowMs(self: Clock, io: std.Io) u64 {
        return switch (self) {
            .awake => ms(std.Io.Timestamp.now(io, .awake)),
            .fixed => |at| at.*,
        };
    }

    fn ms(t: std.Io.Timestamp) u64 {
        // Clamped: the epoch is unspecified, and a negative timestamp would
        // otherwise be a panic rather than an early one.
        return @intCast(@max(0, @divTrunc(t.nanoseconds, std.time.ns_per_ms)));
    }
};

/// The buffers one connection holds, owned by the caller so it picks the
/// sizes. `stream` dominates and is the window we advertise, which a server
/// keeping many connections sets far below what a fetch wants.
pub const Buffers = struct {
    /// The peer's CRYPTO stream in each space. A ServerHello is small; a
    /// handshake flight carries a certificate.
    initial_crypto: []u8,
    handshake_crypto: []u8,
    /// What the peer may send us, and so the window we advertise.
    stream: []u8,
    /// What we have outstanding until it is acknowledged.
    send: []u8,
    /// Our hello and our flight, kept for retransmitting them.
    hello: []u8,
    messages: []u8,
    /// A datagram as it arrived, the copy decryption works on, and where the
    /// plaintext lands.
    datagram: []u8,
    work: []u8,
    plain: []u8,
};

const send_len = stream.Sender.max_chunks * connection.max_stream_chunk;

/// Inline storage for one connection, sized by the window it offers.
pub fn Storage(comptime window: usize) type {
    return struct {
        initial_crypto: [4 * 1024]u8 = undefined,
        handshake_crypto: [16 * 1024]u8 = undefined,
        stream: [window]u8 = undefined,
        send: [send_len]u8 = undefined,
        hello: [connection.max_client_hello]u8 = undefined,
        messages: [connection.max_flight]u8 = undefined,
        datagram: [connection.max_receive_datagram]u8 = undefined,
        work: [connection.max_receive_datagram]u8 = undefined,
        plain: [connection.max_receive_datagram]u8 = undefined,

        pub fn buffers(self: *@This()) Buffers {
            return .{
                .initial_crypto = &self.initial_crypto,
                .handshake_crypto = &self.handshake_crypto,
                .stream = &self.stream,
                .send = &self.send,
                .hello = &self.hello,
                .messages = &self.messages,
                .datagram = &self.datagram,
                .work = &self.work,
                .plain = &self.plain,
            };
        }
    };
}

/// What a client fetching at full speed wants.
pub const DefaultStorage = Storage(connection.default_window);

pub const Options = struct {
    /// Where to dial, or where to bind when serving.
    host: []const u8,
    port: u16,
    /// The one protocol a client offers. A server names what it will take in
    /// `alpns` instead.
    alpn: []const u8 = "",
    /// What a server accepts from a ClientHello's list, preferred first.
    alpns: []const []const u8 = &.{},
    /// Where the connection keeps everything, which sizes its window.
    bufs: Buffers,
    /// The x25519 secret behind our key share.
    secret: tls.SecretKey,
    /// The random in whichever hello we write.
    random: [32]u8,
    /// The connection id a client opens with, which pins both ends' Initial
    /// keys. A server takes that id off the packet and gives `scid` for
    /// itself.
    dcid: []const u8 = &.{},
    scid: []const u8 = &.{},
    /// Signs our half of mutual authentication, and is the node id the peer
    /// sees us as.
    identity: Ed25519.KeyPair,
    server_name: ?[]const u8 = null,
    /// How often the connection hands control back, whatever the timers say.
    timeout_ms: u64 = 3000,
    /// Datagrams to read before giving up on whatever we are waiting for.
    max_datagrams: usize = 6,
    /// Consecutive probe timeouts before the connection is written off. Each
    /// waits twice as long, so this is seconds, not the whole idle timeout.
    /// Source: RFC 9002 s6.2.1.
    max_retries: usize = 2,
    clock: Clock = .awake,
    /// Where to write every datagram that arrives, as hex, one per line. For
    /// recording an exchange as a test fixture.
    capture: ?*std.Io.Writer = null,
};

pub const Endpoint = struct {
    io: std.Io,
    sock: std.Io.net.Socket,
    addr: std.Io.net.IpAddress,
    opts: Options,
    conn: connection.Connection,

    /// The ClientHello as sent, for retransmitting it.
    hello: []const u8 = &.{},
    /// Our handshake flight, for the same reason.
    flight: ?[]const u8 = null,
    flight_out: bool = false,
    /// The clock as of this turn, which every deadline below is measured
    /// against. Refreshed whenever the connection acts.
    now_ms: u64 = 0,
    /// When a datagram last opened, which the idle timeout runs from.
    last_arrival_ms: u64 = 0,
    /// When the stream last moved. A peer that answers but sends nothing keeps
    /// the connection alive, so only this notices a stuck transfer.
    last_stream_ms: u64 = 0,
    /// When the connection opened, which the profile measures from.
    opened_ms: u64 = 0,
    /// When we last sent a keepalive, which does not count as being busy.
    last_ping_ms: u64 = 0,

    /// Bytes in the Initial datagram, and what has come back since.
    sent: usize = 0,
    received: usize = 0,
    datagrams: usize = 0,
    /// The last datagram as it arrived, for recording as a fixture.
    last: []const u8 = &.{},
    /// The most recent failure that did not end the connection.
    last_err: ?anyerror = null,
    /// Whether `hs` holds anything: `open` leaves it undefined until it gets
    /// that far, so nothing may read it before this says so. It stays set
    /// through a close, since the reason the peer gave is still worth telling.
    ready: bool = false,
    /// Whether `sock` is still ours to send on and close.
    sock_open: bool = false,
    /// Counters for the connection, filled whether or not anyone reads them.
    profile: profile.Profile = .{},

    /// Where the connection holds everything, which the caller owns and sized.
    bufs: Buffers,

    /// Binds a socket and sends the first flight. `self` must already be where
    /// it will live, and may hold anything: every field is set here, since a
    /// caller that allocated the struct never ran the field defaults.
    pub fn open(self: *Endpoint, io: std.Io, opts: Options) !void {
        self.* = .{
            .io = io,
            .opts = opts,
            .bufs = opts.bufs,
            .sock = undefined,
            .addr = undefined,
            .conn = undefined,
        };
        const kp = try std.crypto.dh.X25519.KeyPair.generateDeterministic(opts.secret);

        var datagram: [connection.max_initial_datagram]u8 = undefined;
        const initial = try connection.initialDatagram(&datagram, self.bufs.hello, .{
            .dcid = opts.dcid,
            .scid = opts.dcid,
            .random = opts.random,
            .public_key = kp.public_key,
            .alpn = opts.alpn,
            .server_name = opts.server_name,
            .window = self.bufs.stream.len,
        });

        self.addr = try dial.resolve(io, opts.host, opts.port);
        // Bind a wildcard of the same family, since sending needs a local
        // socket.
        var local = switch (self.addr) {
            .ip4 => try std.Io.net.IpAddress.resolve(io, "0.0.0.0", 0),
            .ip6 => try std.Io.net.IpAddress.resolve(io, "::", 0),
        };

        self.sock = try local.bind(io, .{ .mode = .dgram });
        self.hello = initial.hello;
        self.sent = initial.len;
        self.now_ms = opts.clock.nowMs(io);
        self.last_arrival_ms = self.now_ms;
        self.last_stream_ms = self.now_ms;
        self.opened_ms = self.now_ms;
        self.conn = connection.Connection.init(.{
            .original_dcid = opts.dcid,
            .our_scid = opts.dcid,
            .client_hello = initial.hello,
            .secret = opts.secret,
            .initial_buf = self.bufs.initial_crypto,
            .handshake_buf = self.bufs.handshake_crypto,
            .stream_buf = self.bufs.stream,
            .send_buf = self.bufs.send,
            .window = self.bufs.stream.len,
        });
        // Both fields hold something from here on, whatever the send does.
        self.ready = true;
        self.sock_open = true;
        self.conn.now_ms = self.now_ms;
        self.conn.profile = &self.profile;
        // The ClientHello is packet 0 of the Initial space and carries CRYPTO,
        // so it is what the first probe timeout waits on.
        self.conn.recovery.onSent(.initial, 0, initial.len, self.now_ms);

        try self.sendDatagram(datagram[0..initial.len]);
    }

    /// Binds and answers one client, leaving `service` to drive the rest as it
    /// does for a client. Whoever arrives first has the socket: serving more at
    /// once needs a lookup by connection id, which is not built.
    pub fn serve(self: *Endpoint, io: std.Io, opts: Options) !void {
        try self.bind(io, opts);
        try self.accept();
    }

    /// Takes the port, so a caller can be reachable before it accepts. Leaves
    /// the connection undefined until `accept` builds one, which `ready` says.
    pub fn bind(self: *Endpoint, io: std.Io, opts: Options) !void {
        self.* = .{
            .io = io,
            .opts = opts,
            .bufs = opts.bufs,
            .sock = undefined,
            .addr = undefined,
            .conn = undefined,
        };
        var local = try std.Io.net.IpAddress.resolve(io, opts.host, opts.port);
        self.sock = try local.bind(io, .{ .mode = .dgram });
        self.sock_open = true;
    }

    pub fn boundPort(self: *const Endpoint) u16 {
        return self.sock.address.getPort();
    }

    /// Waits for a client's Initial and answers it.
    pub fn accept(self: *Endpoint) !void {
        const io = self.io;
        const opts = self.opts;
        const got = try self.sock.receiveTimeout(io, self.bufs.datagram, .{ .duration = .{
            .raw = .fromNanoseconds(@intCast(opts.timeout_ms * std.time.ns_per_ms)),
            .clock = .awake,
        } });
        // Whoever wrote to us is who we answer. A later datagram from
        // elsewhere is migration, which takes a challenge first.
        // Source: RFC 9000 s9.
        self.addr = got.from;
        self.datagrams = 1;
        self.received = got.data.len;
        self.profile.datagrams_in += 1;
        self.profile.bytes_in += got.data.len;

        // The id the client addressed, which both ends' Initial keys come
        // from. Source: RFC 9001 s5.2.
        const hdr = try packet.parseLongHeader(got.data);
        if (hdr.kind != .initial) return error.NotInitial;

        self.now_ms = opts.clock.nowMs(io);
        self.last_arrival_ms = self.now_ms;
        self.last_stream_ms = self.now_ms;
        self.opened_ms = self.now_ms;
        self.conn = connection.Connection.init(.{
            .role = .server,
            .original_dcid = hdr.dcid,
            .our_scid = opts.scid,
            // The transcript opens with the hello we are about to read.
            .client_hello = "",
            .alpns = opts.alpns,
            .secret = opts.secret,
            .initial_buf = self.bufs.initial_crypto,
            .handshake_buf = self.bufs.handshake_crypto,
            .stream_buf = self.bufs.stream,
            .send_buf = self.bufs.send,
            .window = self.bufs.stream.len,
        });
        self.ready = true;
        self.conn.now_ms = self.now_ms;
        self.conn.profile = &self.profile;

        // Decrypted on the copy, so `last` keeps it as it arrived.
        self.last = got.data;
        if (got.data.len > self.bufs.work.len) return error.DatagramTooLarge;
        @memcpy(self.bufs.work[0..got.data.len], got.data);
        try self.conn.push(self.bufs.plain, self.bufs.work[0..got.data.len]);

        var out: [connection.max_initial_datagram]u8 = undefined;
        const hello = try self.conn.sealServerHello(&out, self.bufs.hello, opts.random);
        self.hello = hello.hello;
        self.sent = hello.len;
        try self.sendDatagram(out[0..hello.len]);

        // The rest of our half, under the keys the ServerHello just made.
        // Written once: resending is `repair` sealing these bytes again.
        self.flight = try self.conn.writeFlight(self.bufs.messages, opts.identity);
        const n = try self.conn.sealFlight(&out, self.flight.?);
        self.sent += n;
        try self.sendDatagram(out[0..n]);
        self.flight_out = true;
    }

    /// Says goodbye before dropping the socket, so the peer releases the state
    /// it holds for us rather than waiting out its idle timeout. Best effort:
    /// there is nothing to do about a close that does not arrive, and a
    /// connection that never reached 1-RTT has no key to send one under.
    ///
    /// Safe to call on a connection that never opened, and safe to call twice,
    /// so a caller can defer it before the connection exists.
    pub fn close(self: *Endpoint) void {
        if (!self.sock_open) return;
        self.sock_open = false;
        // A peer that reset us holds nothing to release, and would answer a
        // goodbye with another reset.
        // Source: RFC 9000 s10.3.
        // `bind` leaves the connection undefined, so a socket can outlive a
        // failed accept with nothing to say goodbye with.
        if (self.ready and self.conn.app_keys != null and self.conn.closed == null and
            !self.conn.stateless_reset)
        {
            var out: [connection.max_initial_datagram]u8 = undefined;
            if (self.conn.sealClose(&out, "done") catch null) |n| {
                self.sendDatagram(out[0..n]) catch {};
            }
        }
        self.sock.close(self.io);
    }

    /// Why the peer closed, or null when it did not or the connection never got
    /// far enough to hear it.
    pub fn peerClose(self: *const Endpoint) ?*const connection.Close {
        if (!self.ready) return null;
        if (self.conn.closed) |*reason| return reason;
        return null;
    }

    /// What one turn of the connection produced.
    pub const Serviced = enum {
        /// A datagram arrived and was handled.
        arrived,
        /// The peer sent CONNECTION_CLOSE; `hs.closed` says why.
        closed,
        /// Nothing arrived, and there is nothing left to resend.
        silent,
    };

    /// Opens a connection and drives the handshake to confirmation, which is
    /// where every exchange over it starts.
    pub fn establish(self: *Endpoint, io: std.Io, opts: Options) !void {
        try self.open(io, opts);
        errdefer self.close();
        try self.handshake();
        if (!self.conn.confirmed) return error.HandshakeUnconfirmed;
    }

    /// Reads datagrams until the handshake is confirmed, the peer closes, or
    /// the datagram budget runs out.
    pub fn handshake(self: *Endpoint) !void {
        while (self.datagrams < self.opts.max_datagrams) {
            if (try self.service() != .arrived) break;
            if (self.conn.confirmed) return;
        }
        if (self.datagrams == 0) return error.NoReply;
    }

    /// One datagram in, and whatever it obliges us to send back out.
    pub fn service(self: *Endpoint) !Serviced {
        const arrived = self.receive() orelse {
            self.profile.silent += 1;
            return .silent;
        };
        self.datagrams += 1;
        self.received += arrived.len;
        self.profile.datagrams_in += 1;
        self.profile.bytes_in += arrived.len;
        self.last = arrived;
        self.now_ms = self.opts.clock.nowMs(self.io);
        self.conn.now_ms = self.now_ms;
        if (self.opts.capture) |w| {
            w.print("{x}\n", .{arrived}) catch {};
            w.flush() catch {};
        }

        // The furthest byte the peer has sent, not what the reader has taken:
        // this is about the transfer moving, not about who is draining it.
        const before = self.conn.stream.highest;
        if (arrived.len > self.bufs.work.len) {
            self.last_err = error.DatagramTooLarge;
        } else {
            @memcpy(self.bufs.work[0..arrived.len], arrived);
            if (self.conn.push(self.bufs.plain, self.bufs.work[0..arrived.len])) {
                // Only a datagram that opened counts as the peer still being
                // there. Anything can be sent at us, and garbage that reset the
                // idle timeout would hold the connection open forever.
                // Source: RFC 9000 s10.1.
                self.last_arrival_ms = self.now_ms;
                // Whatever went wrong before this is not what a later stall is
                // about, and reporting it there points at the wrong thing.
                self.last_err = null;
            } else |e| {
                self.last_err = e;
                self.profile.unopened += 1;
                // A close is the end of the connection, so reading on would
                // only overwrite the reason with the next datagram. A stateless
                // reset is the same ending without the courtesy.
                if (e == error.PeerClosed or e == error.StatelessReset) return .closed;
            }
        }
        if (self.conn.stream.highest != before) self.last_stream_ms = self.now_ms;

        // Acknowledge before reading on: an unacknowledged flight makes the
        // peer retransmit it, and the ACK is what ends that.
        var out: [connection.max_initial_datagram]u8 = undefined;
        for ([_]packet.Space{ .initial, .handshake, .application }) |space| {
            const n = try self.conn.sealAck(&out, space) orelse continue;
            self.sendDatagram(out[0..n]) catch {};
        }

        // Both need 1-RTT keys, so there is nothing owed until they exist.
        if (self.conn.app_keys != null) {
            if (try self.conn.sealPathResponse(&out)) |n| {
                self.sendDatagram(out[0..n]) catch {};
            }
            if (try self.conn.sealMaxData(&out)) |n| {
                self.sendDatagram(out[0..n]) catch {};
            }
            // A server's to send, once its handshake completes and again if
            // the frame is lost. Source: RFC 9001 s4.1.2.
            if (try self.conn.sealHandshakeDone(&out)) |n| {
                self.sendDatagram(out[0..n]) catch {};
            }
        }

        // The peer's Finished checks out, so our own flight can go: it waits
        // for that before confirming the handshake. Writing the flight advances
        // the transcript, so there is one attempt at it and no more, whatever
        // happens to the packet.
        if (self.conn.done() and !self.conn.flight_sent) send: {
            self.flight = self.conn.writeFlight(self.bufs.messages, self.opts.identity) catch |e| {
                self.last_err = e;
                break :send;
            };
            const n = self.conn.sealFlight(&out, self.flight.?) catch |e| {
                self.last_err = e;
                break :send;
            };
            self.sendDatagram(out[0..n]) catch |e| {
                self.last_err = e;
                break :send;
            };
            self.flight_out = true;
        }

        // An ACK can reveal that something earlier never landed. Repairing it
        // now beats waiting for a timer that is only there for silence.
        if (self.conn.takeLost()) _ = self.repair(&out, false);
        return .arrived;
    }

    /// Waits for a datagram, doing what the clock owes while nothing comes.
    /// Null when there is nothing left to wait for, or once a tick has gone by
    /// so the caller can look around.
    fn receive(self: *Endpoint) ?[]const u8 {
        const started = self.opts.clock.nowMs(self.io);
        while (true) {
            self.now_ms = self.opts.clock.nowMs(self.io);
            const wait_ms = self.waitMs();
            if (wait_ms > 0) {
                const asked = std.Io.Timestamp.now(self.io, .awake);
                if (self.sock.receiveTimeout(self.io, self.bufs.datagram, .{ .duration = .{
                    .raw = .fromNanoseconds(@intCast(wait_ms * std.time.ns_per_ms)),
                    .clock = .awake,
                } })) |got| {
                    const waited = std.Io.Timestamp.now(self.io, .awake).nanoseconds -| asked.nanoseconds;
                    self.profile.waited_ns += @intCast(@max(0, waited));
                    if (waited < std.time.ns_per_us) self.profile.ready += 1;
                    return got.data;
                } else |e| switch (e) {
                    // The wait ran out, so whatever the timer was for is due.
                    error.Timeout => {},
                    // Retrying a broken socket spins until the idle timeout.
                    else => {
                        self.last_err = e;
                        return null;
                    },
                }
                self.now_ms = self.opts.clock.nowMs(self.io);
            }
            if (!self.onTimeout()) return null;
            if (self.now_ms -| started >= self.opts.timeout_ms) return null;
        }
    }

    /// How long to sit in the next read: until the earliest thing owed, and
    /// never past one tick.
    fn waitMs(self: *const Endpoint) u64 {
        var wait = self.opts.timeout_ms;
        if (self.conn.recovery.timer()) |t| wait = @min(wait, t.afterMs(self.now_ms));
        // An ACK held back for a second packet that never comes still has to
        // go before the peer's patience runs out.
        if (self.conn.ackDeadlineMs()) |at| wait = @min(wait, at -| self.now_ms);

        // Deadlines too, so neither rests on a tick being shorter than they are.
        const idle = self.conn.idleTimeoutMs();
        const quiet = self.now_ms -| self.last_arrival_ms;
        wait = @min(wait, idle -| quiet);
        if (self.conn.app_keys != null) {
            const since_ping = self.now_ms -| @max(self.last_arrival_ms, self.last_ping_ms);
            wait = @min(wait, (idle / 2) -| since_ping);
        }
        return wait;
    }

    /// The recovery timer, if it is already due.
    fn due(self: *const Endpoint) ?recovery.Timer {
        const t = self.conn.recovery.timer() orelse return null;
        return if (t.afterMs(self.now_ms) == 0) t else null;
    }

    /// Acts on the silence so far. False when the connection is finished with:
    /// the peer has stopped answering, or probing has run out of attempts.
    /// Source: RFC 9002 s6.1.2, s6.2.4.
    fn onTimeout(self: *Endpoint) bool {
        self.now_ms = self.opts.clock.nowMs(self.io);
        self.conn.now_ms = self.now_ms;
        // Past the idle timeout there is nothing left to resend to.
        if (self.stalled()) return false;

        var out: [connection.max_initial_datagram]u8 = undefined;
        // Whatever else the silence means, an ACK that has run out of time
        // goes first: no datagram is coming to carry it.
        if (self.conn.sealAck(&out, .application) catch null) |n| {
            self.sendDatagram(out[0..n]) catch {};
            return true;
        }
        if (self.due()) |t| {
            switch (t.kind) {
                // The reordering window passed, so what it held open is lost.
                .loss => _ = self.conn.recovery.onLossTimer(t.space, self.now_ms),
                // Nothing acknowledged for a whole probe timeout. A run of
                // them means the peer is not there.
                .probe => {
                    self.conn.recovery.onProbe();
                    if (self.conn.recovery.backoff > self.opts.max_retries) return false;
                },
            }
            if (self.repair(&out, t.kind == .probe)) return true;
        }
        _ = self.keepalive(&out);
        return true;
    }

    /// Sends whatever is outstanding again under a fresh packet number, and
    /// whether anything was. `probing` must put something on the wire even if
    /// all of it has already been tried.
    /// Source: RFC 9000 s13.3, RFC 9002 s6.2.4.
    fn repair(self: *Endpoint, out: []u8, probing: bool) bool {
        if (self.conn.confirmed) {
            self.now_ms = self.opts.clock.nowMs(self.io);
            self.conn.now_ms = self.now_ms;
            // A burst of loss in one go rather than a chunk per timeout. Each
            // chunk goes at most once per acknowledgement, so this ends.
            var sent = false;
            for (0..stream.Sender.max_chunks) |_| {
                if (!self.conn.recovery.canSend(connection.min_initial_datagram)) break;
                const n = self.conn.resendStream(out, false) catch null orelse break;
                if (!self.emit(out[0..n])) break;
                sent = true;
            }
            if (sent) return true;
            // Nothing fresh to repair. A probe still has to carry something,
            // so the oldest goes again. A probe may exceed the window.
            // Source: RFC 9002 s7.5.
            if (!probing) return false;
            const n = self.conn.resendStream(out, true) catch null orelse return false;
            return self.emit(out[0..n]);
        }
        if (self.flight) |f| {
            const n = self.conn.sealFlight(out, f) catch null orelse return false;
            return self.emit(out[0..n]);
        }
        // An acknowledged Initial arrived, so silence is about something else
        // and resending would only add noise.
        if (self.conn.acked(.initial).contains(0)) return false;
        const n = self.conn.sealInitialRetransmit(out, self.hello) catch null orelse return false;
        return self.emit(out[0..n]);
    }

    /// A PING once the connection has been quiet for half of what the peer will
    /// put up with, which leaves room for a second before it gives up on us.
    /// Whether one went out.
    /// Source: RFC 9000 s10.1.
    fn keepalive(self: *Endpoint, out: []u8) bool {
        if (self.conn.app_keys == null) return false;
        const since = self.now_ms -| @max(self.last_arrival_ms, self.last_ping_ms);
        if (since < self.conn.idleTimeoutMs() / 2) return false;
        self.last_ping_ms = self.now_ms;
        const n = self.conn.sealPing(out) catch null orelse return false;
        return self.emit(out[0..n]);
    }

    fn emit(self: *Endpoint, datagram: []const u8) bool {
        self.sendDatagram(datagram) catch return false;
        return true;
    }

    /// Every datagram leaves through here, so the counters see all of them.
    fn sendDatagram(self: *Endpoint, datagram: []const u8) !void {
        try self.sock.send(self.io, &self.addr, datagram);
        self.profile.datagrams_out += 1;
        self.profile.bytes_out += datagram.len;
    }

    /// Sends `data` on the stream, split across as many packets as it takes.
    /// Blocks on the peer whenever its window or our unacknowledged data leaves
    /// no room, since only an ACK or a MAX_DATA can make more.
    ///
    /// The loop runs at least once so that empty `data` with `fin` set closes
    /// the stream on its own.
    pub fn send(self: *Endpoint, data: []const u8, fin: bool) !void {
        var rest = data;
        while (true) {
            const room = @min(
                connection.max_stream_chunk,
                @min(self.conn.sendRoom(), self.conn.sender.room()),
            );
            // The peer's windows say what it will hold. The congestion window
            // says what the path will carry, counted as a whole datagram,
            // since that is what goes out and what the window is measured in.
            // Source: RFC 9002 s7.
            if (room == 0 or !self.conn.recovery.canSend(connection.min_initial_datagram)) {
                switch (try self.service()) {
                    .arrived => {},
                    // A peer that has closed will never take more, so the room
                    // we are waiting for is not coming.
                    .closed => return if (self.wasReset()) error.StatelessReset else error.PeerClosed,
                    .silent => return error.SendStalled,
                }
                continue;
            }

            const take = @min(rest.len, room);
            var out: [connection.max_initial_datagram]u8 = undefined;
            // Stamped with the clock as of now: what a packet is sent at is
            // what its round trip is later measured against.
            self.now_ms = self.opts.clock.nowMs(self.io);
            self.conn.now_ms = self.now_ms;
            const n = try self.conn.sealStream(&out, rest[0..take], fin and take == rest.len);
            try self.sendDatagram(out[0..n]);

            rest = rest[take..];
            if (rest.len == 0) return;
        }
    }

    /// Stream bytes in order and not yet consumed.
    pub fn readable(self: *const Endpoint) []const u8 {
        return self.conn.stream.readable();
    }

    /// Whether the peer has finished its half of the stream and all of it has
    /// been read. Not `connection.Connection.done`, which is about the
    /// handshake.
    pub fn streamDone(self: *const Endpoint) bool {
        return self.conn.stream.done();
    }

    /// Whether the peer abandoned its half of the stream.
    pub fn streamReset(self: *const Endpoint) bool {
        return self.ready and self.conn.stream.reset;
    }

    /// Whether the peer proved it has thrown away this connection. Nothing more
    /// can be sent on it, not even a goodbye.
    /// Source: RFC 9000 s10.3.
    pub fn wasReset(self: *const Endpoint) bool {
        return self.ready and self.conn.stateless_reset;
    }

    /// Whether the silence has run past what the peer said it would wait, at
    /// which point it has dropped us and nothing more is coming.
    pub fn stalled(self: *const Endpoint) bool {
        return self.ready and self.now_ms -| self.last_arrival_ms >= self.conn.idleTimeoutMs();
    }

    /// Whether the stream has stopped moving for as long as the peer would
    /// wait, which is a transfer that will not finish even though the
    /// connection is alive: a peer blocked on something it will not get keeps
    /// pinging, so `stalled` never fires on its own.
    pub fn streamStalled(self: *const Endpoint) bool {
        return self.ready and self.now_ms -| self.last_stream_ms >= self.conn.idleTimeoutMs();
    }

    /// What the last datagram went wrong with. `service` records these rather
    /// than raising them, since one unreadable datagram is not the end of the
    /// connection. A stall afterwards usually has its reason here.
    pub fn lastError(self: *const Endpoint) ?anyerror {
        return self.last_err;
    }

    /// Whether the handshake got all the way to confirmation.
    pub fn confirmed(self: *const Endpoint) bool {
        return self.ready and self.conn.confirmed;
    }

    /// What the peer told us about itself, or null before there is a handshake
    /// to have told us anything.
    pub fn accepted(self: *const Endpoint) ?*const connection.Accepted {
        if (!self.ready) return null;
        return &self.conn.accepted;
    }

    /// The counters, with the round trip and window folded in as they stand.
    pub fn profiled(self: *Endpoint) *const profile.Profile {
        if (self.ready) {
            self.profile.rtt_ms = self.conn.recovery.rtt.smoothed_ms;
            self.profile.cwnd = self.conn.recovery.cc.window;
        }
        // When the bytes stopped arriving, which is the transfer whether the
        // peer ended it with a FIN or by closing the connection.
        self.profile.pack_ms = self.last_stream_ms -| self.opened_ms;
        return &self.profile;
    }

    pub fn consume(self: *Endpoint, n: usize) void {
        self.conn.stream.consume(n);
    }
};

const testing = std.testing;
const crypto = @import("crypto.zig");
const testdata = @import("testdata.zig");

test "opening sets every field, whatever the memory held" {
    const c = try testing.allocator.create(Endpoint);
    defer testing.allocator.destroy(c);
    const s = try testing.allocator.create(DefaultStorage);
    defer testing.allocator.destroy(s);
    // What an allocator hands back is not zeroed, and field defaults do not run
    // for it, so `open` has to write everything itself.
    @memset(std.mem.asBytes(c), 0xaa);

    try c.open(testing.io, .{
        .host = "127.0.0.1",
        // Discard: the Initial goes out and nothing answers, which is all this
        // needs. `handshake` is what would wait for a reply.
        .port = 9,
        .alpn = "radicle/gossip/1",
        .bufs = s.buffers(),
        .secret = testdata.hex(testdata.fixed_x25519_secret),
        .random = testdata.hex(testdata.fixed_hello_random),
        .dcid = &.{ 0xc0, 0xff, 0xee, 0x01 },
        .identity = try Ed25519.KeyPair.generateDeterministic(testdata.hex(testdata.fixed_identity_seed)),
    });
    defer c.close();

    try testing.expectEqual(connection.min_initial_datagram, c.sent);
    try testing.expectEqual(@as(usize, 0), c.datagrams);
    try testing.expectEqual(@as(usize, 0), c.received);
    try testing.expectEqual(@as(?anyerror, null), c.last_err);
    try testing.expectEqual(@as(usize, 0), c.last.len);
    try testing.expect(!c.flight_out);
    try testing.expect(!c.conn.confirmed);
}

test "closing is safe however far opening got, and sends one goodbye at most" {
    const unopened = try testing.allocator.create(Endpoint);
    defer testing.allocator.destroy(unopened);
    const s = try testing.allocator.create(DefaultStorage);
    defer testing.allocator.destroy(s);
    @memset(std.mem.asBytes(unopened), 0xaa);

    // Rejected before the socket or the connection exist, so both still hold
    // whatever the allocator handed back.
    try testing.expectError(error.InvalidHostName, unopened.open(testing.io, .{
        .host = "not a host",
        .port = 8776,
        .alpn = "radicle/gossip/1",
        .bufs = s.buffers(),
        .secret = testdata.hex(testdata.fixed_x25519_secret),
        .random = testdata.hex(testdata.fixed_hello_random),
        .dcid = &.{ 0xc0, 0xff, 0xee, 0x03 },
        .identity = try Ed25519.KeyPair.generateDeterministic(testdata.hex(testdata.fixed_identity_seed)),
    }));
    try testing.expect(!unopened.ready);
    try testing.expectEqual(@as(?*const connection.Close, null), unopened.peerClose());
    unopened.close();

    const c = try testing.allocator.create(Endpoint);
    defer testing.allocator.destroy(c);
    // Its own, since two connections sharing buffers would tread on each other.
    const cs = try testing.allocator.create(DefaultStorage);
    defer testing.allocator.destroy(cs);
    @memset(std.mem.asBytes(c), 0xaa);

    try c.open(testing.io, .{
        .host = "127.0.0.1",
        .port = 9,
        .alpn = "radicle/gossip/1",
        .bufs = cs.buffers(),
        .secret = testdata.hex(testdata.fixed_x25519_secret),
        .random = testdata.hex(testdata.fixed_hello_random),
        .dcid = &.{ 0xc0, 0xff, 0xee, 0x04 },
        .identity = try Ed25519.KeyPair.generateDeterministic(testdata.hex(testdata.fixed_identity_seed)),
    });
    try testing.expect(c.sock_open);

    c.close();
    try testing.expect(!c.sock_open);
    // An `errdefer` inside the connection and a `defer` at the call site both
    // fire on the same failure, so the second one has to be a no-op rather
    // than a second goodbye on a closed socket.
    c.close();
    // Still readable afterwards: the reason a peer gave outlives the socket.
    try testing.expect(c.ready);
}

/// A connection on a clock the test moves, with the state a finished handshake
/// would have left: keys, confirmation, and nothing outstanding, since what the
/// handshake sent stops being tracked once it completes.
fn clocked(c: *Endpoint, s: *DefaultStorage, dcid: []const u8, at: *const u64) !void {
    @memset(std.mem.asBytes(c), 0xaa);
    try c.open(testing.io, .{
        .host = "127.0.0.1",
        // Discard: what goes out is not the point, only what the clock makes
        // the connection do about it.
        .port = 9,
        .alpn = "radicle/git/1",
        .bufs = s.buffers(),
        .secret = testdata.hex(testdata.fixed_x25519_secret),
        .random = testdata.hex(testdata.fixed_hello_random),
        .dcid = dcid,
        .identity = try Ed25519.KeyPair.generateDeterministic(testdata.hex(testdata.fixed_identity_seed)),
        .clock = .{ .fixed = at },
    });
    const keys = crypto.keysFromSecret(crypto.initialSecrets(dcid).client);
    c.conn.app_keys = .{ .send = keys, .recv = keys };
    c.conn.confirmed = true;
    c.conn.recovery.confirmed = true;
    c.conn.recovery.discard(.initial);
}

test "a quiet connection is held open by halves, then given up at the idle timeout" {
    const dcid = [_]u8{ 0xc0, 0xff, 0xee, 0x02 };
    const c = try testing.allocator.create(Endpoint);
    defer testing.allocator.destroy(c);
    const s = try testing.allocator.create(DefaultStorage);
    defer testing.allocator.destroy(s);

    var at: u64 = 1_000_000;
    try clocked(c, s, &dcid, &at);
    defer c.close();

    const idle = c.conn.idleTimeoutMs();
    const opened = at;

    // Just short of half the timeout, nothing is owed.
    at = opened + idle / 2 - 1;
    try testing.expect(c.onTimeout());
    try testing.expectEqual(@as(u64, 0), c.last_ping_ms);

    // Past it, a keepalive goes out. Being ack-eliciting, it is itself now
    // something the connection is waiting on.
    at = opened + idle / 2 + 1;
    try testing.expect(c.onTimeout());
    try testing.expectEqual(at, c.last_ping_ms);
    try testing.expectEqual(@as(usize, 1), c.conn.recovery.tracker(.application).count);

    // A keepalive does not count as the connection being busy, so the silence
    // still runs out on schedule. `stalled` reads the clock as the connection
    // last saw it, so it answers for the turn `onTimeout` just took.
    at = opened + idle;
    try testing.expect(!c.onTimeout());
    try testing.expect(c.stalled());
}

test "a peer that stops answering is written off after a run of probes" {
    const dcid = [_]u8{ 0xc0, 0xff, 0xee, 0x05 };
    const c = try testing.allocator.create(Endpoint);
    defer testing.allocator.destroy(c);
    const s = try testing.allocator.create(DefaultStorage);
    defer testing.allocator.destroy(s);

    var at: u64 = 1_000_000;
    try clocked(c, s, &dcid, &at);
    defer c.close();

    // One ack-eliciting packet outstanding, which is what a probe is about.
    var out: [connection.max_initial_datagram]u8 = undefined;
    _ = try c.conn.sealPing(&out);

    // Jump to each timeout as it comes due. Every probe doubles the wait, so
    // this is seconds of silence rather than the full idle timeout.
    var probes: usize = 0;
    while (c.conn.recovery.timer()) |t| {
        at = t.at_ms;
        if (!c.onTimeout()) break;
        probes += 1;
        try testing.expect(probes < 10);
    }
    // Each expiry probes. The one after the budget is spent gives up instead.
    try testing.expectEqual(c.opts.max_retries, probes);
    try testing.expect(!c.stalled());
    try testing.expect(at - 1_000_000 < c.conn.idleTimeoutMs());
}

/// A server slot, which offers far less than a client fetching a packfile.
const ServerStorage = Storage(64 * 1024);

/// Services one side until nothing is waiting for it.
fn drain(e: *Endpoint) !void {
    while (try e.service() == .arrived) {}
}

test "a client and our own server handshake over a socket" {
    const io = testing.io;
    const client = try testing.allocator.create(Endpoint);
    defer testing.allocator.destroy(client);
    const server = try testing.allocator.create(Endpoint);
    defer testing.allocator.destroy(server);
    const client_bufs = try testing.allocator.create(DefaultStorage);
    defer testing.allocator.destroy(client_bufs);
    const server_bufs = try testing.allocator.create(ServerStorage);
    defer testing.allocator.destroy(server_bufs);

    const client_key = try Ed25519.KeyPair.generateDeterministic(
        testdata.hex(testdata.fixed_identity_seed),
    );
    const server_key = try Ed25519.KeyPair.generateDeterministic(
        testdata.hex(testdata.fixed_peer_identity_seed),
    );

    // Bound before anything dials it, so the port is known and the client's
    // Initial is waiting by the time `accept` looks.
    try server.bind(io, .{
        .host = "127.0.0.1",
        .port = 0,
        .alpns = &.{ "radicle/gossip/1", "radicle/git/1" },
        .bufs = server_bufs.buffers(),
        .secret = testdata.hex(testdata.fixed_server_x25519_secret),
        .random = testdata.hex(testdata.fixed_server_hello_random),
        .scid = &.{ 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x01 },
        .identity = server_key,
        .timeout_ms = 100,
    });
    defer server.close();

    try client.open(io, .{
        .host = "127.0.0.1",
        .port = server.boundPort(),
        .alpn = "radicle/git/1",
        .bufs = client_bufs.buffers(),
        .secret = testdata.hex(testdata.fixed_x25519_secret),
        .random = testdata.hex(testdata.fixed_hello_random),
        .dcid = &.{ 0xc0, 0xff, 0xee, 0x06, 0x00, 0x00, 0x00, 0x01 },
        .identity = client_key,
        .timeout_ms = 100,
    });
    defer client.close();

    try server.accept();
    // One turn each until both are finished: the client reads the server's
    // half and answers, the server confirms and says so.
    try drain(client);
    try drain(server);
    try drain(client);

    try testing.expect(client.conn.confirmed);
    try testing.expect(server.conn.confirmed);
    try testing.expectEqualSlices(
        u8,
        &server_key.public_key.toBytes(),
        &client.conn.accepted.peer_key.?,
    );
    try testing.expectEqualSlices(
        u8,
        &client_key.public_key.toBytes(),
        &server.conn.accepted.peer_key.?,
    );
    try testing.expectEqualStrings("radicle/git/1", client.conn.accepted.alpn());
    // The window is the server's buffer, not the default a client offers.
    try testing.expectEqual(@as(u64, server_bufs.stream.len), client.conn.send_stream.limit);
}
