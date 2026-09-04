//! A QUIC connection over a UDP socket: the handshake driven to completion,
//! then stream data.
//!
//! Every buffer lives in the struct and is pointed at by the handshaker, so a
//! `Conn` must be initialized where it will stay, never returned by value.
const std = @import("std");

const dial = @import("../net/dial.zig");
const client = @import("client.zig");
const stream = @import("stream.zig");
const tls = @import("tls.zig");

const Ed25519 = std.crypto.sign.Ed25519;

pub const Error = error{
    NoReply,
    DatagramTooLarge,
    SendStalled,
    HandshakeUnconfirmed,
} || client.Error;

pub const Options = struct {
    host: []const u8,
    port: u16,
    alpn: []const u8,
    /// The x25519 secret behind our key share.
    secret: tls.SecretKey,
    random: [32]u8,
    dcid: []const u8,
    /// Signs our half of mutual authentication, and is the node id the peer
    /// sees us as.
    identity: Ed25519.KeyPair,
    server_name: ?[]const u8 = null,
    timeout_ms: u64 = 3000,
    /// Datagrams to read before giving up on whatever we are waiting for.
    max_datagrams: usize = 6,
    /// Resends of an unacknowledged flight before giving up. Each flight has
    /// its own budget.
    max_retries: usize = 2,
    /// Where to write every datagram that arrives, as hex, one per line. For
    /// recording an exchange as a test fixture.
    capture: ?*std.Io.Writer = null,
};

pub const Conn = struct {
    io: std.Io,
    sock: std.Io.net.Socket,
    addr: std.Io.net.IpAddress,
    opts: Options,
    hs: client.Handshaker,

    /// The ClientHello as sent, for retransmitting it.
    hello: []const u8 = &.{},
    /// Our handshake flight, for the same reason.
    flight: ?[]const u8 = null,
    flight_out: bool = false,
    initial_retries: usize = 0,
    flight_retries: usize = 0,
    /// Consecutive resends of stream data, reset by anything arriving. A
    /// connection that lives on needs a budget that refills, unlike the
    /// handshake's one-shot ones.
    stream_retries: usize = 0,
    /// How long the connection has been quiet, counted in receive timeouts,
    /// which is the only clock this has.
    quiet_ms: u64 = 0,
    /// `quiet_ms` as of the last keepalive, so sending one does not erase the
    /// silence the idle timeout is measured against.
    pinged_ms: u64 = 0,

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

    /// The peer's CRYPTO stream in each space. A ServerHello is small; the
    /// handshake flight carries a certificate, so it gets room to spare.
    initial_crypto: [4 * 1024]u8 = undefined,
    handshake_crypto: [16 * 1024]u8 = undefined,
    stream_buf: [client.default_window]u8 = undefined,
    /// Everything the sender can have outstanding at once.
    send_buf: [stream.Sender.max_chunks * client.max_stream_chunk]u8 = undefined,
    hello_buf: [client.max_client_hello]u8 = undefined,
    messages: [client.max_flight]u8 = undefined,
    /// Received datagrams, and the copy decryption works on so `last` keeps the
    /// bytes as they arrived.
    datagram: [client.max_receive_datagram]u8 = undefined,
    work: [client.max_receive_datagram]u8 = undefined,
    plain: [client.max_receive_datagram]u8 = undefined,

    /// Binds a socket and sends the first flight. `self` must already be where
    /// it will live, and may hold anything: every field is set here, since a
    /// caller that allocated the struct never ran the field defaults.
    pub fn open(self: *Conn, io: std.Io, opts: Options) !void {
        self.* = .{
            .io = io,
            .opts = opts,
            .sock = undefined,
            .addr = undefined,
            .hs = undefined,
        };
        const kp = try std.crypto.dh.X25519.KeyPair.generateDeterministic(opts.secret);

        var datagram: [client.max_initial_datagram]u8 = undefined;
        const initial = try client.initialDatagram(&datagram, &self.hello_buf, .{
            .dcid = opts.dcid,
            .scid = opts.dcid,
            .random = opts.random,
            .public_key = kp.public_key,
            .alpn = opts.alpn,
            .server_name = opts.server_name,
            .window = self.stream_buf.len,
        });

        self.addr = try dial.resolve(io, opts.host, opts.port);
        // Bind a wildcard of the same family, since sending needs a local
        // socket.
        var local = switch (self.addr) {
            .ip4 => try std.Io.net.IpAddress.resolve(io, "0.0.0.0", 0),
            .ip6 => try std.Io.net.IpAddress.resolve(io, "::", 0),
        };

        self.sock = try local.bind(io, .{ .mode = .dgram });
        self.hello = initial.client_hello;
        self.sent = initial.len;
        self.hs = client.Handshaker.init(.{
            .original_dcid = opts.dcid,
            .our_scid = opts.dcid,
            .client_hello = initial.client_hello,
            .secret = opts.secret,
            .initial_buf = &self.initial_crypto,
            .handshake_buf = &self.handshake_crypto,
            .stream_buf = &self.stream_buf,
            .send_buf = &self.send_buf,
        });
        // Both fields hold something from here on, whatever the send does.
        self.ready = true;
        self.sock_open = true;

        try self.sock.send(io, &self.addr, datagram[0..initial.len]);
    }

    /// Says goodbye before dropping the socket, so the peer releases the state
    /// it holds for us rather than waiting out its idle timeout. Best effort:
    /// there is nothing to do about a close that does not arrive, and a
    /// connection that never reached 1-RTT has no key to send one under.
    ///
    /// Safe to call on a connection that never opened, and safe to call twice,
    /// so a caller can defer it before the connection exists.
    pub fn close(self: *Conn) void {
        if (!self.sock_open) return;
        self.sock_open = false;
        if (self.hs.app_keys != null and self.hs.closed == null) {
            var out: [client.max_initial_datagram]u8 = undefined;
            if (self.hs.sealClose(&out, "done") catch null) |n| {
                self.sock.send(self.io, &self.addr, out[0..n]) catch {};
            }
        }
        self.sock.close(self.io);
    }

    /// Why the peer closed, or null when it did not or the connection never got
    /// far enough to hear it.
    pub fn peerClose(self: *const Conn) ?*const client.Close {
        if (!self.ready) return null;
        if (self.hs.closed) |*reason| return reason;
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
    pub fn establish(self: *Conn, io: std.Io, opts: Options) !void {
        try self.open(io, opts);
        errdefer self.close();
        try self.handshake();
        if (!self.hs.confirmed) return error.HandshakeUnconfirmed;
    }

    /// Reads datagrams until the handshake is confirmed, the peer closes, or
    /// the datagram budget runs out.
    pub fn handshake(self: *Conn) !void {
        while (self.datagrams < self.opts.max_datagrams) {
            if (try self.service() != .arrived) break;
            if (self.hs.confirmed) return;
        }
        if (self.datagrams == 0) return error.NoReply;
    }

    /// One datagram in, and whatever it obliges us to send back out.
    pub fn service(self: *Conn) !Serviced {
        const arrived = self.receive() orelse return .silent;
        self.datagrams += 1;
        self.received += arrived.len;
        self.last = arrived;
        self.stream_retries = 0;
        self.quiet_ms = 0;
        self.pinged_ms = 0;
        if (self.opts.capture) |w| {
            w.print("{x}\n", .{arrived}) catch {};
            w.flush() catch {};
        }

        if (arrived.len > self.work.len) {
            self.last_err = error.DatagramTooLarge;
        } else {
            @memcpy(self.work[0..arrived.len], arrived);
            self.hs.push(&self.plain, self.work[0..arrived.len]) catch |e| {
                self.last_err = e;
                // A close is the end of the connection, so reading on would
                // only overwrite the reason with the next datagram.
                if (e == error.PeerClosed) return .closed;
            };
        }

        // Acknowledge before reading on: an unacknowledged flight makes the
        // peer retransmit it, and the ACK is what ends that.
        var out: [client.max_initial_datagram]u8 = undefined;
        for ([_]client.Handshaker.Space{ .initial, .handshake, .application }) |space| {
            const n = try self.hs.sealAck(&out, space) orelse continue;
            self.sock.send(self.io, &self.addr, out[0..n]) catch {};
        }

        // Both need 1-RTT keys, so there is nothing owed until they exist.
        if (self.hs.app_keys != null) {
            if (try self.hs.sealPathResponse(&out)) |n| {
                self.sock.send(self.io, &self.addr, out[0..n]) catch {};
            }
            if (try self.hs.sealMaxData(&out)) |n| {
                self.sock.send(self.io, &self.addr, out[0..n]) catch {};
            }
        }

        // The peer's Finished checks out, so our own flight can go: it waits
        // for that before confirming the handshake. Writing the flight advances
        // the transcript, so there is one attempt at it and no more, whatever
        // happens to the packet.
        if (self.hs.done() and !self.hs.flight_sent) send: {
            self.flight = self.hs.writeFlight(&self.messages, self.opts.identity) catch |e| {
                self.last_err = e;
                break :send;
            };
            const n = self.hs.sealFlight(&out, self.flight.?) catch |e| {
                self.last_err = e;
                break :send;
            };
            self.sock.send(self.io, &self.addr, out[0..n]) catch |e| {
                self.last_err = e;
                break :send;
            };
            self.flight_out = true;
        }
        return .arrived;
    }

    /// Waits for a datagram, resending whatever is outstanding while nothing
    /// comes. Not RFC 9002 loss recovery: nothing measures a round trip or
    /// backs off, which is enough to survive a dropped flight and no more.
    fn receive(self: *Conn) ?[]const u8 {
        while (true) {
            if (self.sock.receiveTimeout(self.io, &self.datagram, .{ .duration = .{
                .raw = .fromNanoseconds(@intCast(self.opts.timeout_ms * std.time.ns_per_ms)),
                .clock = .awake,
            } })) |got| {
                return got.data;
            } else |_| {
                var out: [client.max_initial_datagram]u8 = undefined;
                const n = self.retransmit(&out) orelse return null;
                self.sock.send(self.io, &self.addr, out[0..n]) catch return null;
            }
        }
    }

    /// The packet to send again after silence, or null when there is nothing
    /// outstanding or the budget is spent.
    fn retransmit(self: *Conn, out: []u8) ?usize {
        if (self.hs.confirmed) {
            // Each timeout is one tick of the only clock we have, whatever we
            // end up sending, so that the silence adds up.
            self.quiet_ms += self.opts.timeout_ms;
            // Past the idle timeout the peer has dropped us, so there is
            // nothing left to resend to.
            if (self.quiet_ms >= self.hs.idleTimeoutMs()) return null;
            if (self.stream_retries >= self.opts.max_retries) return null;
            if (self.hs.resendStream(out) catch null) |n| {
                self.stream_retries += 1;
                return n;
            }
            // Nothing outstanding, so the silence is just a quiet connection.
            // Past half the idle timeout, a PING keeps the peer from dropping
            // us.
            if (self.quiet_ms - self.pinged_ms < self.hs.idleTimeoutMs() / 2) return null;
            self.pinged_ms = self.quiet_ms;
            return self.hs.sealPing(out) catch null;
        }
        if (self.flight) |f| {
            if (self.flight_retries >= self.opts.max_retries) return null;
            self.flight_retries += 1;
            return self.hs.sealFlight(out, f) catch null;
        }
        // An acknowledged Initial arrived, so silence is about something else
        // and resending would only add noise.
        if (self.initial_retries >= self.opts.max_retries) return null;
        if (self.hs.acked(.initial).contains(0)) return null;
        self.initial_retries += 1;
        return self.hs.sealInitialRetransmit(out, self.hello) catch null;
    }

    /// Sends `data` on the stream, split across as many packets as it takes.
    /// Blocks on the peer whenever its window or our unacknowledged data leaves
    /// no room, since only an ACK or a MAX_DATA can make more.
    ///
    /// The loop runs at least once so that empty `data` with `fin` set closes
    /// the stream on its own.
    pub fn send(self: *Conn, data: []const u8, fin: bool) !void {
        var rest = data;
        while (true) {
            const room = @min(
                client.max_stream_chunk,
                @min(self.hs.sendRoom(), self.hs.sender.room()),
            );
            if (room == 0) {
                switch (try self.service()) {
                    .arrived => {},
                    // A peer that has closed will never take more, so the room
                    // we are waiting for is not coming.
                    .closed => return error.PeerClosed,
                    .silent => return error.SendStalled,
                }
                continue;
            }

            const take = @min(rest.len, room);
            var out: [client.max_initial_datagram]u8 = undefined;
            const n = try self.hs.sealStream(&out, rest[0..take], fin and take == rest.len);
            try self.sock.send(self.io, &self.addr, out[0..n]);

            rest = rest[take..];
            if (rest.len == 0) return;
        }
    }

    /// Stream bytes in order and not yet consumed.
    pub fn readable(self: *const Conn) []const u8 {
        return self.hs.stream.readable();
    }

    /// Whether the peer has finished its half of the stream and all of it has
    /// been read. Not `Handshaker.done`, which is about the handshake.
    pub fn streamDone(self: *const Conn) bool {
        return self.hs.stream.done();
    }

    /// Whether the silence has run past what the peer said it would wait, at
    /// which point it has dropped us and nothing more is coming.
    pub fn stalled(self: *const Conn) bool {
        return self.ready and self.quiet_ms >= self.hs.idleTimeoutMs();
    }

    /// Whether the handshake got all the way to confirmation.
    pub fn confirmed(self: *const Conn) bool {
        return self.ready and self.hs.confirmed;
    }

    /// What the peer told us about itself, or null before there is a handshake
    /// to have told us anything.
    pub fn accepted(self: *const Conn) ?*const client.Accepted {
        if (!self.ready) return null;
        return &self.hs.accepted;
    }

    pub fn consume(self: *Conn, n: usize) void {
        self.hs.stream.consume(n);
    }
};

const testing = std.testing;
const crypto = @import("crypto.zig");
const testdata = @import("testdata.zig");

test "opening sets every field, whatever the memory held" {
    const c = try testing.allocator.create(Conn);
    defer testing.allocator.destroy(c);
    // What an allocator hands back is not zeroed, and field defaults do not run
    // for it, so `open` has to write everything itself.
    @memset(std.mem.asBytes(c), 0xaa);

    try c.open(testing.io, .{
        .host = "127.0.0.1",
        // Discard: the Initial goes out and nothing answers, which is all this
        // needs. `handshake` is what would wait for a reply.
        .port = 9,
        .alpn = "radicle/gossip/1",
        .secret = testdata.hex(testdata.fixed_x25519_secret),
        .random = testdata.hex(testdata.fixed_hello_random),
        .dcid = &.{ 0xc0, 0xff, 0xee, 0x01 },
        .identity = try Ed25519.KeyPair.generateDeterministic(@splat(4)),
    });
    defer c.close();

    try testing.expectEqual(client.min_initial_datagram, c.sent);
    try testing.expectEqual(@as(usize, 0), c.datagrams);
    try testing.expectEqual(@as(usize, 0), c.received);
    try testing.expectEqual(@as(?anyerror, null), c.last_err);
    try testing.expectEqual(@as(usize, 0), c.last.len);
    try testing.expect(!c.flight_out);
    try testing.expect(!c.hs.confirmed);
}

test "closing is safe however far opening got, and sends one goodbye at most" {
    const unopened = try testing.allocator.create(Conn);
    defer testing.allocator.destroy(unopened);
    @memset(std.mem.asBytes(unopened), 0xaa);

    // Rejected before the socket or the handshaker exist, so both still hold
    // whatever the allocator handed back.
    try testing.expectError(error.InvalidHostName, unopened.open(testing.io, .{
        .host = "not a host",
        .port = 8776,
        .alpn = "radicle/gossip/1",
        .secret = testdata.hex(testdata.fixed_x25519_secret),
        .random = testdata.hex(testdata.fixed_hello_random),
        .dcid = &.{ 0xc0, 0xff, 0xee, 0x03 },
        .identity = try Ed25519.KeyPair.generateDeterministic(@splat(4)),
    }));
    try testing.expect(!unopened.ready);
    try testing.expectEqual(@as(?*const client.Close, null), unopened.peerClose());
    unopened.close();

    const c = try testing.allocator.create(Conn);
    defer testing.allocator.destroy(c);
    @memset(std.mem.asBytes(c), 0xaa);

    try c.open(testing.io, .{
        .host = "127.0.0.1",
        .port = 9,
        .alpn = "radicle/gossip/1",
        .secret = testdata.hex(testdata.fixed_x25519_secret),
        .random = testdata.hex(testdata.fixed_hello_random),
        .dcid = &.{ 0xc0, 0xff, 0xee, 0x04 },
        .identity = try Ed25519.KeyPair.generateDeterministic(@splat(4)),
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

test "silence on a confirmed connection adds up to the idle timeout" {
    const dcid = [_]u8{ 0xc0, 0xff, 0xee, 0x02 };
    const c = try testing.allocator.create(Conn);
    defer testing.allocator.destroy(c);
    @memset(std.mem.asBytes(c), 0xaa);

    try c.open(testing.io, .{
        .host = "127.0.0.1",
        .port = 9,
        .alpn = "radicle/git/1",
        .secret = testdata.hex(testdata.fixed_x25519_secret),
        .random = testdata.hex(testdata.fixed_hello_random),
        .dcid = &dcid,
        .identity = try Ed25519.KeyPair.generateDeterministic(@splat(4)),
    });
    defer c.close();

    // Keys and confirmation are what `retransmit` needs to seal a keepalive,
    // which is the branch that used to keep `quiet_ms` from ever adding up.
    const keys = crypto.keysFromSecret(crypto.initialSecrets(&dcid).client);
    c.hs.app_keys = .{ .send = keys, .recv = keys };
    c.hs.confirmed = true;

    var out: [client.max_initial_datagram]u8 = undefined;
    var pings: usize = 0;
    var ticks: usize = 0;
    // One receive timeout per turn, with nothing arriving to reset the count.
    while (c.quiet_ms < c.hs.idleTimeoutMs()) {
        ticks += 1;
        try testing.expect(ticks < 100);
        if (c.retransmit(&out)) |_| pings += 1;
    }
    // A keepalive went out, and it did not pass for traffic.
    try testing.expect(pings > 0);
    // Past the timeout there is nothing to send, which is what a reader
    // waiting on the stream gives up on.
    try testing.expect(c.retransmit(&out) == null);
}
