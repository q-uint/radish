//! A stand-in for a node, for tests about what happens on a connection rather
//! than about getting one: stream data, a FIN, a close, silence.
//!
//! It seals 1-RTT packets over loopback under a key both sides hold. It does
//! not answer a handshake; `confirm` hands the connection the state a finished
//! one would have left.
const std = @import("std");

const client = @import("client.zig");
const conn = @import("conn.zig");
const crypto = @import("crypto.zig");
const frame = @import("frame.zig");
const packet = @import("packet.zig");

/// How long to wait for the connection's opening datagram.
const accept_timeout_ms = 2000;

pub const FakePeer = struct {
    io: std.Io,
    sock: std.Io.net.Socket,
    /// What our packets are addressed to: `Options.dcid`.
    dcid: []const u8,
    /// One key both ways, so what we seal is what the client opens.
    keys: crypto.Keys,
    /// Where the opening datagram came from, and so where answers go.
    client_addr: std.Io.net.IpAddress = undefined,
    /// Our packet numbers and our half of the stream, both of which only go up.
    pn: u64 = 0,
    offset: u64 = 0,
    datagram: [client.max_receive_datagram]u8 = undefined,
    payload: [client.max_receive_datagram]u8 = undefined,

    pub fn bind(io: std.Io, dcid: []const u8) !FakePeer {
        var local = try std.Io.net.IpAddress.resolve(io, "127.0.0.1", 0);
        return .{
            .io = io,
            .sock = try local.bind(io, .{ .mode = .dgram }),
            .dcid = dcid,
            .keys = crypto.keysFromSecret(crypto.initialSecrets(dcid).client),
        };
    }

    pub fn deinit(self: *FakePeer) void {
        self.sock.close(self.io);
    }

    /// The port to point a connection at.
    pub fn port(self: *const FakePeer) u16 {
        return self.sock.address.getPort();
    }

    /// Takes the Initial, for the address to answer at. Its contents do not
    /// matter: we are not answering the handshake.
    pub fn accept(self: *FakePeer) !void {
        const got = try self.sock.receiveTimeout(self.io, &self.datagram, .{ .duration = .{
            .raw = .fromNanoseconds(accept_timeout_ms * std.time.ns_per_ms),
            .clock = .awake,
        } });
        self.client_addr = got.from;
    }

    /// Gives `c` the state a finished handshake would have left it in.
    pub fn confirm(self: *const FakePeer, c: *conn.Conn, idle_ms: u64) void {
        c.hs.app_keys = .{ .send = self.keys, .recv = self.keys };
        c.hs.confirmed = true;
        c.hs.peer_idle_ms = idle_ms;
        // What our transport parameters would have opened.
        c.hs.send_data.extend(c.stream_buf.len);
        c.hs.send_stream.extend(c.stream_buf.len);
    }

    /// Opens a connection pointed at us, faked through to confirmation.
    pub fn dial(self: *FakePeer, c: *conn.Conn, opts: conn.Options, idle_ms: u64) !void {
        var pointed = opts;
        pointed.host = "127.0.0.1";
        pointed.port = self.port();
        try c.open(self.io, pointed);
        try self.accept();
        self.confirm(c, idle_ms);
    }

    /// Seals `payload` as one 1-RTT packet and sends it. Frames put in
    /// together arrive together.
    pub fn sendFrames(self: *FakePeer, payload: []const u8) !void {
        var out: [client.max_receive_datagram]u8 = undefined;
        const n = try packet.sealShort(&out, .{
            .dcid = self.dcid,
            .pn = self.pn,
            // Four bytes, so no payload is too short to sample.
            .pn_len = 4,
        }, payload, self.keys);
        self.pn += 1;
        try self.sock.send(self.io, &self.client_addr, out[0..n]);
    }

    pub fn sendStream(self: *FakePeer, data: []const u8, fin: bool) !void {
        var w = std.Io.Writer.fixed(&self.payload);
        try self.writeStream(&w, data, fin);
        try self.sendFrames(w.buffered());
    }

    /// Stream data and a close in one packet: what a reader that honours the
    /// close first would drop.
    pub fn sendStreamAndClose(
        self: *FakePeer,
        data: []const u8,
        fin: bool,
        error_code: u64,
        reason: []const u8,
    ) !void {
        var w = std.Io.Writer.fixed(&self.payload);
        try self.writeStream(&w, data, fin);
        try frame.writeConnectionClose(&w, error_code, reason);
        try self.sendFrames(w.buffered());
    }

    fn writeStream(self: *FakePeer, w: *std.Io.Writer, data: []const u8, fin: bool) !void {
        try frame.writeStream(w, .{
            .id = 0,
            .offset = self.offset,
            .data = data,
            .fin = fin,
        });
        self.offset += data.len;
    }
};

const testdata = @import("testdata.zig");

/// One id for every fixture: each has its own socket and connection, so
/// nothing tells them apart by id anyway.
const fixture_dcid = [_]u8{ 0xc0, 0xff, 0xee, 0x20 };

/// The clock a wait is counted in. Short, so waiting out silence is quick.
const fixture_timeout_ms = 20;

/// A connection to a peer that is stood in for. Boxed: a `Conn` points into
/// itself, and what is under test points at it.
pub const Dialed = struct {
    peer: FakePeer,
    conn: *conn.Conn,

    /// `idle_ms` is the timeout the peer would have advertised.
    pub fn init(io: std.Io, idle_ms: u64) !*Dialed {
        const self = try std.testing.allocator.create(Dialed);
        errdefer std.testing.allocator.destroy(self);
        self.* = .{
            .peer = try FakePeer.bind(io, &fixture_dcid),
            .conn = try std.testing.allocator.create(conn.Conn),
        };
        try self.peer.dial(self.conn, .{
            // Host and port come from `dial`.
            .host = "",
            .port = 0,
            .alpn = "radicle/gossip/1",
            .secret = testdata.hex(testdata.fixed_x25519_secret),
            .random = testdata.hex(testdata.fixed_hello_random),
            .dcid = &fixture_dcid,
            .identity = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(7)),
            .timeout_ms = fixture_timeout_ms,
        }, idle_ms);
        return self;
    }

    pub fn deinit(self: *Dialed) void {
        self.conn.close();
        self.peer.deinit();
        std.testing.allocator.destroy(self.conn);
        std.testing.allocator.destroy(self);
    }
};
