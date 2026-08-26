//! One live QUIC first flight: send an Initial, read the reply, derive
//! handshake secrets. Used by `radish quic-probe`, not by the test suite.
const std = @import("std");

const dial = @import("../net/dial.zig");
const client = @import("client.zig");
const frame = @import("frame.zig");
const tls = @import("tls.zig");

pub const Error = error{ NoReply, ReplyTooLarge } || client.Error;

pub const Result = struct {
    sent: usize,
    /// Summed across every datagram read, so not `reply.len`.
    received: usize,
    datagrams: usize,
    /// The last datagram as it arrived, for recording as a fixture.
    reply: []const u8,
    accepted: ?client.Accepted,
    err: ?anyerror,
    closed: ?frame.ConnectionClose,
};

pub const Options = struct {
    host: []const u8,
    port: u16,
    alpn: []const u8,
    /// Fixed so a recorded reply replays. See testdata.fixed_x25519_secret.
    secret: tls.SecretKey,
    random: [32]u8,
    dcid: []const u8,
    server_name: ?[]const u8 = null,
    timeout_ms: u64 = 3000,
    max_datagrams: usize = 6,
};

/// `reply_buf` keeps the datagram as it arrived, so `reply` stays recordable;
/// decryption works on a copy. `plain_buf` receives the decrypted frames. Both
/// are borrowed by the result.
pub fn run(
    io: std.Io,
    opts: Options,
    reply_buf: []u8,
    plain_buf: []u8,
) !Result {
    const kp = try std.crypto.dh.X25519.KeyPair.generateDeterministic(opts.secret);

    var datagram: [1500]u8 = undefined;
    var hello_buf: [client.max_client_hello]u8 = undefined;
    const initial = try client.initialDatagram(&datagram, &hello_buf, .{
        .dcid = opts.dcid,
        .scid = opts.dcid,
        .random = opts.random,
        .public_key = kp.public_key,
        .alpn = opts.alpn,
        .server_name = opts.server_name,
    });
    const sent = initial.len;

    var addr = try dial.resolve(io, opts.host, opts.port);
    // Bind a wildcard of the same family, since sending needs a local socket.
    var local = switch (addr) {
        .ip4 => try std.Io.net.IpAddress.resolve(io, "0.0.0.0", 0),
        .ip6 => try std.Io.net.IpAddress.resolve(io, "::", 0),
    };
    const sock = try local.bind(io, .{ .mode = .dgram });
    defer sock.close(io);

    try sock.send(io, &addr, datagram[0..sent]);
    const msg = sock.receiveTimeout(io, reply_buf, .{ .duration = .{
        .raw = .fromNanoseconds(@intCast(opts.timeout_ms * std.time.ns_per_ms)),
        .clock = .awake,
    } }) catch return error.NoReply;

    // A server's first flight can span datagrams: the first is often an
    // ACK-only Initial, with the ServerHello in a later one.
    var work: [2048]u8 = undefined;
    var received = msg.data.len;
    var datagrams: usize = 1;
    var current = msg.data;
    var last_err: anyerror = error.NoReply;
    var closed: frame.ConnectionClose = .{ .error_code = 0, .frame_type = null, .reason = "" };

    while (true) {
        if (current.len > work.len) {
            last_err = error.ReplyTooLarge;
        } else {
            @memcpy(work[0..current.len], current);
            if (client.acceptServerInitial(
                plain_buf,
                work[0..current.len],
                opts.dcid,
                initial.client_hello,
                opts.secret,
                &closed,
            )) |accepted| {
                return .{
                    .sent = sent,
                    .received = received,
                    .datagrams = datagrams,
                    .reply = current,
                    .accepted = accepted,
                    .err = null,
                    .closed = null,
                };
            } else |e| last_err = e;
        }

        if (datagrams >= opts.max_datagrams) break;
        const next = sock.receiveTimeout(io, reply_buf, .{ .duration = .{
            .raw = .fromNanoseconds(@intCast(opts.timeout_ms * std.time.ns_per_ms)),
            .clock = .awake,
        } }) catch break;
        datagrams += 1;
        received += next.data.len;
        current = next.data;
    }

    return .{
        .sent = sent,
        .received = received,
        .datagrams = datagrams,
        .reply = current,
        .accepted = null,
        .err = last_err,
        .closed = if (last_err == error.PeerClosed) closed else null,
    };
}
