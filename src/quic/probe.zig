//! One live QUIC first flight: send an Initial, read the reply, derive
//! handshake secrets. Used by `radish quic-probe`, not by the test suite.
//!
//! Only raw public keys are offered, so a public server answers with a
//! CRYPTO_ERROR rather than completing. Reaching that point still exercises the
//! socket, the Initial, and decrypting the reply; completing needs an iroh peer.
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
    closed: ?client.Close,
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
    /// Resends of the first flight before giving up.
    max_retries: usize = 2,
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

    // A server's first flight spans datagrams, so the handshake accumulates
    // across them.
    var initial_crypto: [4096]u8 = undefined;
    var handshake_crypto: [16384]u8 = undefined;
    var hs = client.Handshaker.init(.{
        .original_dcid = opts.dcid,
        .our_scid = opts.dcid,
        .client_hello = initial.client_hello,
        .secret = opts.secret,
        .initial_buf = &initial_crypto,
        .handshake_buf = &handshake_crypto,
    });

    var work: [2048]u8 = undefined;
    var received: usize = 0;
    var datagrams: usize = 0;
    var current: []const u8 = &.{};
    var last_err: ?anyerror = null;
    var retries: usize = 0;

    while (true) {
        // Resend the first flight while it goes unacknowledged. Not RFC 9002
        // loss recovery: nothing measures a round trip or backs off, which is
        // enough to survive a dropped Initial and no more.
        var arrived: ?[]const u8 = null;
        while (true) {
            if (sock.receiveTimeout(io, reply_buf, .{ .duration = .{
                .raw = .fromNanoseconds(@intCast(opts.timeout_ms * std.time.ns_per_ms)),
                .clock = .awake,
            } })) |got| {
                arrived = got.data;
                break;
            } else |_| {
                // An acknowledged Initial arrived, so silence is about
                // something else and resending would only add noise.
                if (retries >= opts.max_retries or hs.acked(.initial).contains(0)) break;
                retries += 1;
                var again: [client.max_initial_datagram]u8 = undefined;
                const n = hs.sealInitialRetransmit(&again, initial.client_hello) catch break;
                sock.send(io, &addr, again[0..n]) catch break;
            }
        }
        current = arrived orelse break;
        datagrams += 1;
        received += current.len;

        if (current.len > work.len) {
            last_err = error.ReplyTooLarge;
        } else {
            @memcpy(work[0..current.len], current);
            hs.push(plain_buf, work[0..current.len]) catch |e| {
                last_err = e;
                // A close is the end of the connection, so reading on would
                // only overwrite the reason with the next datagram.
                if (e == error.PeerClosed) break;
            };
        }

        // Acknowledge before reading on: an unacknowledged flight makes the
        // server retransmit it, and the ACK is what ends that.
        var ack: [client.max_initial_datagram]u8 = undefined;
        for ([_]client.Handshaker.Space{ .initial, .handshake, .application }) |space| {
            const n = hs.sealAck(&ack, space) catch continue orelse continue;
            sock.send(io, &addr, ack[0..n]) catch {};
        }

        if (hs.done() or datagrams >= opts.max_datagrams) break;
    }

    if (datagrams == 0) return error.NoReply;

    return .{
        .sent = sent,
        .received = received,
        .datagrams = datagrams,
        .reply = current,
        // Partial progress is still worth reporting, so `accepted` is filled in
        // whenever secrets exist. `closed` and `err` are what say whether the
        // handshake actually finished.
        .accepted = if (hs.accepted.handshake != null) hs.accepted else null,
        .err = last_err,
        .closed = hs.closed,
    };
}
