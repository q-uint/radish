//! Assembling a QUIC client's first flight: a ClientHello in a CRYPTO frame,
//! padded and sealed into an Initial packet.
const std = @import("std");

const codec = @import("../codec.zig");
const crypto = @import("crypto.zig");
const handshake = @import("handshake.zig");
const frame = @import("frame.zig");
const packet = @import("packet.zig");
const tls = @import("tls.zig");

const ExtensionType = std.crypto.tls.ExtensionType;
const NamedGroup = std.crypto.tls.NamedGroup;
const SignatureScheme = std.crypto.tls.SignatureScheme;

pub const Error = error{
    BufferTooSmall,
    Malformed,
    UnsupportedGroup,
    PeerClosed,
    FragmentedCrypto,
    UnsupportedCipherSuite,
    HelloRetryRequest,
} || packet.Error || handshake.Error || frame.Error;

/// A u16-length-prefixed list of u16s, the shape most TLS extensions take.
fn u16List(comptime values: []const u16) [2 + 2 * values.len]u8 {
    var out: [2 + 2 * values.len]u8 = undefined;
    std.mem.writeInt(u16, out[0..2], 2 * values.len, .big);
    for (values, 0..) |v, i| std.mem.writeInt(u16, out[2 + 2 * i ..][0..2], v, .big);
    return out;
}

const supported_groups = u16List(&.{@backingInt(NamedGroup.x25519)});
/// ed25519 is what radicle uses, but a public server signs with ECDSA or RSA,
/// and offering ed25519 alone draws a handshake_failure.
const signature_algorithms = u16List(&.{
    @backingInt(SignatureScheme.ecdsa_secp256r1_sha256),
    @backingInt(SignatureScheme.rsa_pss_rsae_sha256),
    @backingInt(SignatureScheme.ed25519),
});

/// An Initial datagram must reach this before a server will answer, so that a
/// spoofed source cannot make QUIC an amplifier.
/// Source: RFC 9000 s14.1.
pub const min_initial_datagram = 1200;

/// TLS_AES_128_GCM_SHA256, the only suite the Initial keys are sized for.
pub const cipher_suite: u16 = 0x1301;

pub const Config = struct {
    /// Chosen by the client and used to derive both sides' Initial keys.
    dcid: []const u8,
    scid: []const u8 = &.{},
    random: handshake.Random,
    public_key: tls.PublicKey,
    alpn: []const u8,
    /// A server hosting many names needs this to pick a certificate.
    server_name: ?[]const u8 = null,
};

/// Writes the extensions a QUIC ClientHello carries. ALPN is mandatory, and so
/// is quic_transport_parameters.
/// Source: RFC 9001 s8.
fn writeExtensions(w: *std.Io.Writer, cfg: Config) !void {
    if (cfg.server_name) |name| {
        // list length, name type 0 (host_name), then the name.
        var sni: [256]u8 = undefined;
        var sw = std.Io.Writer.fixed(&sni);
        try sw.writeInt(u16, @intCast(name.len + 3), .big);
        try sw.writeInt(u8, 0, .big);
        try sw.writeInt(u16, @intCast(name.len), .big);
        try sw.writeAll(name);
        try handshake.writeExtension(w, @backingInt(ExtensionType.server_name), sw.buffered());
    }

    try handshake.writeSupportedVersions(w);
    try handshake.writeKeyShare(w, cfg.public_key);

    try handshake.writeExtension(w, @backingInt(ExtensionType.supported_groups), &supported_groups);

    try handshake.writeExtension(w, @backingInt(ExtensionType.signature_algorithms), &signature_algorithms);

    var alpn: [64]u8 = undefined;
    var aw = std.Io.Writer.fixed(&alpn);
    try aw.writeInt(u16, @intCast(cfg.alpn.len + 1), .big);
    try aw.writeInt(u8, @intCast(cfg.alpn.len), .big);
    try aw.writeAll(cfg.alpn);
    try handshake.writeExtension(w, @backingInt(ExtensionType.application_layer_protocol_negotiation), aw.buffered());

    var params: [64]u8 = undefined;
    var pw = std.Io.Writer.fixed(&params);
    try handshake.writeIntTransportParam(&pw, .initial_max_data, 1 << 20);
    try handshake.writeIntTransportParam(&pw, .initial_max_stream_data_bidi_local, 1 << 20);
    try handshake.writeIntTransportParam(&pw, .initial_max_stream_data_bidi_remote, 1 << 20);
    try handshake.writeIntTransportParam(&pw, .initial_max_streams_bidi, 8);
    try handshake.writeIntTransportParam(&pw, .max_idle_timeout, 30_000);
    try handshake.writeTransportParam(&pw, .initial_source_connection_id, cfg.scid);
    try handshake.writeExtension(w, @backingInt(ExtensionType.quic_transport_parameters), pw.buffered());
}

/// Enough for a ClientHello with an SNI and one x25519 key share.
pub const max_client_hello = 768;

pub const Initial = struct {
    /// Bytes written to `out`.
    len: usize,
    /// The ClientHello as sent, borrowing from `hello_buf`. The transcript
    /// needs it, and the sealed packet does not give it back.
    client_hello: []const u8,
};

/// Builds the ClientHello, wraps it in a CRYPTO frame, pads to the minimum
/// datagram size, and seals it as Initial packet number 0.
pub fn initialDatagram(out: []u8, hello_buf: []u8, cfg: Config) Error!Initial {
    var ext: [512]u8 = undefined;
    var ew = std.Io.Writer.fixed(&ext);
    writeExtensions(&ew, cfg) catch return error.BufferTooSmall;

    const ch = try handshake.writeClientHello(hello_buf, .{
        .random = cfg.random,
        .cipher_suites = &.{cipher_suite},
        .extensions = ew.buffered(),
    });

    // CRYPTO frame at offset 0, then PADDING to the datagram minimum. The
    // padding is sized so the sealed packet lands exactly on the floor.
    var payload: [min_initial_datagram]u8 = @splat(0);
    var fw = std.Io.Writer.fixed(&payload);
    codec.writeVarint(&fw, @backingInt(frame.Type.crypto)) catch return error.BufferTooSmall;
    codec.writeVarint(&fw, 0) catch return error.BufferTooSmall;
    codec.writeVarint(&fw, ch.len) catch return error.BufferTooSmall;
    fw.writeAll(ch) catch return error.BufferTooSmall;
    const frames_len = fw.buffered().len;

    const keys = crypto.keysFromSecret(crypto.initialSecrets(cfg.dcid).client);
    const build: packet.Build = .{
        .kind = .initial,
        .dcid = cfg.dcid,
        .scid = cfg.scid,
        .pn = 0,
        .pn_len = 4,
    };

    // Grow the payload until the sealed packet reaches the floor.
    var payload_len = frames_len;
    while (true) {
        const header = try packet.writeLongHeader(out, build, payload_len);
        const total = header.len + payload_len + 16;
        if (total >= min_initial_datagram) break;
        payload_len += min_initial_datagram - total;
    }
    if (payload_len > payload.len) return error.BufferTooSmall;

    return .{
        .len = try packet.seal(out, build, payload[0..payload_len], keys),
        .client_hello = ch,
    };
}

/// What the server's Initial yields once opened and its ServerHello read.
/// The connection id is copied rather than borrowed: it lives in the packet
/// buffer, which the caller is free to reuse or drop.
pub const Accepted = struct {
    scid_buf: [packet.max_cid_len]u8,
    scid_len: usize,
    cipher_suite: u16,
    handshake: tls.Directions,

    /// The connection id the server wants us to address it by from now on.
    pub fn scid(self: *const Accepted) []const u8 {
        return self.scid_buf[0..self.scid_len];
    }
};

/// Opens a server Initial, reads its ServerHello, and derives both handshake
/// traffic secrets. `client_hello` is the message we sent, needed for the
/// transcript. `packet_buf` is mutated in place by `open`.
///
/// Reads only the first packet of a coalesced datagram: the ServerHello is in
/// the Initial, and the Handshake packets behind it need the keys this derives.
pub fn acceptServerInitial(
    out: []u8,
    packet_buf: []u8,
    original_dcid: []const u8,
    client_hello: []const u8,
    secret: tls.SecretKey,
    /// Filled in when the peer closes rather than replying, alongside
    /// `error.PeerClosed`.
    closed: *frame.ConnectionClose,
) Error!Accepted {
    const keys = crypto.keysFromSecret(crypto.initialSecrets(original_dcid).server);
    const opened = try packet.open(out, packet_buf, keys, null);

    // Reassembling a CRYPTO stream is not implemented, so the ServerHello has
    // to arrive whole at offset 0.
    var server_hello: ?[]const u8 = null;
    var it = frame.Iterator.init(opened.payload);
    while (try it.next()) |f| switch (f) {
        .crypto => |c| {
            if (c.offset != 0 or server_hello != null) return error.FragmentedCrypto;
            server_hello = c.data;
        },
        .connection_close => |c| {
            closed.* = c;
            return error.PeerClosed;
        },
        else => {},
    };
    const sh_bytes = server_hello orelse return error.Malformed;

    const sh = try handshake.parseServerHello(sh_bytes);

    // Only x25519 is offered, so a retry means the server wants a group we do
    // not have. Reported as itself rather than as a malformed key_share.
    if (sh.isHelloRetryRequest()) return error.HelloRetryRequest;

    // The schedule below is SHA-256 and AES-128 throughout; another suite would
    // derive silently wrong secrets.
    if (sh.cipher_suite != cipher_suite) return error.UnsupportedCipherSuite;

    const ks = (try sh.keyShare()) orelse return error.Malformed;
    if (ks.group != .x25519 or ks.key.len != 32) return error.UnsupportedGroup;

    var transcript: handshake.Transcript = .{};
    transcript.update(client_hello);
    transcript.update(sh_bytes[0..sh.len]);

    const shared = tls.x25519(secret, ks.key[0..32].*) catch return error.UnsupportedGroup;
    const hs = tls.handshakeSecret(tls.earlySecret(), &shared);

    var accepted: Accepted = .{
        .scid_buf = undefined,
        .scid_len = opened.header.scid.len,
        .cipher_suite = sh.cipher_suite,
        .handshake = tls.handshakeTraffic(hs, transcript.hash()),
    };
    @memcpy(accepted.scid_buf[0..accepted.scid_len], opened.header.scid);
    return accepted;
}

const testing = std.testing;
const testdata = @import("testdata.zig");
const hex = testdata.hex;

/// Rebuilds the ClientHello the probe sent, which is deterministic given the
/// fixed key, random and connection id.
fn recordedClientHello(datagram: []u8, hello_buf: []u8) ![]const u8 {
    const dcid = hex(testdata.live_dcid);
    const kp = try std.crypto.dh.X25519.KeyPair.generateDeterministic(hex(testdata.fixed_x25519_secret));
    const initial = try initialDatagram(datagram, hello_buf, .{
        .dcid = &dcid,
        .scid = &dcid,
        .random = hex(testdata.fixed_hello_random),
        .public_key = kp.public_key,
        .alpn = testdata.live_alpn,
        .server_name = testdata.live_sni,
    });
    return initial.client_hello;
}

// A reply captured from a live server, replayed offline. Unlike the RFC
// vectors this pins radish against another implementation's actual output.
test "replays a recorded cloudflare handshake" {
    var mine: [1500]u8 = undefined;
    var hello_buf: [max_client_hello]u8 = undefined;
    const client_hello = try recordedClientHello(&mine, &hello_buf);

    var reply: [1200]u8 = undefined;
    _ = try std.fmt.hexToBytes(&reply, testdata.live_server_initial_hex);

    var plain: [1500]u8 = undefined;
    var closed: frame.ConnectionClose = undefined;
    const a = try acceptServerInitial(
        &plain,
        &reply,
        &hex(testdata.live_dcid),
        client_hello,
        hex(testdata.fixed_x25519_secret),
        &closed,
    );

    try testing.expectEqual(cipher_suite, a.cipher_suite);
    try testing.expectEqualSlices(u8, &hex(testdata.live_scid), a.scid());
    try testing.expectEqualSlices(u8, &hex(testdata.live_client_hs_secret), &a.handshake.client);
    try testing.expectEqualSlices(u8, &hex(testdata.live_server_hs_secret), &a.handshake.server);
}

test "builds an Initial datagram we can open again" {
    const dcid = hex(testdata.other_dcid);
    const kp = try std.crypto.dh.X25519.KeyPair.generateDeterministic(hex(testdata.fixed_x25519_secret));
    // The public key RFC 8448 pairs with that secret.
    try testing.expectEqualSlices(
        u8,
        &hex("99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c"),
        &kp.public_key,
    );

    var out: [1500]u8 = undefined;
    var hello_buf: [max_client_hello]u8 = undefined;
    const initial = try initialDatagram(&out, &hello_buf, .{
        .dcid = &dcid,
        .scid = &dcid,
        .random = hex(testdata.fixed_hello_random),
        .public_key = kp.public_key,
        .alpn = "radicle/1",
    });
    try testing.expectEqual(@as(usize, min_initial_datagram), initial.len);

    const keys = crypto.keysFromSecret(crypto.initialSecrets(&dcid).client);
    var plain: [1500]u8 = undefined;
    const opened = try packet.open(&plain, out[0..initial.len], keys, null);
    try testing.expectEqual(packet.Kind.initial, opened.header.kind);
    try testing.expectEqual(@as(u64, 0), opened.pn);

    // The CRYPTO frame in the sealed packet must be the ClientHello returned.
    var it = frame.Iterator.init(opened.payload);
    const sent = (try it.next()).?.crypto.data;
    try testing.expectEqualSlices(u8, initial.client_hello, sent);

    const ch = try handshake.parseClientHello(sent);

    try testing.expectEqualSlices(u8, &hex("1301"), ch.cipher_suites);
    try testing.expect(try ch.find(.application_layer_protocol_negotiation) != null);
    try testing.expect(try ch.find(.key_share) != null);

    const params = (try ch.find(.quic_transport_parameters)).?;
    var pit = handshake.TransportParamIterator.init(params);
    var saw_scid = false;
    while (try pit.next()) |p| {
        if (p.id == .initial_source_connection_id) {
            try testing.expectEqualSlices(u8, &dcid, p.value);
            saw_scid = true;
        }
    }
    try testing.expect(saw_scid);
}
