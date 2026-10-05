//! One QUIC connection: the handshake either end drives, then the packet
//! number spaces, streams, acknowledgements and keys it leaves behind.
const std = @import("std");

const codec = @import("../codec.zig");
const crypto = @import("crypto.zig");
const handshake = @import("handshake.zig");
const frame = @import("frame.zig");
const packet = @import("packet.zig");
const reassembly = @import("reassembly.zig");
const profile = @import("profile.zig");
const recovery = @import("recovery.zig");
const stream = @import("stream.zig");
const tls = @import("tls.zig");

const ExtensionType = std.crypto.tls.ExtensionType;
const NamedGroup = std.crypto.tls.NamedGroup;
const SignatureScheme = std.crypto.tls.SignatureScheme;
const Ed25519 = std.crypto.sign.Ed25519;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

pub const Error = error{
    BufferTooSmall,
    Malformed,
    UnsupportedGroup,
    PeerClosed,
    FragmentedCrypto,
    UnsupportedCipherSuite,
    HelloRetryRequest,
    UnsupportedSignature,
    BadCertificateVerify,
    BadFinished,
    HandshakeIncomplete,
    UnexpectedMessage,
    UnsupportedCertificateType,
    /// ALPN named nothing both ends speak, which QUIC has no connection for.
    /// Source: RFC 9001 s8.1.
    NoApplicationProtocol,
    KeysUnavailable,
    FlightAlreadySent,
    TransportParameterError,
    UnsupportedStream,
    StreamChunkTooLong,
    KeyUpdateError,
    StatelessReset,
    AmplificationLimited,
} || packet.Error || handshake.Error || frame.Error || stream.Error;

/// The shortest datagram that could be a stateless reset: a short header, a
/// connection id we might have used, and the 16-byte token. Anything smaller
/// cannot be one, whatever its last bytes hold.
/// Source: RFC 9000 s10.3.
pub const min_stateless_reset_len = 21;

/// A u16-length-prefixed list of u16s, the shape most TLS extensions take.
fn u16List(comptime values: []const u16) [2 + 2 * values.len]u8 {
    var out: [2 + 2 * values.len]u8 = undefined;
    std.mem.writeInt(u16, out[0..2], 2 * values.len, .big);
    for (values, 0..) |v, i| std.mem.writeInt(u16, out[2 + 2 * i ..][0..2], v, .big);
    return out;
}

const supported_groups = u16List(&.{@backingInt(NamedGroup.x25519)});

/// Radicle identities are ed25519 and a raw public key carries nothing else, so
/// there is no second scheme to offer. X.509 is not supported: verifying a chain
/// needs ECDSA and RSA, which radish has no use for anywhere else.
const signature_algorithms = u16List(&.{@backingInt(SignatureScheme.ed25519)});

/// The `raw_public_key` CertificateType, the only one radish negotiates. The
/// peer sends a bare SubjectPublicKeyInfo in place of a chain.
/// Source: RFC 7250 s3, s4.
pub const raw_public_key: u8 = 2;

/// The body both certificate_type extensions carry: a list of one entry.
const certificate_types = [_]u8{ 1, raw_public_key };

/// An Initial datagram must reach this before a server will answer, so that a
/// spoofed source cannot make QUIC an amplifier.
/// Source: RFC 9000 s14.1.
pub const min_initial_datagram = 1200;

/// What to size a buffer for an Initial. Padding up to the floor can widen the
/// header's length varint, putting the packet a few bytes over it, which the
/// RFC permits.
pub const max_initial_datagram = min_initial_datagram + 8;

/// TLS_AES_128_GCM_SHA256, the only suite the Initial keys are sized for.
pub const cipher_suite: u16 = 0x1301;

/// The path we size the window for. A receiver whose credit is under the
/// bandwidth-delay product limits its own throughput, so this is a bandwidth
/// and a round trip rather than a round number.
/// Source: RFC 9000 s4.3, and radicle's own quinn fork, which picks the same
/// pair as its default (noq-proto config/transport.rs).
pub const expected_bandwidth: u64 = 12_500_000; // bytes/s, 100 Mbps
pub const expected_rtt_ms: u64 = 100;

/// How much the peer may send before we raise its limit, and so how big a
/// stream buffer must be. Also over one whole message, which a window under
/// would deadlock.
pub const default_window: u64 = expected_bandwidth / 1000 * expected_rtt_ms;

/// How long we let a connection go quiet before treating it as dead. The peer
/// advertises its own and the lower of the two applies.
/// Source: RFC 9000 s10.1.
pub const idle_timeout_ms: u64 = 30_000;

/// Ack-eliciting packets that oblige an ACK. Answering every packet with one
/// doubles the datagrams on the path for no gain, since an ACK names every
/// number it has, not only the newest.
/// Source: RFC 9000 s13.2.2.
pub const ack_threshold: u32 = 2;

/// How long an ACK may be held back. Not advertised, so this is the default
/// the peer assumes of us and must not be exceeded.
/// Source: RFC 9000 s18.2.
pub const max_ack_delay_ms: u64 = 25;

/// A STREAM frame's fields ahead of the data: the type byte, then the stream
/// id, offset and length as varints.
/// Source: RFC 9000 s19.8.
const stream_frame_overhead = 1 + 3 * codec.max_varint_len;

/// The most stream data one packet carries: what is left of a datagram every
/// path must accept, once the header, the frame's fields and the AEAD tag have
/// their room. Anything longer is the caller's to split.
pub const max_stream_chunk = min_initial_datagram -
    packet.max_short_header_len -
    Aes128Gcm.tag_length -
    stream_frame_overhead;

/// What a peer may send us, and what we advertise as `max_udp_payload_size`:
/// the parameter is "the space an endpoint dedicates to holding incoming
/// packets", so the two are the same number. Without it the peer is entitled to
/// the default 65527 and will grow its datagrams past this buffer on a path
/// that allows it, which a socket read then truncates into garbage.
/// Source: RFC 9000 s18.2.
pub const max_receive_datagram = 2048;

/// Room for our handshake flight, measured at the largest either role writes:
/// a server's, which is a client's with EncryptedExtensions and a
/// CertificateRequest in front of it. Every part is fixed for a raw public key
/// and ed25519 except the two the peer's hello sizes.
pub const max_flight = blk: {
    const cid: [packet.max_cid_len]u8 = @splat(0);
    const alpn: [max_alpn]u8 = @splat('a');
    const context: [handshake.max_request_context]u8 = @splat(0);
    const signature: [Ed25519.Signature.encoded_length]u8 = @splat(0);
    const verify_data: [std.crypto.hash.sha2.Sha256.digest_length]u8 = @splat(0);

    var ext: [handshake.max_extensions]u8 = undefined;
    var ew = std.Io.Writer.fixed(&ext);
    writeServerExtensions(&ew, &alpn, &cid, &cid, std.math.maxInt(u62)) catch unreachable;

    var buf: [min_initial_datagram]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    handshake.writeEncryptedExtensions(&w, ew.buffered()) catch unreachable;
    handshake.writeCertificateRequest(&w, &.{}, &certificate_request_extensions) catch unreachable;
    handshake.writeRawPublicKeyCertificate(&w, &context, @splat(0)) catch unreachable;
    handshake.writeCertificateVerify(
        &w,
        @backingInt(SignatureScheme.ed25519),
        &signature,
    ) catch unreachable;
    handshake.writeMessage(&w, .finished, &verify_data) catch unreachable;
    break :blk w.buffered().len;
};

/// The longest ALPN we write or keep. radicle's are `radicle/gossip/1` and
/// `radicle/git/1`, with room to spare for whatever else a peer offers.
pub const max_alpn = 64;

/// The longest SNI hostname, which is a DNS name.
/// Source: RFC 1035 s2.3.4.
pub const max_server_name = 255;

pub const Config = struct {
    /// Chosen by the client and used to derive both sides' Initial keys.
    dcid: []const u8,
    scid: []const u8 = &.{},
    random: handshake.Random,
    public_key: tls.PublicKey,
    alpn: []const u8,
    /// A server hosting many names needs this to pick a certificate. iroh
    /// disables SNI so the endpoint id stays out of the ClientHello, so leave it
    /// null there.
    server_name: ?[]const u8 = null,
    /// The flow control limits to advertise. `Connection.Options.stream_buf`
    /// has to be this long, since it is where the peer's bytes land.
    window: u64 = default_window,
};

/// Room for the transport parameters below: six with a varint value, then the
/// two connection ids. Each is an id and a length around its body, all varints
/// taken at their full width.
const max_transport_params = 6 * (3 * codec.max_varint_len) +
    2 * (2 * codec.max_varint_len + packet.max_cid_len);

/// The transport parameters, as the one extension that carries them. Only a
/// server sends `original_dcid`: it is the id the client first addressed, and
/// echoing it is how the client knows nothing rewrote its Initial.
/// Source: RFC 9000 s7.3, s18.2.
fn writeTransportParams(
    w: *std.Io.Writer,
    role: Role,
    window: u64,
    scid: []const u8,
    original_dcid: ?[]const u8,
) !void {
    var params: [max_transport_params]u8 = undefined;
    var pw = std.Io.Writer.fixed(&params);
    try handshake.writeIntTransportParam(&pw, .initial_max_data, window);
    try handshake.writeIntTransportParam(&pw, .initial_max_stream_data_bidi_local, window);
    try handshake.writeIntTransportParam(&pw, .initial_max_stream_data_bidi_remote, window);
    // The streams the peer may open toward us: the one radish handles is always
    // the client's, so a server allows it and a client allows none.
    // Source: RFC 9000 s18.2.
    try handshake.writeIntTransportParam(&pw, .initial_max_streams_bidi, switch (role) {
        .client => 0,
        .server => 1,
    });
    // What we can hold. The default is 65527, and a peer that probes its way up
    // to it sends datagrams this side reads as truncated garbage.
    // Source: RFC 9000 s18.2.
    try handshake.writeIntTransportParam(&pw, .max_udp_payload_size, max_receive_datagram);
    try handshake.writeIntTransportParam(&pw, .max_idle_timeout, idle_timeout_ms);
    try handshake.writeTransportParam(&pw, .initial_source_connection_id, scid);
    if (original_dcid) |dcid| {
        try handshake.writeTransportParam(&pw, .original_destination_connection_id, dcid);
    }
    try handshake.writeExtension(w, @backingInt(ExtensionType.quic_transport_parameters), pw.buffered());
}

/// The one protocol we are naming, as ALPN wants it: a list of one.
fn writeAlpn(w: *std.Io.Writer, name: []const u8) !void {
    // The list length, then the one name behind its own.
    var alpn: [2 + 1 + max_alpn]u8 = undefined;
    var aw = std.Io.Writer.fixed(&alpn);
    try aw.writeInt(u16, @intCast(name.len + 1), .big);
    try aw.writeInt(u8, @intCast(name.len), .big);
    try aw.writeAll(name);
    try handshake.writeExtension(
        w,
        @backingInt(ExtensionType.application_layer_protocol_negotiation),
        aw.buffered(),
    );
}

/// Writes the extensions a QUIC ClientHello carries. ALPN is mandatory, and so
/// is quic_transport_parameters.
/// Source: RFC 9001 s8.
fn writeExtensions(w: *std.Io.Writer, cfg: Config) !void {
    if (cfg.server_name) |name| {
        // list length, name type 0 (host_name), then the name behind its length.
        var sni: [2 + 1 + 2 + max_server_name]u8 = undefined;
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

    // Both directions, since iroh authenticates mutually: we present a raw
    // public key too.
    try handshake.writeExtension(w, @backingInt(ExtensionType.client_certificate_type), &certificate_types);
    try handshake.writeExtension(w, @backingInt(ExtensionType.server_certificate_type), &certificate_types);

    try writeAlpn(w, cfg.alpn);
    try writeTransportParams(w, .client, cfg.window, cfg.scid, null);
}

/// What a server answers with, in the one message of its flight that is not
/// encrypted under keys the ClientHello could reach: the certificate types it
/// selected, the protocol it took from the client's list, and its own transport
/// parameters.
/// Source: RFC 8446 s4.3.1, RFC 9001 s8.
fn writeServerExtensions(
    w: *std.Io.Writer,
    alpn: []const u8,
    scid: []const u8,
    original_dcid: []const u8,
    window: u64,
) !void {
    // One type each, selected from the lists the client offered.
    // Source: RFC 7250 s4.1.
    try handshake.writeExtension(w, @backingInt(ExtensionType.client_certificate_type), &.{raw_public_key});
    try handshake.writeExtension(w, @backingInt(ExtensionType.server_certificate_type), &.{raw_public_key});

    try writeAlpn(w, alpn);
    try writeTransportParams(w, .server, window, scid, original_dcid);
}

/// A CertificateRequest has to say what it will accept, and ed25519 is the
/// only thing radish can verify.
/// Source: RFC 8446 s4.3.2.
const certificate_request_extensions = blk: {
    var buf: [4 + signature_algorithms.len]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    handshake.writeExtension(
        &w,
        @backingInt(ExtensionType.signature_algorithms),
        &signature_algorithms,
    ) catch unreachable;
    break :blk buf;
};

/// The extensions a ClientHello carries, measured at their largest: both of the
/// ones that vary written as long as we would ever write them, and the window
/// wide enough to spend a full varint. Measuring also bounds-checks the buffers
/// `writeExtensions` writes through, since a short one fails to compile here.
const max_client_extensions = blk: {
    const name: [max_server_name]u8 = @splat('a');
    const alpn: [max_alpn]u8 = @splat('a');
    const scid: [packet.max_cid_len]u8 = @splat(0);

    var buf: [min_initial_datagram]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    writeExtensions(&w, .{
        .dcid = &scid,
        .scid = &scid,
        .random = @splat(0),
        .public_key = @splat(0),
        .alpn = &alpn,
        .server_name = &name,
        .window = std.math.maxInt(u62),
    }) catch unreachable;
    break :blk w.buffered().len;
};

/// The largest ClientHello we write: those extensions and the fixed fields
/// around them. Measured, so it cannot drift from the writers.
pub const max_client_hello = blk: {
    const ext: [max_client_extensions]u8 = @splat(0);
    var buf: [min_initial_datagram]u8 = undefined;
    const ch = handshake.writeClientHello(&buf, .{
        .random = @splat(0),
        .cipher_suites = &.{cipher_suite},
        .extensions = &ext,
    }) catch unreachable;
    break :blk ch.len;
};

/// What `sealServerHello` builds, measured by building one, so it cannot drift
/// from the writers. Exact rather than a bound: nothing in it varies.
pub const max_server_hello = blk: {
    var ext: [min_initial_datagram]u8 = undefined;
    var ew = std.Io.Writer.fixed(&ext);
    handshake.writeServerKeyShare(&ew, @splat(0)) catch unreachable;
    handshake.writeSelectedVersion(&ew) catch unreachable;

    var out: [min_initial_datagram]u8 = undefined;
    const sh = handshake.writeServerHello(&out, .{
        .random = @splat(0),
        .cipher_suite = cipher_suite,
        .extensions = ew.buffered(),
    }) catch unreachable;
    break :blk sh.len;
};

pub const Initial = struct {
    /// Bytes written to `out`.
    len: usize,
    /// The hello as sent, borrowing from `hello_buf`. The transcript needs it
    /// and so does a retransmission, and the sealed packet gives back neither.
    hello: []const u8,
};

/// Grows `frames_len` until the sealed packet reaches the floor a client must
/// expand every datagram carrying an Initial to. The header has to be written
/// to be measured, since its length varint depends on the payload it describes,
/// and growing the payload can widen that varint: the result may land a byte or
/// two above the floor, which the RFC allows.
/// Source: RFC 9000 s14.1.
fn paddedInitialLen(out: []u8, build: packet.Build, frames_len: usize) Error!usize {
    var payload_len = frames_len;
    while (true) {
        const header = try packet.writeLongHeader(out, build, payload_len);
        const total = header.len + payload_len + Aes128Gcm.tag_length;
        if (total >= min_initial_datagram) return payload_len;
        payload_len += min_initial_datagram - total;
    }
}

/// One handshake message alone in an Initial: a CRYPTO frame at offset 0,
/// padded to the floor every datagram carrying an ack-eliciting Initial is
/// expanded to, whichever end sends it.
/// Source: RFC 9000 s14.1.
fn sealInitialCrypto(out: []u8, build: packet.Build, keys: crypto.Keys, message: []const u8) Error!usize {
    var payload: [min_initial_datagram]u8 = undefined;
    var pw = std.Io.Writer.fixed(&payload);
    writeCryptoFrame(&pw, 0, message) catch return error.BufferTooSmall;
    const frames_len = pw.buffered().len;

    const payload_len = try paddedInitialLen(out, build, frames_len);
    if (payload_len > payload.len) return error.BufferTooSmall;
    pw.splatByteAll(0, payload_len - frames_len) catch return error.BufferTooSmall;

    return packet.seal(out, build, pw.buffered(), keys);
}

/// Builds the ClientHello and seals it as Initial packet number 0.
pub fn initialDatagram(out: []u8, hello_buf: []u8, cfg: Config) Error!Initial {
    var ext: [max_client_extensions]u8 = undefined;
    var ew = std.Io.Writer.fixed(&ext);
    writeExtensions(&ew, cfg) catch return error.BufferTooSmall;

    const ch = try handshake.writeClientHello(hello_buf, .{
        .random = cfg.random,
        .cipher_suites = &.{cipher_suite},
        .extensions = ew.buffered(),
    });

    const keys = crypto.keysFromSecret(crypto.initialSecrets(cfg.dcid).client);
    const build: packet.Build = .{
        .kind = .initial,
        .dcid = cfg.dcid,
        .scid = cfg.scid,
        .pn = 0,
        .pn_len = packet.max_pn_len,
    };

    return .{
        .len = try sealInitialCrypto(out, build, keys, ch),
        .hello = ch,
    };
}

/// The longest CONNECTION_CLOSE reason we send or keep. It is diagnostic text
/// on a connection that is already over, so both directions truncate to it
/// rather than treat a longer one as a failure.
pub const max_close_reason = 256;

/// Why the peer closed. `frame.ConnectionClose` borrows the buffer the packet
/// was decrypted into, so this keeps its own copy and stays valid once that
/// buffer is reused. Copyable by value: nothing points back into it.
pub const Close = struct {
    error_code: u64,
    frame_type: ?u64,
    reason_buf: [max_close_reason]u8 = undefined,
    reason_len: usize = 0,

    pub fn reason(self: *const Close) []const u8 {
        return self.reason_buf[0..self.reason_len];
    }

    /// An over-long reason is truncated: it is diagnostic text on a connection
    /// that is already over.
    pub fn from(c: frame.ConnectionClose) Close {
        var self: Close = .{ .error_code = c.error_code, .frame_type = c.frame_type };
        self.reason_len = @min(c.reason.len, self.reason_buf.len);
        @memcpy(self.reason_buf[0..self.reason_len], c.reason[0..self.reason_len]);
        return self;
    }
};

/// What the server has told us so far. The connection id is copied rather than
/// borrowed: it lives in the packet buffer, which the caller may reuse or drop.
pub const Accepted = struct {
    scid_buf: [packet.max_cid_len]u8 = undefined,
    scid_len: usize = 0,
    cipher_suite: u16 = 0,
    handshake: ?tls.Directions = null,
    /// The 1-RTT secrets, once the server's Finished has been verified.
    application: ?tls.Directions = null,
    /// The peer's ed25519 key, once a raw public key certificate has arrived.
    peer_key: ?[32]u8 = null,
    /// Set once `peer_key` has signed the transcript, so the key is the peer's
    /// and not merely something the peer sent.
    peer_verified: bool = false,
    alpn_buf: [max_alpn]u8 = undefined,
    alpn_len: usize = 0,

    /// The connection id the server wants us to address it by from now on.
    pub fn scid(self: *const Accepted) []const u8 {
        return self.scid_buf[0..self.scid_len];
    }

    pub fn alpn(self: *const Accepted) []const u8 {
        return self.alpn_buf[0..self.alpn_len];
    }
};

fn writeCryptoFrame(w: *std.Io.Writer, offset: u64, data: []const u8) !void {
    try codec.writeVarint(w, @backingInt(frame.Type.crypto));
    try codec.writeVarint(w, offset);
    try codec.writeVarint(w, data.len);
    try w.writeAll(data);
}

/// Which end this is. All it decides is which half of each derived pair is
/// ours, and which context the peer signed under.
/// Source: RFC 8446 s4.4.3, RFC 9001 s5.
pub const Role = enum {
    client,
    server,

    /// The half we seal with. Generic, since the Initial secrets and the
    /// traffic secrets are separate types of the same shape.
    pub fn ours(self: Role, pair: anytype) @TypeOf(pair.client) {
        return switch (self) {
            .client => pair.client,
            .server => pair.server,
        };
    }

    /// The one the peer seals with, and so what verifies what it sent.
    pub fn theirs(self: Role, pair: anytype) @TypeOf(pair.client) {
        return switch (self) {
            .client => pair.server,
            .server => pair.client,
        };
    }

    pub fn peerVerifyContext(self: Role) []const u8 {
        return switch (self) {
            .client => handshake.server_verify_context,
            .server => handshake.client_verify_context,
        };
    }

    pub fn ourVerifyContext(self: Role) []const u8 {
        return switch (self) {
            .client => handshake.client_verify_context,
            .server => handshake.server_verify_context,
        };
    }
};

/// A handshake in progress, from either side. Keys for the Handshake packet
/// number space only exist once the hello the role waits on has been read, so
/// the two CRYPTO streams and the transcript outlive any single datagram.
pub const Connection = struct {
    /// Everything the ServerHello yields at once.
    pub const Derived = struct {
        /// The master secret, and so the application keys, still need this
        /// after the traffic secrets have been derived from it.
        secret: tls.Secret,
        keys: crypto.Keys,
    };

    /// How far key agreement has got. A server holds the client's share for
    /// the step between reading the ClientHello and answering it; nothing else
    /// holds anything, so nothing else carries the field.
    pub const Keying = union(enum) {
        none,
        offered: tls.PublicKey,
        derived: Derived,

        pub fn get(self: Keying) ?Derived {
            return switch (self) {
                .derived => |d| d,
                else => null,
            };
        }
    };

    /// One key phase, both ways.
    pub const Directional = struct {
        send: crypto.Keys,
        recv: crypto.Keys,
    };

    /// The order the server's messages must arrive in; a message out of turn is
    /// refused. EncryptedExtensions carries the negotiated certificate type,
    /// and the peer's key can only be read once that is known.
    /// Source: RFC 8446 Appendix A.1.
    pub const Phase = enum {
        /// Where a server starts. From the Certificate on, both roles walk the
        /// same states.
        wait_client_hello,
        wait_server_hello,
        wait_encrypted_extensions,
        /// A CertificateRequest is optional, so either may come next.
        wait_certificate_or_request,
        wait_certificate,
        wait_certificate_verify,
        wait_finished,
        connected,
    };

    role: Role = .client,
    secret: tls.SecretKey,
    initial_keys: Directional,
    keying: Keying = .none,
    /// 1-RTT protection, once the server's Finished has been verified. Named by
    /// direction: the two are not interchangeable, and using the wrong one
    /// produces a packet the peer cannot unmask.
    app_keys: ?Directional = null,
    /// Which generation of 1-RTT keys `app_keys` holds, and the Key Phase bit
    /// every short header we send carries. Starts at 0 and flips once per
    /// update. Source: RFC 9001 s6.
    key_phase: bool = false,
    /// The receive keys an update replaced, kept so a packet reordered across
    /// the update still opens. One generation back is as far as it goes.
    /// Source: RFC 9001 s6.3.
    prev_recv: ?crypto.Keys = null,
    /// The token the peer will prove a lost connection with, from its transport
    /// parameters.
    /// Source: RFC 9000 s10.3.
    peer_reset_token: ?[16]u8 = null,
    /// Set when a datagram arrived bearing that token: the peer has thrown away
    /// everything it knew about this connection.
    stateless_reset: bool = false,
    /// Set by a DATA_BLOCKED or STREAM_DATA_BLOCKED, and cleared by the grant
    /// that answers it.
    grant_asked: bool = false,
    /// The packet the last grant went out in, so a lost one can go again.
    /// Nothing else retransmits flow control, and our own limit has already
    /// moved by then, so `wantsGrant` will not ask for another: a grant the
    /// peer never sees stalls the transfer for good.
    /// Source: RFC 9000 s13.3.
    grant_pn: ?u64 = null,
    /// The id we gave for ourselves. Every long header we send has to carry it,
    /// because it is what we advertised as initial_source_connection_id and the
    /// peer checks the two against each other. Its length is also the only way
    /// to find the packet number in a short header, which carries no length.
    /// Source: RFC 9000 s7.3, s17.3.
    our_scid: [packet.max_cid_len]u8 = undefined,
    our_cid_len: usize,
    /// Set when the peer's hello names raw_public_key in both directions. X.509
    /// is the default when the extension is absent, which radish treats as fatal
    /// rather than continue with a peer it cannot authenticate.
    /// Source: RFC 7250 s4.1, s4.2.
    negotiated_raw_key: bool = false,
    /// What a server accepts, in the order it prefers. Empty on a client, which
    /// named its one protocol in the ClientHello and does not select.
    /// Source: RFC 9001 s8.1.
    alpns: []const []const u8 = &.{},

    /// HANDSHAKE_DONE, so the server accepted our flight. It only ever travels
    /// in a 1-RTT packet. A server sets this the moment the handshake completes
    /// rather than on hearing anything back.
    /// Source: RFC 9001 s4.1.2.
    confirmed: bool = false,
    /// A server owes the client a HANDSHAKE_DONE, and owes it again until one
    /// is acknowledged. `handshake_done_pn` is the packet the last one went in.
    /// Source: RFC 9000 s13.3.
    handshake_done_owed: bool = false,
    handshake_done_pn: ?u64 = null,
    /// `writeFlight` has run, so the transcript now includes our flight.
    flight_sent: bool = false,
    /// Owed back to the peer as a PATH_RESPONSE.
    path_challenge: ?[frame.path_challenge_len]u8 = null,

    transcript: handshake.Transcript = .{},
    /// Each packet number space carries its own CRYPTO stream, with its own
    /// offsets: the ServerHello arrives on the Initial one, everything from
    /// EncryptedExtensions onward on the Handshake one.
    initial_crypto: reassembly.Reassembler,
    handshake_crypto: reassembly.Reassembler,
    initial_read: usize = 0,
    handshake_read: usize = 0,

    /// The one stream radish opens, and what the peer has sent on it. Gossip
    /// runs over a single bidirectional stream, so there is nothing to key by
    /// id yet.
    /// Source: RFC 9000 s2.1.
    stream: stream.Receiver,
    /// What we have sent on it and not seen acknowledged.
    sender: stream.Sender,
    /// The peer's max_idle_timeout, in milliseconds. Zero disables it.
    /// Source: RFC 9000 s10.1.
    peer_idle_ms: u64 = 0,
    /// What the peer lets us send: across the connection, and on the stream.
    /// Both start closed and open when its transport parameters arrive.
    /// Source: RFC 9000 s4.1.
    send_data: stream.Window = .{ .limit = 0 },
    send_stream: stream.Window = .{ .limit = 0 },

    /// Round trip estimate, loss detection and the congestion window. Fed by
    /// every ack-eliciting packet sealed here and every ACK opened here.
    recovery: recovery.Recovery = recovery.Recovery.init(min_initial_datagram),
    /// The clock as the connection last read it, in milliseconds. Nothing here
    /// reads it: `endpoint.zig` sets it each turn, and the sealing paths stamp what
    /// they send with it.
    now_ms: u64 = 0,
    /// When the ACK a held-back packet is owed runs out of time, or null when
    /// nothing is waiting. Set from the first packet an ACK owes for, so a
    /// lone one is still answered inside what the peer expects.
    /// Source: RFC 9000 s13.2.1.
    ack_deadline_ms: ?u64 = null,
    /// The last 1-RTT ACK we sent, and the largest it named. Once the peer
    /// acknowledges that packet, everything up to that number can stop being
    /// reported, which is what keeps an early hole out of every later ACK.
    /// Source: RFC 9000 s13.2.4.
    sent_ack: ?struct { pn: u64, largest: u64 } = null,
    /// When an ACK last carried a PING. A packet holding only an ACK is not
    /// ack-eliciting, so without one the peer never acknowledges our ACKs and
    /// nothing is ever trimmed.
    /// Source: RFC 9000 s13.2.4.
    ack_pinged_ms: u64 = 0,
    /// Counters, when the caller wants them.
    profile: ?*profile.Profile = null,
    /// What the peer scales its ACK delays by, as a power of two microseconds.
    /// Source: RFC 9000 s18.2.
    peer_ack_exponent: u6 = 3,
    /// Set when loss detection found something and cleared by the caller acting
    /// on it, since only the caller can put the bytes back on the wire.
    lost: bool = false,

    /// Every payload byte this connection has been handed, whether or not any
    /// of it opened, and every byte sealed for it. A server may send three
    /// times what it has received until the address is validated, which happens
    /// the moment a Handshake packet from the peer opens.
    /// Source: RFC 9000 s8, s8.1.
    received_bytes: u64 = 0,
    sent_bytes: u64 = 0,
    address_validated: bool = false,

    /// What has arrived in each space, for acknowledging it and for recovering
    /// the next truncated packet number.
    initial_received: frame.Received = .{},
    handshake_received: frame.Received = .{},
    app_received: frame.Received = .{},

    /// The next number to send in each space. Reusing one repeats an AEAD nonce
    /// under the same key. A client starts the Initial space at 1, since
    /// `initialDatagram` sent the ClientHello as 0; `init` puts a server to 0.
    /// Source: RFC 9000 s12.3, RFC 9001 s5.3.
    next_initial_pn: u64 = 1,
    next_handshake_pn: u64 = 0,
    next_app_pn: u64 = 0,

    /// What the peer has acknowledged in each space, so we can tell what still
    /// needs sending again.
    initial_acked: frame.NumberSet = .{},
    handshake_acked: frame.NumberSet = .{},
    app_acked: frame.NumberSet = .{},

    /// The id we chose for the server, kept to check against the
    /// original_destination_connection_id it echoes back.
    original_dcid: [packet.max_cid_len]u8 = undefined,
    original_dcid_len: usize = 0,
    saw_initial_scid: bool = false,
    saw_original_dcid: bool = false,

    /// The context a CertificateRequest asked us to echo. `requested` is what
    /// says the server wants client authentication.
    request_buf: [handshake.max_request_context]u8 = undefined,
    request_len: usize = 0,
    requested: bool = false,

    /// The flow control limit we advertise, which `stream_buf` has to be long
    /// enough to hold. A client already sent it in the ClientHello; a server
    /// sends it in EncryptedExtensions, so it has to keep it until then.
    window: u64 = default_window,

    accepted: Accepted = .{},
    /// Set alongside `error.PeerClosed`.
    closed: ?Close = null,
    phase: Phase = .wait_server_hello,

    /// True once the server's Finished has been verified.
    pub fn done(self: *const Connection) bool {
        return self.phase == .connected;
    }

    pub const Options = struct {
        role: Role = .client,
        /// The id the client chose; Initial keys stay pinned to it.
        original_dcid: []const u8,
        /// The id we gave for ourselves. Its length is the only way to find the
        /// packet number in a 1-RTT header.
        our_scid: []const u8,
        /// Opens the transcript.
        client_hello: []const u8,
        /// What a server accepts from a ClientHello's ALPN list, preferred
        /// first. A client leaves it empty.
        alpns: []const []const u8 = &.{},
        secret: tls.SecretKey,
        /// Hold the reassembled CRYPTO streams, borrowed for the handshake's
        /// life. One per packet number space.
        initial_buf: []u8,
        handshake_buf: []u8,
        /// Holds what arrives on the stream, once the handshake is over. Its
        /// length is the window we advertised, so it has to match
        /// `Config.window`.
        stream_buf: []u8 = &.{},
        /// Holds what we send there until the peer acknowledges it.
        send_buf: []u8 = &.{},
        /// The limit to advertise, which has to match `Config.window` on a
        /// client and `stream_buf`'s length on either.
        window: u64 = default_window,
    };

    pub fn init(opts: Options) Connection {
        const initial = crypto.initialSecrets(opts.original_dcid);
        var self: Connection = .{
            .role = opts.role,
            .alpns = opts.alpns,
            .secret = opts.secret,
            .initial_keys = .{
                .send = crypto.keysFromSecret(opts.role.ours(initial)),
                .recv = crypto.keysFromSecret(opts.role.theirs(initial)),
            },
            .our_cid_len = opts.our_scid.len,
            .window = opts.window,
            .initial_crypto = reassembly.Reassembler.init(opts.initial_buf),
            .handshake_crypto = reassembly.Reassembler.init(opts.handshake_buf),
            .stream = stream.Receiver.init(opts.stream_buf, opts.stream_buf.len),
            .sender = stream.Sender.init(opts.send_buf),
        };
        if (opts.role == .server) {
            self.next_initial_pn = 0;
            self.phase = .wait_client_hello;
        }
        self.original_dcid_len = opts.original_dcid.len;
        @memcpy(self.original_dcid[0..self.original_dcid_len], opts.original_dcid);
        @memcpy(self.our_scid[0..opts.our_scid.len], opts.our_scid);
        self.transcript.update(opts.client_hello);
        return self;
    }

    /// Opens every packet in one datagram, in order, feeding their CRYPTO
    /// frames to the matching stream. `datagram` is decrypted in place;
    /// `scratch` receives each packet's plaintext.
    pub fn push(self: *Connection, scratch: []u8, datagram: []u8) Error!void {
        // Counted before anything is read: the budget covers every byte a
        // datagram brought, including one whose packets are all discarded.
        // Source: RFC 9000 s8.1.
        self.received_bytes +|= datagram.len;
        var rest = datagram;
        while (rest.len > 0) {
            if (!packet.isLongHeader(rest[0])) {
                // No length field, so this packet is the remainder of the
                // datagram and nothing can follow it.
                const opened = try self.openApp(scratch, rest, datagram);
                // Acknowledge only once the frames are in: an ACK for a packet
                // we then dropped tells the peer that data arrived, and it
                // never sends those bytes again.
                try self.appFrames(opened.payload);
                const before = self.app_received.out_of_order;
                self.app_received.record(opened.pn);
                if (self.profile) |p| {
                    p.app_packets += 1;
                    p.app_highest = @max(p.app_highest, opened.pn);
                    if (!before and self.app_received.out_of_order) p.app_gaps += 1;
                }
                return;
            }

            // Version Negotiation, an unsupported version and Retry all surface
            // here, and each ends the attempt rather than leaving the caller
            // unable to tell a rejection from silence.
            const hdr = try packet.parseLongHeader(rest);
            const keys = switch (hdr.kind) {
                .initial => self.initial_keys.recv,
                // Arriving before the ServerHello means reordering, which needs
                // buffering we do not do; the server retransmits.
                .handshake => (self.keying.get() orelse return error.KeysUnavailable).keys,
                else => return error.UnsupportedPacket,
            };

            const tracker = switch (hdr.kind) {
                .initial => &self.initial_received,
                else => &self.handshake_received,
            };
            const opened = try packet.open(scratch, rest, keys, tracker.largest());
            try self.frames(hdr.kind, opened);
            tracker.record(opened.pn);
            // A Handshake packet only opens for a peer that read our Initial,
            // which is proof it is at the address it claimed.
            // Source: RFC 9000 s8.1.
            if (hdr.kind == .handshake) self.address_validated = true;
            rest = rest[opened.len..];

            try self.drain(&self.initial_crypto, &self.initial_read);
            if (self.keying.get() != null) {
                try self.drain(&self.handshake_crypto, &self.handshake_read);
            }
        }
    }

    /// Opens a 1-RTT packet under the current keys, or failing that either
    /// generation around them: one reordered across a key update still opens
    /// under the keys it was sealed with, and one from the generation after is
    /// how an update announces itself. A datagram no key opens may be the peer
    /// saying it has lost us.
    /// Source: RFC 9001 s6.3, RFC 9000 s10.3.1.
    fn openApp(
        self: *Connection,
        scratch: []u8,
        rest: []u8,
        datagram: []const u8,
    ) Error!packet.OpenedShort {
        const dir = self.app_keys orelse return error.KeysUnavailable;
        const largest = self.app_received.largest();

        if (packet.openShort(scratch, rest, self.our_cid_len, dir.recv, largest)) |opened| {
            return opened;
        } else |e| if (e != error.AuthenticationFailed) return e;

        if (self.prev_recv) |old| {
            if (packet.openShort(scratch, rest, self.our_cid_len, old, largest)) |opened| {
                return opened;
            } else |e| if (e != error.AuthenticationFailed) return e;
        }

        return self.openUpdated(scratch, rest) catch |e| {
            if (e == error.AuthenticationFailed and self.isStatelessReset(datagram)) {
                self.stateless_reset = true;
                return error.StatelessReset;
            }
            return e;
        };
    }

    /// Whether `datagram` is the peer proving it has thrown away this
    /// connection: a short header, long enough to hold the token, ending in the
    /// token it gave us. None of it is authenticated, which is why it is only
    /// ever asked once no key would open the packet. Compared in constant time,
    /// since leaking the token would let anyone who can inject a datagram end
    /// the connection at will.
    /// Source: RFC 9000 s10.3, s10.3.1.
    fn isStatelessReset(self: *const Connection, datagram: []const u8) bool {
        const token = self.peer_reset_token orelse return false;
        if (datagram.len < min_stateless_reset_len) return false;
        if (packet.isLongHeader(datagram[0])) return false;
        const tail = datagram[datagram.len - token.len ..][0..token.len].*;
        return std.crypto.timing_safe.eql([token.len]u8, tail, token);
    }

    /// Opens `rest` under the generation after the current one, and on success
    /// moves both directions to it. Sending keys have to move too, since the
    /// acknowledgement for this packet is what tells the peer the update is
    /// complete. The header protection key is not part of an update, so it
    /// carries over, and the receive keys being replaced are kept as
    /// `prev_recv` for whatever is still in flight under them.
    /// Source: RFC 9001 s6.1, s6.2, s6.3.
    fn openUpdated(self: *Connection, scratch: []u8, rest: []u8) Error!packet.OpenedShort {
        const app = self.accepted.application orelse return error.KeysUnavailable;
        const dir = self.app_keys orelse return error.KeysUnavailable;

        const theirs = crypto.nextSecret(self.role.theirs(app));
        const opened = try packet.openShort(
            scratch,
            rest,
            self.our_cid_len,
            crypto.updatedKeys(theirs, dir.recv.hp),
            self.app_received.largest(),
        );
        // These keys are the other phase by construction, so a packet that
        // opens under them and claims the phase we are already in is a peer
        // that has updated twice without waiting for us.
        if (opened.key_phase == self.key_phase) return error.KeyUpdateError;

        const ours = crypto.nextSecret(self.role.ours(app));
        self.accepted.application = switch (self.role) {
            .client => .{ .client = ours, .server = theirs },
            .server => .{ .client = theirs, .server = ours },
        };
        self.prev_recv = dir.recv;
        self.app_keys = .{
            .send = crypto.updatedKeys(ours, dir.send.hp),
            .recv = crypto.updatedKeys(theirs, dir.recv.hp),
        };
        self.key_phase = opened.key_phase;
        return opened;
    }

    /// Frames from a 1-RTT packet.
    fn appFrames(self: *Connection, payload: []const u8) Error!void {
        var it = frame.Iterator.init(payload);
        while (try it.next()) |f| {
            switch (f) {
                .ack => |a| try self.recordAck(.application, a),
                .stream => |s| {
                    if (s.id != stream.first_client_bidi) return error.UnsupportedStream;
                    try self.stream.push(s);
                },
                .max_data => |m| self.send_data.extend(m),
                .max_stream_data => |m| {
                    if (m.id == stream.first_client_bidi) self.send_stream.extend(m.max);
                },
                .handshake_done => {
                    // Only a server sends it.
                    // Source: RFC 9000 s19.20.
                    if (self.role == .server) return error.ProtocolViolation;
                    self.confirmed = true;
                    // Only now may the application space be probed: before it,
                    // an acknowledgement might not be readable by either side.
                    // Source: RFC 9002 s6.2.1.
                    self.recovery.confirmed = true;
                    // Nothing in the handshake spaces can be acknowledged from
                    // here, so their timers and in-flight bytes go. radish
                    // keeps the keys themselves, having no reason to drop them.
                    // Source: RFC 9002 s6.4.
                    self.recovery.discard(.initial);
                    self.recovery.discard(.handshake);
                },
                .path_challenge => |c| self.path_challenge = c,
                .connection_close => |c| {
                    self.closed = .from(c);
                    return error.PeerClosed;
                },
                .ignored => |i| switch (i.kind) {
                    // Only stream 0 is ever open, so a reset naming another id
                    // is about a stream that never existed here.
                    // Source: RFC 9000 s19.4.
                    .reset_stream => if (i.about(stream.first_client_bidi)) {
                        self.stream.reset = true;
                    },
                    // The peer is out of credit and saying so, which earns a
                    // grant even when the reader has not freed enough for one.
                    // Source: RFC 9000 s19.12, s19.13.
                    .data_blocked => self.grant_asked = true,
                    .stream_data_blocked => if (i.about(stream.first_client_bidi)) {
                        self.grant_asked = true;
                    },
                    else => {},
                },
                else => {},
            }
            // Only once the frame is in: a frame we then refused takes the
            // packet with it, and there is nothing to acknowledge.
            if (frame.isAckEliciting(f)) {
                self.app_received.elicited();
                if (self.ack_deadline_ms == null) self.ack_deadline_ms = self.now_ms + max_ack_delay_ms;
            }
        }
    }

    /// Sends `data` on the stream, sealed as 1-RTT. The offset advances by what
    /// goes out, so successive calls continue the same stream.
    /// Source: RFC 9000 s19.8.
    pub fn sealStream(self: *Connection, out: []u8, data: []const u8, fin: bool) Error!usize {
        if (data.len > max_stream_chunk) return error.StreamChunkTooLong;
        // Both limits bind, and neither is spent until the packet is built.
        if (data.len > self.sendRoom()) return error.FlowControlBlocked;

        const pn = self.takePacketNumber(.application);
        const n = try self.sealStreamAt(out, pn, self.sender.next(), data, fin);
        try self.sender.sent(pn, data, fin);
        try self.send_data.take(data.len);
        try self.send_stream.take(data.len);
        return self.tracked(.application, pn, n);
    }

    /// Sends an unacknowledged chunk again, under a fresh packet number, or
    /// null when there is nothing to send. Successive calls work through what
    /// is outstanding; `force` starts from the oldest again whether or not it
    /// has already been tried, which is what a probe needs.
    /// Source: RFC 9000 s13.3, RFC 9002 s6.2.4.
    pub fn resendStream(self: *Connection, out: []u8, force: bool) Error!?usize {
        self.sender.ack(&self.app_acked);
        const chunk = (if (force)
            self.sender.oldestUnacked()
        else
            self.sender.unacked()) orelse return null;

        const pn = self.takePacketNumber(.application);
        const n = try self.sealStreamAt(
            out,
            pn,
            chunk.offset,
            self.sender.bytes(chunk.*),
            chunk.fin,
        );
        chunk.pn = pn;
        chunk.resent = true;
        return self.tracked(.application, pn, n);
    }

    fn sealStreamAt(
        self: *Connection,
        out: []u8,
        pn: u64,
        offset: u64,
        data: []const u8,
        fin: bool,
    ) Error!usize {
        const keys = (self.app_keys orelse return error.HandshakeIncomplete).send;
        var payload: [max_stream_chunk + stream_frame_overhead]u8 = undefined;
        var pw = std.Io.Writer.fixed(&payload);
        frame.writeStream(&pw, .{
            .id = stream.first_client_bidi,
            .offset = offset,
            .data = data,
            .fin = fin,
        }) catch return error.BufferTooSmall;

        return packet.sealShort(out, .{
            .dcid = self.accepted.scid(),
            .pn = pn,
            .pn_len = packet.max_pn_len,
            .key_phase = self.key_phase,
        }, pw.buffered(), keys);
    }

    /// An application CONNECTION_CLOSE, so the peer can release what it holds
    /// for us instead of waiting out its idle timeout.
    /// Source: RFC 9000 s10.2.
    pub fn sealClose(self: *Connection, out: []u8, reason: []const u8) Error!usize {
        const keys = (self.app_keys orelse return error.HandshakeIncomplete).send;
        // The frame is three varints around the reason.
        var payload: [3 * codec.max_varint_len + max_close_reason]u8 = undefined;
        var pw = std.Io.Writer.fixed(&payload);
        // NO_ERROR: leaving is not a failure. A long reason is cut to what the
        // peer would keep of it anyway.
        const text = reason[0..@min(reason.len, max_close_reason)];
        frame.writeConnectionClose(&pw, 0, text) catch return error.BufferTooSmall;

        return self.counted(try packet.sealShort(out, .{
            .dcid = self.accepted.scid(),
            .pn = self.takePacketNumber(.application),
            .pn_len = packet.max_pn_len,
            .key_phase = self.key_phase,
        }, pw.buffered(), keys));
    }

    /// A PING, which carries nothing and only asks to be acknowledged. Sent
    /// before the idle timeout to hold a quiet connection open.
    /// Source: RFC 9000 s19.2, s10.1.
    pub fn sealPing(self: *Connection, out: []u8) Error!usize {
        const keys = (self.app_keys orelse return error.HandshakeIncomplete).send;
        var payload: [codec.max_varint_len]u8 = @splat(0);
        var pw = std.Io.Writer.fixed(&payload);
        codec.writeVarint(&pw, @backingInt(frame.Type.ping)) catch return error.BufferTooSmall;

        const pn = self.takePacketNumber(.application);
        const n = try packet.sealShort(out, .{
            .dcid = self.accepted.scid(),
            .pn = pn,
            .pn_len = packet.max_pn_len,
            .key_phase = self.key_phase,
        }, pw.buffered(), keys);
        return self.tracked(.application, pn, n);
    }

    /// When the connection dies without traffic: the lower of the two
    /// advertised timeouts, or zero when neither side set one.
    /// Source: RFC 9000 s10.1.
    pub fn idleTimeoutMs(self: *const Connection) u64 {
        if (self.peer_idle_ms == 0) return idle_timeout_ms;
        return @min(idle_timeout_ms, self.peer_idle_ms);
    }

    /// How much the peer will still take from us.
    pub fn sendRoom(self: *const Connection) u64 {
        return @min(self.send_data.room(), self.send_stream.room());
    }

    /// Whether the last grant is neither acknowledged nor still in flight,
    /// which leaves loss as the only explanation for it.
    fn grantLost(self: *const Connection) bool {
        const pn = self.grant_pn orelse return false;
        if (self.app_acked.contains(pn)) return false;
        return !self.recovery.outstanding(.application, pn);
    }

    /// Raises the peer's limits once the reader has freed enough of the buffer,
    /// or null when there is nothing worth sending. One stream, so the
    /// connection limit and the stream limit move together.
    /// Source: RFC 9000 s4.1.
    pub fn sealMaxData(self: *Connection, out: []u8) Error!?usize {
        const keys = (self.app_keys orelse return error.HandshakeIncomplete).send;
        if (!self.stream.wantsGrant() and !self.grant_asked and !self.grantLost()) return null;
        self.grant_asked = false;
        const grant = self.stream.grant();

        // MAX_STREAM_DATA is a type and two varints, MAX_DATA a type and one.
        var payload: [2 + 3 * codec.max_varint_len]u8 = undefined;
        var pw = std.Io.Writer.fixed(&payload);
        frame.writeMaxStreamData(&pw, .{
            .id = stream.first_client_bidi,
            .max = grant,
        }) catch return error.BufferTooSmall;
        frame.writeMaxData(&pw, grant) catch return error.BufferTooSmall;

        const pn = self.takePacketNumber(.application);
        const n = try packet.sealShort(out, .{
            .dcid = self.accepted.scid(),
            .pn = pn,
            .pn_len = packet.max_pn_len,
            .key_phase = self.key_phase,
        }, pw.buffered(), keys);
        // Extended now, not on the acknowledgement: the peer may use the grant
        // as soon as it reads it, and data past our own limit is a violation.
        self.stream.window.extend(grant);
        self.grant_pn = pn;
        if (self.profile) |p| p.grants_sent += 1;
        return self.tracked(.application, pn, n);
    }

    /// Whether the last HANDSHAKE_DONE is neither acknowledged nor still in
    /// flight, which leaves loss as the only explanation for it.
    fn handshakeDoneLost(self: *const Connection) bool {
        const pn = self.handshake_done_pn orelse return false;
        if (self.app_acked.contains(pn)) return false;
        return !self.recovery.outstanding(.application, pn);
    }

    /// HANDSHAKE_DONE, which is how a server tells the client the handshake is
    /// confirmed. It carries nothing and travels only in a 1-RTT packet. Null
    /// when none is owed; a lost one is owed again until it is acknowledged.
    /// Source: RFC 9000 s19.20, s13.3, RFC 9001 s4.1.2.
    pub fn sealHandshakeDone(self: *Connection, out: []u8) Error!?usize {
        if (self.role != .server) return null;
        if (!self.handshake_done_owed and !self.handshakeDoneLost()) return null;
        const keys = (self.app_keys orelse return error.HandshakeIncomplete).send;

        var payload: [codec.max_varint_len]u8 = undefined;
        var pw = std.Io.Writer.fixed(&payload);
        codec.writeVarint(&pw, @backingInt(frame.Type.handshake_done)) catch
            return error.BufferTooSmall;

        const pn = self.takePacketNumber(.application);
        const n = try packet.sealShort(out, .{
            .dcid = self.accepted.scid(),
            .pn = pn,
            .pn_len = packet.max_pn_len,
            .key_phase = self.key_phase,
        }, pw.buffered(), keys);

        self.handshake_done_owed = false;
        self.handshake_done_pn = pn;
        return self.tracked(.application, pn, n);
    }

    /// A PATH_RESPONSE echoing the challenge the peer sent, sealed as 1-RTT.
    /// Source: RFC 9000 s8.2.
    pub fn sealPathResponse(self: *Connection, out: []u8) Error!?usize {
        const challenge = self.path_challenge orelse return null;
        const keys = (self.app_keys orelse return error.HandshakeIncomplete).send;
        const pn = self.takePacketNumber(.application);

        var payload: [codec.max_varint_len + frame.path_challenge_len]u8 = @splat(0);
        var pw = std.Io.Writer.fixed(&payload);
        codec.writeVarint(&pw, @backingInt(frame.Type.path_response)) catch return error.BufferTooSmall;
        pw.writeAll(&challenge) catch return error.BufferTooSmall;

        const n = try packet.sealShort(out, .{
            .dcid = self.accepted.scid(),
            .pn = pn,
            .pn_len = packet.max_pn_len,
            .key_phase = self.key_phase,
        }, pw.buffered(), keys);
        self.path_challenge = null;
        return self.tracked(.application, pn, n);
    }

    /// Sends our hello again under a fresh packet number. A lost packet is never
    /// resent as-is: the information goes in a new packet, and repeating a
    /// number would repeat an AEAD nonce and be discarded as a duplicate anyway.
    /// Source: RFC 9000 s13.3, s12.3.
    pub fn sealInitialRetransmit(self: *Connection, out: []u8, hello: []const u8) Error!usize {
        // Until the server's Initial arrives there is no id to address it by,
        // so keep using the one that derived the keys.
        const build: packet.Build = .{
            .kind = .initial,
            .dcid = if (self.accepted.scid_len > 0)
                self.accepted.scid()
            else
                self.original_dcid[0..self.original_dcid_len],
            .scid = self.our_scid[0..self.our_cid_len],
            .pn = self.takePacketNumber(.initial),
            .pn_len = packet.max_pn_len,
        };

        const n = try sealInitialCrypto(out, build, self.initial_keys.send, hello);
        return self.tracked(.initial, build.pn, n);
    }

    /// Hands a packet about to go out to loss detection and the congestion
    /// window, and passes its length back through. Only ack-eliciting packets
    /// are worth this: an ACK or a CONNECTION_CLOSE is never repeated and never
    /// counted against the window.
    /// Source: RFC 9002 s2, s7.
    fn tracked(self: *Connection, space: packet.Space, pn: u64, n: usize) usize {
        self.recovery.onSent(space, pn, n, self.now_ms);
        return self.counted(n);
    }

    /// Every sealed packet passes through here, so the amplification budget
    /// sees all of them and not only the ones loss detection tracks.
    fn counted(self: *Connection, n: usize) usize {
        self.sent_bytes +|= n;
        return n;
    }

    /// What a server may still send to an address it has not validated: three
    /// times what arrived, less what has gone out. No limit for a client, and
    /// none once a Handshake packet has proved the peer is there.
    /// Source: RFC 9000 s8, s8.1.
    pub fn amplificationRoom(self: *const Connection) u64 {
        if (self.role == .client or self.address_validated) return std.math.maxInt(u64);
        return (self.received_bytes *| 3) -| self.sent_bytes;
    }

    /// Whether a whole datagram still fits in that budget. Measured in whole
    /// datagrams, since that is what goes out.
    fn amplificationBlocked(self: *const Connection) bool {
        return self.amplificationRoom() < min_initial_datagram;
    }

    pub fn received(self: *Connection, space: packet.Space) *frame.Received {
        return switch (space) {
            .initial => &self.initial_received,
            .handshake => &self.handshake_received,
            .application => &self.app_received,
        };
    }

    pub fn acked(self: *Connection, space: packet.Space) *frame.NumberSet {
        return switch (space) {
            .initial => &self.initial_acked,
            .handshake => &self.handshake_acked,
            .application => &self.app_acked,
        };
    }

    /// Folds an ACK the peer sent into what we know it has. Bounded by what we
    /// actually sent, which also catches an acknowledgement of a packet that
    /// never existed.
    /// Source: RFC 9000 s13.1.
    fn recordAck(self: *Connection, space: packet.Space, a: frame.Ack) Error!void {
        const next = self.nextPacketNumber(space).*;
        if (a.largest >= next) return error.ProtocolViolation;

        const set = self.acked(space);
        var pn = (try a.firstRange()).smallest;
        while (pn < next and pn <= a.largest) : (pn += 1) {
            set.record(pn);
            self.recovery.acked(space, pn);
        }

        var it = try a.ranges();
        while (try it.next()) |r| {
            pn = r.smallest;
            while (pn <= r.largest) : (pn += 1) {
                set.record(pn);
                self.recovery.acked(space, pn);
            }
        }

        if (self.recovery.onAck(space, a.largest, self.ackDelayMs(a.delay), self.now_ms).any()) {
            self.lost = true;
        }

        // An ACK of ours that got through means the peer has read everything it
        // named, so those numbers need not be reported again.
        // Source: RFC 9000 s13.2.4.
        if (space == .application) {
            if (self.sent_ack) |sent| {
                if (set.contains(sent.pn)) {
                    self.app_received.numbers.trimTo(sent.largest);
                    self.sent_ack = null;
                }
            }
        }
    }

    /// An ACK's delay field in milliseconds. It arrives as microseconds scaled
    /// down by the exponent the peer advertised, so scaling it back up is what
    /// recovers the value it meant.
    /// Source: RFC 9000 s19.3.
    fn ackDelayMs(self: *const Connection, delay: u64) u64 {
        const scaled = delay *| (@as(u64, 1) << self.peer_ack_exponent);
        return scaled / std.time.us_per_ms;
    }

    /// Whether loss detection has found something since the caller last asked.
    /// Repairing it is the caller's: only it can put bytes back on the wire.
    pub fn takeLost(self: *Connection) bool {
        defer self.lost = false;
        return self.lost;
    }

    fn nextPacketNumber(self: *Connection, space: packet.Space) *u64 {
        return switch (space) {
            .initial => &self.next_initial_pn,
            .handshake => &self.next_handshake_pn,
            .application => &self.next_app_pn,
        };
    }

    /// Consumes the next packet number in `space`.
    fn takePacketNumber(self: *Connection, space: packet.Space) u64 {
        const slot = self.nextPacketNumber(space);
        defer slot.* += 1;
        return slot.*;
    }

    /// Seals an ACK for everything received in `space`, or null when nothing
    /// there is waiting to be acknowledged. Sent in the same space it covers,
    /// under that space's own keys.
    /// Source: RFC 9000 s13.2.
    pub fn sealAck(self: *Connection, out: []u8, space: packet.Space) Error!?usize {
        const tracker = self.received(space);
        if (!tracker.ack_eliciting) return null;
        if (!self.ackDue(space)) return null;
        // Silence is better than exceeding the budget: the peer retransmits,
        // and what it sends raises what we may send back.
        if (self.amplificationBlocked()) return null;

        var payload: [min_initial_datagram]u8 = undefined;
        var pw = std.Io.Writer.fixed(&payload);
        // Zero delay: measuring it needs a clock, and a peer only uses it to
        // refine an RTT estimate.
        tracker.writeAck(&pw, 0) catch |e| switch (e) {
            // Nothing to name, so whatever set the flag never made it into the
            // set. Cleared, or every turn from here comes back for a packet
            // number and sends nothing.
            error.NothingToAck => {
                tracker.ack_eliciting = false;
                return null;
            },
            else => return error.BufferTooSmall,
        };
        // Once a round trip, the ACK carries a PING so the peer has to
        // acknowledge it, which is the only way we learn what it has read.
        // Source: RFC 9000 s13.2.4.
        const ping = space == .application and
            self.now_ms -| self.ack_pinged_ms >= self.recovery.rtt.smoothed_ms;
        if (ping) {
            codec.writeVarint(&pw, @backingInt(frame.Type.ping)) catch return error.BufferTooSmall;
            self.ack_pinged_ms = self.now_ms;
        }
        // Taken only once there is a packet to spend it on: a number consumed
        // and not sent is a gap the peer reads as loss.
        const pn = self.takePacketNumber(space);

        const build: packet.Build = .{
            .kind = if (space == .initial) .initial else .handshake,
            .dcid = self.accepted.scid(),
            .scid = self.our_scid[0..self.our_cid_len],
            .pn = pn,
            .pn_len = packet.max_pn_len,
        };

        // A client expands every datagram carrying an Initial to 1200 bytes,
        // with no exception for one holding only an ACK: a server discards a
        // smaller one before it reads the frames. A server owes the expansion
        // only on an ack-eliciting Initial, and would be spending its
        // amplification budget on padding.
        // Source: RFC 9000 s14.1.
        if (space == .initial and self.role == .client) {
            const want = try paddedInitialLen(out, build, pw.buffered().len);
            pw.splatByteAll(0, want - pw.buffered().len) catch return error.BufferTooSmall;
        }
        const n = switch (space) {
            .initial => try packet.seal(out, build, pw.buffered(), self.initial_keys.send),
            .handshake => try packet.seal(out, build, pw.buffered(), crypto.keysFromSecret(
                self.role.ours(self.accepted.handshake orelse return error.KeysUnavailable),
            )),
            .application => try packet.sealShort(out, .{
                .dcid = self.accepted.scid(),
                .pn = pn,
                .pn_len = packet.max_pn_len,
                .key_phase = self.key_phase,
            }, pw.buffered(), (self.app_keys orelse return error.KeysUnavailable).send),
        };
        if (self.profile) |p| {
            p.acks_sent += 1;
            p.ack_ranges += tracker.numbers.count;
            p.ack_ranges_max = @max(p.ack_ranges_max, tracker.numbers.count);
        }
        if (space == .application) {
            self.ack_deadline_ms = null;
            // Only the ACK carrying a PING: the peer acknowledges nothing else
            // we send, so remembering any other would be waiting on an
            // acknowledgement that never comes.
            if (ping) {
                if (tracker.numbers.largest()) |l| self.sent_ack = .{ .pn = pn, .largest = l };
            }
        }
        tracker.cleared();
        // A PING makes the packet ack-eliciting, so it is one loss detection
        // and the congestion window have to know about. Either way the bytes
        // are counted once.
        if (ping) return self.tracked(space, pn, n);
        return self.counted(n);
    }

    /// Whether an ACK for `space` is owed yet. The handshake spaces answer
    /// every ack-eliciting packet at once, since the flights are small and a
    /// held-back ACK is a retransmitted flight. The application space waits
    /// for a second packet, for one out of order, or for the delay to run
    /// out, which is what stops a bulk transfer from answering every datagram
    /// with one of its own.
    /// Source: RFC 9000 s13.2.1, s13.2.2.
    fn ackDue(self: *const Connection, space: packet.Space) bool {
        if (space != .application) return true;
        if (self.app_received.pending >= ack_threshold) return true;
        if (self.app_received.out_of_order) return true;
        return if (self.ack_deadline_ms) |at| self.now_ms >= at else false;
    }

    /// When the application space's held-back ACK must go, or null when
    /// nothing is waiting on one.
    pub fn ackDeadlineMs(self: *const Connection) ?u64 {
        if (!self.app_received.ack_eliciting) return null;
        return self.ack_deadline_ms;
    }

    fn frames(self: *Connection, kind: packet.Kind, opened: packet.Opened) Error!void {
        if (kind == .initial and self.accepted.scid_len == 0) {
            self.accepted.scid_len = opened.header.scid.len;
            @memcpy(self.accepted.scid_buf[0..self.accepted.scid_len], opened.header.scid);
        }

        const tracker = if (kind == .initial) &self.initial_received else &self.handshake_received;

        var it = frame.Iterator.init(opened.payload);
        while (try it.next()) |f| {
            switch (f) {
                .ack => |a| try self.recordAck(if (kind == .initial) .initial else .handshake, a),
                .crypto => |c| {
                    const crypto_stream = if (kind == .initial) &self.initial_crypto else &self.handshake_crypto;
                    try crypto_stream.push(c.offset, c.data);
                },
                .connection_close => |c| {
                    self.closed = .from(c);
                    return error.PeerClosed;
                },
                else => {},
            }
            if (frame.isAckEliciting(f)) tracker.elicited();
        }
    }

    /// Hands every newly complete message to `message`, advancing the stream's
    /// read watermark by whole messages so the next pass starts on a boundary.
    fn drain(self: *Connection, crypto_stream: *const reassembly.Reassembler, read: *usize) Error!void {
        var it = handshake.MessageIterator.init(crypto_stream.contiguous()[read.*..]);
        while (it.next()) |msg| {
            // Consumed before dispatch: `message` hashes into the transcript
            // before it can fail, so a retry would hash it twice.
            read.* += msg.raw.len;
            try self.message(msg);
        }
    }

    fn message(self: *Connection, msg: handshake.Message) Error!void {
        switch (msg.type) {
            .certificate, .certificate_verify, .finished => {},
            else => return switch (self.role) {
                .client => self.clientMessage(msg),
                .server => self.serverMessage(msg),
            },
        }
        return self.authMessage(msg);
    }

    /// Source: RFC 8446 s4.1.2.
    fn serverMessage(self: *Connection, msg: handshake.Message) Error!void {
        if (msg.type != .client_hello) return error.UnexpectedMessage;
        if (self.phase != .wait_client_hello) return error.UnexpectedMessage;

        const ch = try handshake.parseClientHello(msg.raw);
        try uniqueExtensions(ch.extensions);
        // Only a version the client offered may be selected, and 1.3 is the
        // only one there is a ServerHello for here.
        // Source: RFC 8446 s4.2.1, RFC 9001 s4.2.
        if (!try offersTls13(ch)) return error.UnsupportedVersion;
        // Middlebox compatibility mode, which has no use over QUIC and which a
        // server is told to refuse.
        // Source: RFC 9001 s8.4.
        if (ch.session_id.len != 0) return error.ProtocolViolation;
        if (!try offers(ch.cipher_suites, cipher_suite)) return error.UnsupportedCipherSuite;

        const ks = try clientKeyShare(ch) orelse return error.Malformed;
        if (ks.group != .x25519 or ks.key.len != 32) return error.UnsupportedGroup;

        var offered_ours = false;
        var offered_theirs = false;
        var it = handshake.ExtensionIterator.init(ch.extensions);
        while (try it.next()) |e| switch (e.type) {
            // Raw public keys have to be on offer, since a certificate chain is
            // not something either end here can read.
            // Source: RFC 7250 s4.1.
            .client_certificate_type => offered_theirs = try offersRawPublicKey(e.body),
            .server_certificate_type => offered_ours = try offersRawPublicKey(e.body),
            .application_layer_protocol_negotiation => try self.selectAlpn(e.body),
            .quic_transport_parameters => try self.transportParams(e.body),
            else => {},
        };

        // Both directions, and only what the client offered may be echoed: a
        // client that named one of them cannot be authenticated mutually and
        // has to be turned down rather than sent an extension it never asked
        // for. Source: RFC 7250 s4.1, RFC 8446 s4.2.
        if (!offered_ours or !offered_theirs) return error.UnsupportedCertificateType;
        self.negotiated_raw_key = true;
        // Nothing in common, so there is no connection to have.
        // Source: RFC 9001 s8.1.
        if (self.accepted.alpn_len == 0) return error.NoApplicationProtocol;
        try self.requiredParams();

        self.transcript.update(msg.raw);
        self.keying = .{ .offered = ks.key[0..32].* };
        self.phase = .wait_certificate;
    }

    /// No extension type may appear twice in one block. A repeat would leave
    /// what we took from the hello depending on which copy was read last, so it
    /// is refused rather than resolved.
    /// Source: RFC 8446 s4.2.
    fn uniqueExtensions(block: []const u8) Error!void {
        var outer = handshake.ExtensionIterator.init(block);
        while (try outer.next()) |a| {
            var inner = handshake.ExtensionIterator.init(block);
            var seen: usize = 0;
            while (try inner.next()) |b| {
                if (b.type == a.type) seen += 1;
            }
            if (seen > 1) return error.ProtocolViolation;
        }
    }

    /// The one key share we can use, out of however many the client offered.
    fn clientKeyShare(ch: handshake.ParsedClientHello) Error!?handshake.KeyShare {
        const body = (try ch.find(.key_share)) orelse return null;
        var r = codec.Reader{ .buf = body };
        var shares = codec.Reader{ .buf = try r.take(try r.readU16()) };
        while (shares.pos < shares.buf.len) {
            const group = try shares.readU16();
            const key = try shares.take(try shares.readU16());
            if (group == @backingInt(NamedGroup.x25519)) {
                return .{ .group = .x25519, .key = key };
            }
        }
        return null;
    }

    /// Whether the ClientHello's supported_versions names TLS 1.3. A client
    /// sends a u8-length list of versions where a ServerHello selects one.
    /// Source: RFC 8446 s4.2.1.
    fn offersTls13(ch: handshake.ParsedClientHello) Error!bool {
        const body = (try ch.find(.supported_versions)) orelse return false;
        var r = codec.Reader{ .buf = body };
        var list = codec.Reader{ .buf = try r.take(try r.readU8()) };
        while (list.pos < list.buf.len) {
            if (try list.readU16() == @backingInt(std.crypto.tls.ProtocolVersion.tls_1_3)) {
                return true;
            }
        }
        return false;
    }

    /// A cipher suite list is whole suites and nothing else, so an odd length
    /// is a message we misread rather than one with a byte to spare.
    /// Source: RFC 8446 s4.1.2.
    fn offers(suites: []const u8, want: u16) Error!bool {
        if (suites.len % 2 != 0) return error.Malformed;
        var i: usize = 0;
        while (i < suites.len) : (i += 2) {
            if (std.mem.readInt(u16, suites[i..][0..2], .big) == want) return true;
        }
        return false;
    }

    /// A certificate_type extension's list, which is a u8 length around one
    /// byte per type. Source: RFC 7250 s4.1.
    fn offersRawPublicKey(body: []const u8) Error!bool {
        var r = codec.Reader{ .buf = body };
        const types = try r.take(try r.readU8());
        return std.mem.indexOfScalar(u8, types, raw_public_key) != null;
    }

    /// The protocol both ends name, taking `alpns` as the order of preference.
    /// Leaves the selection empty when there is no overlap, which the caller
    /// refuses. Source: RFC 9001 s8.1.
    fn selectAlpn(self: *Connection, body: []const u8) Error!void {
        var r = codec.Reader{ .buf = body };
        const offered = try r.take(try r.readU16());
        for (self.alpns) |ours| {
            var list = codec.Reader{ .buf = offered };
            while (list.pos < list.buf.len) {
                const name = try list.take(try list.readU8());
                if (!std.mem.eql(u8, name, ours)) continue;
                if (name.len > self.accepted.alpn_buf.len) return error.BufferTooSmall;
                @memcpy(self.accepted.alpn_buf[0..name.len], name);
                self.accepted.alpn_len = name.len;
                return;
            }
        }
    }

    /// The ServerHello answering the ClientHello, sealed as our first Initial.
    /// Writing it and deriving are one step: the handshake traffic secrets take
    /// the transcript through it inclusive, so this runs once, and `hello_buf`
    /// keeps the message for `sealInitialRetransmit` to send again.
    /// Source: RFC 8446 s4.1.3, RFC 9001 s5.
    pub fn sealServerHello(
        self: *Connection,
        out: []u8,
        hello_buf: []u8,
        random: handshake.Random,
    ) Error!Initial {
        const offered = switch (self.keying) {
            .offered => |key| key,
            else => return error.HandshakeIncomplete,
        };
        if (self.amplificationBlocked()) return error.AmplificationLimited;
        const kp = std.crypto.dh.X25519.KeyPair.generateDeterministic(self.secret);

        // The extensions are part of the message, so its length covers them too.
        var ext: [max_server_hello]u8 = undefined;
        var ew = std.Io.Writer.fixed(&ext);
        handshake.writeServerKeyShare(&ew, kp.public_key) catch return error.BufferTooSmall;
        handshake.writeSelectedVersion(&ew) catch return error.BufferTooSmall;

        const sh = try handshake.writeServerHello(hello_buf, .{
            .random = random,
            .cipher_suite = cipher_suite,
            .extensions = ew.buffered(),
        });

        const shared = tls.x25519(self.secret, offered) catch return error.UnsupportedGroup;

        // Everything that can fail happens first: the transcript cannot be
        // unhashed, and a keying left `.derived` with nothing sent has no way
        // back to answering the ClientHello.
        const pn = self.nextPacketNumber(.initial).*;
        const n = try sealInitialCrypto(out, .{
            .kind = .initial,
            .dcid = self.accepted.scid(),
            .scid = self.our_scid[0..self.our_cid_len],
            .pn = pn,
            .pn_len = packet.max_pn_len,
        }, self.initial_keys.send, sh);

        self.transcript.update(sh);
        const secret = tls.handshakeSecret(tls.earlySecret(), &shared);
        const hs = tls.handshakeTraffic(secret, self.transcript.hash());

        self.accepted.cipher_suite = cipher_suite;
        self.accepted.handshake = hs;
        self.keying = .{ .derived = .{
            .secret = secret,
            .keys = crypto.keysFromSecret(self.role.theirs(hs)),
        } };

        _ = self.takePacketNumber(.initial);
        return .{ .len = self.tracked(.initial, pn, n), .hello = sh };
    }

    fn clientMessage(self: *Connection, msg: handshake.Message) Error!void {
        switch (msg.type) {
            .server_hello => {
                if (self.phase != .wait_server_hello) return error.UnexpectedMessage;
                const sh = try handshake.parseServerHello(msg.raw);
                if (sh.isHelloRetryRequest()) return error.HelloRetryRequest;
                if (sh.cipher_suite != cipher_suite) return error.UnsupportedCipherSuite;

                const ks = (try sh.keyShare()) orelse return error.Malformed;
                if (ks.group != .x25519 or ks.key.len != 32) return error.UnsupportedGroup;

                // The handshake traffic secrets take the transcript through
                // ServerHello inclusive, so hash before deriving.
                self.transcript.update(msg.raw);
                const shared = tls.x25519(self.secret, ks.key[0..32].*) catch
                    return error.UnsupportedGroup;
                const secret = tls.handshakeSecret(tls.earlySecret(), &shared);
                const hs = tls.handshakeTraffic(secret, self.transcript.hash());

                self.accepted.cipher_suite = sh.cipher_suite;
                self.accepted.handshake = hs;
                self.keying = .{ .derived = .{ .secret = secret, .keys = crypto.keysFromSecret(self.role.theirs(hs)) } };
                self.phase = .wait_encrypted_extensions;
            },
            .encrypted_extensions => {
                if (self.phase != .wait_encrypted_extensions) return error.UnexpectedMessage;
                self.transcript.update(msg.raw);
                try self.encryptedExtensions(msg.body);
                self.phase = .wait_certificate_or_request;
            },
            .certificate_request => {
                if (self.phase != .wait_certificate_or_request) return error.UnexpectedMessage;
                var r = codec.Reader{ .buf = msg.body };
                const ctx = try r.take(try r.readU8());
                if (ctx.len > self.request_buf.len) return error.BufferTooSmall;
                @memcpy(self.request_buf[0..ctx.len], ctx);
                self.request_len = ctx.len;
                self.requested = true;
                self.transcript.update(msg.raw);
                self.phase = .wait_certificate;
            },
            .new_session_ticket => {
                // Post-handshake, so outside the transcript entirely.
                if (self.phase != .connected) return error.UnexpectedMessage;
            },
            else => return error.UnexpectedMessage,
        }
    }

    fn authMessage(self: *Connection, msg: handshake.Message) Error!void {
        switch (msg.type) {
            .certificate => {
                switch (self.phase) {
                    .wait_certificate_or_request, .wait_certificate => {},
                    else => return error.UnexpectedMessage,
                }
                self.transcript.update(msg.raw);
                self.accepted.peer_key = try handshake.rawPublicKey(msg.body);
                self.phase = .wait_certificate_verify;
            },
            .certificate_verify => {
                if (self.phase != .wait_certificate_verify) return error.UnexpectedMessage;
                try self.certificateVerify(msg.body);
                self.transcript.update(msg.raw);
                self.phase = .wait_finished;
            },
            .finished => {
                if (self.phase != .wait_finished) return error.UnexpectedMessage;
                // Reaching 1-RTT with an unauthenticated peer must not be
                // possible: the key in the certificate has to have signed the
                // transcript.
                if (!self.accepted.peer_verified) return error.BadCertificateVerify;
                const hs = self.accepted.handshake orelse return error.Malformed;
                const expect = tls.verifyData(self.role.theirs(hs), self.transcript.hash());
                if (msg.body.len != expect.len) return error.BadFinished;
                if (!std.crypto.timing_safe.eql([32]u8, expect, msg.body[0..32].*)) {
                    return error.BadFinished;
                }
                self.transcript.update(msg.raw);
                // A client is reading the server's Finished, which is where the
                // 1-RTT secrets come from. A server is reading the client's,
                // and derived its own back when it wrote the flight.
                if (self.role == .client) try self.deriveApplication();
                self.phase = .connected;
                // A server's handshake is confirmed the moment it completes,
                // and it owes the client the frame that says so.
                // Source: RFC 9001 s4.1.2.
                if (self.role == .server) {
                    self.confirmed = true;
                    self.recovery.confirmed = true;
                    self.handshake_done_owed = true;
                }
            },
            else => return error.UnexpectedMessage,
        }
    }

    /// The 1-RTT secrets, taken from the transcript through the server's
    /// Finished. Both roles derive at that one point, which a server reaches by
    /// writing that message and a client by reading it.
    /// Source: RFC 8446 s7.1.
    fn deriveApplication(self: *Connection) Error!void {
        const d = self.keying.get() orelse return error.KeysUnavailable;
        const app = tls.applicationTraffic(tls.masterSecret(d.secret), self.transcript.hash());
        self.accepted.application = app;
        self.app_keys = .{
            .send = crypto.keysFromSecret(self.role.ours(app)),
            .recv = crypto.keysFromSecret(self.role.theirs(app)),
        };
    }

    /// Hashes the message `writeFlight` just appended, which is everything
    /// written since `at`, and returns where the next one starts.
    fn hashFrom(self: *Connection, w: *const std.Io.Writer, at: usize) usize {
        self.transcript.update(w.buffered()[at..]);
        return w.buffered().len;
    }

    /// Our half of the handshake, as one CRYPTO stream. A server leads with
    /// EncryptedExtensions and a CertificateRequest, then both roles write
    /// Certificate and CertificateVerify when the peer wants authenticating,
    /// and Finished last. Each message is hashed as it is written, since the
    /// two that sign the transcript cover everything before themselves.
    ///
    /// Advances the transcript, so it can only be called once.
    /// Source: RFC 8446 s4.3, s4.4.
    pub fn writeFlight(self: *Connection, out: []u8, key: Ed25519.KeyPair) Error![]const u8 {
        switch (self.role) {
            // A client answers a handshake it has already verified. A server
            // writes as soon as the ServerHello gave it keys to encrypt under,
            // which is well before it has heard back.
            .client => if (!self.done()) return error.HandshakeIncomplete,
            .server => if (self.keying.get() == null) return error.HandshakeIncomplete,
        }
        // The transcript advances past the flight, so a second call would sign
        // and MAC over the wrong prefix. Retransmission resends these bytes.
        if (self.flight_sent) return error.FlightAlreadySent;
        self.flight_sent = true;
        const hs = self.accepted.handshake orelse return error.HandshakeIncomplete;

        var w = std.Io.Writer.fixed(out);
        var at: usize = 0;
        if (self.role == .server) {
            var ext: [handshake.max_extensions]u8 = undefined;
            var ew = std.Io.Writer.fixed(&ext);
            writeServerExtensions(
                &ew,
                self.accepted.alpn(),
                self.our_scid[0..self.our_cid_len],
                self.original_dcid[0..self.original_dcid_len],
                self.window,
            ) catch return error.BufferTooSmall;

            handshake.writeEncryptedExtensions(&w, ew.buffered()) catch return error.BufferTooSmall;
            at = self.hashFrom(&w, at);

            // radicle authenticates both ends, so the client is asked for a key
            // too. The context is empty: there is only ever one request here,
            // so nothing needs matching up.
            // Source: RFC 8446 s4.3.2.
            handshake.writeCertificateRequest(
                &w,
                &.{},
                &certificate_request_extensions,
            ) catch return error.BufferTooSmall;
            at = self.hashFrom(&w, at);
        }

        // A server always authenticates; a client only when asked to.
        if (self.role == .server or self.requested) {
            handshake.writeRawPublicKeyCertificate(
                &w,
                self.request_buf[0..self.request_len],
                key.public_key.toBytes(),
            ) catch return error.BufferTooSmall;
            at = self.hashFrom(&w, at);

            var content: [handshake.max_verify_content]u8 = undefined;
            const signed = try handshake.verifyContent(
                &content,
                self.role.ourVerifyContext(),
                self.transcript.hash(),
            );
            const sig = (key.sign(signed, null) catch return error.BadCertificateVerify).toBytes();

            handshake.writeCertificateVerify(
                &w,
                @backingInt(SignatureScheme.ed25519),
                &sig,
            ) catch return error.BufferTooSmall;
            at = self.hashFrom(&w, at);
        }

        const vd = tls.verifyData(self.role.ours(hs), self.transcript.hash());
        handshake.writeMessage(&w, .finished, &vd) catch return error.BufferTooSmall;
        _ = self.hashFrom(&w, at);

        // This is the server's Finished, so the transcript now stands where
        // both roles take their 1-RTT secrets from.
        if (self.role == .server) try self.deriveApplication();
        return w.buffered();
    }

    /// A `writeFlight` stream sealed into a Handshake packet, addressed to the
    /// id the server gave us. The packet number is fresh each time, so resending
    /// is calling this again with the same bytes.
    pub fn sealFlight(self: *Connection, out: []u8, flight: []const u8) Error!usize {
        const hs = self.accepted.handshake orelse return error.HandshakeIncomplete;
        if (self.amplificationBlocked()) return error.AmplificationLimited;
        const pn = self.takePacketNumber(.handshake);

        // A CRYPTO frame is a type byte then two varints, around the flight.
        var frame_buf: [max_flight + 1 + 2 * codec.max_varint_len]u8 = undefined;
        var fw = std.Io.Writer.fixed(&frame_buf);
        writeCryptoFrame(&fw, 0, flight) catch return error.BufferTooSmall;

        const n = try packet.seal(out, .{
            .kind = .handshake,
            .dcid = self.accepted.scid(),
            .scid = self.our_scid[0..self.our_cid_len],
            .pn = pn,
            .pn_len = packet.max_pn_len,
        }, fw.buffered(), crypto.keysFromSecret(self.role.ours(hs)));
        return self.tracked(.handshake, pn, n);
    }

    /// Checks the peer's signature over the transcript through Certificate.
    /// Only the raw public key profile is verifiable: an X.509 chain signs with
    /// ECDSA or RSA, neither of which radish has.
    fn certificateVerify(self: *Connection, body: []const u8) Error!void {
        const cv = try handshake.parseCertificateVerify(body);
        if (cv.algorithm != @backingInt(SignatureScheme.ed25519)) return error.UnsupportedSignature;
        if (cv.signature.len != Ed25519.Signature.encoded_length) return error.BadCertificateVerify;
        const key = self.accepted.peer_key orelse return error.Malformed;

        var content: [handshake.max_verify_content]u8 = undefined;
        const signed = try handshake.verifyContent(
            &content,
            self.role.peerVerifyContext(),
            self.transcript.hash(),
        );

        const pk = Ed25519.PublicKey.fromBytes(key) catch return error.BadCertificateVerify;
        const sig = Ed25519.Signature.fromBytes(cv.signature[0..Ed25519.Signature.encoded_length].*);
        sig.verify(signed, pk) catch return error.BadCertificateVerify;
        self.accepted.peer_verified = true;
    }

    fn encryptedExtensions(self: *Connection, body: []const u8) Error!void {
        var r = codec.Reader{ .buf = body };
        var it = handshake.ExtensionIterator.init(try r.take(try r.readU16()));
        while (try it.next()) |e| switch (e.type) {
            .server_certificate_type => {
                if (e.body.len != 1) return error.Malformed;
                // The server must select from the list the client offered, and
                // raw_public_key is the only entry.
                // Source: RFC 7250 s4.1.
                if (e.body[0] != raw_public_key) return error.UnsupportedCertificateType;
                self.negotiated_raw_key = true;
            },
            .application_layer_protocol_negotiation => {
                var ar = codec.Reader{ .buf = e.body };
                _ = try ar.readU16(); // list length
                const name = try ar.take(try ar.readU8());
                if (name.len > self.accepted.alpn_buf.len) return error.BufferTooSmall;
                @memcpy(self.accepted.alpn_buf[0..name.len], name);
                self.accepted.alpn_len = name.len;
            },
            .quic_transport_parameters => try self.transportParams(e.body),
            else => {},
        };

        // A server that cannot do raw public keys either omits the extension or
        // sends an unsupported_certificate alert. Both end the connection here,
        // since the alternative is an unauthenticated peer.
        // Source: RFC 7250 s4.2.
        if (!self.negotiated_raw_key) return error.UnsupportedCertificateType;
        // A server that selected nothing we offered, or no protocol at all.
        // Source: RFC 9001 s8.1.
        if (self.accepted.alpn_len == 0) return error.NoApplicationProtocol;
        try self.requiredParams();
    }

    /// The connection ids the peer owed us, once the extension carrying them
    /// has been read. Only a server sends `original_dcid`.
    /// Source: RFC 9000 s7.3.
    fn requiredParams(self: *const Connection) Error!void {
        if (!self.saw_initial_scid) return error.TransportParameterError;
        if (self.role == .client and !self.saw_original_dcid) {
            return error.TransportParameterError;
        }
    }

    /// A transport parameter whose value is a single varint.
    fn varintParam(value: []const u8) Error!u64 {
        var r = codec.Reader{ .buf = value };
        const v = try r.varint();
        if (r.pos != value.len) return error.TransportParameterError;
        return v;
    }

    /// Checks the connection ids the peer claims against the ones actually on
    /// the packets. Nothing else authenticates them: they travel in cleartext
    /// headers, so only this comparison ties them to the handshake. Four are a
    /// server's to send, and a client sending one is an error.
    /// Source: RFC 9000 s7.3, s18.2.
    fn transportParams(self: *Connection, body: []const u8) Error!void {
        var it = handshake.TransportParamIterator.init(body);
        while (try it.next()) |p| switch (p.id) {
            .initial_source_connection_id => {
                if (!std.mem.eql(u8, p.value, self.accepted.scid())) {
                    return error.TransportParameterError;
                }
                self.saw_initial_scid = true;
            },
            .original_destination_connection_id => {
                if (self.role == .server) return error.TransportParameterError;
                if (!std.mem.eql(u8, p.value, self.original_dcid[0..self.original_dcid_len])) {
                    return error.TransportParameterError;
                }
                self.saw_original_dcid = true;
            },
            .preferred_address, .retry_source_connection_id => {
                if (self.role == .server) return error.TransportParameterError;
            },
            .max_idle_timeout => self.peer_idle_ms = try varintParam(p.value),
            // What a lost connection will be proved with, and how long the peer
            // may sit on an acknowledgement before sending it.
            // Source: RFC 9000 s10.3, s13.2.1.
            .stateless_reset_token => {
                if (self.role == .server) return error.TransportParameterError;
                if (p.value.len != 16) return error.TransportParameterError;
                self.peer_reset_token = p.value[0..16].*;
            },
            .max_ack_delay => self.recovery.peer_max_ack_delay_ms = try varintParam(p.value),
            .ack_delay_exponent => {
                const e = try varintParam(p.value);
                // Anything larger would scale a delay past any real time.
                // Source: RFC 9000 s18.2.
                if (e > 20) return error.TransportParameterError;
                self.peer_ack_exponent = @intCast(e);
            },
            .initial_max_data => self.send_data.extend(try varintParam(p.value)),
            // The limit on the one stream, which the client always opens: the
            // peer's `bidi_local` covers a stream it opened itself, and its
            // `bidi_remote` one we opened.
            // Source: RFC 9000 s18.2.
            .initial_max_stream_data_bidi_local => {
                if (self.role == .server) self.send_stream.extend(try varintParam(p.value));
            },
            .initial_max_stream_data_bidi_remote => {
                if (self.role == .client) self.send_stream.extend(try varintParam(p.value));
            },
            else => {},
        };
    }
};

const testing = std.testing;
const testdata = @import("testdata.zig");
const hex = testdata.hex;

/// Buffers a connection borrows, declared by the caller because they outlive
/// the call that made it. The send buffer holds two full packets' worth, for
/// the tests that fill the sender.
const TestBufs = struct {
    initial: [1024]u8 = undefined,
    handshake: [1024]u8 = undefined,
    send: [2 * max_stream_chunk]u8 = undefined,
};

/// A connection addressing itself, for tests that only drive one side.
fn testConnection(dcid: []const u8, bufs: *TestBufs) Connection {
    return Connection.init(.{
        .original_dcid = dcid,
        .our_scid = dcid,
        .client_hello = "",
        .secret = hex(testdata.fixed_x25519_secret),
        .initial_buf = &bufs.initial,
        .handshake_buf = &bufs.handshake,
    });
}

/// The same, with application keys in place so the 1-RTT paths run. One key
/// both ways, so a packet we seal is one we can also open.
fn appConnection(dcid: []const u8, bufs: *TestBufs, stream_buf: []u8) Connection {
    var h = Connection.init(.{
        .original_dcid = dcid,
        .our_scid = dcid,
        .client_hello = "",
        .secret = hex(testdata.fixed_x25519_secret),
        .initial_buf = &bufs.initial,
        .handshake_buf = &bufs.handshake,
        .stream_buf = stream_buf,
        .send_buf = &bufs.send,
    });
    const keys = crypto.keysFromSecret(crypto.initialSecrets(dcid).client);
    h.app_keys = .{ .send = keys, .recv = keys };
    h.accepted.scid_len = dcid.len;
    @memcpy(h.accepted.scid_buf[0..dcid.len], dcid);
    return h;
}

/// Opens a packet we sealed ourselves. `open` decrypts in place, so it works on
/// a copy and leaves the sealed bytes intact for further assertions.
fn openOurs(dcid: []const u8, sealed: []const u8, scratch: []u8, plain: []u8) !packet.Opened {
    @memcpy(scratch[0..sealed.len], sealed);
    return packet.open(
        plain,
        scratch[0..sealed.len],
        crypto.keysFromSecret(crypto.initialSecrets(dcid).client),
        null,
    );
}

// The wiring end to end: one datagram carrying an Initial and a Handshake
// packet, with the Handshake CRYPTO stream split in two and the tail arriving
// first. The server side is built here, so this pins the plumbing rather than
// another implementation.
test "walks a coalesced flight and reads a raw public key certificate" {
    const dcid = hex(testdata.other_dcid);
    const server_scid = hex("aabbccdd");
    const secret = hex(testdata.fixed_x25519_secret);

    var mine: [1500]u8 = undefined;
    var hello_buf: [max_client_hello]u8 = undefined;
    const kp = std.crypto.dh.X25519.KeyPair.generateDeterministic(secret);
    const initial = try initialDatagram(&mine, &hello_buf, .{
        .dcid = &dcid,
        .scid = &dcid,
        .random = hex(testdata.fixed_hello_random),
        .public_key = kp.public_key,
        .alpn = "radicle/2",
    });

    // RFC 8448's ServerHello: its key share pairs with fixed_x25519_secret, so
    // the schedule below actually runs.
    var sh: [90]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sh, testdata.rfc8448_server_hello_hex);

    // The keys the server would use, derived the same way the Connection will.
    var t: handshake.Transcript = .{};
    t.update(initial.hello);
    t.update(&sh);
    const share = (try (try handshake.parseServerHello(&sh)).keyShare()).?.key;
    const shared = try tls.x25519(secret, share[0..32].*);
    const hs = tls.handshakeTraffic(tls.handshakeSecret(tls.earlySecret(), &shared), t.hash());

    // EncryptedExtensions announcing raw public keys and the ALPN, then a
    // Certificate holding one ed25519 SubjectPublicKeyInfo, then Finished.
    // A real key from a fixed seed, so CertificateVerify can sign against it
    // once that lands.
    const server_key = try Ed25519.KeyPair.generateDeterministic(hex(testdata.fixed_peer_identity_seed));
    const peer_key = server_key.public_key.toBytes();
    // Hashed one message at a time: CertificateVerify and Finished each cover
    // the transcript up to but not including themselves.
    var server_flight: [1024]u8 = undefined;
    var stw = std.Io.Writer.fixed(&server_flight);
    var st: handshake.Transcript = .{};
    st.update(initial.hello);
    st.update(&sh);

    {
        var ext: [64]u8 = undefined;
        var ew = std.Io.Writer.fixed(&ext);
        try handshake.writeExtension(&ew, @backingInt(ExtensionType.server_certificate_type), &.{raw_public_key});
        // The list is one name, length-prefixed twice: the list, then the name.
        const alpn = "radicle/2";
        const alpn_ext = [_]u8{ 0, alpn.len + 1, alpn.len } ++ alpn.*;
        try handshake.writeExtension(&ew, @backingInt(ExtensionType.application_layer_protocol_negotiation), &alpn_ext);

        // Both ids are mandatory and must echo what is on the packets.
        var params: [64]u8 = undefined;
        var ppw = std.Io.Writer.fixed(&params);
        try handshake.writeTransportParam(&ppw, .initial_source_connection_id, &server_scid);
        try handshake.writeTransportParam(&ppw, .original_destination_connection_id, &dcid);
        try handshake.writeExtension(&ew, @backingInt(ExtensionType.quic_transport_parameters), ppw.buffered());

        var body: [128]u8 = undefined;
        var bw = std.Io.Writer.fixed(&body);
        try bw.writeInt(u16, @intCast(ew.buffered().len), .big);
        try bw.writeAll(ew.buffered());

        const at = stw.buffered().len;
        try handshake.writeMessage(&stw, .encrypted_extensions, bw.buffered());
        st.update(stw.buffered()[at..]);
    }
    {
        // Asking for a client certificate, so the mTLS path is exercised.
        var body: [8]u8 = undefined;
        var bw = std.Io.Writer.fixed(&body);
        try bw.writeInt(u8, 0, .big); // certificate_request_context
        try bw.writeInt(u16, 0, .big); // extensions

        const at = stw.buffered().len;
        try handshake.writeMessage(&stw, .certificate_request, bw.buffered());
        st.update(stw.buffered()[at..]);
    }
    {
        const at = stw.buffered().len;
        try handshake.writeRawPublicKeyCertificate(&stw, &.{}, peer_key);
        st.update(stw.buffered()[at..]);
    }
    {
        var content: [handshake.max_verify_content]u8 = undefined;
        const signed = try handshake.verifyContent(&content, handshake.server_verify_context, st.hash());
        const sig = (try server_key.sign(signed, null)).toBytes();

        const at = stw.buffered().len;
        try handshake.writeCertificateVerify(&stw, @backingInt(SignatureScheme.ed25519), &sig);
        st.update(stw.buffered()[at..]);
    }
    {
        const vd = tls.verifyData(hs.server, st.hash());
        const at = stw.buffered().len;
        try handshake.writeMessage(&stw, .finished, &vd);
        st.update(stw.buffered()[at..]);
    }
    const messages = stw.buffered();

    var buf: [2048]u8 = undefined;
    var used: usize = 0;
    {
        var fw = std.Io.Writer.fixed(buf[0..]);
        try writeCryptoFrame(&fw, 0, &sh);
        var pkt: [512]u8 = undefined;
        const n = try packet.seal(&pkt, .{
            .kind = .initial,
            .dcid = &dcid,
            .scid = &server_scid,
            .pn = 0,
            .pn_len = packet.max_pn_len,
        }, fw.buffered(), crypto.keysFromSecret(crypto.initialSecrets(&dcid).server));
        @memcpy(buf[used..][0..n], pkt[0..n]);
        used += n;
    }
    {
        // Tail first, so `contiguous` yields nothing until the head lands.
        const split = 20;
        var frames_buf: [1024]u8 = undefined;
        var fw = std.Io.Writer.fixed(&frames_buf);
        try writeCryptoFrame(&fw, split, messages[split..]);
        try writeCryptoFrame(&fw, 0, messages[0..split]);

        var pkt: [1024]u8 = undefined;
        const n = try packet.seal(&pkt, .{
            .kind = .handshake,
            .dcid = &dcid,
            .scid = &server_scid,
            .pn = 0,
            .pn_len = packet.max_pn_len,
        }, fw.buffered(), crypto.keysFromSecret(hs.server));
        @memcpy(buf[used..][0..n], pkt[0..n]);
        used += n;
    }

    var plain: [2048]u8 = undefined;
    var initial_crypto: [4096]u8 = undefined;
    var handshake_crypto: [4096]u8 = undefined;
    var h = Connection.init(.{
        .original_dcid = &dcid,
        .our_scid = &dcid,
        .client_hello = initial.hello,
        .secret = secret,
        .initial_buf = &initial_crypto,
        .handshake_buf = &handshake_crypto,
    });
    try h.push(&plain, buf[0..used]);

    const a = h.accepted;
    try testing.expectEqual(cipher_suite, a.cipher_suite);
    try testing.expectEqualSlices(u8, &server_scid, a.scid());
    try testing.expectEqualSlices(u8, &hs.server, &a.handshake.?.server);
    try testing.expect(h.negotiated_raw_key);
    try testing.expectEqualSlices(u8, &peer_key, &a.peer_key.?);
    try testing.expectEqualStrings("radicle/2", a.alpn());
    try testing.expect(a.peer_verified);
    try testing.expect(h.done());
    try testing.expect(a.application != null);

    // Our half of mutual authentication, checked the way the server would:
    // Certificate echoing the request context, CertificateVerify over the
    // transcript through it, then Finished under the client secret.
    const our_key = try Ed25519.KeyPair.generateDeterministic(hex(testdata.fixed_identity_seed));
    var messages_buf: [1024]u8 = undefined;
    var flight: [1024]u8 = undefined;
    const sent = try h.sealFlight(&flight, try h.writeFlight(&messages_buf, our_key));

    var mirror: handshake.Transcript = .{};
    mirror.update(initial.hello);
    mirror.update(&sh);
    mirror.update(messages);

    var opened_buf: [1024]u8 = undefined;
    var copy: [1024]u8 = undefined;
    @memcpy(copy[0..sent], flight[0..sent]);
    const ours = try packet.open(&opened_buf, copy[0..sent], crypto.keysFromSecret(hs.client), null);

    var fit = frame.Iterator.init(ours.payload);
    const ours_crypto = (try fit.next()).?.crypto;
    try testing.expectEqual(@as(u64, 0), ours_crypto.offset);

    var mit = handshake.MessageIterator.init(ours_crypto.data);
    const cert = mit.next().?;
    try testing.expectEqual(std.crypto.tls.HandshakeType.certificate, cert.type);
    try testing.expectEqualSlices(u8, &our_key.public_key.toBytes(), &try handshake.rawPublicKey(cert.body));
    mirror.update(cert.raw);

    const cv = mit.next().?;
    try testing.expectEqual(std.crypto.tls.HandshakeType.certificate_verify, cv.type);
    {
        const parsed = try handshake.parseCertificateVerify(cv.body);
        try testing.expectEqual(@as(u16, @backingInt(SignatureScheme.ed25519)), parsed.algorithm);
        var content: [handshake.max_verify_content]u8 = undefined;
        const signed = try handshake.verifyContent(&content, handshake.client_verify_context, mirror.hash());
        const sig = Ed25519.Signature.fromBytes(parsed.signature[0..64].*);
        try sig.verify(signed, our_key.public_key);
    }
    mirror.update(cv.raw);

    const fin = mit.next().?;
    try testing.expectEqual(std.crypto.tls.HandshakeType.finished, fin.type);
    try testing.expectEqualSlices(u8, &tls.verifyData(hs.client, mirror.hash()), fin.body);
    try testing.expectEqual(@as(?handshake.Message, null), mit.next());

    // The server's 1-RTT reply: HANDSHAKE_DONE confirming our flight, and a
    // PATH_CHALLENGE we owe an answer to. Sent to the id we chose for ourselves,
    // whose length is all a short header gives the receiver.
    const app = a.application.?;
    var one_rtt: [256]u8 = undefined;
    var ow = std.Io.Writer.fixed(&one_rtt);
    try codec.writeVarint(&ow, @backingInt(frame.Type.handshake_done));
    try codec.writeVarint(&ow, @backingInt(frame.Type.path_challenge));
    try ow.writeAll(&[_]u8{ 9, 9, 9, 9, 9, 9, 9, 9 });

    var sealed: [512]u8 = undefined;
    const m = try packet.sealShort(&sealed, .{
        .dcid = &dcid,
        .pn = 0,
        .pn_len = packet.max_pn_len,
    }, ow.buffered(), crypto.keysFromSecret(app.server));

    try h.push(&plain, sealed[0..m]);
    try testing.expect(h.confirmed);
    try testing.expectEqualSlices(u8, &.{ 9, 9, 9, 9, 9, 9, 9, 9 }, &h.path_challenge.?);

    // Echoed back under our own application key, and the debt cleared.
    var response: [256]u8 = undefined;
    const r = (try h.sealPathResponse(&response)).?;
    var rcopy: [256]u8 = undefined;
    @memcpy(rcopy[0..r], response[0..r]);
    const echoed = try packet.openShort(&opened_buf, rcopy[0..r], server_scid.len, crypto.keysFromSecret(app.client), null);

    var rit = frame.Iterator.init(echoed.payload);
    try testing.expectEqualSlices(u8, &.{ 9, 9, 9, 9, 9, 9, 9, 9 }, &(try rit.next()).?.path_response);
    try testing.expectEqual(@as(?[8]u8, null), h.path_challenge);
    try testing.expectEqual(@as(?usize, null), try h.sealPathResponse(&response));
}

/// A server waiting on a ClientHello. `scid` is the id it gives for itself,
/// which is its own to choose and so is not the one the client addressed. The
/// client's id arrives on the first Initial, so a test that pushes no datagram
/// hands the hello over with `tellsHello` instead.
fn serverConnection(dcid: []const u8, scid: []const u8, bufs: *TestBufs) Connection {
    return Connection.init(.{
        .role = .server,
        .original_dcid = dcid,
        .our_scid = scid,
        .client_hello = "",
        .alpns = &.{ "radicle/gossip/1", "radicle/git/1" },
        .secret = hex(testdata.fixed_server_x25519_secret),
        .initial_buf = &bufs.initial,
        .handshake_buf = &bufs.handshake,
    });
}

/// A ClientHello as a datagram would deliver it: the client's source
/// connection id off the Initial header, then the message. The transport
/// parameters are checked against that id, so it has to be there first.
fn tellsHello(h: *Connection, scid: []const u8, raw: []const u8) Error!void {
    h.accepted.scid_len = scid.len;
    @memcpy(h.accepted.scid_buf[0..scid.len], scid);
    return h.message(firstMessage(raw));
}

test "a server reads what a ClientHello offered, and refuses one without raw public keys" {
    const dcid = hex(testdata.other_dcid);
    const server_scid = hex("aabbccdd");
    const kp = std.crypto.dh.X25519.KeyPair.generateDeterministic(hex(testdata.fixed_x25519_secret));

    var out: [1500]u8 = undefined;
    var hello_buf: [max_client_hello]u8 = undefined;
    const initial = try initialDatagram(&out, &hello_buf, .{
        .dcid = &dcid,
        .scid = &dcid,
        .random = hex(testdata.fixed_hello_random),
        .public_key = kp.public_key,
        .alpn = "radicle/git/1",
        .window = 4096,
    });

    var bufs: TestBufs = .{};
    var h = serverConnection(&dcid, &server_scid, &bufs);
    try tellsHello(&h, &dcid, initial.hello);

    try testing.expectEqualStrings("radicle/git/1", h.accepted.alpn());
    try testing.expect(h.negotiated_raw_key);
    try testing.expectEqualSlices(u8, &kp.public_key, &h.keying.offered);
    // What the client said it would hold, and so what we may send it.
    try testing.expectEqual(@as(u64, 4096), h.send_stream.limit);
    try testing.expectEqual(Connection.Phase.wait_certificate, h.phase);

    // An X.509 chain in place of a raw key: neither end here can read a
    // certificate chain, so there is nothing to fall back to.
    var chain: [max_client_hello]u8 = undefined;
    var cw = std.Io.Writer.fixed(&chain);
    try handshake.writeSupportedVersions(&cw);
    try handshake.writeKeyShare(&cw, kp.public_key);
    try handshake.writeExtension(&cw, @backingInt(ExtensionType.server_certificate_type), &.{ 1, 0 });
    try refuses(&dcid, &server_scid, .{
        .random = hex(testdata.fixed_hello_random),
        .cipher_suites = &.{cipher_suite},
        .extensions = cw.buffered(),
    }, error.UnsupportedCertificateType);

    // The extensions a good hello carries, so the two below differ from a
    // workable one by exactly the thing being refused.
    var ext: [512]u8 = undefined;
    var ew = std.Io.Writer.fixed(&ext);
    try handshake.writeSupportedVersions(&ew);
    try handshake.writeKeyShare(&ew, kp.public_key);
    try handshake.writeExtension(&ew, @backingInt(ExtensionType.server_certificate_type), &certificate_types);

    // Middlebox compatibility mode, which is what a non-empty session id means
    // and which has no use over QUIC.
    // Source: RFC 9001 s8.4.
    try refuses(&dcid, &server_scid, .{
        .random = hex(testdata.fixed_hello_random),
        .session_id = &@as([32]u8, @splat(0)),
        .cipher_suites = &.{cipher_suite},
        .extensions = ew.buffered(),
    }, error.ProtocolViolation);

    // Only a version the client offered may be selected, and a hello with no
    // supported_versions has offered 1.2 at best.
    // Source: RFC 8446 s4.2.1.
    var old: [max_client_hello]u8 = undefined;
    var ow = std.Io.Writer.fixed(&old);
    try handshake.writeKeyShare(&ow, kp.public_key);
    try handshake.writeExtension(&ow, @backingInt(ExtensionType.server_certificate_type), &certificate_types);
    try refuses(&dcid, &server_scid, .{
        .random = hex(testdata.fixed_hello_random),
        .cipher_suites = &.{cipher_suite},
        .extensions = ow.buffered(),
    }, error.UnsupportedVersion);
}

test "a server's stream credit is the limit for the stream the client opened" {
    const dcid = hex(testdata.other_dcid);
    const server_scid = hex("aabbccdd");
    const kp = std.crypto.dh.X25519.KeyPair.generateDeterministic(hex(testdata.fixed_x25519_secret));

    // Asymmetric on purpose: `bidi_remote` is the limit on a stream the server
    // opens, and there is never one.
    // Source: RFC 9000 s18.2.
    var params: [max_transport_params]u8 = undefined;
    var pw = std.Io.Writer.fixed(&params);
    try handshake.writeIntTransportParam(&pw, .initial_max_data, 8192);
    try handshake.writeIntTransportParam(&pw, .initial_max_stream_data_bidi_local, 4096);
    try handshake.writeIntTransportParam(&pw, .initial_max_stream_data_bidi_remote, 0);
    try handshake.writeTransportParam(&pw, .initial_source_connection_id, &dcid);

    var buf: [max_client_hello]u8 = undefined;
    const raw = try testHello(&buf, .{ .key = kp.public_key, .params = pw.buffered() });

    var bufs: TestBufs = .{};
    var h = serverConnection(&dcid, &server_scid, &bufs);
    try tellsHello(&h, &dcid, raw);
    try testing.expectEqual(@as(u64, 4096), h.send_stream.limit);
    try testing.expectEqual(@as(u64, 8192), h.send_data.limit);
}

test "the streams a hello allows are the ones the peer opens" {
    // radish handles one stream and the client is always the end that opens it,
    // so a server allows one and a client none.
    // Source: RFC 9000 s18.2.
    const scid = hex(testdata.other_dcid);

    var server: [max_client_extensions]u8 = undefined;
    var sw = std.Io.Writer.fixed(&server);
    try writeServerExtensions(&sw, "radicle/git/1", &scid, &scid, default_window);
    try testing.expectEqual(@as(u64, 1), try streamsBidi(sw.buffered()));

    var client: [max_client_extensions]u8 = undefined;
    var cw = std.Io.Writer.fixed(&client);
    try writeExtensions(&cw, .{
        .dcid = &scid,
        .scid = &scid,
        .random = @splat(0),
        .public_key = @splat(0),
        .alpn = "radicle/git/1",
    });
    try testing.expectEqual(@as(u64, 0), try streamsBidi(cw.buffered()));
}

/// The initial_max_streams_bidi in an extension block's transport parameters.
fn streamsBidi(extensions: []const u8) !u64 {
    var it = handshake.ExtensionIterator.init(extensions);
    while (try it.next()) |e| {
        if (e.type != .quic_transport_parameters) continue;
        var pit = handshake.TransportParamIterator.init(e.body);
        while (try pit.next()) |p| {
            if (p.id == .initial_max_streams_bidi) return Connection.varintParam(p.value);
        }
    }
    return error.Malformed;
}

test "a server refuses a ClientHello it has nothing in common with" {
    const dcid = hex(testdata.other_dcid);
    const server_scid = hex("aabbccdd");
    const kp = std.crypto.dh.X25519.KeyPair.generateDeterministic(hex(testdata.fixed_x25519_secret));
    var buf: [max_client_hello]u8 = undefined;
    var params: [max_transport_params]u8 = undefined;

    // A protocol we do not speak: echoing the client's first would agree to
    // something nothing here can answer.
    // Source: RFC 9001 s8.1.
    try refusesHello(&dcid, &server_scid, try testHello(&buf, .{
        .key = kp.public_key,
        .alpn = "h3",
        .params = try testParams(&params, &dcid),
    }), error.NoApplicationProtocol);

    // Nothing said about what the client will present, so what it presents is
    // an X.509 chain by default and there is nothing to authenticate it by.
    // Source: RFC 7250 s4.1.
    try refusesHello(&dcid, &server_scid, try testHello(&buf, .{
        .key = kp.public_key,
        .client_certificate_type = false,
        .params = try testParams(&params, &dcid),
    }), error.UnsupportedCertificateType);

    // The id on the packets, unclaimed in the parameters: nothing else ties the
    // cleartext headers to the handshake.
    // Source: RFC 9000 s7.3.
    try refusesHello(&dcid, &server_scid, try testHello(&buf, .{
        .key = kp.public_key,
        .params = try testParams(&params, null),
    }), error.TransportParameterError);

    // A server's parameter, and one a client must not send even when its value
    // is the id it did choose.
    // Source: RFC 9000 s18.2.
    var pw = std.Io.Writer.fixed(&params);
    try handshake.writeTransportParam(&pw, .initial_source_connection_id, &dcid);
    try handshake.writeTransportParam(&pw, .original_destination_connection_id, &dcid);
    try refusesHello(&dcid, &server_scid, try testHello(&buf, .{
        .key = kp.public_key,
        .params = pw.buffered(),
    }), error.TransportParameterError);

    // One extension twice, naming a protocol we speak and one we do not. Which
    // one wins would be whichever copy was read last, so neither does.
    // Source: RFC 8446 s4.2.
    var ext: [max_client_extensions]u8 = undefined;
    var ew = std.Io.Writer.fixed(&ext);
    try handshake.writeSupportedVersions(&ew);
    try handshake.writeKeyShare(&ew, kp.public_key);
    try writeAlpn(&ew, "radicle/git/1");
    try writeAlpn(&ew, "h3");
    try refuses(&dcid, &server_scid, .{
        .random = hex(testdata.fixed_hello_random),
        .cipher_suites = &.{cipher_suite},
        .extensions = ew.buffered(),
    }, error.ProtocolViolation);
}

test "a cipher suite list that is not whole suites is refused" {
    // A trailing byte means the length prefix and the list disagree, so the
    // pairs read out of it are not the ones the client wrote.
    // Source: RFC 8446 s4.1.2.
    try testing.expectError(
        error.Malformed,
        Connection.offers(&.{ 0x13, 0x01, 0x13 }, cipher_suite),
    );
    try testing.expect(try Connection.offers(&.{ 0x13, 0x01 }, cipher_suite));
    try testing.expect(!try Connection.offers(&.{}, cipher_suite));
}

test "a server refuses a HANDSHAKE_DONE, which is its own to send" {
    // Source: RFC 9000 s19.20.
    const dcid = hex(testdata.other_dcid);
    const server_scid = hex("aabbccdd");
    var bufs: TestBufs = .{};
    var h = serverConnection(&dcid, &server_scid, &bufs);

    const done = [_]u8{@backingInt(frame.Type.handshake_done)};
    try testing.expectError(error.ProtocolViolation, h.appFrames(&done));
    try testing.expect(!h.confirmed);
}

/// A ClientHello carrying what a server needs, so a test can leave out or
/// change exactly one part of it.
const TestHello = struct {
    key: tls.PublicKey,
    alpn: []const u8 = "radicle/git/1",
    /// What the client offers to present, which a server needs to ask it for a
    /// raw public key.
    client_certificate_type: bool = true,
    params: []const u8,
};

fn testHello(buf: []u8, h: TestHello) ![]const u8 {
    var ext: [max_client_extensions]u8 = undefined;
    var ew = std.Io.Writer.fixed(&ext);
    try handshake.writeSupportedVersions(&ew);
    try handshake.writeKeyShare(&ew, h.key);
    if (h.client_certificate_type) {
        try handshake.writeExtension(
            &ew,
            @backingInt(ExtensionType.client_certificate_type),
            &certificate_types,
        );
    }
    try handshake.writeExtension(
        &ew,
        @backingInt(ExtensionType.server_certificate_type),
        &certificate_types,
    );
    try writeAlpn(&ew, h.alpn);
    try handshake.writeExtension(
        &ew,
        @backingInt(ExtensionType.quic_transport_parameters),
        h.params,
    );
    return handshake.writeClientHello(buf, .{
        .random = hex(testdata.fixed_hello_random),
        .cipher_suites = &.{cipher_suite},
        .extensions = ew.buffered(),
    });
}

/// The transport parameters a client owes, or all but the one it left out.
fn testParams(buf: []u8, scid: ?[]const u8) ![]const u8 {
    var pw = std.Io.Writer.fixed(buf);
    try handshake.writeIntTransportParam(&pw, .initial_max_data, default_window);
    try handshake.writeIntTransportParam(&pw, .initial_max_stream_data_bidi_local, default_window);
    if (scid) |id| try handshake.writeTransportParam(&pw, .initial_source_connection_id, id);
    return pw.buffered();
}

test "a server sends no more than three times what has arrived" {
    const dcid = hex(testdata.other_dcid);
    const server_scid = hex("aabbccdd");
    const kp = std.crypto.dh.X25519.KeyPair.generateDeterministic(hex(testdata.fixed_x25519_secret));
    const server_key = try Ed25519.KeyPair.generateDeterministic(hex(testdata.fixed_peer_identity_seed));

    var out: [max_initial_datagram]u8 = undefined;
    var hello_buf: [max_client_hello]u8 = undefined;
    const initial = try initialDatagram(&out, &hello_buf, .{
        .dcid = &dcid,
        .scid = &dcid,
        .random = hex(testdata.fixed_hello_random),
        .public_key = kp.public_key,
        .alpn = "radicle/git/1",
    });

    var scratch: [max_initial_datagram]u8 = undefined;
    var bufs: TestBufs = .{};
    var server = serverConnection(&dcid, &server_scid, &bufs);
    // Opened in place, so each arrival gets its own copy and `out` stays as it
    // went out.
    var wire: [max_initial_datagram]u8 = undefined;
    @memcpy(wire[0..initial.len], out[0..initial.len]);
    try server.push(&scratch, wire[0..initial.len]);

    var reply: [max_initial_datagram]u8 = undefined;
    var server_hello: [max_server_hello]u8 = undefined;
    _ = try server.sealServerHello(&reply, &server_hello, hex(testdata.fixed_server_hello_random));
    var messages: [max_flight]u8 = undefined;
    const flight = try server.writeFlight(&messages, server_key);

    // Probing the flight over and over, which is what a peer that answers
    // nothing would have a server do, runs out of budget rather than
    // amplifying a spoofed address.
    // Source: RFC 9000 s8.1.
    while (true) {
        _ = server.sealFlight(&reply, flight) catch |e| {
            try testing.expectEqual(error.AmplificationLimited, e);
            break;
        };
    }
    try testing.expect(!server.address_validated);
    try testing.expect(server.sent_bytes <= 3 * server.received_bytes);

    // What the peer sends raises what may go back, so nothing deadlocks.
    try server.push(&scratch, out[0..initial.len]);
    _ = try server.sealFlight(&reply, flight);
}

/// Feeds one ClientHello to a fresh server and expects it to be turned down.
fn refuses(
    dcid: []const u8,
    scid: []const u8,
    ch: handshake.ClientHello,
    want: anyerror,
) !void {
    var buf: [max_client_hello]u8 = undefined;
    try refusesHello(dcid, scid, try handshake.writeClientHello(&buf, ch), want);
}

/// The same, for a hello a test has built itself.
fn refusesHello(dcid: []const u8, scid: []const u8, raw: []const u8, want: anyerror) !void {
    var bufs: TestBufs = .{};
    var h = serverConnection(dcid, scid, &bufs);
    try testing.expectError(want, tellsHello(&h, dcid, raw));
}

test "a client and our own server walk the handshake to 1-RTT" {
    const dcid = hex(testdata.other_dcid);
    const server_scid = hex("aabbccdd");
    const secret = hex(testdata.fixed_x25519_secret);
    const kp = std.crypto.dh.X25519.KeyPair.generateDeterministic(secret);
    const client_key = try Ed25519.KeyPair.generateDeterministic(hex(testdata.fixed_identity_seed));
    const server_key = try Ed25519.KeyPair.generateDeterministic(hex(testdata.fixed_peer_identity_seed));
    const window = 4096;

    var out: [max_initial_datagram]u8 = undefined;
    var hello_buf: [max_client_hello]u8 = undefined;
    const initial = try initialDatagram(&out, &hello_buf, .{
        .dcid = &dcid,
        .scid = &dcid,
        .random = hex(testdata.fixed_hello_random),
        .public_key = kp.public_key,
        .alpn = "radicle/git/1",
        .window = window,
    });

    var scratch: [max_initial_datagram]u8 = undefined;
    var server_bufs: TestBufs = .{};
    var server = serverConnection(&dcid, &server_scid, &server_bufs);
    server.window = window;
    // The datagram as it would arrive, so the server reads the ClientHello off
    // the wire and the amplification budget sees what came in.
    try server.push(&scratch, out[0..initial.len]);
    try testing.expectEqual(@as(u64, initial.len), server.received_bytes);
    try testing.expectEqual(@as(u64, 3 * initial.len), server.amplificationRoom());

    var reply: [max_initial_datagram]u8 = undefined;
    var server_hello: [max_server_hello]u8 = undefined;
    const hello = try server.sealServerHello(
        &reply,
        &server_hello,
        hex(testdata.fixed_server_hello_random),
    );
    // Numbered from 0, and expanded like any datagram carrying an Initial.
    try testing.expectEqual(@as(u64, 1), server.next_initial_pn);
    try testing.expect(hello.len >= min_initial_datagram);
    // Kept for a retransmission, which is the only way it can go again.
    try testing.expectEqual(
        std.crypto.tls.HandshakeType.server_hello,
        firstMessage(hello.hello).type,
    );

    var client_bufs: TestBufs = .{};
    var client = Connection.init(.{
        .original_dcid = &dcid,
        .our_scid = &dcid,
        .client_hello = initial.hello,
        .secret = secret,
        .initial_buf = &client_bufs.initial,
        .handshake_buf = &client_bufs.handshake,
        .window = window,
    });

    try client.push(&scratch, reply[0..hello.len]);

    try testing.expectEqual(Connection.Phase.wait_encrypted_extensions, client.phase);
    try testing.expectEqualSlices(
        u8,
        &server.accepted.handshake.?.server,
        &client.accepted.handshake.?.server,
    );
    // Deriving is what leaves `.offered`, so there is no second one to build.
    try testing.expectError(
        error.HandshakeIncomplete,
        server.sealServerHello(&reply, &server_hello, @splat(0)),
    );

    // The rest of the server's half, under the keys the ServerHello just made.
    var messages: [max_flight]u8 = undefined;
    const flight = try server.writeFlight(&messages, server_key);
    const flight_len = try server.sealFlight(&reply, flight);
    try client.push(&scratch, reply[0..flight_len]);

    try testing.expect(client.done());
    try testing.expect(client.accepted.peer_verified);
    try testing.expectEqualSlices(u8, &server_key.public_key.toBytes(), &client.accepted.peer_key.?);
    try testing.expectEqualStrings("radicle/git/1", client.accepted.alpn());
    // The CertificateRequest landed, so the client knows to authenticate back.
    try testing.expect(client.requested);
    // Both connection ids echoed back and matched what is on the packets, and
    // the limits arrived with them.
    try testing.expect(client.saw_initial_scid and client.saw_original_dcid);
    try testing.expectEqual(@as(u64, window), client.send_stream.limit);
    try testing.expectEqual(idle_timeout_ms, client.peer_idle_ms);

    // The client's own half closes the loop.
    var client_messages: [max_flight]u8 = undefined;
    const answer = try client.writeFlight(&client_messages, client_key);
    var sealed: [max_initial_datagram]u8 = undefined;
    const answer_len = try client.sealFlight(&sealed, answer);
    try server.push(&scratch, sealed[0..answer_len]);

    try testing.expect(server.done());
    try testing.expect(server.accepted.peer_verified);
    try testing.expectEqualSlices(u8, &client_key.public_key.toBytes(), &server.accepted.peer_key.?);
    // A Handshake packet only opens for a peer that read our Initial, so the
    // address is proved and the budget stops applying.
    // Source: RFC 9000 s8.1.
    try testing.expect(server.address_validated);
    try testing.expectEqual(std.math.maxInt(u64), server.amplificationRoom());

    // The server's handshake is confirmed the moment it completes; the client's
    // waits on being told. Owed once, and not again until one is lost.
    // Source: RFC 9001 s4.1.2, RFC 9000 s13.3.
    try testing.expect(server.confirmed);
    try testing.expect(!client.confirmed);
    const done_len = (try server.sealHandshakeDone(&sealed)).?;
    try client.push(&scratch, sealed[0..done_len]);
    try testing.expect(client.confirmed);
    try testing.expectEqual(@as(?usize, null), try server.sealHandshakeDone(&sealed));

    // Same transcript on both sides, so neither hashed anything the other did
    // not, and the 1-RTT keys that come off it agree.
    try testing.expectEqualSlices(u8, &server.transcript.hash(), &client.transcript.hash());
    try testing.expectEqualSlices(
        u8,
        &server.accepted.application.?.client,
        &client.accepted.application.?.client,
    );
    try testing.expectEqualSlices(
        u8,
        &server.accepted.application.?.server,
        &client.accepted.application.?.server,
    );
}

test "builds an Initial datagram we can open again" {
    const dcid = hex(testdata.other_dcid);
    const kp = std.crypto.dh.X25519.KeyPair.generateDeterministic(hex(testdata.fixed_x25519_secret));
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
    try testing.expectEqualSlices(u8, initial.hello, sent);

    const ch = try handshake.parseClientHello(sent);

    try testing.expectEqualSlices(u8, &hex("1301"), ch.cipher_suites);
    try testing.expect(try ch.find(.application_layer_protocol_negotiation) != null);
    try testing.expect(try ch.find(.key_share) != null);

    // What iroh requires: raw public keys in both directions, ed25519 alone,
    // and no SNI unless one was asked for.
    try testing.expectEqualSlices(u8, &certificate_types, (try ch.find(.client_certificate_type)).?);
    try testing.expectEqualSlices(u8, &certificate_types, (try ch.find(.server_certificate_type)).?);
    try testing.expectEqualSlices(u8, &signature_algorithms, (try ch.find(.signature_algorithms)).?);
    try testing.expectEqual(@as(?[]const u8, null), try ch.find(.server_name));

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

// A packet radish cannot decrypt yet must not read as an empty success, or a
// rejection is indistinguishable from silence.
test "packets that cannot be opened are reported" {
    const dcid = hex(testdata.other_dcid);
    var bufs: TestBufs = .{};
    var h = testConnection(&dcid, &bufs);

    var scratch: [512]u8 = undefined;
    var payload: [32]u8 = @splat(0);
    payload[0] = 0x01;

    // A Handshake packet before the ServerHello: its keys do not exist yet.
    var early: [256]u8 = undefined;
    const n = try packet.seal(&early, .{
        .kind = .handshake,
        .dcid = &dcid,
        .pn = 0,
        .pn_len = packet.max_pn_len,
    }, &payload, crypto.keysFromSecret(crypto.initialSecrets(&dcid).server));
    try testing.expectError(error.KeysUnavailable, h.push(&scratch, early[0..n]));

    // A 1-RTT packet, likewise.
    var short: [256]u8 = undefined;
    const m = try packet.sealShort(&short, .{
        .dcid = &dcid,
        .pn = 0,
        .pn_len = packet.max_pn_len,
    }, &payload, crypto.keysFromSecret(crypto.initialSecrets(&dcid).server));
    try testing.expectError(error.KeysUnavailable, h.push(&scratch, short[0..m]));

    // Version Negotiation, which is a rejection rather than a packet to open.
    var vn = hex("8000000000" ++ "00" ++ "00" ++ "00000001");
    try testing.expectError(error.VersionNegotiation, h.push(&scratch, &vn));
}

test "stream data survives a 1-RTT round trip" {
    const dcid = hex(testdata.other_dcid);
    var bufs: TestBufs = .{};
    // Small, so reading one message crosses the half the grant waits for.
    var stream_buf: [8]u8 = undefined;
    var h = appConnection(&dcid, &bufs, &stream_buf);
    const keys = crypto.keysFromSecret(crypto.initialSecrets(&dcid).client);

    // What the peer's transport parameters would have opened.
    h.send_data.extend(32);
    h.send_stream.extend(32);

    var sealed: [256]u8 = undefined;
    const n = try h.sealStream(&sealed, "gossip", false);
    try testing.expectEqual(@as(u64, 6), h.sender.next());

    var scratch: [256]u8 = undefined;
    try h.push(&scratch, sealed[0..n]);
    try testing.expectEqualSlices(u8, "gossip", h.stream.readable());

    h.stream.consume(6);
    try testing.expectEqual(@as(usize, 0), h.stream.readable().len);
    try testing.expect(!h.stream.done());

    // Reading freed most of the window, so the peer is owed a new limit.
    var grant: [256]u8 = undefined;
    const g = (try h.sealMaxData(&grant)).?;
    try testing.expectEqual(@as(u64, 14), h.stream.window.limit);
    try testing.expectEqual(@as(?usize, null), try h.sealMaxData(&grant));

    var opened: [256]u8 = undefined;
    var copy: [256]u8 = undefined;
    @memcpy(copy[0..g], grant[0..g]);
    const seen = try packet.openShort(&opened, copy[0..g], dcid.len, keys, null);
    var it = frame.Iterator.init(seen.payload);
    try testing.expectEqual(@as(u64, 14), (try it.next()).?.max_stream_data.max);
    try testing.expectEqual(@as(u64, 14), (try it.next()).?.max_data);

    // Our limit moved when the grant went out, so `wantsGrant` will not ask
    // again: if that packet was lost, only this sends the peer another.
    const lost_pn = h.grant_pn.?;
    _ = h.recovery.tracker(.application).take(lost_pn);
    try testing.expect((try h.sealMaxData(&grant)) != null);
    try testing.expect(h.grant_pn.? != lost_pn);

    // Acknowledged, so there is nothing owed on it.
    h.app_acked.record(h.grant_pn.?);
    _ = h.recovery.tracker(.application).take(h.grant_pn.?);
    try testing.expectEqual(@as(?usize, null), try h.sealMaxData(&grant));
}

test "an ACK's delay is scaled by the exponent the peer advertised" {
    const dcid = hex(testdata.other_dcid);
    var bufs: TestBufs = .{};
    var h = testConnection(&dcid, &bufs);

    // The default exponent is 3, so a unit is 8 microseconds.
    try testing.expectEqual(@as(u64, 8), h.ackDelayMs(1000));
    h.peer_ack_exponent = 0;
    try testing.expectEqual(@as(u64, 1), h.ackDelayMs(1000));

    // A delay no clock could mean saturates rather than wrapping to nothing.
    h.peer_ack_exponent = 20;
    try testing.expect(h.ackDelayMs(std.math.maxInt(u64)) > 0);
}

test "unacknowledged stream data goes again under a new number" {
    const dcid = hex(testdata.other_dcid);
    var bufs: TestBufs = .{};
    var stream_buf: [64]u8 = undefined;
    var h = appConnection(&dcid, &bufs, &stream_buf);
    const keys = crypto.keysFromSecret(crypto.initialSecrets(&dcid).client);

    h.send_data.extend(64);
    h.send_stream.extend(64);

    var out: [256]u8 = undefined;
    _ = try h.sealStream(&out, "hello", false);
    const again = (try h.resendStream(&out, false)).?;

    // Same offset and bytes, a number the first packet did not use.
    var opened: [256]u8 = undefined;
    var copy: [256]u8 = undefined;
    @memcpy(copy[0..again], out[0..again]);
    const seen = try packet.openShort(&opened, copy[0..again], dcid.len, keys, null);
    try testing.expectEqual(@as(u64, 1), seen.pn);
    var it = frame.Iterator.init(seen.payload);
    const s = (try it.next()).?.stream;
    try testing.expectEqual(@as(u64, 0), s.offset);
    try testing.expectEqualSlices(u8, "hello", s.data);

    // A repair has nothing left to try until an acknowledgement says
    // otherwise, though a probe would still send the chunk again.
    try testing.expectEqual(@as(?usize, null), try h.resendStream(&out, false));
    try testing.expect(try h.resendStream(&out, true) != null);

    // Acknowledging the resend retires the chunk, so nothing is owed.
    h.app_acked.record(2);
    try testing.expectEqual(@as(?usize, null), try h.resendStream(&out, false));
    try testing.expectEqual(@as(?usize, null), try h.resendStream(&out, true));
    try testing.expectEqual(@as(u64, 5), h.sender.base);
}

test "sending stops at the limit the peer gave" {
    const dcid = hex(testdata.other_dcid);
    var bufs: TestBufs = .{};
    var stream_buf: [64]u8 = undefined;
    var h = appConnection(&dcid, &bufs, &stream_buf);

    var out: [256]u8 = undefined;
    // Nothing may be sent until the peer's parameters open a window.
    try testing.expectError(error.FlowControlBlocked, h.sealStream(&out, "x", false));

    h.send_data.extend(4);
    h.send_stream.extend(2);
    // The stream limit binds first, since it is the lower of the two.
    try testing.expectEqual(@as(u64, 2), h.sendRoom());
    try testing.expectError(error.FlowControlBlocked, h.sealStream(&out, "abc", false));

    _ = try h.sealStream(&out, "ab", false);
    try testing.expectEqual(@as(u64, 0), h.sendRoom());

    // A MAX_STREAM_DATA for our stream reopens it, up to the connection limit.
    try h.appFrames(&[_]u8{ 0x11, 0x00, 0x40, 0x40 });
    try testing.expectEqual(@as(u64, 2), h.sendRoom());

    // One packet holds only so much, whatever the window says: more than that
    // is the caller's to split.
    h.send_data.extend(4 * max_stream_chunk);
    h.send_stream.extend(4 * max_stream_chunk);
    var big: [max_stream_chunk + 1]u8 = @splat(0xab);
    try testing.expectError(error.StreamChunkTooLong, h.sealStream(&out, &big, false));

    var full: [max_stream_chunk]u8 = @splat(0xab);
    var packet_buf: [max_initial_datagram]u8 = undefined;
    _ = try h.sealStream(&packet_buf, &full, false);
    // A send continues the stream rather than restarting it: the two bytes
    // above, then a full packet.
    try testing.expectEqual(2 + max_stream_chunk, h.sender.next());
}

test "a handshake message out of turn is refused" {
    const dcid = hex(testdata.other_dcid);
    var bufs: TestBufs = .{};
    var h = testConnection(&dcid, &bufs);

    try testing.expectEqual(Connection.Phase.wait_server_hello, h.phase);

    var msg: [64]u8 = undefined;
    var mw = std.Io.Writer.fixed(&msg);
    try handshake.writeRawPublicKeyCertificate(&mw, &.{}, @splat(1));
    try testing.expectError(error.UnexpectedMessage, h.message(firstMessage(mw.buffered())));

    // A Finished needs the handshake secret, which no ServerHello has produced.
    var fin: [64]u8 = undefined;
    var fw = std.Io.Writer.fixed(&fin);
    try handshake.writeMessage(&fw, .finished, &@as([32]u8, @splat(0)));
    try testing.expectError(error.UnexpectedMessage, h.message(firstMessage(fw.buffered())));
}

fn firstMessage(bytes: []const u8) handshake.Message {
    var it = handshake.MessageIterator.init(bytes);
    return it.next().?;
}

test "acknowledges an Initial the server can open" {
    const dcid = hex(testdata.other_dcid);
    const server_scid = hex("aabbccdd");
    var bufs: TestBufs = .{};
    var h = testConnection(&dcid, &bufs);

    // Nothing has arrived, so nothing is owed.
    var out: [max_initial_datagram]u8 = undefined;
    try testing.expectEqual(@as(?usize, null), try h.sealAck(&out, .initial));

    // A PING is ack-eliciting, so receiving one puts us in debt.
    const keys = crypto.initialSecrets(&dcid);
    var payload: [32]u8 = @splat(0);
    payload[0] = @backingInt(frame.Type.ping);
    var server: [256]u8 = undefined;
    const n = try packet.seal(&server, .{
        .kind = .initial,
        .dcid = &dcid,
        .scid = &server_scid,
        .pn = 3,
        .pn_len = packet.max_pn_len,
    }, &payload, crypto.keysFromSecret(keys.server));

    var scratch: [512]u8 = undefined;
    try h.push(&scratch, server[0..n]);
    try testing.expect(h.received(.initial).ack_eliciting);
    try testing.expectEqual(@as(?u64, 3), h.received(.initial).largest());
    // Nothing arrived in the other spaces, so nothing is owed there.
    try testing.expectEqual(@as(?usize, null), try h.sealAck(&out, .handshake));

    const acked = (try h.sealAck(&out, .initial)).?;
    var copy: [max_initial_datagram]u8 = undefined;
    var plain: [max_initial_datagram]u8 = undefined;
    const opened = try openOurs(&dcid, out[0..acked], &copy, &plain);

    // The ClientHello used 0 in this space under this key, and repeating it
    // would repeat the AEAD nonce.
    try testing.expectEqual(@as(u64, 1), opened.pn);

    var it = frame.Iterator.init(opened.payload);
    const ack = (try it.next()).?.ack;
    try testing.expectEqual(@as(u64, 3), ack.largest);
    try testing.expectEqual(frame.AckRange{ .largest = 3, .smallest = 3 }, try ack.firstRange());

    // The debt is settled, so a second call owes nothing.
    try testing.expectEqual(@as(?usize, null), try h.sealAck(&out, .initial));
}

test "only a client expands a datagram holding nothing but an Initial ACK" {
    // A client owes the expansion on every datagram carrying an Initial; a
    // server owes it on an ack-eliciting one, which an ACK is not, and would be
    // spending its amplification budget on padding.
    // Source: RFC 9000 s14.1.
    const dcid = hex(testdata.other_dcid);
    const server_scid = hex("aabbccdd");
    const kp = std.crypto.dh.X25519.KeyPair.generateDeterministic(hex(testdata.fixed_x25519_secret));

    var hello: [max_initial_datagram]u8 = undefined;
    var hello_buf: [max_client_hello]u8 = undefined;
    const initial = try initialDatagram(&hello, &hello_buf, .{
        .dcid = &dcid,
        .scid = &dcid,
        .random = hex(testdata.fixed_hello_random),
        .public_key = kp.public_key,
        .alpn = "radicle/git/1",
    });

    var scratch: [max_initial_datagram]u8 = undefined;
    var bufs: TestBufs = .{};
    var server = serverConnection(&dcid, &server_scid, &bufs);
    try server.push(&scratch, hello[0..initial.len]);

    var out: [max_initial_datagram]u8 = undefined;
    const from_server = (try server.sealAck(&out, .initial)).?;
    try testing.expect(from_server < min_initial_datagram);

    // The client's, for the same ACK in the same space.
    var client_bufs: TestBufs = .{};
    var client = testConnection(&dcid, &client_bufs);
    client.initial_received.record(0);
    client.initial_received.elicited();
    const from_client = (try client.sealAck(&out, .initial)).?;
    try testing.expect(from_client >= min_initial_datagram);
}

test "an ACK carrying a PING counts its bytes once" {
    const dcid = hex(testdata.other_dcid);
    var bufs: TestBufs = .{};
    var stream_buf: [4096]u8 = undefined;
    var h = appConnection(&dcid, &bufs, &stream_buf);

    // A round trip since the last one, so this ACK carries the PING that has
    // the peer acknowledge it.
    // Source: RFC 9000 s13.2.4.
    h.now_ms = 10 * h.recovery.rtt.smoothed_ms;
    h.app_received.record(0);
    h.app_received.elicited();
    h.app_received.record(1);
    h.app_received.elicited();

    var out: [max_initial_datagram]u8 = undefined;
    const n = (try h.sealAck(&out, .application)).?;
    // Remembered, so the PING went out with it.
    try testing.expect(h.sent_ack != null);
    try testing.expectEqual(@as(u64, n), h.sent_bytes);
}

test "a bulk transfer is acknowledged every second packet, not every packet" {
    const dcid = hex(testdata.other_dcid);
    var bufs: TestBufs = .{};
    var stream_buf: [4096]u8 = undefined;
    var h = appConnection(&dcid, &bufs, &stream_buf);

    var out: [max_initial_datagram]u8 = undefined;

    h.app_received.record(0);
    h.app_received.elicited();
    h.ack_deadline_ms = h.now_ms + max_ack_delay_ms;
    try testing.expectEqual(@as(?usize, null), try h.sealAck(&out, .application));

    h.app_received.record(1);
    h.app_received.elicited();
    try testing.expect(try h.sealAck(&out, .application) != null);

    try testing.expectEqual(@as(?usize, null), try h.sealAck(&out, .application));
    try testing.expectEqual(@as(?u64, null), h.ackDeadlineMs());
}

test "a held ACK goes once the delay runs out, or at once when a packet is out of order" {
    const dcid = hex(testdata.other_dcid);
    var bufs: TestBufs = .{};
    var stream_buf: [4096]u8 = undefined;
    var h = appConnection(&dcid, &bufs, &stream_buf);

    var out: [max_initial_datagram]u8 = undefined;
    h.now_ms = 1_000;
    h.app_received.record(0);
    h.app_received.elicited();
    h.ack_deadline_ms = h.now_ms + max_ack_delay_ms;
    try testing.expectEqual(@as(?usize, null), try h.sealAck(&out, .application));

    try testing.expectEqual(@as(?u64, 1_000 + max_ack_delay_ms), h.ackDeadlineMs());
    h.now_ms = 1_000 + max_ack_delay_ms;
    try testing.expect(try h.sealAck(&out, .application) != null);

    h.app_received.record(9);
    h.app_received.elicited();
    try testing.expect(h.app_received.out_of_order);
    try testing.expect(try h.sealAck(&out, .application) != null);
}

// A packet whose frames are refused is dropped without its number being
// recorded, which can leave the flag set over an empty set. Spending a number
// on that every turn sends nothing and runs our numbers away from the peer's.
test "an ack-eliciting flag with nothing behind it clears instead of spending a number" {
    const dcid = hex(testdata.other_dcid);
    var bufs: TestBufs = .{};
    var h = testConnection(&dcid, &bufs);

    const before = h.next_initial_pn;
    h.received(.initial).ack_eliciting = true;

    var out: [max_initial_datagram]u8 = undefined;
    try testing.expectEqual(@as(?usize, null), try h.sealAck(&out, .initial));
    try testing.expect(!h.received(.initial).ack_eliciting);
    try testing.expectEqual(before, h.next_initial_pn);
}

test "retransmitting the ClientHello uses a fresh packet number" {
    const dcid = hex(testdata.other_dcid);
    var bufs: TestBufs = .{};
    var h = testConnection(&dcid, &bufs);

    const hello: [32]u8 = @splat(0xaa);
    var out: [max_initial_datagram]u8 = undefined;
    var copy: [max_initial_datagram]u8 = undefined;
    var plain: [max_initial_datagram]u8 = undefined;

    const n = try h.sealInitialRetransmit(&out, &hello);
    // Expanded to the floor, since a server discards a smaller Initial.
    try testing.expect(n >= min_initial_datagram);

    const opened = try openOurs(&dcid, out[0..n], &copy, &plain);
    // 0 belongs to the ClientHello that initialDatagram already sent.
    try testing.expectEqual(@as(u64, 1), opened.pn);
    try testing.expectEqualSlices(u8, &dcid, opened.header.scid);

    var it = frame.Iterator.init(opened.payload);
    const c = (try it.next()).?.crypto;
    try testing.expectEqual(@as(u64, 0), c.offset);
    try testing.expectEqualSlices(u8, &hello, c.data);

    // A second one moves on again, so no nonce is ever repeated.
    const again = try h.sealInitialRetransmit(&out, &hello);
    try testing.expectEqual(@as(u64, 2), (try openOurs(&dcid, out[0..again], &copy, &plain)).pn);
}
