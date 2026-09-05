//! The client side of a QUIC handshake, from the first flight through 1-RTT.
const std = @import("std");

const codec = @import("../codec.zig");
const crypto = @import("crypto.zig");
const handshake = @import("handshake.zig");
const frame = @import("frame.zig");
const packet = @import("packet.zig");
const reassembly = @import("reassembly.zig");
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
    KeysUnavailable,
    FlightAlreadySent,
    TransportParameterError,
    UnsupportedStream,
    StreamChunkTooLong,
    KeyUpdateError,
    StatelessReset,
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

/// How much the peer may send before we raise its limit, and so how big a
/// stream buffer must be. A window under one whole message deadlocks the
/// stream; this clears a 64 KiB message and its length prefix.
pub const default_window: u64 = 1 << 17;

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

/// Room for our handshake flight. Certificate, CertificateVerify and Finished
/// are all fixed size for a raw public key and ed25519, the largest part being
/// the Certificate's request context.
pub const max_flight = 512;

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
    /// The flow control limits to advertise. `Handshaker.Options.stream_buf`
    /// has to be this long, since it is where the peer's bytes land.
    window: u64 = default_window,
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

    // Both directions, since iroh authenticates mutually: we present a raw
    // public key too.
    try handshake.writeExtension(w, @backingInt(ExtensionType.client_certificate_type), &certificate_types);
    try handshake.writeExtension(w, @backingInt(ExtensionType.server_certificate_type), &certificate_types);

    var alpn: [64]u8 = undefined;
    var aw = std.Io.Writer.fixed(&alpn);
    try aw.writeInt(u16, @intCast(cfg.alpn.len + 1), .big);
    try aw.writeInt(u8, @intCast(cfg.alpn.len), .big);
    try aw.writeAll(cfg.alpn);
    try handshake.writeExtension(w, @backingInt(ExtensionType.application_layer_protocol_negotiation), aw.buffered());

    var params: [64]u8 = undefined;
    var pw = std.Io.Writer.fixed(&params);
    try handshake.writeIntTransportParam(&pw, .initial_max_data, cfg.window);
    try handshake.writeIntTransportParam(&pw, .initial_max_stream_data_bidi_local, cfg.window);
    try handshake.writeIntTransportParam(&pw, .initial_max_stream_data_bidi_remote, cfg.window);
    // None: only the one stream we open ourselves is handled, and this limit
    // covers the streams a peer opens toward us.
    // Source: RFC 9000 s18.2.
    try handshake.writeIntTransportParam(&pw, .initial_max_streams_bidi, 0);
    // What we can hold. The default is 65527, and a peer that probes its way up
    // to it sends datagrams this side reads as truncated garbage.
    // Source: RFC 9000 s18.2.
    try handshake.writeIntTransportParam(&pw, .max_udp_payload_size, max_receive_datagram);
    try handshake.writeIntTransportParam(&pw, .max_idle_timeout, idle_timeout_ms);
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
    var payload: [min_initial_datagram]u8 = undefined;
    var fw = std.Io.Writer.fixed(&payload);
    writeCryptoFrame(&fw, 0, ch) catch return error.BufferTooSmall;
    const frames_len = fw.buffered().len;

    const keys = crypto.keysFromSecret(crypto.initialSecrets(cfg.dcid).client);
    const build: packet.Build = .{
        .kind = .initial,
        .dcid = cfg.dcid,
        .scid = cfg.scid,
        .pn = 0,
        .pn_len = packet.max_pn_len,
    };

    const payload_len = try paddedInitialLen(out, build, frames_len);
    if (payload_len > payload.len) return error.BufferTooSmall;

    fw.splatByteAll(0, payload_len - frames_len) catch return error.BufferTooSmall;

    return .{
        .len = try packet.seal(out, build, fw.buffered(), keys),
        .client_hello = ch,
    };
}

/// Why the peer closed. `frame.ConnectionClose` borrows the buffer the packet
/// was decrypted into, so this keeps its own copy and stays valid once that
/// buffer is reused. Copyable by value: nothing points back into it.
pub const Close = struct {
    error_code: u64,
    frame_type: ?u64,
    reason_buf: [256]u8 = undefined,
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
    alpn_buf: [64]u8 = undefined,
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

/// A client handshake in progress. Keys for the Handshake packet number space
/// only exist once the ServerHello has been read, so the two CRYPTO streams and
/// the transcript outlive any single datagram.
pub const Handshaker = struct {
    /// Everything the ServerHello yields at once. One optional, because a
    /// packet key without the secret that made it is not a state this can be in.
    pub const Derived = struct {
        /// The master secret, and so the application keys, still need this
        /// after the traffic secrets have been derived from it.
        secret: tls.Secret,
        keys: crypto.Keys,
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
        wait_server_hello,
        wait_encrypted_extensions,
        /// A CertificateRequest is optional, so either may come next.
        wait_certificate_or_request,
        wait_certificate,
        wait_certificate_verify,
        wait_finished,
        connected,
    };

    secret: tls.SecretKey,
    initial_keys: Directional,
    derived: ?Derived = null,
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
    /// Set when EncryptedExtensions names raw_public_key. X.509 is the default
    /// when the extension is absent, which radish treats as fatal rather than
    /// continue with a peer it cannot authenticate.
    /// Source: RFC 7250 s4.1, s4.2.
    negotiated_raw_key: bool = false,

    /// HANDSHAKE_DONE, so the server accepted our flight. It only ever travels
    /// in a 1-RTT packet.
    confirmed: bool = false,
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
    /// reads it: `conn.zig` sets it each turn, and the sealing paths stamp what
    /// they send with it.
    now_ms: u64 = 0,
    /// When the ACK a held-back packet is owed runs out of time, or null when
    /// nothing is waiting. Set from the first packet an ACK owes for, so a
    /// lone one is still answered inside what the peer expects.
    /// Source: RFC 9000 s13.2.1.
    ack_deadline_ms: ?u64 = null,
    /// What the peer scales its ACK delays by, as a power of two microseconds.
    /// Source: RFC 9000 s18.2.
    peer_ack_exponent: u6 = 3,
    /// Set when loss detection found something and cleared by the caller acting
    /// on it, since only the caller can put the bytes back on the wire.
    lost: bool = false,

    /// What has arrived in each space, for acknowledging it and for recovering
    /// the next truncated packet number.
    initial_received: frame.Received = .{},
    handshake_received: frame.Received = .{},
    app_received: frame.Received = .{},

    /// The next number to send in each space. Reusing one repeats an AEAD nonce
    /// under the same key. The Initial space starts at 1: `initialDatagram` sent
    /// the ClientHello as 0.
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
    request_buf: [255]u8 = undefined,
    request_len: usize = 0,
    requested: bool = false,

    accepted: Accepted = .{},
    /// Set alongside `error.PeerClosed`.
    closed: ?Close = null,
    phase: Phase = .wait_server_hello,

    /// True once the server's Finished has been verified.
    pub fn done(self: *const Handshaker) bool {
        return self.phase == .connected;
    }

    pub const Options = struct {
        /// The id the client chose; Initial keys stay pinned to it.
        original_dcid: []const u8,
        /// The id we gave for ourselves. Its length is the only way to find the
        /// packet number in a 1-RTT header.
        our_scid: []const u8,
        /// Opens the transcript.
        client_hello: []const u8,
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
    };

    pub fn init(opts: Options) Handshaker {
        const initial = crypto.initialSecrets(opts.original_dcid);
        var self: Handshaker = .{
            .secret = opts.secret,
            .initial_keys = .{
                .send = crypto.keysFromSecret(initial.client),
                .recv = crypto.keysFromSecret(initial.server),
            },
            .our_cid_len = opts.our_scid.len,
            .initial_crypto = reassembly.Reassembler.init(opts.initial_buf),
            .handshake_crypto = reassembly.Reassembler.init(opts.handshake_buf),
            .stream = stream.Receiver.init(opts.stream_buf, opts.stream_buf.len),
            .sender = stream.Sender.init(opts.send_buf),
        };
        self.original_dcid_len = opts.original_dcid.len;
        @memcpy(self.original_dcid[0..self.original_dcid_len], opts.original_dcid);
        @memcpy(self.our_scid[0..opts.our_scid.len], opts.our_scid);
        self.transcript.update(opts.client_hello);
        return self;
    }

    /// Opens every packet in one datagram, in order, feeding their CRYPTO
    /// frames to the matching stream. `datagram` is decrypted in place;
    /// `scratch` receives each packet's plaintext.
    pub fn push(self: *Handshaker, scratch: []u8, datagram: []u8) Error!void {
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
                self.app_received.record(opened.pn);
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
                .handshake => (self.derived orelse return error.KeysUnavailable).keys,
                else => return error.UnsupportedPacket,
            };

            const tracker = switch (hdr.kind) {
                .initial => &self.initial_received,
                else => &self.handshake_received,
            };
            const opened = try packet.open(scratch, rest, keys, tracker.largest());
            try self.frames(hdr.kind, opened);
            tracker.record(opened.pn);
            rest = rest[opened.len..];

            try self.drain(&self.initial_crypto, &self.initial_read);
            if (self.derived != null) {
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
        self: *Handshaker,
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
    fn isStatelessReset(self: *const Handshaker, datagram: []const u8) bool {
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
    fn openUpdated(self: *Handshaker, scratch: []u8, rest: []u8) Error!packet.OpenedShort {
        const app = self.accepted.application orelse return error.KeysUnavailable;
        const dir = self.app_keys orelse return error.KeysUnavailable;

        const server = crypto.nextSecret(app.server);
        const opened = try packet.openShort(
            scratch,
            rest,
            self.our_cid_len,
            crypto.updatedKeys(server, dir.recv.hp),
            self.app_received.largest(),
        );
        // These keys are the other phase by construction, so a packet that
        // opens under them and claims the phase we are already in is a peer
        // that has updated twice without waiting for us.
        if (opened.key_phase == self.key_phase) return error.KeyUpdateError;

        const client = crypto.nextSecret(app.client);
        self.accepted.application = .{ .client = client, .server = server };
        self.prev_recv = dir.recv;
        self.app_keys = .{
            .send = crypto.updatedKeys(client, dir.send.hp),
            .recv = crypto.updatedKeys(server, dir.recv.hp),
        };
        self.key_phase = opened.key_phase;
        return opened;
    }

    /// Frames from a 1-RTT packet.
    fn appFrames(self: *Handshaker, payload: []const u8) Error!void {
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
    pub fn sealStream(self: *Handshaker, out: []u8, data: []const u8, fin: bool) Error!usize {
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
    pub fn resendStream(self: *Handshaker, out: []u8, force: bool) Error!?usize {
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
        self: *Handshaker,
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
    pub fn sealClose(self: *Handshaker, out: []u8, reason: []const u8) Error!usize {
        const keys = (self.app_keys orelse return error.HandshakeIncomplete).send;
        var payload: [128]u8 = undefined;
        var pw = std.Io.Writer.fixed(&payload);
        // NO_ERROR: leaving is not a failure.
        frame.writeConnectionClose(&pw, 0, reason) catch return error.BufferTooSmall;

        return packet.sealShort(out, .{
            .dcid = self.accepted.scid(),
            .pn = self.takePacketNumber(.application),
            .pn_len = packet.max_pn_len,
            .key_phase = self.key_phase,
        }, pw.buffered(), keys);
    }

    /// A PING, which carries nothing and only asks to be acknowledged. Sent
    /// before the idle timeout to hold a quiet connection open.
    /// Source: RFC 9000 s19.2, s10.1.
    pub fn sealPing(self: *Handshaker, out: []u8) Error!usize {
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
    pub fn idleTimeoutMs(self: *const Handshaker) u64 {
        if (self.peer_idle_ms == 0) return idle_timeout_ms;
        return @min(idle_timeout_ms, self.peer_idle_ms);
    }

    /// How much the peer will still take from us.
    pub fn sendRoom(self: *const Handshaker) u64 {
        return @min(self.send_data.room(), self.send_stream.room());
    }

    /// Whether the last grant is neither acknowledged nor still in flight,
    /// which leaves loss as the only explanation for it.
    fn grantLost(self: *const Handshaker) bool {
        const pn = self.grant_pn orelse return false;
        if (self.app_acked.contains(pn)) return false;
        return !self.recovery.outstanding(.application, pn);
    }

    /// Raises the peer's limits once the reader has freed enough of the buffer,
    /// or null when there is nothing worth sending. One stream, so the
    /// connection limit and the stream limit move together.
    /// Source: RFC 9000 s4.1.
    pub fn sealMaxData(self: *Handshaker, out: []u8) Error!?usize {
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
        return self.tracked(.application, pn, n);
    }

    /// A PATH_RESPONSE echoing the challenge the peer sent, sealed as 1-RTT.
    /// Source: RFC 9000 s8.2.
    pub fn sealPathResponse(self: *Handshaker, out: []u8) Error!?usize {
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

    /// Sends the ClientHello again under a fresh packet number. A lost packet is
    /// never resent as-is: the information goes in a new packet, and repeating a
    /// number would repeat an AEAD nonce and be discarded as a duplicate anyway.
    /// Source: RFC 9000 s13.3, s12.3.
    pub fn sealInitialRetransmit(self: *Handshaker, out: []u8, client_hello: []const u8) Error!usize {
        var payload: [min_initial_datagram]u8 = undefined;
        var pw = std.Io.Writer.fixed(&payload);
        writeCryptoFrame(&pw, 0, client_hello) catch return error.BufferTooSmall;
        const frames_len = pw.buffered().len;

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

        const payload_len = try paddedInitialLen(out, build, frames_len);
        if (payload_len > payload.len) return error.BufferTooSmall;
        pw.splatByteAll(0, payload_len - frames_len) catch return error.BufferTooSmall;

        const n = try packet.seal(out, build, pw.buffered(), self.initial_keys.send);
        return self.tracked(.initial, build.pn, n);
    }

    /// Hands a packet about to go out to loss detection and the congestion
    /// window, and passes its length back through. Only ack-eliciting packets
    /// are worth this: an ACK or a CONNECTION_CLOSE is never repeated and never
    /// counted against the window.
    /// Source: RFC 9002 s2, s7.
    fn tracked(self: *Handshaker, space: packet.Space, pn: u64, n: usize) usize {
        self.recovery.onSent(space, pn, n, self.now_ms);
        return n;
    }

    pub fn received(self: *Handshaker, space: packet.Space) *frame.Received {
        return switch (space) {
            .initial => &self.initial_received,
            .handshake => &self.handshake_received,
            .application => &self.app_received,
        };
    }

    pub fn acked(self: *Handshaker, space: packet.Space) *frame.NumberSet {
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
    fn recordAck(self: *Handshaker, space: packet.Space, a: frame.Ack) Error!void {
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
    }

    /// An ACK's delay field in milliseconds. It arrives as microseconds scaled
    /// down by the exponent the peer advertised, so scaling it back up is what
    /// recovers the value it meant.
    /// Source: RFC 9000 s19.3.
    fn ackDelayMs(self: *const Handshaker, delay: u64) u64 {
        const scaled = delay *| (@as(u64, 1) << self.peer_ack_exponent);
        return scaled / std.time.us_per_ms;
    }

    /// Whether loss detection has found something since the caller last asked.
    /// Repairing it is the caller's: only it can put bytes back on the wire.
    pub fn takeLost(self: *Handshaker) bool {
        defer self.lost = false;
        return self.lost;
    }

    fn nextPacketNumber(self: *Handshaker, space: packet.Space) *u64 {
        return switch (space) {
            .initial => &self.next_initial_pn,
            .handshake => &self.next_handshake_pn,
            .application => &self.next_app_pn,
        };
    }

    /// Consumes the next packet number in `space`.
    fn takePacketNumber(self: *Handshaker, space: packet.Space) u64 {
        const slot = self.nextPacketNumber(space);
        defer slot.* += 1;
        return slot.*;
    }

    /// Seals an ACK for everything received in `space`, or null when nothing
    /// there is waiting to be acknowledged. Sent in the same space it covers,
    /// under that space's own keys.
    /// Source: RFC 9000 s13.2.
    pub fn sealAck(self: *Handshaker, out: []u8, space: packet.Space) Error!?usize {
        const tracker = self.received(space);
        if (!tracker.ack_eliciting) return null;
        if (!self.ackDue(space)) return null;

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
        // smaller one before it reads the frames.
        // Source: RFC 9000 s14.1.
        if (space == .initial) {
            const want = try paddedInitialLen(out, build, pw.buffered().len);
            pw.splatByteAll(0, want - pw.buffered().len) catch return error.BufferTooSmall;
        }
        const n = switch (space) {
            .initial => try packet.seal(out, build, pw.buffered(), self.initial_keys.send),
            .handshake => try packet.seal(out, build, pw.buffered(), crypto.keysFromSecret(
                (self.accepted.handshake orelse return error.KeysUnavailable).client,
            )),
            .application => try packet.sealShort(out, .{
                .dcid = self.accepted.scid(),
                .pn = pn,
                .pn_len = packet.max_pn_len,
                .key_phase = self.key_phase,
            }, pw.buffered(), (self.app_keys orelse return error.KeysUnavailable).send),
        };
        tracker.cleared();
        if (space == .application) self.ack_deadline_ms = null;
        return n;
    }

    /// Whether an ACK for `space` is owed yet. The handshake spaces answer
    /// every ack-eliciting packet at once, since the flights are small and a
    /// held-back ACK is a retransmitted flight. The application space waits
    /// for a second packet, for one out of order, or for the delay to run
    /// out, which is what stops a bulk transfer from answering every datagram
    /// with one of its own.
    /// Source: RFC 9000 s13.2.1, s13.2.2.
    fn ackDue(self: *const Handshaker, space: packet.Space) bool {
        if (space != .application) return true;
        if (self.app_received.pending >= ack_threshold) return true;
        if (self.app_received.out_of_order) return true;
        return if (self.ack_deadline_ms) |at| self.now_ms >= at else false;
    }

    /// When the application space's held-back ACK must go, or null when
    /// nothing is waiting on one.
    pub fn ackDeadlineMs(self: *const Handshaker) ?u64 {
        if (!self.app_received.ack_eliciting) return null;
        return self.ack_deadline_ms;
    }

    fn frames(self: *Handshaker, kind: packet.Kind, opened: packet.Opened) Error!void {
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
    fn drain(self: *Handshaker, crypto_stream: *const reassembly.Reassembler, read: *usize) Error!void {
        var it = handshake.MessageIterator.init(crypto_stream.contiguous()[read.*..]);
        while (it.next()) |msg| {
            // Consumed before dispatch: `message` hashes into the transcript
            // before it can fail, so a retry would hash it twice.
            read.* += msg.raw.len;
            try self.message(msg);
        }
    }

    fn message(self: *Handshaker, msg: handshake.Message) Error!void {
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
                self.derived = .{ .secret = secret, .keys = crypto.keysFromSecret(hs.server) };
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
            .new_session_ticket => {
                // Post-handshake, so outside the transcript entirely.
                if (self.phase != .connected) return error.UnexpectedMessage;
            },
            .finished => {
                if (self.phase != .wait_finished) return error.UnexpectedMessage;
                // Reaching 1-RTT with an unauthenticated peer must not be
                // possible: the key in the certificate has to have signed the
                // transcript.
                if (!self.accepted.peer_verified) return error.BadCertificateVerify;
                const d = self.derived orelse return error.Malformed;
                const hs = self.accepted.handshake orelse return error.Malformed;
                const expect = tls.verifyData(hs.server, self.transcript.hash());
                if (msg.body.len != expect.len) return error.BadFinished;
                if (!std.crypto.timing_safe.eql([32]u8, expect, msg.body[0..32].*)) {
                    return error.BadFinished;
                }
                // The application traffic secrets take the transcript through
                // this message, so hash it once it is trusted.
                self.transcript.update(msg.raw);
                const app = tls.applicationTraffic(
                    tls.masterSecret(d.secret),
                    self.transcript.hash(),
                );
                self.accepted.application = app;
                self.app_keys = .{
                    .send = crypto.keysFromSecret(app.client),
                    .recv = crypto.keysFromSecret(app.server),
                };
                self.phase = .connected;
            },
            else => return error.UnexpectedMessage,
        }
    }

    /// Our half of mutual authentication, as one CRYPTO stream: Certificate and
    /// CertificateVerify when the server asked for them, then Finished. Each
    /// message is hashed as it is written, since the two that sign the
    /// transcript cover everything before themselves.
    ///
    /// Advances the transcript, so it can only be called once.
    /// Source: RFC 8446 s4.4.
    pub fn writeFlight(self: *Handshaker, out: []u8, key: Ed25519.KeyPair) Error![]const u8 {
        if (!self.done()) return error.HandshakeIncomplete;
        // The transcript advances past the flight, so a second call would sign
        // and MAC over the wrong prefix. Retransmission resends these bytes.
        if (self.flight_sent) return error.FlightAlreadySent;
        self.flight_sent = true;
        const hs = self.accepted.handshake orelse return error.HandshakeIncomplete;

        var w = std.Io.Writer.fixed(out);
        if (self.requested) {
            const cert_at = w.buffered().len;
            handshake.writeRawPublicKeyCertificate(
                &w,
                self.request_buf[0..self.request_len],
                key.public_key.toBytes(),
            ) catch return error.BufferTooSmall;
            self.transcript.update(w.buffered()[cert_at..]);

            var content: [handshake.max_verify_content]u8 = undefined;
            const signed = try handshake.verifyContent(
                &content,
                handshake.client_verify_context,
                self.transcript.hash(),
            );
            const sig = (key.sign(signed, null) catch return error.BadCertificateVerify).toBytes();

            const cv_at = w.buffered().len;
            handshake.writeCertificateVerify(
                &w,
                @backingInt(SignatureScheme.ed25519),
                &sig,
            ) catch return error.BufferTooSmall;
            self.transcript.update(w.buffered()[cv_at..]);
        }

        const vd = tls.verifyData(hs.client, self.transcript.hash());
        const fin_at = w.buffered().len;
        handshake.writeMessage(&w, .finished, &vd) catch return error.BufferTooSmall;
        self.transcript.update(w.buffered()[fin_at..]);

        return w.buffered();
    }

    /// A `writeFlight` stream sealed into a Handshake packet, addressed to the
    /// id the server gave us. The packet number is fresh each time, so resending
    /// is calling this again with the same bytes.
    pub fn sealFlight(self: *Handshaker, out: []u8, flight: []const u8) Error!usize {
        const hs = self.accepted.handshake orelse return error.HandshakeIncomplete;
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
        }, fw.buffered(), crypto.keysFromSecret(hs.client));
        return self.tracked(.handshake, pn, n);
    }

    /// Checks the peer's signature over the transcript through Certificate.
    /// Only the raw public key profile is verifiable: an X.509 chain signs with
    /// ECDSA or RSA, neither of which radish has.
    fn certificateVerify(self: *Handshaker, body: []const u8) Error!void {
        const cv = try handshake.parseCertificateVerify(body);
        if (cv.algorithm != @backingInt(SignatureScheme.ed25519)) return error.UnsupportedSignature;
        if (cv.signature.len != Ed25519.Signature.encoded_length) return error.BadCertificateVerify;
        const key = self.accepted.peer_key orelse return error.Malformed;

        var content: [handshake.max_verify_content]u8 = undefined;
        const signed = try handshake.verifyContent(
            &content,
            handshake.server_verify_context,
            self.transcript.hash(),
        );

        const pk = Ed25519.PublicKey.fromBytes(key) catch return error.BadCertificateVerify;
        const sig = Ed25519.Signature.fromBytes(cv.signature[0..Ed25519.Signature.encoded_length].*);
        sig.verify(signed, pk) catch return error.BadCertificateVerify;
        self.accepted.peer_verified = true;
    }

    fn encryptedExtensions(self: *Handshaker, body: []const u8) Error!void {
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

        // Both are mandatory, and their absence is an error in its own right.
        // Source: RFC 9000 s7.3.
        if (!self.saw_initial_scid or !self.saw_original_dcid) {
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

    /// Checks the connection ids the server claims against the ones actually on
    /// the packets. Nothing else authenticates them: they travel in cleartext
    /// headers, so only this comparison ties them to the handshake.
    /// Source: RFC 9000 s7.3.
    fn transportParams(self: *Handshaker, body: []const u8) Error!void {
        var it = handshake.TransportParamIterator.init(body);
        while (try it.next()) |p| switch (p.id) {
            .initial_source_connection_id => {
                if (!std.mem.eql(u8, p.value, self.accepted.scid())) {
                    return error.TransportParameterError;
                }
                self.saw_initial_scid = true;
            },
            .original_destination_connection_id => {
                if (!std.mem.eql(u8, p.value, self.original_dcid[0..self.original_dcid_len])) {
                    return error.TransportParameterError;
                }
                self.saw_original_dcid = true;
            },
            // The limits on what we may send. `bidi_remote` is the one that
            // covers streams we open ourselves.
            // Source: RFC 9000 s18.2.
            .max_idle_timeout => self.peer_idle_ms = try varintParam(p.value),
            // What a lost connection will be proved with, and how long the peer
            // may sit on an acknowledgement before sending it.
            // Source: RFC 9000 s10.3, s13.2.1.
            .stateless_reset_token => {
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
            .initial_max_stream_data_bidi_remote => {
                self.send_stream.extend(try varintParam(p.value));
            },
            else => {},
        };
    }
};

const testing = std.testing;
const testdata = @import("testdata.zig");
const hex = testdata.hex;

/// Buffers a handshaker borrows, declared by the caller because they outlive
/// the call that made it. The send buffer holds two full packets' worth, for
/// the tests that fill the sender.
const TestBufs = struct {
    initial: [1024]u8 = undefined,
    handshake: [1024]u8 = undefined,
    send: [2 * max_stream_chunk]u8 = undefined,
};

/// A handshaker addressing itself, for tests that only drive one side.
fn testHandshaker(dcid: []const u8, bufs: *TestBufs) Handshaker {
    return Handshaker.init(.{
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
fn appHandshaker(dcid: []const u8, bufs: *TestBufs, stream_buf: []u8) Handshaker {
    var h = Handshaker.init(.{
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
    const kp = try std.crypto.dh.X25519.KeyPair.generateDeterministic(secret);
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

    // The keys the server would use, derived the same way the Handshaker will.
    var t: handshake.Transcript = .{};
    t.update(initial.client_hello);
    t.update(&sh);
    const share = (try (try handshake.parseServerHello(&sh)).keyShare()).?.key;
    const shared = try tls.x25519(secret, share[0..32].*);
    const hs = tls.handshakeTraffic(tls.handshakeSecret(tls.earlySecret(), &shared), t.hash());

    // EncryptedExtensions announcing raw public keys and the ALPN, then a
    // Certificate holding one ed25519 SubjectPublicKeyInfo, then Finished.
    // A real key from a fixed seed, so CertificateVerify can sign against it
    // once that lands.
    const server_key = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(7));
    const peer_key = server_key.public_key.toBytes();
    // Hashed one message at a time: CertificateVerify and Finished each cover
    // the transcript up to but not including themselves.
    var server_flight: [1024]u8 = undefined;
    var stw = std.Io.Writer.fixed(&server_flight);
    var st: handshake.Transcript = .{};
    st.update(initial.client_hello);
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
    var h = Handshaker.init(.{
        .original_dcid = &dcid,
        .our_scid = &dcid,
        .client_hello = initial.client_hello,
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
    const our_key = try Ed25519.KeyPair.generateDeterministic(@splat(9));
    var messages_buf: [1024]u8 = undefined;
    var flight: [1024]u8 = undefined;
    const sent = try h.sealFlight(&flight, try h.writeFlight(&messages_buf, our_key));

    var mirror: handshake.Transcript = .{};
    mirror.update(initial.client_hello);
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
    var h = testHandshaker(&dcid, &bufs);

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
    var h = appHandshaker(&dcid, &bufs, &stream_buf);
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
    var h = testHandshaker(&dcid, &bufs);

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
    var h = appHandshaker(&dcid, &bufs, &stream_buf);
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
    var h = appHandshaker(&dcid, &bufs, &stream_buf);

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
    var h = testHandshaker(&dcid, &bufs);

    try testing.expectEqual(Handshaker.Phase.wait_server_hello, h.phase);

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
    var h = testHandshaker(&dcid, &bufs);

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

test "a bulk transfer is acknowledged every second packet, not every packet" {
    const dcid = hex(testdata.other_dcid);
    var bufs: TestBufs = .{};
    var stream_buf: [4096]u8 = undefined;
    var h = appHandshaker(&dcid, &bufs, &stream_buf);

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
    var h = appHandshaker(&dcid, &bufs, &stream_buf);

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
    var h = testHandshaker(&dcid, &bufs);

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
    var h = testHandshaker(&dcid, &bufs);

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
