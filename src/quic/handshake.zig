//! TLS 1.3 handshake messages as QUIC carries them: raw messages with no
//! record layer, delivered in CRYPTO frames.
//! Source: RFC 8446 s4.
const std = @import("std");
const codec = @import("../codec.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const HandshakeType = std.crypto.tls.HandshakeType;
const ExtensionType = std.crypto.tls.ExtensionType;
const NamedGroup = std.crypto.tls.NamedGroup;
const ProtocolVersion = std.crypto.tls.ProtocolVersion;

pub const Error = error{
    BufferTooSmall,
    NotServerHello,
    Malformed,
} || codec.Error;

/// TLS 1.3 pins this field at the TLS 1.2 value and negotiates the real
/// version through the supported_versions extension.
pub const legacy_version: u16 = 0x0303;

/// Fixed at 32 bytes by RFC 8446 s4.1.2.
pub const Random = [32]u8;

pub const PublicKey = [std.crypto.dh.X25519.public_length]u8;

pub const ClientHello = struct {
    random: Random,
    session_id: []const u8 = &.{},
    cipher_suites: []const u16,
    /// Already encoded, each as `type ++ u16 len ++ body`.
    extensions: []const u8,

    fn bodyLen(self: ClientHello) usize {
        return 2 + self.random.len + 1 + self.session_id.len +
            2 + 2 * self.cipher_suites.len + 2 + 2 + self.extensions.len;
    }
};

/// Writes a ClientHello into `out`, returning the used prefix.
pub fn writeClientHello(out: []u8, ch: ClientHello) Error![]u8 {
    var w = std.Io.Writer.fixed(out);
    writeFields(&w, ch) catch return error.BufferTooSmall;
    return w.buffered();
}

fn writeFields(w: *std.Io.Writer, ch: ClientHello) !void {
    try w.writeInt(u8, @backingInt(HandshakeType.client_hello), .big);
    try w.writeInt(u24, @intCast(ch.bodyLen()), .big);

    try w.writeInt(u16, legacy_version, .big);
    try w.writeAll(&ch.random);

    try w.writeInt(u8, @intCast(ch.session_id.len), .big);
    try w.writeAll(ch.session_id);

    try w.writeInt(u16, @intCast(2 * ch.cipher_suites.len), .big);
    for (ch.cipher_suites) |cs| try w.writeInt(u16, cs, .big);

    // legacy_compression_methods: one method, null.
    try w.writeInt(u8, 1, .big);
    try w.writeInt(u8, 0, .big);

    try w.writeInt(u16, @intCast(ch.extensions.len), .big);
    try w.writeAll(ch.extensions);
}

/// Writes one extension as `type ++ u16 len ++ body`.
pub fn writeExtension(w: *std.Io.Writer, ext_type: u16, body: []const u8) !void {
    try w.writeInt(u16, ext_type, .big);
    try w.writeInt(u16, @intCast(body.len), .big);
    try w.writeAll(body);
}

pub const Extension = struct {
    type: ExtensionType,
    body: []const u8,
};

pub const ExtensionIterator = struct {
    r: codec.Reader,

    pub fn init(bytes: []const u8) ExtensionIterator {
        return .{ .r = .{ .buf = bytes } };
    }

    pub fn next(self: *ExtensionIterator) Error!?Extension {
        if (self.r.pos >= self.r.buf.len) return null;
        const t = try self.r.readU16();
        const len = try self.r.readU16();
        return .{ .type = @fromBackingInt(t), .body = try self.r.take(len) };
    }
};

/// key_share carrying a single x25519 entry, as a ClientHello sends it.
pub fn writeKeyShare(w: *std.Io.Writer, public_key: PublicKey) !void {
    try w.writeInt(u16, @backingInt(ExtensionType.key_share), .big);
    try w.writeInt(u16, 2 + 2 + 2 + public_key.len, .big);
    try w.writeInt(u16, 2 + 2 + public_key.len, .big); // client_shares
    try w.writeInt(u16, @backingInt(NamedGroup.x25519), .big);
    try w.writeInt(u16, public_key.len, .big);
    try w.writeAll(&public_key);
}

/// supported_versions offering TLS 1.3 only.
pub fn writeSupportedVersions(w: *std.Io.Writer) !void {
    try w.writeInt(u16, @backingInt(ExtensionType.supported_versions), .big);
    try w.writeInt(u16, 3, .big);
    try w.writeInt(u8, 2, .big);
    try w.writeInt(u16, @backingInt(ProtocolVersion.tls_1_3), .big);
}

pub const KeyShare = struct {
    group: NamedGroup,
    key: []const u8,
};

/// A HelloRetryRequest is a ServerHello carrying this in place of a random.
/// Its key_share holds only a group, so it needs a separate path.
/// SHA256 of "HelloRetryRequest".
/// Source: RFC 8446 s4.1.3.
pub const hello_retry_request_random: Random = .{
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02,
    0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
    0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
};

pub const ServerHello = struct {
    random: Random,
    cipher_suite: u16,
    extensions: []const u8,
    /// Bytes this message occupies, so the transcript covers exactly it and not
    /// whatever trails it in the CRYPTO frame.
    len: usize,

    pub fn isHelloRetryRequest(self: ServerHello) bool {
        return std.mem.eql(u8, &self.random, &hello_retry_request_random);
    }

    pub fn find(self: ServerHello, t: ExtensionType) Error!?[]const u8 {
        var it = ExtensionIterator.init(self.extensions);
        while (try it.next()) |e| {
            if (e.type == t) return e.body;
        }
        return null;
    }

    /// The server's chosen group and public key. One entry, not a list.
    pub fn keyShare(self: ServerHello) Error!?KeyShare {
        const body = try self.find(.key_share) orelse return null;
        var r = codec.Reader{ .buf = body };
        const group = try r.readU16();
        const len = try r.readU16();
        return .{ .group = @fromBackingInt(group), .key = try r.take(len) };
    }

    /// The negotiated version, which TLS 1.3 puts here rather than in
    /// legacy_version.
    pub fn selectedVersion(self: ServerHello) Error!?u16 {
        const body = try self.find(.supported_versions) orelse return null;
        var r = codec.Reader{ .buf = body };
        return try r.readU16();
    }
};

pub const ParsedClientHello = struct {
    random: Random,
    cipher_suites: []const u8,
    extensions: []const u8,
    /// Bytes this message occupies, so a CRYPTO frame holding more than one
    /// can be walked and the transcript can cover exactly this message.
    len: usize,

    pub fn find(self: ParsedClientHello, t: ExtensionType) Error!?[]const u8 {
        var it = ExtensionIterator.init(self.extensions);
        while (try it.next()) |e| {
            if (e.type == t) return e.body;
        }
        return null;
    }
};

pub fn parseClientHello(msg: []const u8) Error!ParsedClientHello {
    var r = codec.Reader{ .buf = msg };
    if (try r.readU8() != @backingInt(HandshakeType.client_hello)) return error.Malformed;

    const body_len = std.mem.readInt(u24, (try r.take(3))[0..3], .big);
    const len = 4 + @as(usize, body_len);
    if (msg.len < len) return error.Malformed;
    // Confine the reader to the declared body, so a message that follows in the
    // same CRYPTO frame cannot be read as this one's fields.
    r.buf = msg[0..len];

    _ = try r.readU16(); // legacy_version
    const random: Random = (try r.take(@sizeOf(Random)))[0..@sizeOf(Random)].*;
    _ = try r.take(try r.readU8()); // legacy_session_id
    const suites = try r.take(try r.readU16());
    _ = try r.take(try r.readU8()); // legacy_compression_methods

    return .{
        .random = random,
        .cipher_suites = suites,
        .extensions = try r.take(try r.readU16()),
        .len = len,
    };
}

pub fn parseServerHello(msg: []const u8) Error!ServerHello {
    var r = codec.Reader{ .buf = msg };
    if (try r.readU8() != @backingInt(HandshakeType.server_hello)) return error.NotServerHello;

    const body_len = std.mem.readInt(u24, (try r.take(3))[0..3], .big);
    const len = 4 + @as(usize, body_len);
    if (msg.len < len) return error.Malformed;
    r.buf = msg[0..len];

    _ = try r.readU16(); // legacy_version
    const random: Random = (try r.take(@sizeOf(Random)))[0..@sizeOf(Random)].*;
    _ = try r.take(try r.readU8()); // legacy_session_id_echo
    const cipher_suite = try r.readU16();
    _ = try r.readU8(); // legacy_compression_method

    const ext_len = try r.readU16();
    return .{
        .random = random,
        .cipher_suite = cipher_suite,
        .extensions = try r.take(ext_len),
        .len = len,
    };
}

/// Transport parameter ids. Source: RFC 9000 s18.2.
pub const TransportParam = enum(u64) {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    max_udp_payload_size = 0x03,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    ack_delay_exponent = 0x0a,
    max_ack_delay = 0x0b,
    disable_active_migration = 0x0c,
    preferred_address = 0x0d,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    retry_source_connection_id = 0x10,
    _,
};

/// Each parameter is `id ++ length ++ value`, all varints.
pub fn writeTransportParam(w: *std.Io.Writer, id: TransportParam, value: []const u8) !void {
    try codec.writeVarint(w, @backingInt(id));
    try codec.writeVarint(w, value.len);
    try w.writeAll(value);
}

/// The common case: a parameter whose value is itself a varint.
pub fn writeIntTransportParam(w: *std.Io.Writer, id: TransportParam, v: u64) !void {
    var buf: [8]u8 = undefined;
    var vw = std.Io.Writer.fixed(&buf);
    try codec.writeVarint(&vw, v);
    try writeTransportParam(w, id, vw.buffered());
}

pub const TransportParamIterator = struct {
    r: codec.Reader,

    pub fn init(bytes: []const u8) TransportParamIterator {
        return .{ .r = .{ .buf = bytes } };
    }

    pub fn next(self: *TransportParamIterator) Error!?struct { id: TransportParam, value: []const u8 } {
        if (self.r.pos >= self.r.buf.len) return null;
        const id = try self.r.varint();
        const len = try self.r.varint();
        return .{ .id = @fromBackingInt(id), .value = try self.r.take(@intCast(len)) };
    }
};

/// Running hash over handshake messages, in the order they are sent. QUIC has
/// no record layer, so the messages are hashed exactly as they go on the wire.
pub const Transcript = struct {
    hasher: Sha256 = Sha256.init(.{}),

    pub fn update(self: *Transcript, msg: []const u8) void {
        self.hasher.update(msg);
    }

    pub fn hash(self: Transcript) [Sha256.digest_length]u8 {
        var copy = self.hasher;
        var out: [Sha256.digest_length]u8 = undefined;
        copy.final(&out);
        return out;
    }
};

const testing = std.testing;
const testdata = @import("testdata.zig");
const hex = testdata.hex;

// Its extensions go in verbatim: several are TLS-only and QUIC never sends them.
test "RFC 8448 ClientHello bytes" {
    var expected: [196]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, testdata.rfc8448_client_hello_hex);

    // 4 header + 2 version + 32 random + 1 session id + 8 suites + 2
    // compression + 2 extension length.
    const ext_offset = 51;

    var out: [256]u8 = undefined;
    const got = try writeClientHello(&out, .{
        .random = expected[6..38].*,
        .cipher_suites = &.{ 0x1301, 0x1303, 0x1302 },
        .extensions = expected[ext_offset..],
    });
    try testing.expectEqualSlices(u8, &expected, got);
}

// This hash is the traffic-secret context in tls.zig's RFC 8448 test.
test "RFC 8448 transcript through ServerHello" {
    var ch: [196]u8 = undefined;
    _ = try std.fmt.hexToBytes(&ch, testdata.rfc8448_client_hello_hex);
    var sh: [90]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sh, testdata.rfc8448_server_hello_hex);

    var t: Transcript = .{};
    t.update(&ch);
    t.update(&sh);
    try testing.expectEqualSlices(
        u8,
        &hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"),
        &t.hash(),
    );
}

test "parses the RFC 8448 ServerHello" {
    var sh: [90]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sh, testdata.rfc8448_server_hello_hex);

    const parsed = try parseServerHello(&sh);
    try testing.expectEqual(@as(u16, 0x1301), parsed.cipher_suite); // TLS_AES_128_GCM_SHA256
    try testing.expectEqual(@as(?u16, 0x0304), try parsed.selectedVersion());

    const ks = (try parsed.keyShare()).?;
    try testing.expectEqual(NamedGroup.x25519, ks.group);
    try testing.expectEqualSlices(
        u8,
        &hex("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f"),
        ks.key,
    );
}

test "rejects a message that is not a ServerHello" {
    var ch: [196]u8 = undefined;
    _ = try std.fmt.hexToBytes(&ch, testdata.rfc8448_client_hello_hex);
    try testing.expectError(error.NotServerHello, parseServerHello(&ch));
}

test "key_share and supported_versions round trip" {
    const public = hex("99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c");
    var buf: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeKeyShare(&w, public);
    try writeSupportedVersions(&w);

    var it = ExtensionIterator.init(w.buffered());
    const ks = (try it.next()).?;
    try testing.expectEqual(ExtensionType.key_share, ks.type);
    // list length, group, key length, then the key.
    try testing.expectEqualSlices(u8, &public, ks.body[6..]);

    const sv = (try it.next()).?;
    try testing.expectEqual(ExtensionType.supported_versions, sv.type);
    try testing.expectEqualSlices(u8, &hex("020304"), sv.body);
    try testing.expectEqual(@as(?Extension, null), try it.next());
}

test "transport parameters round trip" {
    var buf: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeIntTransportParam(&w, .initial_max_data, 1048576);
    try writeTransportParam(&w, .initial_source_connection_id, &hex("8394c8f03e515708"));

    var it = TransportParamIterator.init(w.buffered());
    const first = (try it.next()).?;
    try testing.expectEqual(TransportParam.initial_max_data, first.id);
    var vr = codec.Reader{ .buf = first.value };
    try testing.expectEqual(@as(u64, 1048576), try vr.varint());

    const cid = (try it.next()).?;
    try testing.expectEqual(TransportParam.initial_source_connection_id, cid.id);
    try testing.expectEqualSlices(u8, &hex("8394c8f03e515708"), cid.value);
    try testing.expectEqual(@as(usize, w.buffered().len), it.r.pos);
}

test "extensions are type, length, body" {
    var buf: [16]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeExtension(&w, 0x002b, &.{ 0x02, 0x03, 0x04 });
    try testing.expectEqualSlices(u8, &hex("002b0003020304"), w.buffered());
}
