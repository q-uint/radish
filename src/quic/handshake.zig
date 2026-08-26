//! TLS 1.3 handshake messages as QUIC carries them: raw messages with no
//! record layer, delivered in CRYPTO frames.
//! Source: RFC 8446 s4.
const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;
const HandshakeType = std.crypto.tls.HandshakeType;

pub const Error = error{BufferTooSmall};

/// TLS 1.3 pins this field at the TLS 1.2 value and negotiates the real
/// version through the supported_versions extension.
pub const legacy_version: u16 = 0x0303;

pub const ClientHello = struct {
    random: [32]u8,
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

// Several of this ClientHello's extensions are TLS-only and QUIC never sends
// them, so they go in verbatim rather than being constructed.
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

// Closes the loop with the key schedule: this hash is the `c hs traffic` and
// `s hs traffic` context in tls.zig's RFC 8448 test.
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

test "extensions are type, length, body" {
    var buf: [16]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeExtension(&w, 0x002b, &.{ 0x02, 0x03, 0x04 });
    try testing.expectEqualSlices(u8, &hex("002b0003020304"), w.buffered());
}
