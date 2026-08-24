//! QUIC packet headers and header protection (RFC 9000 s17, RFC 9001 s5.4).
//!
//! QUIC hides two things in every header: the packet number, and the low bits
//! of the first byte, which include how long that packet number is. Hiding the
//! length is what creates the ordering problem below, and it is the reason
//! protecting and unprotecting a header are not the same function.
const std = @import("std");
const codec = @import("../codec.zig");
const crypto = @import("crypto.zig");
const frame = @import("frame.zig");
const testdata = @import("testdata.zig");

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

pub const Error = error{
    PacketTooShort,
    NotLongHeader,
    UnsupportedPacket,
    ConnectionIdTooLong,
    BufferTooSmall,
    AuthenticationFailed,
} || codec.Error;

/// The first byte's high bit selects the header form. Long headers carry the
/// version and both connection ids and are used until the handshake completes;
/// short headers are everything after.
pub fn isLongHeader(first: u8) bool {
    return first & 0x80 != 0;
}

/// Low bits of the first byte that header protection masks. Long headers hide
/// four; short headers hide five, the extra one being the key phase bit.
fn maskedBits(first: u8) u8 {
    return if (isLongHeader(first)) 0x0f else 0x1f;
}

/// Packet number length, in bytes, encoded in the low two bits of the first
/// byte. Only meaningful once the first byte is unprotected.
fn pnLen(first: u8) usize {
    return (first & 0x03) + 1;
}

/// Where the sample for header protection starts, given the packet number's
/// offset. The Packet Number field is *assumed* to be its maximum 4 bytes
/// regardless of its real length. A receiver cannot know the real length until
/// it has already removed protection, so the sample position must not depend
/// on it.
/// Source: RFC 9001 s5.4.2.
pub fn sampleOffset(pn_offset: usize) usize {
    return pn_offset + 4;
}

/// Removes header protection in the only order the receiver can: unmask the
/// first byte, read the now-visible packet number length from it, then unmask
/// exactly that many packet number bytes. Returns the packet number length.
///
/// `header` must be the packet buffer, mutated in place.
/// Source: RFC 9001 s5.4.1.
pub fn unprotectHeader(header: []u8, pn_offset: usize, mask: [crypto.mask_len]u8) Error!usize {
    if (header.len < pn_offset + 1) return error.PacketTooShort;

    header[0] ^= mask[0] & maskedBits(header[0]);
    const n = pnLen(header[0]);
    if (header.len < pn_offset + n) return error.PacketTooShort;

    for (0..n) |i| header[pn_offset + i] ^= mask[1 + i];
    return n;
}

/// Applies header protection. The sender knows the packet number length up
/// front, so unlike the receive path this needs no discovery step.
pub fn protectHeader(header: []u8, pn_offset: usize, mask: [crypto.mask_len]u8) Error!void {
    if (header.len < pn_offset + 1) return error.PacketTooShort;
    const n = pnLen(header[0]);
    if (header.len < pn_offset + n) return error.PacketTooShort;

    for (0..n) |i| header[pn_offset + i] ^= mask[1 + i];
    header[0] ^= mask[0] & maskedBits(header[0]);
}

/// Long header packet types in QUIC v1, carried in bits 5-4 of the first byte.
/// Source: RFC 9000 s17.2.
pub const Kind = enum(u2) { initial = 0, zero_rtt = 1, handshake = 2, retry = 3 };

/// Largest connection id QUIC v1 allows.
pub const max_cid_len = 20;

/// A parsed long header. The slices borrow from the packet buffer.
pub const LongHeader = struct {
    kind: Kind,
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    token: []const u8,
    /// Covers the packet number, the payload, and the authentication tag, so
    /// everything after this field.
    length: u64,
    /// Where the packet number begins, and so what the sample offset is
    /// measured from. This is the `18` the header protection tests hardcoded.
    pn_offset: usize,
};

/// Parses a long header. Retry packets are rejected: they carry an integrity
/// tag instead of a length and packet number, so they need their own path.
/// Source: RFC 9000 s17.2.
pub fn parseLongHeader(packet: []const u8) Error!LongHeader {
    var r = codec.Reader{ .buf = packet };

    const first = try r.readU8();
    if (!isLongHeader(first)) return error.NotLongHeader;
    // The "fixed bit". Always 1 in QUIC v1, and a packet with it clear is not
    // QUIC at all. It is what lets other protocols share the UDP port.
    if (first & 0x40 == 0) return error.NotLongHeader;

    const kind: Kind = @fromBackingInt(@intCast(@as(u2, @truncate(first >> 4))));
    if (kind == .retry) return error.UnsupportedPacket;

    const version = std.mem.readInt(u32, (try r.take(4))[0..4], .big);

    // Both connection ids are length-prefixed by a single byte, which is why
    // QUIC can change them mid-connection without renegotiating anything.
    const dcid_len = try r.readU8();
    if (dcid_len > max_cid_len) return error.ConnectionIdTooLong;
    const dcid = try r.take(dcid_len);

    const scid_len = try r.readU8();
    if (scid_len > max_cid_len) return error.ConnectionIdTooLong;
    const scid = try r.take(scid_len);

    // Only Initial packets carry a token, used by the server to validate an
    // address after a Retry.
    var token: []const u8 = &.{};
    if (kind == .initial) token = try r.take(@intCast(try r.varint()));

    const length = try r.varint();
    return .{
        .kind = kind,
        .version = version,
        .dcid = dcid,
        .scid = scid,
        .token = token,
        .length = length,
        .pn_offset = r.pos,
    };
}

/// Recovers a full packet number from the truncated one on the wire. Only the
/// low bytes are sent, so the receiver picks the candidate nearest to the next
/// number it expects. With no packets received yet, that expectation is zero.
/// Source: RFC 9000 A.3.
pub fn decodePacketNumber(largest_pn: ?u64, truncated: u64, pn_len: usize) u64 {
    const nbits: u7 = @intCast(pn_len * 8);
    const expected: i128 = if (largest_pn) |l| @as(i128, l) + 1 else 0;
    const win = @as(i128, 1) << nbits;
    const hwin = @divTrunc(win, 2);
    const candidate = (expected & ~(win - 1)) | @as(i128, @intCast(truncated));

    if (candidate <= expected - hwin and candidate < (@as(i128, 1) << 62) - win) {
        return @intCast(candidate + win);
    }
    if (candidate > expected + hwin and candidate >= win) {
        return @intCast(candidate - win);
    }
    return @intCast(candidate);
}

/// The AEAD nonce: the static IV XORed with the packet number, right-aligned.
/// Nothing is transmitted, since both ends already agree on the packet number,
/// so uniqueness comes free as long as a number is never reused under one key.
/// Source: RFC 9001 s5.3.
pub fn nonce(iv: [12]u8, pn: u64) [12]u8 {
    var n = iv;
    var pn_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &pn_be, pn, .big);
    for (0..8) |i| n[4 + i] ^= pn_be[i];
    return n;
}

pub const Opened = struct {
    header: LongHeader,
    pn: u64,
    /// Decrypted frames, borrowing from the caller's `out` buffer.
    payload: []const u8,
};

/// Unprotects and decrypts one long-header packet in place, writing the
/// plaintext frames to `out`. `packet` is mutated: header protection is
/// removed from it, which is also what makes it usable as the AEAD's
/// associated data afterwards.
pub fn open(out: []u8, packet: []u8, keys: crypto.Keys, largest_pn: ?u64) Error!Opened {
    const hdr = try parseLongHeader(packet);

    const so = sampleOffset(hdr.pn_offset);
    if (packet.len < so + crypto.sample_len) return error.PacketTooShort;
    const mask = crypto.headerMask(keys.hp, packet[so..][0..crypto.sample_len].*);

    const pn_len = try unprotectHeader(packet, hdr.pn_offset, mask);

    var truncated: u64 = 0;
    for (packet[hdr.pn_offset..][0..pn_len]) |b| truncated = (truncated << 8) | b;
    const pn = decodePacketNumber(largest_pn, truncated, pn_len);

    // The AEAD authenticates but does not encrypt the header, in exactly the
    // unprotected form it now has. Tamper with any header byte and this fails.
    const aad = packet[0 .. hdr.pn_offset + pn_len];

    const length = std.math.cast(usize, hdr.length) orelse return error.PacketTooShort;
    const end = hdr.pn_offset + length;
    if (packet.len < end or length < pn_len + Aes128Gcm.tag_length) return error.PacketTooShort;

    const body = packet[hdr.pn_offset + pn_len .. end];
    const ct = body[0 .. body.len - Aes128Gcm.tag_length];
    const tag = body[body.len - Aes128Gcm.tag_length ..][0..Aes128Gcm.tag_length].*;
    if (out.len < ct.len) return error.BufferTooSmall;

    Aes128Gcm.decrypt(out[0..ct.len], ct, tag, aad, nonce(keys.iv, pn), keys.key) catch {
        return error.AuthenticationFailed;
    };
    return .{ .header = hdr, .pn = pn, .payload = out[0..ct.len] };
}

const testing = std.testing;

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

// RFC 9001 A.2 works the example through by hand: an unprotected header with a
// packet number of 2, the mask derived from the payload sample, and the
// protected result. pn_offset is 18 here, which the parser will compute once it
// exists: 7 + dcid(8) + scid(0) + payload length varint(2) + token length(1).
const a2_unprotected = "c300000001088394c8f03e5157080000449e00000002";
const a2_protected = "c000000001088394c8f03e5157080000449e7b9aec34";
const a2_mask = "437b9aec36";
const a2_pn_offset = 18;

test "RFC 9001 A.2 protects the client Initial header" {
    var header = hex(a2_unprotected);
    try protectHeader(&header, a2_pn_offset, hex(a2_mask));
    try testing.expectEqualSlices(u8, &hex(a2_protected), &header);
}

test "RFC 9001 A.2 unprotects the client Initial header" {
    var header = hex(a2_protected);
    const n = try unprotectHeader(&header, a2_pn_offset, hex(a2_mask));

    try testing.expectEqual(@as(usize, 4), n);
    try testing.expectEqualSlices(u8, &hex(a2_unprotected), &header);

    // The packet number the RFC states for this packet.
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, header[a2_pn_offset..][0..4], .big));
}

// The length is hidden in the bits protection covers, so a receiver that
// unmasked the packet number before the first byte would not know how many
// bytes to unmask. Protecting reverses that order for the same reason.
test "packet number length is only readable after the first byte is unmasked" {
    const protected = hex(a2_protected);
    try testing.expectEqual(@as(usize, 1), pnLen(protected[0])); // wrong, still masked

    var header = protected;
    header[0] ^= hex(a2_mask)[0] & maskedBits(header[0]);
    try testing.expectEqual(@as(usize, 4), pnLen(header[0])); // correct
}

// RFC 9000 A.3's worked example.
test "packet number decoding picks the candidate nearest what is expected" {
    try testing.expectEqual(@as(u64, 0xa82f9b32), decodePacketNumber(0xa82f30ea, 0x9b32, 2));
    // With nothing received yet, a truncated 2 decodes to 2.
    try testing.expectEqual(@as(u64, 2), decodePacketNumber(null, 2, 4));
}

test "nonce is the iv xored with the packet number" {
    const iv = hex("fa044b2f42a3fd3b46fb255c");
    // Packet number 0 must leave the iv untouched.
    try testing.expectEqualSlices(u8, &iv, &nonce(iv, 0));
    // Packet number 2 flips only the last byte.
    try testing.expectEqualSlices(u8, &hex("fa044b2f42a3fd3b46fb255e"), &nonce(iv, 2));
}

test "parses the RFC 9001 A.2 long header" {
    var packet: [1200]u8 = undefined;
    _ = try std.fmt.hexToBytes(&packet, testdata.client_initial_protected_hex);

    const h = try parseLongHeader(&packet);
    try testing.expectEqual(Kind.initial, h.kind);
    try testing.expectEqual(@as(u32, 1), h.version); // QUIC v1
    try testing.expectEqualSlices(u8, &hex("8394c8f03e515708"), h.dcid);
    try testing.expectEqual(@as(usize, 0), h.scid.len);
    try testing.expectEqual(@as(usize, 0), h.token.len);
    try testing.expectEqual(@as(u64, 1182), h.length); // 4 pn + 1162 frames + 16 tag

    // The offset the header protection tests had to be told.
    try testing.expectEqual(@as(usize, a2_pn_offset), h.pn_offset);
}

// The whole packet layer end to end: a real 1200-byte QUIC packet in, the
// TLS ClientHello that started a connection out.
test "opens the RFC 9001 A.2 client Initial and finds the ClientHello" {
    var packet: [1200]u8 = undefined;
    _ = try std.fmt.hexToBytes(&packet, testdata.client_initial_protected_hex);

    const keys = crypto.keysFromSecret(crypto.initialSecrets(&hex("8394c8f03e515708")).client);

    var out: [1200]u8 = undefined;
    const opened = try open(&out, &packet, keys, null);

    try testing.expectEqual(@as(u64, 2), opened.pn);
    try testing.expectEqual(@as(usize, 1162), opened.payload.len);

    // The payload is one CRYPTO frame, then padding out to the 1200-byte
    // minimum an Initial datagram has to reach.
    var it = frame.Iterator.init(opened.payload);
    const first = (try it.next()).?;
    try testing.expectEqual(@as(u64, 0), first.crypto.offset);
    try testing.expectEqual(@as(usize, 241), first.crypto.data.len);

    var expected: [245]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, testdata.client_initial_crypto_frame_hex);
    try testing.expectEqualSlices(u8, expected[4..], first.crypto.data);

    try testing.expectEqual(@as(usize, 917), (try it.next()).?.padding);
    try testing.expectEqual(@as(?frame.Frame, null), try it.next());

    // TLS handshake type 1 is client_hello, with a 3-byte length that must
    // account for the rest of the frame.
    try testing.expectEqual(@as(u8, 0x01), first.crypto.data[0]);
    const hs_len = std.mem.readInt(u24, first.crypto.data[1..4], .big);
    try testing.expectEqual(first.crypto.data.len - 4, hs_len);
}

// Flipping one header byte must break the payload: the header is the AEAD's
// associated data, so the two cannot be tampered with independently.
test "a modified header fails authentication" {
    var packet: [1200]u8 = undefined;
    _ = try std.fmt.hexToBytes(&packet, testdata.client_initial_protected_hex);
    // First byte of the destination connection id: byte 0 is the header form,
    // 1-4 the version, 5 the id's length, so the id itself starts at 6. The
    // keys stay derived from the original id, so only the AEAD's view changes.
    packet[6] ^= 0x01;

    const keys = crypto.keysFromSecret(crypto.initialSecrets(&hex("8394c8f03e515708")).client);
    var out: [1200]u8 = undefined;
    try testing.expectError(error.AuthenticationFailed, open(&out, &packet, keys, null));
}

test "a header too short to hold its packet number is rejected" {
    var header = hex("c300000001088394c8f03e5157080000449e0000");
    try testing.expectError(error.PacketTooShort, protectHeader(&header, a2_pn_offset, hex(a2_mask)));
}
