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
    InvalidPacketNumberLength,
    PacketNumberTooLarge,
    PayloadTooShortToSample,
    VersionNegotiation,
    UnsupportedVersion,
    ProtocolViolation,
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
    if (header.len < pn_offset + n) {
        // Undo it, so a refused packet is still the bytes that arrived. The
        // form bit is outside the mask, so `maskedBits` has not changed.
        header[0] ^= mask[0] & maskedBits(header[0]);
        return error.PacketTooShort;
    }

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

/// The only version we speak. Version 0 marks a Version Negotiation packet,
/// which carries a list of versions instead of a v1 header and so needs its
/// own parser.
pub const version_1: u32 = 1;

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

    // Read the version before checking anything else in the first byte: a
    // Version Negotiation packet leaves those bits arbitrary, so the fixed-bit
    // check below would reject it before we could recognise what it is.
    const version = std.mem.readInt(u32, (try r.take(4))[0..4], .big);
    if (version == 0) return error.VersionNegotiation;

    // The "fixed bit". Always 1 in QUIC v1, and a packet with it clear is not
    // QUIC at all. It is what lets other protocols share the UDP port.
    if (first & 0x40 == 0) return error.NotLongHeader;
    if (version != version_1) return error.UnsupportedVersion;

    const kind: Kind = @fromBackingInt(@as(u2, @truncate(first >> 4)));
    if (kind == .retry) return error.UnsupportedPacket;

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
    /// Bytes this packet occupies, so where the next one in a coalesced
    /// datagram starts.
    len: usize,
};

/// Unprotects and decrypts one long-header packet in place, writing the
/// plaintext frames to `out`. On failure `packet` is restored to the bytes
/// that arrived.
pub fn open(out: []u8, packet: []u8, keys: crypto.Keys, largest_pn: ?u64) Error!Opened {
    const hdr = try parseLongHeader(packet);

    const length = std.math.cast(usize, hdr.length) orelse return error.PacketTooShort;
    const end = hdr.pn_offset + length;
    if (packet.len < end) return error.PacketTooShort;

    // Bounded by this packet's declared end, not the datagram's: a short
    // packet must be discarded rather than sample the next one's bytes.
    // Source: RFC 9001 s5.4.2.
    const so = sampleOffset(hdr.pn_offset);
    if (end < so + crypto.sample_len) return error.PacketTooShort;
    const mask = crypto.headerMask(keys.hp, packet[so..][0..crypto.sample_len].*);

    const pn_len = try unprotectHeader(packet, hdr.pn_offset, mask);
    // XOR is its own inverse; bounds already checked above.
    errdefer protectHeader(packet[0 .. hdr.pn_offset + pn_len], hdr.pn_offset, mask) catch unreachable;

    // Reserved bits must be zero once unprotected.
    // Source: RFC 9000 s17.2.
    if (packet[0] & 0x0c != 0) return error.ProtocolViolation;
    if (length < pn_len + Aes128Gcm.tag_length) return error.PacketTooShort;

    const truncated = std.mem.readVarInt(u64, packet[hdr.pn_offset..][0..pn_len], .big);
    const pn = decodePacketNumber(largest_pn, truncated, pn_len);

    // The AEAD authenticates the header in the unprotected form it now has.
    const aad = packet[0 .. hdr.pn_offset + pn_len];

    const body = packet[hdr.pn_offset + pn_len .. end];
    const ct = body[0 .. body.len - Aes128Gcm.tag_length];
    const tag = body[body.len - Aes128Gcm.tag_length ..][0..Aes128Gcm.tag_length].*;
    if (out.len < ct.len) return error.BufferTooSmall;

    Aes128Gcm.decrypt(out[0..ct.len], ct, tag, aad, nonce(keys.iv, pn), keys.key) catch {
        return error.AuthenticationFailed;
    };
    return .{ .header = hdr, .pn = pn, .payload = out[0..ct.len], .len = end };
}

/// Everything needed to write a long header. `pn_len` is the caller's choice:
/// fewer bytes make a smaller header, but the peer can only recover the number
/// from its low bytes, so it has to be wide enough to cover how far
/// acknowledgements may lag.
pub const Build = struct {
    kind: Kind,
    version: u32 = 1,
    dcid: []const u8,
    scid: []const u8 = &.{},
    token: []const u8 = &.{},
    pn: u64,
    pn_len: usize,
};

pub const Header = struct {
    /// Bytes written, through the end of the packet number.
    len: usize,
    pn_offset: usize,
};

fn writeFields(w: *std.Io.Writer, b: Build, payload_len: usize) !usize {
    // form(1) fixed(1) type(2) reserved(2) pn_len(2)
    try w.writeInt(u8, 0xc0 | (@as(u8, @backingInt(b.kind)) << 4) | @as(u8, @intCast(b.pn_len - 1)), .big);
    try w.writeInt(u32, b.version, .big);

    try w.writeInt(u8, @intCast(b.dcid.len), .big);
    try w.writeAll(b.dcid);
    try w.writeInt(u8, @intCast(b.scid.len), .big);
    try w.writeAll(b.scid);

    if (b.kind == .initial) {
        try codec.writeVarint(w, b.token.len);
        try w.writeAll(b.token);
    }
    try codec.writeVarint(w, b.pn_len + payload_len + Aes128Gcm.tag_length);

    const pn_offset = w.buffered().len;
    var pn_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &pn_be, b.pn, .big);
    try w.writeAll(pn_be[8 - b.pn_len ..]);
    return pn_offset;
}

/// Smallest payload that still leaves room for a header protection sample:
/// the packet number and payload together must cover the four bytes the sample
/// skips.
/// Source: RFC 9001 s5.4.2.
pub fn minPayloadLen(pn_len: usize) usize {
    return if (pn_len >= 4) 0 else 4 - pn_len;
}

/// Writes an unprotected long header for a packet whose payload will be
/// `payload_len` bytes.
pub fn writeLongHeader(out: []u8, b: Build, payload_len: usize) Error!Header {
    // Retry carries an integrity tag instead of a length and packet number, so
    // this layout cannot express it. `parseLongHeader` rejects it too.
    if (b.kind == .retry) return error.UnsupportedPacket;
    if (b.pn_len < 1 or b.pn_len > 4) return error.InvalidPacketNumberLength;
    if (b.dcid.len > max_cid_len or b.scid.len > max_cid_len) return error.ConnectionIdTooLong;

    // Only the low `pn_len` bytes reach the wire, but the nonce uses the whole
    // number, so truncating quietly would make the peer derive a different
    // nonce. Catches dropped bits only; the full rule in RFC 9000 s17.1 needs
    // ack state we do not track yet.
    if (b.pn >> @intCast(8 * b.pn_len) != 0) return error.PacketNumberTooLarge;

    var w = std.Io.Writer.fixed(out);
    const pn_offset = writeFields(&w, b, payload_len) catch |e| return switch (e) {
        error.VarIntTooLarge => error.VarIntTooLarge,
        else => error.BufferTooSmall,
    };
    return .{ .len = w.buffered().len, .pn_offset = pn_offset };
}

/// Writes a complete protected packet into `out` and returns its length.
///
/// The two steps run in the opposite order from `open`, and they have to:
/// header protection samples the ciphertext, so the payload must be encrypted
/// before the header can be masked. On the way in, the header must be unmasked
/// before the payload can be decrypted.
pub fn seal(out: []u8, b: Build, payload: []const u8, keys: crypto.Keys) Error!usize {
    // Before the header is written, so a refused packet leaves `out` untouched.
    // Padding is the caller's call: PADDING frames are frames the peer parses.
    if (payload.len < minPayloadLen(b.pn_len)) return error.PayloadTooShortToSample;

    const h = try writeLongHeader(out, b, payload.len);

    const end = h.len + payload.len + Aes128Gcm.tag_length;
    if (out.len < end) return error.BufferTooSmall;

    // The header authenticates as associated data, unprotected as it is now.
    var tag: [Aes128Gcm.tag_length]u8 = undefined;
    Aes128Gcm.encrypt(
        out[h.len..][0..payload.len],
        &tag,
        payload,
        out[0..h.len],
        nonce(keys.iv, b.pn),
        keys.key,
    );
    @memcpy(out[h.len + payload.len ..][0..Aes128Gcm.tag_length], &tag);

    const so = sampleOffset(h.pn_offset);
    try protectHeader(out[0..h.len], h.pn_offset, crypto.headerMask(keys.hp, out[so..][0..crypto.sample_len].*));

    return end;
}

const testing = std.testing;
const hex = testdata.hex;

// RFC 9001 A.2 works the example through by hand. pn_offset is 18 here, which
// `parseLongHeader` computes: 7 + dcid(8) + scid(0) + length varint(2) + token
// length(1).
const a2_unprotected = "c300000001088394c8f03e5157080000449e00000002";
const a2_protected = "c000000001088394c8f03e5157080000449e7b9aec34";
const a2_mask = "437b9aec36";
const a2_pn_offset = 18;

fn clientKeys(comptime dcid_hex: []const u8) crypto.Keys {
    return crypto.keysFromSecret(crypto.initialSecrets(&hex(dcid_hex)).client);
}

// Protect and unprotect are inverses, but not the same function: the packet
// number length lives in the bits protection covers, so the receiver must
// unmask the first byte before it knows how many more to unmask.
test "RFC 9001 A.2 header protection round trips" {
    var header = hex(a2_unprotected);
    try protectHeader(&header, a2_pn_offset, hex(a2_mask));
    try testing.expectEqualSlices(u8, &hex(a2_protected), &header);

    // Still masked, so the length reads as 1 rather than the true 4.
    try testing.expectEqual(@as(usize, 1), pnLen(header[0]));

    try testing.expectEqual(@as(usize, 4), try unprotectHeader(&header, a2_pn_offset, hex(a2_mask)));
    try testing.expectEqualSlices(u8, &hex(a2_unprotected), &header);
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, header[a2_pn_offset..][0..4], .big));
}

test "packet number and nonce helpers" {
    // RFC 9000 A.3's worked example, then the no-history case.
    try testing.expectEqual(@as(u64, 0xa82f9b32), decodePacketNumber(0xa82f30ea, 0x9b32, 2));
    try testing.expectEqual(@as(u64, 2), decodePacketNumber(null, 2, 4));

    const iv = hex("fa044b2f42a3fd3b46fb255c");
    try testing.expectEqualSlices(u8, &iv, &nonce(iv, 0));
    try testing.expectEqualSlices(u8, &hex("fa044b2f42a3fd3b46fb255e"), &nonce(iv, 2));

    // The RFC states these two directly, so they check the derivation.
    try testing.expectEqual(@as(usize, 3), minPayloadLen(1));
    try testing.expectEqual(@as(usize, 2), minPayloadLen(2));
    try testing.expectEqual(@as(usize, 0), minPayloadLen(4));
}

test "parses the RFC 9001 A.2 long header" {
    var packet: [1200]u8 = undefined;
    _ = try std.fmt.hexToBytes(&packet, testdata.rfc9001_client_initial_hex);

    const h = try parseLongHeader(&packet);
    try testing.expectEqual(Kind.initial, h.kind);
    try testing.expectEqual(@as(u32, 1), h.version); // QUIC v1
    try testing.expectEqualSlices(u8, &hex(testdata.rfc9001_dcid), h.dcid);
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
    _ = try std.fmt.hexToBytes(&packet, testdata.rfc9001_client_initial_hex);

    const keys = crypto.keysFromSecret(crypto.initialSecrets(&hex(testdata.rfc9001_dcid)).client);

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
    _ = try std.fmt.hexToBytes(&expected, testdata.rfc9001_client_crypto_hex);
    try testing.expectEqualSlices(u8, expected[4..], first.crypto.data);

    try testing.expectEqual(@as(usize, 917), (try it.next()).?.padding);
    try testing.expectEqual(@as(?frame.Frame, null), try it.next());

    // TLS handshake type 1 is client_hello, with a 3-byte length that must
    // account for the rest of the frame.
    try testing.expectEqual(@as(u8, 0x01), first.crypto.data[0]);
    const hs_len = std.mem.readInt(u24, first.crypto.data[1..4], .big);
    try testing.expectEqual(first.crypto.data.len - 4, hs_len);
}

// The other direction, and the first real ServerHello: server Initial keys come
// from the client's *original* connection id, not the new one this packet
// carries in its header.
test "opens the RFC 9001 A.3 server Initial and finds the ServerHello" {
    var packet: [135]u8 = undefined;
    _ = try std.fmt.hexToBytes(&packet, testdata.rfc9001_server_initial_hex);

    const keys = crypto.keysFromSecret(crypto.initialSecrets(&hex(testdata.rfc9001_dcid)).server);
    var out: [256]u8 = undefined;
    const opened = try open(&out, &packet, keys, null);

    try testing.expectEqual(@as(u64, 1), opened.pn);
    // The client's source id was empty, so the server addresses it with none;
    // f067a5502a4262b5 is the new id the server offers for itself.
    try testing.expectEqual(@as(usize, 0), opened.header.dcid.len);
    try testing.expectEqualSlices(u8, &hex("f067a5502a4262b5"), opened.header.scid);

    var expected: [99]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, testdata.rfc9001_server_payload_hex);
    try testing.expectEqualSlices(u8, &expected, opened.payload);

    // An ACK for the client's packet 0, then the ServerHello.
    var it = frame.Iterator.init(opened.payload);
    const ack = (try it.next()).?.ack;
    try testing.expectEqual(@as(u64, 0), ack.largest);
    try testing.expectEqual(@as(u64, 0), ack.range_count);

    const ch = (try it.next()).?.crypto;
    try testing.expectEqual(@as(usize, 90), ch.data.len);
    try testing.expectEqual(@as(u8, 0x02), ch.data[0]); // server_hello
    try testing.expectEqual(@as(?frame.Frame, null), try it.next());
}

// The strictest test available: rebuild the RFC's packet from its plaintext
// and compare all 1200 bytes. Decryption alone can hide two errors that cancel
// out; reproducing the exact bytes cannot.
test "seals the RFC 9001 A.2 client Initial byte for byte" {
    // The plaintext is the CRYPTO frame, then PADDING out to 1162 bytes.
    var payload: [1162]u8 = @splat(0);
    _ = try std.fmt.hexToBytes(payload[0..245], testdata.rfc9001_client_crypto_hex);

    const dcid = hex("8394c8f03e515708");
    const keys = crypto.keysFromSecret(crypto.initialSecrets(&dcid).client);

    var out: [1200]u8 = undefined;
    const n = try seal(&out, .{
        .kind = .initial,
        .dcid = &dcid,
        .pn = 2,
        .pn_len = 4,
    }, &payload, keys);

    var expected: [1200]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, testdata.rfc9001_client_initial_hex);
    try testing.expectEqual(@as(usize, 1200), n);
    try testing.expectEqualSlices(u8, &expected, out[0..n]);
}

test "seal and open round trip" {
    const dcid = hex(testdata.other_dcid);
    const keys = crypto.keysFromSecret(crypto.initialSecrets(&dcid).server);

    var payload: [64]u8 = @splat(0);
    payload[0] = 0x01; // a PING frame, then padding

    var out: [256]u8 = undefined;
    const n = try seal(&out, .{ .kind = .handshake, .dcid = &dcid, .pn = 7, .pn_len = 2 }, &payload, keys);

    var plain: [256]u8 = undefined;
    const opened = try open(&plain, out[0..n], keys, 6);
    try testing.expectEqual(@as(u64, 7), opened.pn);
    try testing.expectEqual(n, opened.len);
    try testing.expectEqualSlices(u8, &payload, opened.payload);
}

// Several packets per UDP datagram is normal, so `len` has to reach the next.
test "walks a coalesced datagram" {
    const dcid = hex(testdata.other_dcid);
    const keys = clientKeys(testdata.other_dcid);
    var one_payload: [32]u8 = @splat(0);
    one_payload[0] = 0x01; // a PING frame, then padding
    var two_payload: [16]u8 = @splat(0);
    two_payload[0] = 0x01;

    var buf: [512]u8 = undefined;
    const a = try seal(&buf, .{ .kind = .initial, .dcid = &dcid, .pn = 1, .pn_len = 4 }, &one_payload, keys);
    const b = try seal(buf[a..], .{ .kind = .handshake, .dcid = &dcid, .pn = 2, .pn_len = 4 }, &two_payload, keys);

    var out: [512]u8 = undefined;
    const one = try open(&out, buf[0 .. a + b], keys, null);
    try testing.expectEqual(Kind.initial, one.header.kind);
    try testing.expectEqual(a, one.len);
    try testing.expectEqualSlices(u8, &one_payload, one.payload);

    const two = try open(&out, buf[one.len .. a + b], keys, one.pn);
    try testing.expectEqual(Kind.handshake, two.header.kind);
    try testing.expectEqualSlices(u8, &two_payload, two.payload);
}

test "invalid builds are refused" {
    const dcid = hex(testdata.other_dcid);
    const keys = clientKeys(testdata.other_dcid);
    const payload: [16]u8 = @splat(0);
    var out: [256]u8 = @splat(0xaa);

    // Retry carries an integrity tag, not a length and packet number.
    try testing.expectError(error.UnsupportedPacket, seal(&out, .{ .kind = .retry, .dcid = &dcid, .pn = 1, .pn_len = 1 }, &payload, keys));
    try testing.expectError(error.InvalidPacketNumberLength, seal(&out, .{ .kind = .initial, .dcid = &dcid, .pn = 1, .pn_len = 5 }, &payload, keys));
    // 0x10002 needs three bytes; two would put 0002 on the wire while the nonce
    // still used the full value.
    try testing.expectError(error.PacketNumberTooLarge, seal(&out, .{ .kind = .handshake, .dcid = &dcid, .pn = 0x10002, .pn_len = 2 }, &payload, keys));
    // One byte short of a sample for a 1-byte packet number.
    try testing.expectError(error.PayloadTooShortToSample, seal(&out, .{ .kind = .handshake, .dcid = &dcid, .pn = 1, .pn_len = 1 }, &[_]u8{ 1, 1 }, keys));

    // All refused before a single byte was written, header included.
    try testing.expectEqualSlices(u8, &@as([256]u8, @splat(0xaa)), &out);
}

test "malformed packets are rejected" {
    // Fixed bit clear, since Version Negotiation leaves it arbitrary.
    try testing.expectError(error.VersionNegotiation, parseLongHeader(&hex("8000000000" ++ "00" ++ "00" ++ "00000001")));
    try testing.expectError(error.UnsupportedVersion, parseLongHeader(&hex("c0aabbccdd" ++ "00" ++ "00" ++ "00")));
    try testing.expectError(error.ConnectionIdTooLong, parseLongHeader(&hex("c000000001" ++ "15")));

    var short = hex("c300000001088394c8f03e5157080000449e0000");
    try testing.expectError(error.PacketTooShort, protectHeader(&short, a2_pn_offset, hex(a2_mask)));

    // Declared length too small to hold a sample.
    const dcid = hex(testdata.other_dcid);
    var tiny: [64]u8 = @splat(0);
    _ = try writeLongHeader(&tiny, .{ .kind = .handshake, .dcid = &dcid, .pn = 1, .pn_len = 1 }, 0);
    var out: [64]u8 = undefined;
    try testing.expectError(error.PacketTooShort, open(&out, &tiny, clientKeys(testdata.other_dcid), null));
}

// The header is the AEAD's associated data, so the two cannot be tampered with
// independently. On failure the caller needs the bytes that arrived, not
// half-unmasked ones.
test "a failed open reports the tamper and restores the packet" {
    var packet: [1200]u8 = undefined;
    _ = try std.fmt.hexToBytes(&packet, testdata.rfc9001_client_initial_hex);
    // Byte 0 is the header form, 1-4 the version, 5 the id length, so the
    // connection id starts at 6. Keys stay derived from the original id.
    packet[6] ^= 0x01;
    const arrived = packet;

    var out: [1200]u8 = undefined;
    try testing.expectError(error.AuthenticationFailed, open(&out, &packet, clientKeys(testdata.rfc9001_dcid), null));
    try testing.expectEqualSlices(u8, &arrived, &packet);
}

// Masking is XOR, so flipping a reserved bit in the protected byte flips it in
// the unprotected one. Reported ahead of the authentication failure it also
// causes.
test "reserved bits set is a protocol violation" {
    const dcid = hex(testdata.other_dcid);
    const keys = clientKeys(testdata.other_dcid);
    var payload: [32]u8 = @splat(0);
    payload[0] = 0x01;

    var buf: [256]u8 = undefined;
    const n = try seal(&buf, .{ .kind = .handshake, .dcid = &dcid, .pn = 1, .pn_len = 4 }, &payload, keys);
    buf[0] ^= 0x08;

    var out: [256]u8 = undefined;
    try testing.expectError(error.ProtocolViolation, open(&out, buf[0..n], keys, null));
}
