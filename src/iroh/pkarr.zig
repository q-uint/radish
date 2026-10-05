//! pkarr signed packets: a DNS reply signed by the key it is published under,
//! which is how a public key resolves to the addresses behind it.
//!
//! Wire format: `<32 pubkey><64 signature><8 timestamp><DNS packet>`, with the
//! timestamp big-endian microseconds since the unix epoch and the packet at
//! most 1000 bytes. The signature covers a bencode of the last two, which is
//! BEP44's `seq` and `v` so the same record can live in the mainline DHT.
//! Source: pkarr design/base.md, and iroh-dns-1.0.3/src/pkarr.rs.
const std = @import("std");

const dns = @import("dns.zig");
const signature = @import("../crypto/signature.zig");
const zbase32 = @import("../crypto/zbase32.zig");

pub const key_len = 32;
pub const sig_len = 64;
pub const timestamp_len = 8;
pub const header_len = key_len + sig_len + timestamp_len;

/// What the DNS packet may occupy, and what that makes the whole record.
pub const max_packet = 1000;
pub const max_signed = header_len + max_packet;
/// A relay carries the record without the key, which is already in the URL.
pub const max_payload = max_signed - key_len;

pub const Error = error{ TooShort, TooLarge, BadSignature, NoSpaceLeft } || dns.Error;

/// The longest bencode prefix: a u64 of microseconds is at most 20 digits, and
/// a packet length at most 4.
const max_prefix = "3:seqi".len + 20 + "e1:v".len + 4 + ":".len;

pub const SignedPacket = struct {
    key: signature.PublicKey,
    sig: signature.Signature,
    /// Microseconds since the unix epoch. The only freshness rule pkarr has is
    /// that a newer timestamp wins, so a publisher must never go backwards.
    timestamp: u64,
    /// The DNS reply, borrowed from the bytes it was parsed from.
    packet: []const u8,

    /// Parses and verifies a whole record.
    pub fn parse(bytes: []const u8) Error!SignedPacket {
        if (bytes.len < header_len) return error.TooShort;
        if (bytes.len > max_signed) return error.TooLarge;
        return verified(bytes[0..key_len].*, bytes[key_len..]);
    }

    /// Parses and verifies a relay's payload, whose key is the one the record
    /// was fetched under rather than a field.
    pub fn fromPayload(key: signature.PublicKey, payload: []const u8) Error!SignedPacket {
        if (payload.len < sig_len + timestamp_len) return error.TooShort;
        if (payload.len > max_payload) return error.TooLarge;
        return verified(key, payload);
    }

    /// Reads the answers, which is where the `key=value` TXT strings live.
    pub fn answers(self: SignedPacket) dns.Error!dns.Reader {
        return dns.Reader.init(self.packet);
    }
};

fn verified(key: signature.PublicKey, payload: []const u8) Error!SignedPacket {
    const sig: signature.Signature = .{ .bytes = payload[0..sig_len].* };
    const timestamp = std.mem.readInt(u64, payload[sig_len..][0..timestamp_len], .big);
    const packet = payload[sig_len + timestamp_len ..];

    var buf: [max_prefix + max_packet]u8 = undefined;
    const msg = signable(&buf, timestamp, packet);
    signature.verify(key, msg, sig) catch return error.BadSignature;

    // Parsed for validity only, since the answers are read on demand.
    _ = dns.Reader.init(packet) catch return error.Malformed;

    return .{ .key = key, .sig = sig, .timestamp = timestamp, .packet = packet };
}

/// Signs `packet` into `out`, returning the record. `timestamp` is the
/// caller's to supply: there is no clock here, and a republish must carry a
/// larger one than the record it replaces or a relay answers 409.
pub fn sign(
    out: []u8,
    secret: signature.SecretKey,
    packet: []const u8,
    timestamp: u64,
) Error![]u8 {
    if (packet.len > max_packet) return error.TooLarge;
    if (out.len < header_len + packet.len) return error.NoSpaceLeft;

    var buf: [max_prefix + max_packet]u8 = undefined;
    const msg = signable(&buf, timestamp, packet);
    const sig = secret.sign(msg) catch return error.BadSignature;

    @memcpy(out[0..key_len], &secret.publicKey());
    @memcpy(out[key_len..][0..sig_len], &sig.bytes);
    std.mem.writeInt(u64, out[key_len + sig_len ..][0..timestamp_len], timestamp, .big);
    @memcpy(out[header_len..][0..packet.len], packet);
    return out[0 .. header_len + packet.len];
}

/// What a relay PUT carries: the record without its leading key.
pub fn payloadOf(record: []const u8) []const u8 {
    return record[key_len..];
}

/// The bencode BEP44 signs: `3:seqi<timestamp>e1:v<len>:<packet>`.
fn signable(buf: []u8, timestamp: u64, packet: []const u8) []u8 {
    const prefix = std.fmt.bufPrint(buf, "3:seqi{d}e1:v{d}:", .{ timestamp, packet.len }) catch
        unreachable; // max_prefix bounds it
    @memcpy(buf[prefix.len..][0..packet.len], packet);
    return buf[0 .. prefix.len + packet.len];
}

const testing = std.testing;

test "BEP 44 signing vector" {
    // bittorrent.org/beps/bep_0044.html, test 1: the mutable item with no
    // salt, which is the exact bencode pkarr signs. An external vector for
    // both the prefix and the signature over it, where everything else here is
    // this file checking its own work.
    var key: signature.PublicKey = undefined;
    _ = try std.fmt.hexToBytes(&key, "77ff84905a91936367c01360803104f92432fcd904a43511876df5cdf3e7e548");
    var sig: [sig_len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sig, "305ac8aeb6c9c151fa120f120ea2cfb923564e11552d06a5d856091e5e853cff" ++
        "1260d3f39e4999684aa92eb73ffd136e6f4f3ecbfda0ce53a1608ecd7ae21f01");

    var buf: [max_prefix + max_packet]u8 = undefined;
    const msg = signable(&buf, 1, "Hello World!");
    try testing.expectEqualStrings("3:seqi1e1:v12:Hello World!", msg);
    try signature.verify(key, msg, .{ .bytes = sig });
}

/// `_iroh.<z32 of the key that signs it>`, since a record only says anything
/// about the key it is published under.
fn testName(buf: []u8, key: signature.PublicKey) ![]const u8 {
    var z: [zbase32.encoded_key_len]u8 = undefined;
    return std.fmt.bufPrint(buf, "_iroh.{s}", .{try zbase32.encodeBuf(&z, &key)});
}

fn testPacket(buf: []u8, name: []const u8) ![]u8 {
    var b = try dns.Builder.init(buf);
    try b.addTxt(name, 30, "relay=https://euw1-1.relay.n0.iroh.link./");
    try b.addTxt(name, 30, "addr=192.0.2.1:4433");
    return b.finish();
}

test "sign, parse, and read the records back" {
    const seed: [32]u8 = @splat(7);
    const secret = try signature.SecretKey.fromSeed(seed);

    var name_text: [64]u8 = undefined;
    const name = try testName(&name_text, secret.publicKey());

    var packet_buf: [max_packet]u8 = undefined;
    const packet = try testPacket(&packet_buf, name);

    var record_buf: [max_signed]u8 = undefined;
    const record = try sign(&record_buf, secret, packet, 1_700_000_000_000_000);

    const parsed = try SignedPacket.parse(record);
    try testing.expectEqualSlices(u8, &secret.publicKey(), &parsed.key);
    try testing.expectEqual(@as(u64, 1_700_000_000_000_000), parsed.timestamp);
    try testing.expectEqualSlices(u8, packet, parsed.packet);

    var r = try parsed.answers();
    var name_buf: [dns.max_name]u8 = undefined;
    const first = (try r.next(&name_buf)).?;
    try testing.expectEqualStrings(name, first.name);
    var it = dns.txtStrings(first.rdata);
    try testing.expectEqualStrings("relay=https://euw1-1.relay.n0.iroh.link./", (try it.next()).?);
}

test "relay payload drops the key and verifies against it" {
    const seed: [32]u8 = @splat(9);
    const secret = try signature.SecretKey.fromSeed(seed);

    var name_text: [64]u8 = undefined;
    var packet_buf: [max_packet]u8 = undefined;
    const packet = try testPacket(&packet_buf, try testName(&name_text, secret.publicKey()));
    var record_buf: [max_signed]u8 = undefined;
    const record = try sign(&record_buf, secret, packet, 42);

    const payload = payloadOf(record);
    try testing.expectEqual(record.len - key_len, payload.len);

    const parsed = try SignedPacket.fromPayload(secret.publicKey(), payload);
    try testing.expectEqual(@as(u64, 42), parsed.timestamp);
    try testing.expectEqualSlices(u8, packet, parsed.packet);
}

test "a tampered record does not verify" {
    const seed: [32]u8 = @splat(3);
    const secret = try signature.SecretKey.fromSeed(seed);

    var name_text: [64]u8 = undefined;
    var packet_buf: [max_packet]u8 = undefined;
    const packet = try testPacket(&packet_buf, try testName(&name_text, secret.publicKey()));
    var record_buf: [max_signed]u8 = undefined;
    const record = try sign(&record_buf, secret, packet, 1000);

    // The timestamp is signed too, so moving it invalidates the record even
    // though the packet is untouched.
    record[header_len - 1] +%= 1;
    try testing.expectError(error.BadSignature, SignedPacket.parse(record));

    record[header_len - 1] -%= 1;
    record[record.len - 1] +%= 1;
    try testing.expectError(error.BadSignature, SignedPacket.parse(record));
}

test "size limits" {
    var short: [header_len - 1]u8 = @splat(0);
    try testing.expectError(error.TooShort, SignedPacket.parse(&short));

    var long: [max_signed + 1]u8 = @splat(0);
    try testing.expectError(error.TooLarge, SignedPacket.parse(&long));

    const secret = try signature.SecretKey.fromSeed(@splat(1));
    var out: [max_signed + 8]u8 = undefined;
    var oversized: [max_packet + 1]u8 = @splat(0);
    try testing.expectError(error.TooLarge, sign(&out, secret, &oversized, 1));
}
