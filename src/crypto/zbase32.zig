//! z-base-32, the human-oriented base32 pkarr names keys with.
//!
//! Unlike RFC 4648 it has its own alphabet and no padding, and it packs bits
//! continuously rather than in 40-bit blocks: a 32-byte key is 52 characters,
//! the last carrying 4 bits of key and 1 bit of zero.
const std = @import("std");

const ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769";

const decode_map: [256]i16 = blk: {
    var m: [256]i16 = @splat(-1);
    for (ALPHABET, 0..) |c, i| m[c] = @intCast(i);
    break :blk m;
};

pub const Error = error{ InvalidCharacter, NoSpaceLeft };

/// A 32-byte key is what everything here encodes in practice.
pub const key_len = 32;
pub const encoded_key_len = encodedLen(key_len);

/// Characters `n` bytes encode to: 5 bits each, rounded up.
pub fn encodedLen(n: usize) usize {
    return (n * 8 + 4) / 5;
}

/// Whole bytes `n` characters decode to. Any remainder is padding, which
/// `decodeBuf` drops.
pub fn decodedLen(n: usize) usize {
    return n * 5 / 8;
}

/// Encodes into `out`, returning the used prefix.
pub fn encodeBuf(out: []u8, input: []const u8) Error![]u8 {
    const size = encodedLen(input.len);
    if (out.len < size) return error.NoSpaceLeft;

    var acc: u16 = 0;
    var bits: u4 = 0;
    var n: usize = 0;
    for (input) |b| {
        acc = (acc << 8) | b;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[n] = ALPHABET[(acc >> bits) & 0x1f];
            n += 1;
        }
    }
    // The tail is left-aligned: the unused low bits are zero, not dropped.
    if (bits > 0) {
        out[n] = ALPHABET[(acc << (5 - bits)) & 0x1f];
        n += 1;
    }
    return out[0..n];
}

/// Decodes into `out`, returning the used prefix. Bits past the last whole
/// byte are discarded, so a string whose padding is nonzero still decodes.
pub fn decodeBuf(out: []u8, input: []const u8) Error![]u8 {
    const size = decodedLen(input.len);
    if (out.len < size) return error.NoSpaceLeft;

    var acc: u16 = 0;
    var bits: u4 = 0;
    var n: usize = 0;
    for (input) |c| {
        const d = decode_map[c];
        if (d < 0) return error.InvalidCharacter;
        acc = (acc << 5) | @as(u16, @intCast(d));
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out[n] = @truncate(acc >> bits);
            n += 1;
        }
    }
    return out[0..n];
}

const testing = std.testing;

test "a node id encodes as iroh spells it" {
    // iris.radicle.network's key, from radicle's own preferred seeds. The
    // encoding is the load-bearing part: n0's pkarr server accepts this exact
    // string as a well-formed key, and rejects a corrupted one.
    const key = [_]u8{
        0xb0, 0x87, 0x2f, 0xfa, 0x5b, 0xca, 0x36, 0x7c,
        0x32, 0x6d, 0x5e, 0xb2, 0x1e, 0xab, 0x5d, 0xee,
        0x71, 0xfd, 0x04, 0x83, 0xcc, 0xf5, 0x2d, 0x89,
        0x1d, 0x11, 0x64, 0xc8, 0x51, 0xa8, 0xfa, 0x1e,
    };
    const want = "snd196153e58acupm43b7k4773a94brd3u415ne7nf1cowpe9exy";

    var buf: [encoded_key_len]u8 = undefined;
    try testing.expectEqualStrings(want, try encodeBuf(&buf, &key));
    try testing.expectEqual(@as(usize, 52), want.len);

    var back: [key_len]u8 = undefined;
    try testing.expectEqualSlices(u8, &key, try decodeBuf(&back, want));
}

test "empty" {
    var buf: [1]u8 = undefined;
    try testing.expectEqualStrings("", try encodeBuf(&buf, ""));
    try testing.expectEqualSlices(u8, "", try decodeBuf(&buf, ""));
}

test "round trip" {
    var prng = std.Random.DefaultPrng.init(0xc0ffee);
    const rand = prng.random();
    for (0..256) |_| {
        var raw: [40]u8 = undefined;
        const n = rand.uintLessThan(usize, raw.len);
        rand.bytes(raw[0..n]);

        var enc: [encodedLen(raw.len)]u8 = undefined;
        const text = try encodeBuf(&enc, raw[0..n]);
        var dec: [raw.len]u8 = undefined;
        try testing.expectEqualSlices(u8, raw[0..n], try decodeBuf(&dec, text));
    }
}

test "invalid character rejected" {
    var buf: [8]u8 = undefined;
    // 'l', 'v', '2' and '0' are the characters z-base-32 leaves out.
    try testing.expectError(error.InvalidCharacter, decodeBuf(&buf, "lv20"));
}

test "buffer too small" {
    var buf: [1]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, encodeBuf(&buf, "hello"));
}
