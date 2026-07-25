//! base58btc (Bitcoin alphabet) encode/decode. Used as the multibase `z` base.
const std = @import("std");

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

var decode_map: [256]i16 = blk: {
    var m: [256]i16 = @splat(-1);
    for (ALPHABET, 0..) |c, i| m[c] = @intCast(i);
    break :blk m;
};

pub const Error = error{ InvalidCharacter, OutOfMemory };

/// Encodes `input` into a freshly allocated base58 string. Caller owns the result.
pub fn encode(allocator: std.mem.Allocator, input: []const u8) Error![]u8 {
    // Count leading zero bytes; each maps to a leading '1'.
    var zeros: usize = 0;
    while (zeros < input.len and input[zeros] == 0) zeros += 1;

    // Upper bound: log(256)/log(58) ~= 1.365.
    const size = zeros + (input.len - zeros) * 138 / 100 + 1;
    var buf = try allocator.alloc(u8, size);
    defer allocator.free(buf);
    @memset(buf, 0);

    for (input[zeros..]) |b| {
        var carry: u32 = b;
        var j: usize = size;
        while (j > 0) {
            j -= 1;
            carry += @as(u32, 256) * buf[j];
            buf[j] = @intCast(carry % 58);
            carry /= 58;
        }
    }

    // Skip leading zeros in the base58 buffer.
    var it = zeros;
    while (it < size and buf[it] == 0) it += 1;

    var out = try allocator.alloc(u8, zeros + (size - it));
    @memset(out[0..zeros], ALPHABET[0]);
    for (buf[it..], zeros..) |v, k| out[k] = ALPHABET[v];
    return out;
}

/// Decodes a base58 string into freshly allocated bytes. Caller owns the result.
pub fn decode(allocator: std.mem.Allocator, input: []const u8) Error![]u8 {
    var zeros: usize = 0;
    while (zeros < input.len and input[zeros] == ALPHABET[0]) zeros += 1;

    const size = zeros + (input.len - zeros) * 733 / 1000 + 1;
    var buf = try allocator.alloc(u8, size);
    defer allocator.free(buf);
    @memset(buf, 0);

    for (input[zeros..]) |c| {
        const d = decode_map[c];
        if (d < 0) return error.InvalidCharacter;
        var carry: u32 = @intCast(d);
        var j: usize = size;
        while (j > 0) {
            j -= 1;
            carry += @as(u32, 58) * buf[j];
            buf[j] = @intCast(carry % 256);
            carry /= 256;
        }
    }

    var it = zeros;
    while (it < size and buf[it] == 0) it += 1;

    var out = try allocator.alloc(u8, zeros + (size - it));
    @memset(out[0..zeros], 0);
    @memcpy(out[zeros..], buf[it..]);
    return out;
}

const testing = std.testing;

test "round trip empty" {
    const enc = try encode(testing.allocator, "");
    defer testing.allocator.free(enc);
    try testing.expectEqualStrings("", enc);
}

test "known vectors" {
    // Source: base58 draft (draft-msporny-base58) test vectors,
    // https://datatracker.ietf.org/doc/html/draft-msporny-base58
    const cases = .{
        .{ "Hello World!", "2NEpo7TZRRrLZSi2U" },
        .{ "The quick brown fox jumps over the lazy dog.", "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z" },
        .{ "\x00\x00\x28\x7f\xb4\xcd", "11233QC4" },
    };
    inline for (cases) |c| {
        const enc = try encode(testing.allocator, c[0]);
        defer testing.allocator.free(enc);
        try testing.expectEqualStrings(c[1], enc);

        const dec = try decode(testing.allocator, c[1]);
        defer testing.allocator.free(dec);
        try testing.expectEqualSlices(u8, c[0], dec);
    }
}

test "round trip random" {
    var prng = std.Random.DefaultPrng.init(0xc0ffee);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 256) : (i += 1) {
        var raw: [40]u8 = undefined;
        const n = rand.uintLessThan(usize, raw.len);
        rand.bytes(raw[0..n]);

        const enc = try encode(testing.allocator, raw[0..n]);
        defer testing.allocator.free(enc);
        const dec = try decode(testing.allocator, enc);
        defer testing.allocator.free(dec);
        try testing.expectEqualSlices(u8, raw[0..n], dec);
    }
}

test "invalid character rejected" {
    try testing.expectError(error.InvalidCharacter, decode(testing.allocator, "0OIl"));
}

fn fuzzRoundTrip(_: void, smith: *std.testing.Smith) anyerror!void {
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    while (!smith.eos()) {
        try input.append(testing.allocator, smith.value(u8));
    }
    const enc = try encode(testing.allocator, input.items);
    defer testing.allocator.free(enc);
    const dec = try decode(testing.allocator, enc);
    defer testing.allocator.free(dec);
    try testing.expectEqualSlices(u8, input.items, dec);
}

test "fuzz round trip" {
    try testing.fuzz({}, fuzzRoundTrip, .{});
}
