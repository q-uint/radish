//! Git pkt-line framing (gitprotocol-common). A line is a 4-hex length prefix
//! (counting itself) followed by that many bytes. Special lengths: 0000 flush,
//! 0001 delimiter, 0002 response-end. Data lines carry 4..65516 payload bytes.
const std = @import("std");

/// The 4-hex length prefix, which counts itself.
pub const LENGTH_LEN = 4;

/// The longest a whole line may be, prefix included. Not 0xffff, which the
/// four hex digits could express: the spec stops here.
/// Source: gitprotocol-common, "Implementations MUST NOT send pkt-line whose
/// length exceeds 65520".
pub const MAX_LINE = 65520;

pub const MAX_DATA = MAX_LINE - LENGTH_LEN;

/// The three special zero-payload pkt-lines, by their length-field value.
pub const Marker = enum(u16) {
    flush = 0,
    delim = 1,
    response_end = 2,

    pub fn wire(self: Marker) *const [4]u8 {
        return switch (self) {
            .flush => "0000",
            .delim => "0001",
            .response_end => "0002",
        };
    }
};

pub const Line = union(enum) {
    marker: Marker,
    data: []const u8,
};

pub const Error = error{ ShortBuffer, BadLength, Overflow };

/// Parses one pkt-line from the front of `buf`. Returns the line (data slices
/// borrow `buf`) and the total bytes consumed.
pub fn parse(buf: []const u8) Error!struct { line: Line, consumed: usize } {
    if (buf.len < 4) return error.ShortBuffer;
    const n = std.fmt.parseInt(u16, buf[0..4], 16) catch return error.BadLength;
    switch (n) {
        0, 1, 2 => return .{ .line = .{ .marker = @fromBackingInt(@intCast(n)) }, .consumed = 4 },
        3 => return error.BadLength,
        else => {},
    }
    if (buf.len < n) return error.ShortBuffer;
    return .{ .line = .{ .data = buf[4..n] }, .consumed = n };
}

/// Writes a data pkt-line (`4-hex len ++ payload`) into `out`. Returns the
/// slice written. `payload` must be <= MAX_DATA.
pub fn writeData(out: []u8, payload: []const u8) Error![]u8 {
    if (payload.len > MAX_DATA) return error.Overflow;
    const total = payload.len + 4;
    if (out.len < total) return error.ShortBuffer;
    _ = std.fmt.bufPrint(out[0..4], "{x:0>4}", .{total}) catch return error.Overflow;
    @memcpy(out[4..total], payload);
    return out[0..total];
}

const testing = std.testing;

test "parses flush, delim and response-end" {
    try testing.expectEqual(Marker.flush, (try parse("0000")).line.marker);
    try testing.expectEqual(Marker.delim, (try parse("0001")).line.marker);
    try testing.expectEqual(Marker.response_end, (try parse("0002")).line.marker);
    try testing.expectEqualStrings("0000", Marker.flush.wire());
}

test "writeData round trips through parse" {
    var buf: [64]u8 = undefined;
    const line = try writeData(&buf, "command=ls-refs\n");
    // "command=ls-refs\n" is 16 bytes -> total 20 -> 0014
    try testing.expectEqualStrings("0014command=ls-refs\n", line);

    const r = try parse(line);
    try testing.expectEqualStrings("command=ls-refs\n", r.line.data);
    try testing.expectEqual(line.len, r.consumed);
}

test "short buffer is detected, not misparsed" {
    try testing.expectError(error.ShortBuffer, parse("00"));
    try testing.expectError(error.ShortBuffer, parse("0014command")); // len says 20, have 11
}
