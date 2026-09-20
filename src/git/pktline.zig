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

/// The most one sideband line can carry, once the band byte has its share.
pub const MAX_BAND_DATA = MAX_DATA - 1;

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

pub const Error = error{ ShortBuffer, BadLength, Overflow, LineTooLong };

/// Parses one pkt-line from the front of `buf`. Returns the line (data slices
/// borrow `buf`) and the total bytes consumed.
pub fn parse(buf: []const u8) Error!struct { line: Line, consumed: usize } {
    if (buf.len < LENGTH_LEN) return error.ShortBuffer;
    const n = parseLength(buf[0..LENGTH_LEN]) orelse return error.BadLength;
    switch (n) {
        0, 1, 2 => return .{
            .line = .{ .marker = @fromBackingInt(@intCast(n)) },
            .consumed = LENGTH_LEN,
        },
        3 => return error.BadLength,
        else => {},
    }
    if (buf.len < n) return error.ShortBuffer;
    return .{ .line = .{ .data = buf[LENGTH_LEN..n] }, .consumed = n };
}

/// Reads one pkt-line into `buf`, so the payload survives the next read. A
/// line past what `buf` holds is refused rather than truncated.
///
/// `readSliceAll` rather than `take`: the length comes from the peer, and
/// `take` asserts that much fits in the reader's own buffer.
pub fn read(r: *std.Io.Reader, buf: []u8) !Line {
    var head: [LENGTH_LEN]u8 = undefined;
    try r.readSliceAll(&head);

    const n = parseLength(&head) orelse return error.BadLength;
    switch (n) {
        0, 1, 2 => return .{ .marker = @fromBackingInt(@intCast(n)) },
        3 => return error.BadLength,
        else => {},
    }
    const len = n - LENGTH_LEN;
    if (len > buf.len) return error.LineTooLong;
    try r.readSliceAll(buf[0..len]);
    return .{ .data = buf[0..len] };
}

/// The four hex digits of a length prefix, and nothing else. `parseInt` would
/// also take a sign and digit separators, which the grammar does not allow and
/// a hostile peer picks these bytes.
fn parseLength(head: *const [LENGTH_LEN]u8) ?u16 {
    var n: u16 = 0;
    for (head) |c| {
        const digit = std.fmt.charToDigit(c, 16) catch return null;
        n = n * 16 + digit;
    }
    return n;
}

/// Writes a data pkt-line to `w`.
pub fn write(w: *std.Io.Writer, payload: []const u8) !void {
    if (payload.len > MAX_DATA) return error.LineTooLong;
    var head: [LENGTH_LEN]u8 = undefined;
    _ = std.fmt.bufPrint(&head, "{x:0>4}", .{payload.len + LENGTH_LEN}) catch unreachable;
    try w.writeAll(&head);
    try w.writeAll(payload);
}

/// Writes a sideband pkt-line: one band number, then the payload.
/// Source: gitprotocol-pack, "side-band-64k".
pub fn writeBand(w: *std.Io.Writer, band: u8, payload: []const u8) !void {
    if (payload.len > MAX_BAND_DATA) return error.LineTooLong;
    var head: [LENGTH_LEN + 1]u8 = undefined;
    _ = std.fmt.bufPrint(head[0..LENGTH_LEN], "{x:0>4}", .{payload.len + LENGTH_LEN + 1}) catch
        unreachable;
    head[LENGTH_LEN] = band;
    try w.writeAll(&head);
    try w.writeAll(payload);
}

/// Writes a data pkt-line (`4-hex len ++ payload`) into `out`. Returns the
/// slice written. `payload` must be <= MAX_DATA.
pub fn bufWrite(out: []u8, payload: []const u8) Error![]u8 {
    if (payload.len > MAX_DATA) return error.Overflow;
    const total = payload.len + LENGTH_LEN;
    if (out.len < total) return error.ShortBuffer;
    _ = std.fmt.bufPrint(out[0..LENGTH_LEN], "{x:0>4}", .{total}) catch return error.Overflow;
    @memcpy(out[LENGTH_LEN..total], payload);
    return out[0..total];
}

const testing = std.testing;

test "parses flush, delim and response-end" {
    try testing.expectEqual(Marker.flush, (try parse("0000")).line.marker);
    try testing.expectEqual(Marker.delim, (try parse("0001")).line.marker);
    try testing.expectEqual(Marker.response_end, (try parse("0002")).line.marker);
    try testing.expectEqualStrings("0000", Marker.flush.wire());
}

test "bufWrite round trips through parse" {
    var buf: [64]u8 = undefined;
    const line = try bufWrite(&buf, "command=ls-refs\n");
    // "command=ls-refs\n" is 16 bytes -> total 20 -> 0014
    try testing.expectEqualStrings("0014command=ls-refs\n", line);

    const r = try parse(line);
    try testing.expectEqualStrings("command=ls-refs\n", r.line.data);
    try testing.expectEqual(line.len, r.consumed);
}

test "bad framing is refused, not misparsed" {
    try testing.expectError(error.ShortBuffer, parse("00"));
    try testing.expectError(error.ShortBuffer, parse("0014command")); // len says 20, have 11

    // A length is four hex digits; `parseInt` would take all three of these.
    try testing.expectError(error.BadLength, parse("+123"));
    try testing.expectError(error.BadLength, parse("00_4"));
    try testing.expectError(error.BadLength, parse("00 4"));

    // Longer than the caller's buffer, which is a refusal and not a truncation.
    var r = std.Io.Reader.fixed("0009abcde");
    var small: [4]u8 = undefined;
    try testing.expectError(error.LineTooLong, read(&r, &small));
}

test "lines written to a writer read back off a reader" {
    var out: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    try write(&w, "packfile\n");
    try writeBand(&w, 1, "PACK");
    try w.writeAll(Marker.flush.wire());

    var r = std.Io.Reader.fixed(w.buffered());
    var buf: [MAX_DATA]u8 = undefined;
    try testing.expectEqualStrings("packfile\n", (try read(&r, &buf)).data);
    try testing.expectEqualStrings("\x01PACK", (try read(&r, &buf)).data);
    try testing.expectEqual(Marker.flush, (try read(&r, &buf)).marker);
}
