//! Canonical JSON serialization, matching Radicle Heartwood's
//! CanonicalFormatter (a variant of Canonical JSON):
//!   - object keys sorted lexicographically by their serialized-string bytes
//!   - compact: no insignificant whitespace, `,` and `:` separators
//!   - strings NFC-normalized; control chars escaped per RFC 8259 with
//!     lower-case hex (\u00xx)
//!   - integers only; floats are rejected
//!
//! Source: heartwood crates/radicle/src/canonical/formatter.rs
const std = @import("std");
const unicode = @import("unicode.zig");

pub const Error = error{FloatNotAllowed} || std.mem.Allocator.Error;

pub const Value = union(enum) {
    null,
    bool: bool,
    int: i64,
    string: []const u8,
    array: []const Value,
    /// Object entries; keys need not be pre-sorted (sorting happens on encode).
    object: []const Entry,

    pub const Entry = struct { key: []const u8, value: Value };
};

/// Serializes `v` as canonical JSON into a freshly allocated buffer.
pub fn encode(allocator: std.mem.Allocator, v: Value) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try writeValue(allocator, &out, v);
    return out.toOwnedSlice(allocator);
}

fn writeValue(allocator: std.mem.Allocator, out: *std.ArrayList(u8), v: Value) Error!void {
    switch (v) {
        .null => try out.appendSlice(allocator, "null"),
        .bool => |b| try out.appendSlice(allocator, if (b) "true" else "false"),
        .int => |n| {
            var buf: [20]u8 = undefined;
            const s = std.fmt.bufPrint(&buf, "{d}", .{n}) catch unreachable;
            try out.appendSlice(allocator, s);
        },
        .string => |s| try writeString(allocator, out, s),
        .array => |items| {
            try out.append(allocator, '[');
            for (items, 0..) |item, i| {
                if (i != 0) try out.append(allocator, ',');
                try writeValue(allocator, out, item);
            }
            try out.append(allocator, ']');
        },
        .object => |entries| try writeObject(allocator, out, entries),
    }
}

fn writeObject(allocator: std.mem.Allocator, out: *std.ArrayList(u8), entries: []const Value.Entry) Error!void {
    // Serialize each key to its canonical string bytes, then sort by those bytes.
    const Encoded = struct { key: []u8, value: Value };
    var encoded = try allocator.alloc(Encoded, entries.len);
    defer {
        for (encoded) |e| allocator.free(e.key);
        allocator.free(encoded);
    }
    for (entries, 0..) |e, i| {
        var kbuf: std.ArrayList(u8) = .empty;
        errdefer kbuf.deinit(allocator);
        try writeString(allocator, &kbuf, e.key);
        encoded[i] = .{ .key = try kbuf.toOwnedSlice(allocator), .value = e.value };
    }
    std.mem.sort(Encoded, encoded, {}, struct {
        fn lt(_: void, a: Encoded, b: Encoded) bool {
            return std.mem.lessThan(u8, a.key, b.key);
        }
    }.lt);

    try out.append(allocator, '{');
    for (encoded, 0..) |e, i| {
        if (i != 0) try out.append(allocator, ',');
        try out.appendSlice(allocator, e.key);
        try out.append(allocator, ':');
        try writeValue(allocator, out, e.value);
    }
    try out.append(allocator, '}');
}

fn writeString(allocator: std.mem.Allocator, out: *std.ArrayList(u8), s: []const u8) Error!void {
    const norm = try unicode.nfc(allocator, s);
    defer norm.deinit(allocator);

    // Radicle escaping == serde_json default == std.json with escape_unicode=false:
    // escape \\ \" and control chars (lower-case \u00xx); pass UTF-8 bytes raw.
    var aw: std.Io.Writer.Allocating = .fromArrayList(allocator, out);
    defer out.* = aw.toArrayList();
    std.json.Stringify.encodeJsonString(norm.slice, .{ .escape_unicode = false }, &aw.writer) catch |e| switch (e) {
        error.WriteFailed => return error.OutOfMemory,
    };
}

const testing = std.testing;

fn expectEncode(expected: []const u8, v: Value) !void {
    const got = try encode(testing.allocator, v);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(expected, got);
}

test "primitives encode compactly" {
    try expectEncode("null", .null);
    try expectEncode("true", .{ .bool = true });
    try expectEncode("false", .{ .bool = false });
    try expectEncode("42", .{ .int = 42 });
    try expectEncode("-7", .{ .int = -7 });
    try expectEncode("\"hi\"", .{ .string = "hi" });
    try expectEncode("[1,2,3]", .{ .array = &.{
        .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 },
    } });
    try expectEncode("{\"delegates\":[],\"payload\":{},\"threshold\":1}", .{ .object = &.{
        .{ .key = "threshold", .value = .{ .int = 1 } },
        .{ .key = "delegates", .value = .{ .array = &.{} } },
        .{ .key = "payload", .value = .{ .object = &.{} } },
    } });
}

test "strings are nfc-normalized and control chars escaped in lower-case hex" {
    try expectEncode("{\"k\":\"\u{00E9}\"}", .{ .object = &.{
        .{ .key = "k", .value = .{ .string = "e\u{0301}" } },
    } });
    try expectEncode("{\"k\":\"a\\u0001\\n\\t\"}", .{ .object = &.{
        .{ .key = "k", .value = .{ .string = "a\x01\n\t" } },
    } });
}

test "keys are nfc-normalized then sorted" {
    // "e"+acute normalizes to U+00E9 (0xC3 0xA9), which sorts AFTER "z" (0x7A).
    try expectEncode("{\"z\":2,\"\u{00E9}\":1}", .{ .object = &.{
        .{ .key = "e\u{0301}", .value = .{ .int = 1 } },
        .{ .key = "z", .value = .{ .int = 2 } },
    } });
}

// Golden vector from heartwood's own CanonicalFormatter,
// crates/radicle/src/canonical/formatter.rs.
test "realistic doc with unicode payload hashes to the expected git oid" {
    const expected =
        "{\"delegates\":[\"did:key:z6Mkt\"]," ++
        "\"payload\":{\"xyz.radicle.project\":{\"description\":\"\u{017A}a\",\"name\":\"caf\u{00E9}\"}}," ++
        "\"threshold\":1}";
    const doc = Value{ .object = &.{
        .{ .key = "payload", .value = .{ .object = &.{
            .{ .key = "xyz.radicle.project", .value = .{ .object = &.{
                .{ .key = "name", .value = .{ .string = "cafe\u{0301}" } },
                .{ .key = "description", .value = .{ .string = "z\u{0301}a" } },
            } } },
        } } },
        .{ .key = "delegates", .value = .{ .array = &.{.{ .string = "did:key:z6Mkt" }} } },
        .{ .key = "threshold", .value = .{ .int = 1 } },
    } };
    try expectEncode(expected, doc);

    // printf '%s' <bytes> | git hash-object --stdin
    const git = @import("../git/git.zig");
    const bytes = try encode(testing.allocator, doc);
    defer testing.allocator.free(bytes);
    const oid = try git.hashBlob(bytes);
    var hex: [40]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{oid}) catch unreachable;
    try testing.expectEqualStrings("4aad12ef5b9691de8eb7c05e1f264a30838eb4ac", &hex);
}
