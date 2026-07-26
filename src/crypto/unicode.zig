//! NFC normalization, backed by the forked zg Unicode library.
//! Radicle canonical JSON requires NFC-normalized string content.
const std = @import("std");
const Normalize = @import("zg_normalize");

pub const Result = Normalize.Result;

/// Normalizes `str` to NFC. Returns a Result; call `deinit` to free.
/// No allocation occurs when `str` is already NFC.
pub fn nfc(allocator: std.mem.Allocator, str: []const u8) std.mem.Allocator.Error!Result {
    return Normalize.nfc(allocator, str);
}

const testing = std.testing;

test "nfc composes e + combining acute" {
    const r = try nfc(testing.allocator, "e\u{0301}");
    defer r.deinit(testing.allocator);
    try testing.expectEqualStrings("\u{00E9}", r.slice);
}

test "nfc leaves ascii unchanged" {
    const r = try nfc(testing.allocator, "rad:z42hL2jL4XNk6K8oHQaSWfMgCL7ji");
    defer r.deinit(testing.allocator);
    try testing.expectEqualStrings("rad:z42hL2jL4XNk6K8oHQaSWfMgCL7ji", r.slice);
}

test "nfc composes hangul" {
    const r = try nfc(testing.allocator, "\u{1100}\u{1161}");
    defer r.deinit(testing.allocator);
    try testing.expectEqualStrings("\u{AC00}", r.slice);
}
