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

test "nfc composes decomposed sequences and leaves ascii alone" {
    const cases = .{
        .{ "e\u{0301}", "\u{00E9}" },
        .{ "\u{1100}\u{1161}", "\u{AC00}" },
        .{ "rad:z42hL2jL4XNk6K8oHQaSWfMgCL7ji", "rad:z42hL2jL4XNk6K8oHQaSWfMgCL7ji" },
    };
    inline for (cases) |c| {
        const r = try nfc(testing.allocator, c[0]);
        defer r.deinit(testing.allocator);
        try testing.expectEqualStrings(c[1], r.slice);
    }
}
