//! Writing resolved values back into a build.zig.zon.
//!
//! Zig requires every dependency to carry a location (`dependency requires
//! location field, one of 'url' or 'path'`), and its location union has no
//! `rad` variant. So `.rad` is the source of truth and `.path` is generated:
//! radish resolves the RID and writes the checkout path back into the manifest,
//! where Zig then reads it.
//!
//! Edits are text splices at the AST node, not a reserialization, so comments,
//! formatting, and field order survive.

const std = @import("std");
const zon = @import("zon.zig");

/// A field to set on one dependency.
pub const Set = struct {
    dep: []const u8,
    field: []const u8,
    value: []const u8,
};

/// Returns `source` with each `Set` applied: the field is replaced if present,
/// appended to that dependency otherwise. Caller owns the result.
pub fn apply(gpa: std.mem.Allocator, source: [:0]const u8, sets: []const Set) ![]u8 {
    var current = try gpa.allocSentinel(u8, source.len, 0);
    defer gpa.free(current);
    @memcpy(current, source);
    // One reparse per edit, since a splice invalidates every later offset.
    for (sets) |set| {
        const next = try applyOne(gpa, current, set);
        gpa.free(current);
        current = next;
    }
    return gpa.dupe(u8, current);
}

fn applyOne(gpa: std.mem.Allocator, source: [:0]const u8, set: Set) ![:0]u8 {
    var ast = try zon.parse(gpa, source);
    defer ast.deinit(gpa);

    var root_buf: zon.Buf = undefined;
    var deps_buf: zon.Buf = undefined;
    const deps = try zon.dependencies(ast, try zon.root(ast, &root_buf), &deps_buf) orelse
        return error.NoSuchDependency;

    for (deps.ast.fields) |dep_node| {
        if (!std.mem.eql(u8, zon.nameOf(ast, dep_node), set.dep)) continue;

        var dep_buf: zon.Buf = undefined;
        const dep = ast.fullStructInit(&dep_buf, dep_node) orelse return error.BadManifest;

        if (zon.findField(ast, dep, set.field)) |existing| {
            const tok = ast.nodeMainToken(existing);
            return splice(gpa, source, ast.tokenStart(tok), zon.tokenEnd(ast, tok), set.value, true);
        }

        // Append on its own line after the last field, indented like that
        // field and leaving the closing brace where it was. Splicing at the
        // brace instead would inherit whatever indentation a previous edit
        // left behind, compounding across edits.
        const last = dep.ast.fields[dep.ast.fields.len - 1];
        const indent = indentOf(source, ast.tokenStart(ast.firstToken(last)));
        var insert_at = zon.tokenEnd(ast, ast.lastToken(last));
        if (insert_at < source.len and source[insert_at] == ',') insert_at += 1;

        const text = try std.fmt.allocPrint(gpa, "\n{s}.{s} = \"{s}\",", .{
            indent, set.field, set.value,
        });
        defer gpa.free(text);
        return splice(gpa, source, insert_at, insert_at, text, false);
    }
    return error.NoSuchDependency;
}

fn splice(
    gpa: std.mem.Allocator,
    source: [:0]const u8,
    start: usize,
    end: usize,
    value: []const u8,
    quote: bool,
) ![:0]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, source[0..start]);
    if (quote) try out.append(gpa, '"');
    try out.appendSlice(gpa, value);
    if (quote) try out.append(gpa, '"');
    try out.appendSlice(gpa, source[end..]);
    return out.toOwnedSliceSentinel(gpa, 0);
}

/// The whitespace run starting the line that `offset` sits on.
fn indentOf(source: []const u8, offset: usize) []const u8 {
    var line_start = offset;
    while (line_start > 0 and source[line_start - 1] != '\n') line_start -= 1;
    var i = line_start;
    while (i < source.len and (source[i] == ' ' or source[i] == '\t')) i += 1;
    return source[line_start..i];
}

const testing = std.testing;

test "adds a missing field to the right dependency" {
    const src =
        \\.{
        \\    .dependencies = .{
        \\        .radish = .{
        \\            .rad = "z4VSy",
        \\        },
        \\        .other = .{
        \\            .rad = "zOTHER",
        \\        },
        \\    },
        \\}
    ;
    const out = try apply(testing.allocator, src, &.{
        .{ .dep = "radish", .field = "path", .value = ".rad-deps/radish" },
    });
    defer testing.allocator.free(out);

    try testing.expect(std.mem.indexOf(u8, out, ".path = \".rad-deps/radish\",") != null);
    // The other dependency is untouched.
    try testing.expect(std.mem.indexOf(u8, out, ".other = .{\n            .rad = \"zOTHER\",\n        },") != null);
}

test "replaces an existing field in place" {
    const src =
        \\.{
        \\    .dependencies = .{
        \\        .radish = .{
        \\            .rad = "z4VSy",
        \\            .path = "stale",
        \\        },
        \\    },
        \\}
    ;
    const out = try apply(testing.allocator, src, &.{
        .{ .dep = "radish", .field = "path", .value = "fresh" },
    });
    defer testing.allocator.free(out);

    try testing.expect(std.mem.indexOf(u8, out, "\"fresh\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "stale") == null);
}

// The manifest is the user's file, so a rewrite that dropped their comments or
// reflowed their formatting would be worse than not rewriting at all.
test "comments and formatting survive a rewrite" {
    const src =
        \\.{
        \\    // keep me
        \\    .name = .demo,
        \\    .dependencies = .{
        \\        .radish = .{
        \\            // and me
        \\            .rad = "z4VSy",
        \\        },
        \\    },
        \\}
    ;
    const out = try apply(testing.allocator, src, &.{
        .{ .dep = "radish", .field = "path", .value = "p" },
    });
    defer testing.allocator.free(out);

    try testing.expect(std.mem.indexOf(u8, out, "// keep me") != null);
    try testing.expect(std.mem.indexOf(u8, out, "// and me") != null);
    try testing.expect(std.mem.indexOf(u8, out, ".name = .demo,") != null);
}

test "two edits to one dependency both land" {
    const src =
        \\.{
        \\    .dependencies = .{
        \\        .radish = .{
        \\            .rad = "z4VSy",
        \\        },
        \\    },
        \\}
    ;
    const out = try apply(testing.allocator, src, &.{
        .{ .dep = "radish", .field = "path", .value = "p" },
        .{ .dep = "radish", .field = "rad_hash", .value = "h" },
    });
    defer testing.allocator.free(out);

    try testing.expect(std.mem.indexOf(u8, out, ".path = \"p\",") != null);
    try testing.expect(std.mem.indexOf(u8, out, ".rad_hash = \"h\",") != null);
}

// Indentation has to come from the field being followed, not from wherever a
// previous splice left the closing brace, or successive edits stair-step.
test "appended fields keep the surrounding indentation" {
    const src =
        \\.{
        \\    .dependencies = .{
        \\        .radish = .{
        \\            .rad = "z4VSy",
        \\        },
        \\    },
        \\}
    ;
    const out = try apply(testing.allocator, src, &.{
        .{ .dep = "radish", .field = "path", .value = "p" },
        .{ .dep = "radish", .field = "rad_hash", .value = "h" },
    });
    defer testing.allocator.free(out);

    try testing.expectEqualStrings(
        \\.{
        \\    .dependencies = .{
        \\        .radish = .{
        \\            .rad = "z4VSy",
        \\            .path = "p",
        \\            .rad_hash = "h",
        \\        },
        \\    },
        \\}
    , out);
}

test "an unknown dependency is an error, not a silent no-op" {
    const src =
        \\.{
        \\    .dependencies = .{
        \\        .radish = .{ .rad = "z4VSy" },
        \\    },
        \\}
    ;
    try testing.expectError(error.NoSuchDependency, apply(testing.allocator, src, &.{
        .{ .dep = "absent", .field = "path", .value = "p" },
    }));
}
