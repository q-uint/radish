//! Reading `.rad` dependencies out of a build.zig.zon.
//!
//! Zig's own manifest parser ignores fields it does not know (see the Zig
//! source, Package/Manifest.zig, "Ignore unknown fields so that we can add
//! fields in future zig versions"), so a `.rad` field can sit in a real
//! build.zig.zon without breaking `zig build`. Zig will not act on it: the
//! dependency location is a closed union of `url` and `path`. Resolving `.rad`
//! is therefore a separate step, run before Zig sees the manifest.

const std = @import("std");
const zon = @import("zon.zig");

/// One `.rad` dependency.
pub const RadDep = struct {
    name: []const u8,
    rid: []const u8,
    /// The package root inside the repo, for repos where build.zig is not at
    /// the top level.
    subdir: ?[]const u8,
    /// An exact commit to check out. Without it the identity document's
    /// `defaultBranch` is resolved, which moves as the repo is pushed to.
    rev: ?[]const u8,
    /// Expected hash of the resolved tree. Radish checks this; Zig ignores it,
    /// since it is not Zig's own `.hash` over its package format.
    rad_hash: ?[]const u8,
};

/// Parses `source` and returns its `.rad` dependencies. Caller owns the result
/// and the strings in it.
pub fn radDeps(gpa: std.mem.Allocator, source: [:0]const u8) ![]RadDep {
    var ast = try zon.parse(gpa, source);
    defer ast.deinit(gpa);

    var out: std.ArrayList(RadDep) = .empty;
    errdefer {
        for (out.items) |d| freeDep(gpa, d);
        out.deinit(gpa);
    }

    var root_buf: zon.Buf = undefined;
    var deps_buf: zon.Buf = undefined;
    const deps = try zon.dependencies(ast, try zon.root(ast, &root_buf), &deps_buf) orelse
        return out.toOwnedSlice(gpa);

    for (deps.ast.fields) |dep_node| {
        var dep_buf: zon.Buf = undefined;
        const dep = ast.fullStructInit(&dep_buf, dep_node) orelse continue;

        const rad_node = zon.findField(ast, dep, "rad") orelse continue;
        const rid = try gpa.dupe(u8, try zon.stringValue(ast, rad_node));
        errdefer gpa.free(rid);

        const name = try gpa.dupe(u8, zon.nameOf(ast, dep_node));
        errdefer gpa.free(name);

        try out.append(gpa, .{
            .name = name,
            .rid = rid,
            .subdir = try optionalString(gpa, ast, dep, "subdir"),
            .rev = try optionalString(gpa, ast, dep, "rev"),
            .rad_hash = try optionalString(gpa, ast, dep, "rad_hash"),
        });
    }
    return out.toOwnedSlice(gpa);
}

/// An owned copy of an optional string field's value, or null when absent.
fn optionalString(
    gpa: std.mem.Allocator,
    ast: zon.Ast,
    init: zon.StructInit,
    want: []const u8,
) !?[]const u8 {
    const node = zon.findField(ast, init, want) orelse return null;
    return try gpa.dupe(u8, try zon.stringValue(ast, node));
}

pub fn freeDeps(gpa: std.mem.Allocator, deps: []const RadDep) void {
    for (deps) |d| freeDep(gpa, d);
    gpa.free(deps);
}

fn freeDep(gpa: std.mem.Allocator, d: RadDep) void {
    gpa.free(d.name);
    gpa.free(d.rid);
    if (d.subdir) |s| gpa.free(s);
    if (d.rev) |s| gpa.free(s);
    if (d.rad_hash) |s| gpa.free(s);
}

const testing = std.testing;

test "reads rad dependencies, ignoring zig's own fields" {
    const src =
        \\.{
        \\    .name = .demo,
        \\    .version = "0.0.0",
        \\    .dependencies = .{
        \\        .radish = .{
        \\            .rad = "z4VSyUhaBGUJQrFdS7nWULf1dJdos",
        \\        },
        \\        .zg = .{
        \\            .url = "https://example.com/zg.tar.gz",
        \\            .hash = "zg-0.16.2-oGqU3FqftgJahbkg5J1iDsZUuEQDQMD8qD7OnEhkXjaN",
        \\        },
        \\    },
        \\}
    ;
    const deps = try radDeps(testing.allocator, src);
    defer freeDeps(testing.allocator, deps);

    try testing.expectEqual(@as(usize, 1), deps.len);
    try testing.expectEqualStrings("radish", deps[0].name);
    try testing.expectEqualStrings("z4VSyUhaBGUJQrFdS7nWULf1dJdos", deps[0].rid);
    try testing.expectEqual(@as(?[]const u8, null), deps[0].subdir);
}

// A repo whose build.zig is not at the top level still has to resolve to the
// directory Zig would treat as the package root.
test "subdir names the package root inside the repo" {
    const src =
        \\.{
        \\    .dependencies = .{
        \\        .lib = .{
        \\            .rad = "z4VSyUhaBGUJQrFdS7nWULf1dJdos",
        \\            .subdir = "packages/lib",
        \\        },
        \\    },
        \\}
    ;
    const deps = try radDeps(testing.allocator, src);
    defer freeDeps(testing.allocator, deps);

    try testing.expectEqualStrings("packages/lib", deps[0].subdir.?);
}

// A branch head moves as the repo is pushed to, so a reproducible build has to
// name the commit. The delegate check still applies: a pinned rev must be one
// a delegate published.
test "rev and rad_hash pin an exact tree" {
    const src =
        \\.{
        \\    .dependencies = .{
        \\        .radish = .{
        \\            .rad = "z4VSyUhaBGUJQrFdS7nWULf1dJdos",
        \\            .rev = "b8bd413c6c3adaad672f8700ba84cf0d1d3785c1",
        \\            .rad_hash = "sha256-0000",
        \\        },
        \\    },
        \\}
    ;
    const deps = try radDeps(testing.allocator, src);
    defer freeDeps(testing.allocator, deps);

    try testing.expectEqualStrings("b8bd413c6c3adaad672f8700ba84cf0d1d3785c1", deps[0].rev.?);
    try testing.expectEqualStrings("sha256-0000", deps[0].rad_hash.?);
}

test "a manifest with no dependencies yields nothing" {
    const deps = try radDeps(testing.allocator, ".{ .name = .demo }");
    defer freeDeps(testing.allocator, deps);
    try testing.expectEqual(@as(usize, 0), deps.len);
}
