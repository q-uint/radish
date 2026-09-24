//! Writing a commit's tree into a directory, which is how a blob is read out
//! by path: the identity document, and the two files sigrefs is made of.
//!
//! gitpack has a checkout of its own, but it reads one pack and no loose
//! object, so it cannot see most of what a repository `rad` wrote holds.
//! Source: gitformat-tree.
const std = @import("std");
const gitpack = @import("gitpack");
const odb = @import("odb.zig");
const walk = @import("walk.zig");
const safepath = @import("../safepath.zig");

pub const Error = error{
    NotACommit,
    NotATree,
    NotABlob,
    TreeTooDeep,
    UnsafeName,
    PathMissing,
} || walk.Error;

/// Deeper than any tree git writes, shallow enough that a pack naming itself
/// ends rather than runs out of stack.
const max_depth = 64;

/// Writes what `oid` names into `dest`, which must already exist and which
/// this does not clear: the caller's own temp directory, or a directory it
/// means to fill.
pub fn commit(
    gpa: std.mem.Allocator,
    io: std.Io,
    o: *odb.Odb,
    dest: std.Io.Dir,
    oid: gitpack.Oid,
) !void {
    const object = try o.read(gpa, oid);
    defer object.deinit(gpa);
    if (object.type != .commit) return error.NotACommit;

    try tree(gpa, io, o, dest, try commitTree(o.format, object.data), 0);
}

/// A commit names its tree on its first line, before anything that could be
/// mistaken for one.
fn commitTree(format: gitpack.Oid.Format, data: []const u8) !gitpack.Oid {
    const prefix = "tree ";
    const width = format.formattedLength();
    if (data.len < prefix.len + width + 1) return error.MalformedObject;
    if (!std.mem.startsWith(u8, data, prefix)) return error.MalformedObject;
    if (data[prefix.len + width] != '\n') return error.MalformedObject;

    return gitpack.Oid.parse(format, data[prefix.len..][0..width]) catch
        error.MalformedObject;
}

fn tree(
    gpa: std.mem.Allocator,
    io: std.Io,
    o: *odb.Odb,
    dir: std.Io.Dir,
    oid: gitpack.Oid,
    depth: usize,
) !void {
    if (depth > max_depth) return error.TreeTooDeep;

    // Held for the whole walk: the entries below borrow these bytes.
    const object = try o.read(gpa, oid);
    defer object.deinit(gpa);
    if (object.type != .tree) return error.NotATree;

    var entries: walk.Tree = .{ .format = o.format, .data = object.data };
    while (try entries.next()) |entry| {
        if (!safeName(entry.name)) return error.UnsafeName;
        switch (entry.kind) {
            .directory => {
                try dir.createDir(io, entry.name, .default_dir);
                var sub = try dir.openDir(io, entry.name, .{});
                defer sub.close(io);
                try tree(gpa, io, o, sub, entry.oid, depth + 1);
            },
            .file => {
                const blob = try readBlob(gpa, o, entry.oid);
                defer gpa.free(blob);
                try dir.writeFile(io, .{
                    .sub_path = entry.name,
                    .data = blob,
                    .flags = .{
                        .exclusive = true,
                        .permissions = if (entry.executable) .executable_file else .default_file,
                        // Belt to `safeName`'s braces, where the OS has it.
                        .resolve_beneath = true,
                    },
                });
            },
            // A symlink's blob is the path it points at.
            .symlink => {
                const target = try readBlob(gpa, o, entry.oid);
                defer gpa.free(target);
                try dir.symLink(io, target, entry.name, .{});
            },
            // The commit belongs to the submodule's repository, so there is
            // nothing here to write. `git archive` leaves the directory empty
            // too.
            .gitlink => try dir.createDir(io, entry.name, .default_dir),
        }
    }
}

/// One safe component, and not `.git`: a tree is written by whoever we fetched
/// it from, and a `.git` would write into the repository checking it out.
///
/// Not checked, and gitoxide's `gix-validate` does: the spellings of `.git`
/// that only some filesystems fold together, NTFS short names (`git~1`) and
/// HFS+ ignorable code points.
fn safeName(name: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(name, ".git")) return false;
    return safepath.component(name);
}

/// The blob at `path` under `oid`'s tree, read straight out of the object
/// database. Caller owns the result.
///
/// The alternative is checking the commit out and opening the path, which
/// resolves through whatever symlinks the tree contains: those targets are
/// written by whoever served the repository, so the read would leave the tree
/// and land anywhere in the caller's filesystem. A symlink component here is
/// refused instead of followed.
pub fn blobAt(
    gpa: std.mem.Allocator,
    o: *odb.Odb,
    oid: gitpack.Oid,
    path: []const u8,
) ![]u8 {
    const object = try o.read(gpa, oid);
    defer object.deinit(gpa);
    if (object.type != .commit) return error.NotACommit;

    var current = try commitTree(o.format, object.data);
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |name| {
        const entry = (try entryIn(gpa, o, current, name)) orelse return error.PathMissing;
        const last = it.peek() == null;
        switch (entry.kind) {
            .directory => {
                if (last) return error.NotABlob;
                current = entry.oid;
            },
            .file => {
                if (!last) return error.PathMissing;
                return readBlob(gpa, o, entry.oid);
            },
            .symlink, .gitlink => return error.UnsafeName,
        }
    }
    return error.PathMissing;
}

/// Only the fields that outlive the tree object: a `walk.TreeEntry`'s name
/// borrows bytes this frees.
const Found = struct { kind: walk.EntryKind, oid: gitpack.Oid };

fn entryIn(
    gpa: std.mem.Allocator,
    o: *odb.Odb,
    tree_oid: gitpack.Oid,
    name: []const u8,
) !?Found {
    const object = try o.read(gpa, tree_oid);
    defer object.deinit(gpa);
    if (object.type != .tree) return error.NotATree;

    var entries: walk.Tree = .{ .format = o.format, .data = object.data };
    while (try entries.next()) |entry| {
        if (!std.mem.eql(u8, entry.name, name)) continue;
        return .{ .kind = entry.kind, .oid = entry.oid };
    }
    return null;
}

fn readBlob(gpa: std.mem.Allocator, o: *odb.Odb, oid: gitpack.Oid) ![]u8 {
    const object = try o.read(gpa, oid);
    errdefer object.deinit(gpa);
    if (object.type != .blob) return error.NotABlob;
    return object.data;
}
