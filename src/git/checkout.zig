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

pub const Error = error{ NotACommit, NotATree, NotABlob, TreeTooDeep, UnsafeName } || walk.Error;

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

/// Whether `name` is one path component and nothing else. A tree is written by
/// whoever we fetched it from, and this runs before anything has verified it:
/// a name carrying a separator or a `..` would write outside `dest`, and a
/// `.git` would write into the repository checking it out.
///
/// Not checked, and gitoxide's `gix-validate` does: the spellings of `.git`
/// that only some filesystems fold together, NTFS short names (`git~1`) and
/// HFS+ ignorable code points.
/// Source: git's `verify_path`, and the `hasDot`/`hasDotdot`/`hasDotgit`/
/// `fullPathname` checks git-fsck documents.
fn safeName(name: []const u8) bool {
    if (name.len == 0) return false;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return false;
    if (std.ascii.eqlIgnoreCase(name, ".git")) return false;
    // Backslash included: it separates paths on Windows, and a tree written
    // there is a tree we may be asked to check out here.
    return std.mem.indexOfAny(u8, name, "/\\\x00") == null;
}

fn readBlob(gpa: std.mem.Allocator, o: *odb.Odb, oid: gitpack.Oid) ![]u8 {
    const object = try o.read(gpa, oid);
    errdefer object.deinit(gpa);
    if (object.type != .blob) return error.NotABlob;
    return object.data;
}
