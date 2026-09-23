//! What an object points at, and the closure of that over a pack. Serving a
//! fetch is this: everything behind the refs the peer wants, less everything
//! behind the refs it says it already has.
//! Source: gitformat-commit, gitformat-tree.
const std = @import("std");
const gitpack = @import("gitpack");
const odb = @import("odb.zig");

/// What parsing an object's links can go wrong with. The walk itself reaches
/// the pack, so it carries whatever reading one can fail with.
pub const Error = error{MalformedObject} || std.mem.Allocator.Error;

/// The oids one object references, in the order they appear: a commit's tree
/// then its parents, a tree's entries, a tag's target. A blob references
/// nothing, which is what ends the walk.
pub const Links = struct {
    format: gitpack.Oid.Format,
    kind: odb.Type,
    data: []const u8,
    pos: usize = 0,

    pub fn next(self: *Links) Error!?gitpack.Oid {
        return switch (self.kind) {
            .blob => null,
            .tree => self.nextEntry(),
            .commit, .tag => self.nextHeader(),
        };
    }

    /// Commits and tags both carry their links as header lines, so the only
    /// difference is which field names count.
    fn nextHeader(self: *Links) Error!?gitpack.Oid {
        const width = self.format.formattedLength();
        while (self.pos < self.data.len) {
            const rest = self.data[self.pos..];
            const nl = std.mem.indexOfScalar(u8, rest, '\n') orelse return null;
            const line = rest[0..nl];
            self.pos += nl + 1;
            // The header ends at the first blank line; a message cannot link.
            if (line.len == 0) return null;

            // A continuation line of a multi-line header (a signature) starts
            // with the space, so its field name comes out empty and is ignored.
            const sp = std.mem.indexOfScalar(u8, line, ' ') orelse continue;
            if (!self.links(line[0..sp])) continue;

            const value = line[sp + 1 ..];
            if (value.len < width) return error.MalformedObject;
            return gitpack.Oid.parse(self.format, value[0..width]) catch
                return error.MalformedObject;
        }
        return null;
    }

    fn links(self: *const Links, field: []const u8) bool {
        return switch (self.kind) {
            .commit => std.mem.eql(u8, field, "tree") or std.mem.eql(u8, field, "parent"),
            .tag => std.mem.eql(u8, field, "object"),
            else => false,
        };
    }

    fn nextEntry(self: *Links) Error!?gitpack.Oid {
        var entries: Tree = .{ .format = self.format, .data = self.data, .pos = self.pos };
        defer self.pos = entries.pos;

        while (try entries.next()) |entry| {
            // A gitlink's commit lives in the submodule's own repository, so
            // it is not ours to send. git packs them the same way.
            if (entry.kind == .gitlink) continue;
            return entry.oid;
        }
        return null;
    }
};

/// What a tree entry points at, which is the high bits of its mode. These four
/// are all git writes, and `git fsck` refuses the rest.
///
/// Trivia: the field is POSIX `st_mode`'s file type, whose other values (fifo,
/// device, socket) cannot appear in a tree, and 0o16 is git's own, for a value
/// POSIX left unused.
pub const EntryKind = enum(u4) {
    directory = 0o4,
    file = 0o10,
    symlink = 0o12,
    /// A submodule's commit, which this repository does not hold.
    gitlink = 0o16,
};

pub const TreeEntry = struct {
    kind: EntryKind,
    /// Only a file may carry it; git writes 0o755 or 0o644 and nothing else.
    executable: bool,
    name: []const u8,
    oid: gitpack.Oid,
};

/// The entries of a tree: "<mode> <name>\x00<oid>" each, with the oid raw
/// rather than hex, and nothing delimiting them but their own lengths.
/// Source: gitformat-tree.
pub const Tree = struct {
    format: gitpack.Oid.Format,
    data: []const u8,
    pos: usize = 0,

    pub fn next(self: *Tree) Error!?TreeEntry {
        if (self.pos >= self.data.len) return null;
        const width = self.format.byteLength();
        const rest = self.data[self.pos..];

        const nul = std.mem.indexOfScalar(u8, rest, 0) orelse return error.MalformedObject;
        if (rest.len < nul + 1 + width) return error.MalformedObject;
        const sp = std.mem.indexOfScalar(u8, rest[0..nul], ' ') orelse
            return error.MalformedObject;
        self.pos += nul + 1 + width;

        const mode = std.fmt.parseUnsigned(u16, rest[0..sp], 8) catch
            return error.MalformedObject;
        const kind = std.enums.fromInt(EntryKind, mode >> 12) orelse
            return error.MalformedObject;
        return .{
            .kind = kind,
            .executable = kind == .file and mode & 0o111 != 0,
            .name = rest[sp + 1 .. nul],
            .oid = gitpack.Oid.fromBytes(self.format, rest[nul + 1 ..][0..width]),
        };
    }
};

const Set = std.AutoHashMapUnmanaged(gitpack.Oid, void);

/// The objects reachable from `tips` and not from `haves`, which is exactly
/// what a fetch owes the peer. Caller owns the result.
///
/// A tip we do not hold is an error: the peer asked for something that is not
/// ours to send, and a pack missing it would look complete.
pub fn missing(
    gpa: std.mem.Allocator,
    o: *odb.Odb,
    tips: []const gitpack.Oid,
    haves: []const gitpack.Oid,
) ![]gitpack.Oid {
    var seen: Set = .empty;
    defer seen.deinit(gpa);

    // Marked before the tips are walked, so the tip walk stops of its own
    // accord wherever the two histories meet.
    try mark(gpa, o, haves, &seen);

    var out: std.ArrayList(gitpack.Oid) = .empty;
    errdefer out.deinit(gpa);
    var queue: std.ArrayList(gitpack.Oid) = .empty;
    defer queue.deinit(gpa);
    try queue.appendSlice(gpa, tips);

    while (queue.pop()) |oid| {
        if ((try seen.getOrPut(gpa, oid)).found_existing) continue;
        // Typed before it is read, so a blob is never inflated: blobs are most
        // of a repository by bytes and none of them are graph.
        const kind = try o.typeOf(oid);
        try out.append(gpa, oid);
        if (kind == .blob) continue;

        const obj = try o.read(gpa, oid);
        defer obj.deinit(gpa);
        try push(gpa, o.format, obj, &seen, &queue);
    }
    return out.toOwnedSlice(gpa);
}

/// Marks everything behind `tips` as the peer's already. An oid we do not hold
/// is skipped rather than fatal: a peer may name a `have` from a history we
/// never stored, and all that costs us is a larger pack.
fn mark(gpa: std.mem.Allocator, o: *odb.Odb, tips: []const gitpack.Oid, seen: *Set) !void {
    var queue: std.ArrayList(gitpack.Oid) = .empty;
    defer queue.deinit(gpa);
    try queue.appendSlice(gpa, tips);

    while (queue.pop()) |oid| {
        if (seen.contains(oid)) continue;
        const kind = o.typeOf(oid) catch |e| switch (e) {
            // Marked only once it is ours to mark: a `have` we never stored
            // would otherwise also hide a `want` naming the same oid, and the
            // pack would go out short of it and look complete.
            error.ObjectMissing => continue,
            else => return e,
        };
        try seen.put(gpa, oid, {});
        if (kind == .blob) continue;

        const obj = try o.read(gpa, oid);
        defer obj.deinit(gpa);
        try push(gpa, o.format, obj, seen, &queue);
    }
}

fn push(
    gpa: std.mem.Allocator,
    format: gitpack.Oid.Format,
    obj: odb.Object,
    seen: *const Set,
    queue: *std.ArrayList(gitpack.Oid),
) !void {
    var it: Links = .{ .format = format, .kind = obj.type, .data = obj.data };
    while (try it.next()) |link| {
        if (!seen.contains(link)) try queue.append(gpa, link);
    }
}

const testing = std.testing;

fn treeEntry(
    out: *std.ArrayList(u8),
    gpa: std.mem.Allocator,
    mode: []const u8,
    name: []const u8,
    oid: [20]u8,
) !void {
    try out.appendSlice(gpa, mode);
    try out.append(gpa, ' ');
    try out.appendSlice(gpa, name);
    try out.append(gpa, 0);
    try out.appendSlice(gpa, &oid);
}

// Returning a gitlink would send the walk looking for a commit that lives in
// the submodule's pack, not ours, and the whole fetch would fail on it.
test "a tree links its entries, but never a gitlink" {
    const gpa = testing.allocator;
    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(gpa);

    const blob: [20]u8 = @splat(0xaa);
    const submodule: [20]u8 = @splat(0xbb);
    try treeEntry(&data, gpa, "100644", "file.txt", blob);
    try treeEntry(&data, gpa, "160000", "vendored", submodule);
    try treeEntry(&data, gpa, "40000", "sub", blob);

    var it: Links = .{ .format = .sha1, .kind = .tree, .data = data.items };
    try testing.expectEqualSlices(u8, &blob, (try it.next()).?.slice());
    try testing.expectEqualSlices(u8, &blob, (try it.next()).?.slice());
    try testing.expectEqual(@as(?gitpack.Oid, null), try it.next());
}

const hex_a: [40]u8 = @splat('a');
const hex_b: [40]u8 = @splat('b');
const hex_c: [40]u8 = @splat('c');

// A signature header runs over several lines, and a continuation line can hold
// anything, including something that reads like a parent line.
test "a multi-line header does not contribute links" {
    const commit = "tree " ++ hex_a ++ "\n" ++
        "parent " ++ hex_b ++ "\n" ++
        "gpgsig -----BEGIN SSH SIGNATURE-----\n" ++
        " parent " ++ hex_c ++ "\n" ++
        " -----END SSH SIGNATURE-----\n" ++
        "\n" ++
        "parent " ++ hex_c ++ "\n";

    var it: Links = .{ .format = .sha1, .kind = .commit, .data = commit };
    var count: usize = 0;
    while (try it.next()) |_| count += 1;
    try testing.expectEqual(@as(usize, 2), count);
}
