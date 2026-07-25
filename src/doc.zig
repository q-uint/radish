//! Radicle identity document.
//!
//! Serializes to canonical JSON; its git blob oid is the repository's RID.
//! Fields and skip rules mirror heartwood crates/radicle/src/identity/doc.rs:
//!   - version: skipped when <= 1 (the initial version)
//!   - visibility: skipped when public
//!   - payload keyed by type name (e.g. "xyz.radicle.project")
//!   - delegates: list of did:key strings
//!   - threshold: signature threshold
const std = @import("std");
const canonical = @import("canonical.zig");
const git = @import("git.zig");
const rid = @import("rid.zig");

pub const PROJECT_PAYLOAD = "xyz.radicle.project";

pub const Project = struct {
    name: []const u8,
    description: []const u8,
    default_branch: []const u8,

    fn value(self: Project, arena: std.mem.Allocator) std.mem.Allocator.Error!canonical.Value {
        const entries = try arena.alloc(canonical.Value.Entry, 3);
        entries[0] = .{ .key = "name", .value = .{ .string = self.name } };
        entries[1] = .{ .key = "description", .value = .{ .string = self.description } };
        entries[2] = .{ .key = "defaultBranch", .value = .{ .string = self.default_branch } };
        return .{ .object = entries };
    }
};

/// The initial identity document for a project repository: version 1 (public,
/// both omitted from output), a single delegate, threshold 1.
pub const Doc = struct {
    project: Project,
    delegate: []const u8,
    threshold: i64 = 1,

    /// Builds the canonical Value tree. Borrows the Doc's slices.
    pub fn value(self: Doc, arena: std.mem.Allocator) std.mem.Allocator.Error!canonical.Value {
        const delegates = try arena.alloc(canonical.Value, 1);
        delegates[0] = .{ .string = self.delegate };

        const project_entries = try arena.alloc(canonical.Value.Entry, 1);
        project_entries[0] = .{ .key = PROJECT_PAYLOAD, .value = try self.project.value(arena) };

        const root = try arena.alloc(canonical.Value.Entry, 3);
        root[0] = .{ .key = "payload", .value = .{ .object = project_entries } };
        root[1] = .{ .key = "delegates", .value = .{ .array = delegates } };
        root[2] = .{ .key = "threshold", .value = .{ .int = self.threshold } };
        return .{ .object = root };
    }

    /// Encodes to canonical JSON bytes. Caller owns the result.
    pub fn encode(self: Doc, allocator: std.mem.Allocator) ![]u8 {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const v = try self.value(arena.allocator());
        return canonical.encode(allocator, v);
    }

    /// Derives the repository's RID from the canonical document.
    pub fn repoId(self: Doc, allocator: std.mem.Allocator) !rid.RepoId {
        const bytes = try self.encode(allocator);
        defer allocator.free(bytes);
        return rid.RepoId.fromDoc(bytes);
    }
};

const testing = std.testing;

// Golden vector: Doc::initial for the heartwood project, produced by Radicle
// Heartwood's CanonicalFormatter (crates/radicle/src/identity/doc.rs +
// canonical/formatter.rs). version(1) and visibility(public) are omitted.
const HEARTWOOD_DOC = Doc{
    .project = .{
        .name = "heartwood",
        .description = "Radicle Heartwood Protocol & Stack",
        .default_branch = "master",
    },
    .delegate = "did:key:z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi",
};

test "encode matches heartwood canonical bytes" {
    const bytes = try HEARTWOOD_DOC.encode(testing.allocator);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        "{\"delegates\":[\"did:key:z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi\"]," ++
            "\"payload\":{\"xyz.radicle.project\":{\"defaultBranch\":\"master\"," ++
            "\"description\":\"Radicle Heartwood Protocol & Stack\",\"name\":\"heartwood\"}}," ++
            "\"threshold\":1}",
        bytes,
    );
}

test "doc bytes hash to expected git oid" {
    const bytes = try HEARTWOOD_DOC.encode(testing.allocator);
    defer testing.allocator.free(bytes);
    // printf '%s' <bytes> | git hash-object --stdin
    const oid = git.hashBlob(bytes);
    var hex: [40]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{oid}) catch unreachable;
    try testing.expectEqualStrings("d96f425412c9f8ad5d9a9a05c9831d0728e2338d", &hex);
}

test "repoId round trips through rad: string" {
    const repo = try HEARTWOOD_DOC.repoId(testing.allocator);
    const s = try repo.encode(testing.allocator);
    defer testing.allocator.free(s);
    const back = try rid.RepoId.parse(testing.allocator, s);
    try testing.expectEqualSlices(u8, &repo.oid, &back.oid);
}
