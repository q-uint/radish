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

pub const MAX_DELEGATES = 255;

/// Structural validity per heartwood Delegates::new / Threshold::new.
/// Note: this checks structure only, not signatures.
pub const VerifyError = error{
    NoDelegates,
    TooManyDelegates,
    DuplicateDelegate,
    ThresholdZero,
    ThresholdTooLarge,
    ThresholdExceedsDelegates,
};

/// An identity document for a project repository. version 1 and public
/// visibility are the defaults and are omitted from the canonical output.
pub const Doc = struct {
    project: Project,
    delegates: []const []const u8,
    threshold: i64 = 1,

    /// Builds the canonical Value tree. Borrows the Doc's slices.
    pub fn value(self: Doc, arena: std.mem.Allocator) std.mem.Allocator.Error!canonical.Value {
        const delegates = try arena.alloc(canonical.Value, self.delegates.len);
        for (self.delegates, 0..) |d, i| delegates[i] = .{ .string = d };

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
        return try rid.RepoId.fromDoc(bytes);
    }

    /// Structural verification: delegates non-empty, unique, <= MAX_DELEGATES;
    /// threshold in 1..=min(MAX_DELEGATES, delegate_count).
    /// Mirrors heartwood Delegates::new + Threshold::new (unique-delegate count).
    pub fn verify(self: Doc) VerifyError!void {
        const unique = try self.uniqueDelegateCount();
        if (unique == 0) return error.NoDelegates;

        if (self.threshold < 1) return error.ThresholdZero;
        if (self.threshold > MAX_DELEGATES) return error.ThresholdTooLarge;
        if (self.threshold > @as(i64, @intCast(unique))) return error.ThresholdExceedsDelegates;
    }

    fn uniqueDelegateCount(self: Doc) VerifyError!usize {
        if (self.delegates.len > MAX_DELEGATES) return error.TooManyDelegates;
        for (self.delegates, 0..) |d, i| {
            for (self.delegates[0..i]) |prev| {
                if (std.mem.eql(u8, d, prev)) return error.DuplicateDelegate;
            }
        }
        return self.delegates.len;
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
    .delegates = &.{"did:key:z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi"},
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
    const oid = try git.hashBlob(bytes);
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

const A = "did:key:z6MkA";
const B = "did:key:z6MkB";
const C = "did:key:z6MkC";

fn docWith(delegates: []const []const u8, threshold: i64) Doc {
    return .{ .project = HEARTWOOD_DOC.project, .delegates = delegates, .threshold = threshold };
}

test "verify accepts the initial doc" {
    try HEARTWOOD_DOC.verify();
}

test "verify accepts multi-delegate with valid threshold" {
    try docWith(&.{ A, B, C }, 2).verify();
    try docWith(&.{ A, B, C }, 3).verify();
}

test "verify rejects empty delegates" {
    try testing.expectError(error.NoDelegates, docWith(&.{}, 1).verify());
}

test "verify rejects duplicate delegate" {
    try testing.expectError(error.DuplicateDelegate, docWith(&.{ A, B, A }, 1).verify());
}

test "verify rejects zero threshold" {
    try testing.expectError(error.ThresholdZero, docWith(&.{A}, 0).verify());
}

test "verify rejects threshold exceeding delegate count" {
    try testing.expectError(error.ThresholdExceedsDelegates, docWith(&.{ A, B }, 3).verify());
}

test "verify rejects threshold over max" {
    try testing.expectError(error.ThresholdTooLarge, docWith(&.{A}, 256).verify());
}
