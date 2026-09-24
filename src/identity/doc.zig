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
const canonical = @import("../crypto/canonical.zig");
const rid = @import("rid.zig");
const node_id = @import("node_id.zig");
const safepath = @import("../safepath.zig");

pub const PROJECT_PAYLOAD = "xyz.radicle.project";

/// Delegates are `did:key:z6Mk...`; namespaces on disk are the bare key.
pub const DID_KEY_PREFIX = "did:key:";

/// `nid` with the did:key prefix removed, or `nid` unchanged when it has none.
pub fn bareNid(nid: []const u8) []const u8 {
    return if (std.mem.startsWith(u8, nid, DID_KEY_PREFIX)) nid[DID_KEY_PREFIX.len..] else nid;
}

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

/// Who may fetch the repository. Omitted from the canonical encoding when
/// public, which is why an absent field parses as public.
/// Source: heartwood identity/doc.rs Visibility (serde tag = "type").
pub const Visibility = union(enum) {
    public,
    /// Delegates, plus these dids. Sorted on encode, as heartwood's BTreeSet is.
    private: []const []const u8,

    pub fn isPublic(self: Visibility) bool {
        return self == .public;
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
    visibility: Visibility = .public,

    /// Builds the canonical Value tree. Borrows the Doc's slices.
    pub fn value(self: Doc, arena: std.mem.Allocator) std.mem.Allocator.Error!canonical.Value {
        const delegates = try arena.alloc(canonical.Value, self.delegates.len);
        for (self.delegates, 0..) |d, i| delegates[i] = .{ .string = d };

        const project_entries = try arena.alloc(canonical.Value.Entry, 1);
        project_entries[0] = .{ .key = PROJECT_PAYLOAD, .value = try self.project.value(arena) };

        // Four only when private: public is the default and is left out, so
        // emitting it would change the document's hash, which is the RID.
        const root = try arena.alloc(canonical.Value.Entry, if (self.visibility.isPublic()) 3 else 4);
        root[0] = .{ .key = "payload", .value = .{ .object = project_entries } };
        root[1] = .{ .key = "delegates", .value = .{ .array = delegates } };
        root[2] = .{ .key = "threshold", .value = .{ .int = self.threshold } };
        if (self.visibility == .private) {
            root[3] = .{ .key = "visibility", .value = try self.visibilityValue(arena) };
        }
        return .{ .object = root };
    }

    /// `{"type":"private"}`, with `allow` only when it has entries, matching
    /// heartwood's `skip_serializing_if = "BTreeSet::is_empty"`.
    fn visibilityValue(self: Doc, arena: std.mem.Allocator) std.mem.Allocator.Error!canonical.Value {
        const dids = self.visibility.private;
        if (dids.len == 0) {
            const one = try arena.alloc(canonical.Value.Entry, 1);
            one[0] = .{ .key = "type", .value = .{ .string = "private" } };
            return .{ .object = one };
        }

        const sorted = try arena.dupe([]const u8, dids);
        std.mem.sort([]const u8, sorted, {}, struct {
            fn lt(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.lt);
        const allow = try arena.alloc(canonical.Value, sorted.len);
        for (sorted, 0..) |d, i| allow[i] = .{ .string = d };

        const two = try arena.alloc(canonical.Value.Entry, 2);
        two[0] = .{ .key = "type", .value = .{ .string = "private" } };
        two[1] = .{ .key = "allow", .value = .{ .array = allow } };
        return .{ .object = two };
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

pub const ParseError = error{
    MissingProjectPayload,
    Json,
    BadBranchName,
    BadDelegate,
    BadVisibility,
} || std.mem.Allocator.Error;

/// A parsed Doc that owns its backing memory. Call `deinit` when done.
pub const Parsed = struct {
    arena: *std.heap.ArenaAllocator,
    doc: Doc,

    pub fn deinit(self: Parsed) void {
        const allocator = self.arena.child_allocator;
        self.arena.deinit();
        allocator.destroy(self.arena);
    }
};

// JSON shape of the identity doc (only the fields we model). version and
// visibility are ignored on read; unknown payload types are ignored.
const RawProject = struct {
    name: []const u8,
    description: []const u8,
    defaultBranch: []const u8,
};
const RawPayload = struct {
    @"xyz.radicle.project": ?RawProject = null,
};
const RawVisibility = struct {
    type: []const u8,
    allow: []const []const u8 = &.{},
};
const RawDoc = struct {
    payload: RawPayload,
    delegates: []const []const u8,
    threshold: i64 = 1,
    visibility: ?RawVisibility = null,
};

/// Parses canonical identity-document bytes into a `Doc`.
pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) ParseError!Parsed {
    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    const raw = std.json.parseFromSliceLeaky(RawDoc, a, bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return error.Json;
    const proj = raw.payload.@"xyz.radicle.project" orelse return error.MissingProjectPayload;

    // Both reach the filesystem as path components, so they are checked here
    // rather than at each of the five places that interpolate them.
    if (!safepath.path(proj.defaultBranch)) return error.BadBranchName;
    for (raw.delegates) |d| {
        _ = node_id.NodeId.parse(bareNid(d)) catch return error.BadDelegate;
    }

    return .{ .arena = arena, .doc = .{
        .project = .{
            .name = proj.name,
            .description = proj.description,
            .default_branch = proj.defaultBranch,
        },
        .delegates = raw.delegates,
        .threshold = raw.threshold,
        .visibility = try parseVisibility(raw.visibility),
    } };
}

/// An absent field is public, which is how heartwood omits the default.
fn parseVisibility(raw: ?RawVisibility) ParseError!Visibility {
    const v = raw orelse return .public;
    if (std.mem.eql(u8, v.type, "public")) return .public;
    if (!std.mem.eql(u8, v.type, "private")) return error.BadVisibility;

    for (v.allow) |d| {
        _ = node_id.NodeId.parse(bareNid(d)) catch return error.BadDelegate;
    }
    return .{ .private = v.allow };
}

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

test "encode matches heartwood canonical bytes, whose oid is the RID" {
    const bytes = try HEARTWOOD_DOC.encode(testing.allocator);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings(
        \\{"delegates":["did:key:z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi"],"payload":{"xyz.radicle.project":{"defaultBranch":"master","description":"Radicle Heartwood Protocol & Stack","name":"heartwood"}},"threshold":1}
    ,
        bytes,
    );

    // printf '%s' <bytes> | git hash-object --stdin
    const repo = try HEARTWOOD_DOC.repoId(testing.allocator);
    var hex: [40]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{repo.oid}) catch unreachable;
    try testing.expectEqualStrings("d96f425412c9f8ad5d9a9a05c9831d0728e2338d", &hex);
}

const A = "did:key:z6MkA";
const B = "did:key:z6MkB";
const C = "did:key:z6MkC";

fn docWith(delegates: []const []const u8, threshold: i64) Doc {
    return .{ .project = HEARTWOOD_DOC.project, .delegates = delegates, .threshold = threshold };
}

test "verify accepts a threshold within a unique delegate set" {
    try HEARTWOOD_DOC.verify();
    try docWith(&.{ A, B, C }, 2).verify();
    try docWith(&.{ A, B, C }, 3).verify();
}

test "verify rejects every structural violation" {
    try testing.expectError(error.NoDelegates, docWith(&.{}, 1).verify());
    try testing.expectError(error.DuplicateDelegate, docWith(&.{ A, B, A }, 1).verify());
    try testing.expectError(error.ThresholdZero, docWith(&.{A}, 0).verify());
    try testing.expectError(error.ThresholdExceedsDelegates, docWith(&.{ A, B }, 3).verify());
    try testing.expectError(error.ThresholdTooLarge, docWith(&.{A}, 256).verify());
}

test "parse round-trips heartwood canonical bytes" {
    const original = try HEARTWOOD_DOC.encode(testing.allocator);
    defer testing.allocator.free(original);

    const parsed = try parse(testing.allocator, original);
    defer parsed.deinit();

    try testing.expectEqualStrings("heartwood", parsed.doc.project.name);
    try testing.expectEqual(@as(usize, 1), parsed.doc.delegates.len);
    try testing.expectEqual(@as(i64, 1), parsed.doc.threshold);

    const reencoded = try parsed.doc.encode(testing.allocator);
    defer testing.allocator.free(reencoded);
    try testing.expectEqualStrings(original, reencoded);
}

test "parse rejects a doc without the project payload" {
    const bytes =
        \\{"delegates":["did:key:z6MkA"],"payload":{},"threshold":1}
    ;
    try testing.expectError(error.MissingProjectPayload, parse(testing.allocator, bytes));
}

const REAL_NID = "did:key:z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi";

/// A document with `defaultBranch` set to `branch`, otherwise well-formed.
fn docWithBranch(comptime branch: []const u8) []const u8 {
    return "{\"delegates\":[\"" ++ REAL_NID ++ "\"],\"payload\":{\"xyz.radicle.project\":" ++
        "{\"defaultBranch\":\"" ++ branch ++ "\",\"description\":\"\",\"name\":\"n\"}},\"threshold\":1}";
}

// `defaultBranch` is interpolated into `refs/heads/{s}` and read back out of
// `refs/namespaces/{nid}/refs/heads/{s}`, both as paths the kernel resolves.
// The document is authored by whoever created the repository, and its hash is
// the RID, so the RID check cannot catch this.
test "parse refuses a defaultBranch that would escape the refs directory" {
    try testing.expectError(error.BadBranchName, parse(testing.allocator, docWithBranch("../../../../etc/x")));
    try testing.expectError(error.BadBranchName, parse(testing.allocator, docWithBranch("..")));
    try testing.expectError(error.BadBranchName, parse(testing.allocator, docWithBranch("a/../b")));
    try testing.expectError(error.BadBranchName, parse(testing.allocator, docWithBranch("")));
    try testing.expectError(error.BadBranchName, parse(testing.allocator, docWithBranch("/abs")));
    try testing.expectError(error.BadBranchName, parse(testing.allocator, docWithBranch("a\\\\b")));

    const ok = try parse(testing.allocator, docWithBranch("feature/x"));
    defer ok.deinit();
    try testing.expectEqualStrings("feature/x", ok.doc.project.default_branch);
}

// Delegates are interpolated into `refs/namespaces/{s}/...`, so they get the
// same treatment. Parsing as a node id is stricter than a path check and is
// the real invariant: a delegate is an ed25519 key.
fn docWithDelegate(comptime did: []const u8) []const u8 {
    return "{\"delegates\":[\"" ++ did ++ "\"],\"payload\":{\"xyz.radicle.project\":" ++
        "{\"defaultBranch\":\"main\",\"description\":\"\",\"name\":\"n\"}},\"threshold\":1}";
}

test "parse refuses a delegate that is not a node id" {
    try testing.expectError(error.BadDelegate, parse(testing.allocator, docWithDelegate("did:key:../../../etc")));
    try testing.expectError(error.BadDelegate, parse(testing.allocator, docWithDelegate("did:key:z6MkA")));
    try testing.expectError(error.BadDelegate, parse(testing.allocator, docWithDelegate("")));

    const ok = try parse(testing.allocator, docWithDelegate(REAL_NID));
    defer ok.deinit();
    try testing.expectEqual(@as(usize, 1), ok.doc.delegates.len);
}

test "visibility is public when absent and round-trips when private" {
    const pub_doc = try parse(testing.allocator, docWithBranch("main"));
    defer pub_doc.deinit();
    try testing.expect(pub_doc.doc.visibility.isPublic());

    const private =
        "{\"delegates\":[\"" ++ REAL_NID ++ "\"],\"payload\":{\"xyz.radicle.project\":" ++
        "{\"defaultBranch\":\"main\",\"description\":\"\",\"name\":\"n\"}},\"threshold\":1," ++
        "\"visibility\":{\"allow\":[\"" ++ REAL_NID ++ "\"],\"type\":\"private\"}}";
    const parsed = try parse(testing.allocator, private);
    defer parsed.deinit();
    try testing.expect(!parsed.doc.visibility.isPublic());
    try testing.expectEqual(@as(usize, 1), parsed.doc.visibility.private.len);

    // The encoding has to survive the round trip: the document's hash is the
    // RID, so dropping `visibility` would rename the repository.
    const reencoded = try parsed.doc.encode(testing.allocator);
    defer testing.allocator.free(reencoded);
    try testing.expectEqualStrings(private, reencoded);
}
