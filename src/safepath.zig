//! Whether a name from a repository may be handed to the filesystem.
//!
//! Ref names, tree entry names and the identity document's `defaultBranch` all
//! arrive from whoever served the repository and all end up interpolated into
//! a path, where the kernel resolves `..`. The checks are the same in each
//! case, so they live here rather than once per caller.
//! Source: git's `verify_path`, and the checks git-fsck documents.
const std = @import("std");

/// One path component: not empty, not a directory traversal, and carrying no
/// separator. Backslash counts: it separates paths on Windows, and a tree
/// written there is a tree we may be asked to check out here.
pub fn component(name: []const u8) bool {
    if (name.len == 0) return false;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return false;
    return std.mem.indexOfAny(u8, name, "/\\\x00") == null;
}

/// A `/`-separated path whose every component is safe. Rejects a leading or
/// trailing slash, and a doubled one, since each leaves an empty component.
pub fn path(name: []const u8) bool {
    if (name.len == 0) return false;
    var it = std.mem.splitScalar(u8, name, '/');
    while (it.next()) |seg| {
        if (!component(seg)) return false;
    }
    return true;
}

const testing = std.testing;

test "a component rejects traversal, separators and emptiness" {
    try testing.expect(component("main"));
    try testing.expect(component("a.txt"));
    try testing.expect(!component(""));
    try testing.expect(!component("."));
    try testing.expect(!component(".."));
    try testing.expect(!component("a/b"));
    try testing.expect(!component("a\\b"));
    try testing.expect(!component("a\x00b"));
}

// `..` in any position is the case that matters: the kernel resolves it, so a
// single accepted segment is enough to leave the directory we meant to stay in.
test "a path is safe only when every component is" {
    try testing.expect(path("main"));
    try testing.expect(path("feature/x"));
    try testing.expect(path("refs/heads/main"));
    try testing.expect(!path(""));
    try testing.expect(!path(".."));
    try testing.expect(!path("../etc"));
    try testing.expect(!path("refs/heads/../../../etc"));
    try testing.expect(!path("a/../b"));
    try testing.expect(!path("/leading"));
    try testing.expect(!path("trailing/"));
    try testing.expect(!path("double//slash"));
}
