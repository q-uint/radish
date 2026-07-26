//! Thin access to the system libgit2, via translate-c bindings (the `git2`
//! build module). Higher-level storage code builds on this.
const std = @import("std");
pub const c = @import("git2");

/// The libgit2 version radish is developed and tested against. Bump this
/// deliberately (and re-verify) when moving to a new libgit2.
pub const EXPECTED_VERSION = "1.9.4";

// Compile-time guard: the translated header must be EXPECTED_VERSION. Catches a
// stale or mismatched libgit2 on the include path (Nix or system).
comptime {
    if (!std.mem.eql(u8, c.LIBGIT2_VERSION, EXPECTED_VERSION)) {
        @compileError("libgit2 header is not the expected " ++ EXPECTED_VERSION);
    }
}

/// Errors surfaced from libgit2 return codes. `Error` is the catch-all for a
/// generic failure (-1); call `lastError()` for libgit2's message.
pub const Error = error{
    NotFound,
    Exists,
    Ambiguous,
    Buffer,
    User,
    BareRepo,
    UnbornBranch,
    Unmerged,
    NonFastForward,
    InvalidSpec,
    Conflict,
    Locked,
    Modified,
    Auth,
    Certificate,
    Applied,
    Peel,
    Eof,
    Invalid,
    Uncommitted,
    Directory,
    MergeConflict,
    Git,
};

/// Maps a libgit2 return code to an `Error`. Non-negative codes are success.
pub fn check(rc: c_int) Error!void {
    if (rc >= 0) return;
    return switch (rc) {
        c.GIT_ENOTFOUND => error.NotFound,
        c.GIT_EEXISTS => error.Exists,
        c.GIT_EAMBIGUOUS => error.Ambiguous,
        c.GIT_EBUFS => error.Buffer,
        c.GIT_EUSER => error.User,
        c.GIT_EBAREREPO => error.BareRepo,
        c.GIT_EUNBORNBRANCH => error.UnbornBranch,
        c.GIT_EUNMERGED => error.Unmerged,
        c.GIT_ENONFASTFORWARD => error.NonFastForward,
        c.GIT_EINVALIDSPEC => error.InvalidSpec,
        c.GIT_ECONFLICT => error.Conflict,
        c.GIT_ELOCKED => error.Locked,
        c.GIT_EMODIFIED => error.Modified,
        c.GIT_EAUTH => error.Auth,
        c.GIT_ECERTIFICATE => error.Certificate,
        c.GIT_EAPPLIED => error.Applied,
        c.GIT_EPEEL => error.Peel,
        c.GIT_EEOF => error.Eof,
        c.GIT_EINVALID => error.Invalid,
        c.GIT_EUNCOMMITTED => error.Uncommitted,
        c.GIT_EDIRECTORY => error.Directory,
        c.GIT_EMERGECONFLICT => error.MergeConflict,
        else => error.Git,
    };
}

/// libgit2's last error message for the current thread, if any.
pub fn lastError() ?[]const u8 {
    const e = c.git_error_last() orelse return null;
    if (e.*.message == null) return null;
    return std.mem.span(e.*.message);
}

pub const Version = struct { major: u16, minor: u16, rev: u16 };

/// The version of the linked libgit2 (from the shared library at runtime).
pub fn version() Version {
    var major: c_int = 0;
    var minor: c_int = 0;
    var rev: c_int = 0;
    _ = c.git_libgit2_version(&major, &minor, &rev);
    return .{
        .major = @intCast(major),
        .minor = @intCast(minor),
        .rev = @intCast(rev),
    };
}

const testing = std.testing;

test "check maps return codes" {
    try check(0);
    try check(1);
    try testing.expectError(error.NotFound, check(c.GIT_ENOTFOUND));
    try testing.expectError(error.Exists, check(c.GIT_EEXISTS));
    try testing.expectError(error.Git, check(-1));
}

test "linked libgit2 is the expected version" {
    const v = version();
    var buf: [32]u8 = undefined;
    const linked = std.fmt.bufPrint(&buf, "{d}.{d}.{d}", .{ v.major, v.minor, v.rev }) catch unreachable;
    try testing.expectEqualStrings(EXPECTED_VERSION, linked);
}
