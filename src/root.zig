//! radish - a radicle client and node.
const std = @import("std");

pub const crypto = @import("crypto/mod.zig");
pub const identity = @import("identity/mod.zig");
pub const git = @import("git/mod.zig");
pub const net = @import("net/mod.zig");

// Common types, hoisted for convenience.
pub const NodeId = identity.NodeId;
pub const RepoId = identity.RepoId;
pub const Doc = identity.Doc;
pub const Signature = crypto.Signature;
pub const SecretKey = crypto.SecretKey;

test {
    std.testing.refAllDecls(@This());
}

test "gitpack module is importable from the toolchain" {
    const gitpack = @import("gitpack");
    _ = gitpack.Oid;
    _ = gitpack.indexPack;
    _ = gitpack.Repository;
}
