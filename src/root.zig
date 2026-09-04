//! radish - a radicle client and node.
const std = @import("std");

/// QUIC variable-length integers and big-endian fixed integers. Shared: QUIC
/// defines them, and radicle's own framing borrowed them.
pub const codec = @import("codec.zig");
pub const crypto = @import("crypto/mod.zig");
pub const identity = @import("identity/mod.zig");
pub const git = @import("git/mod.zig");
pub const net = @import("net/mod.zig");
pub const quic = @import("quic/mod.zig");
pub const pkg = @import("pkg/mod.zig");

// Common types, hoisted for convenience.
pub const NodeId = identity.NodeId;
pub const RepoId = identity.RepoId;
pub const Doc = identity.Doc;
pub const Signature = crypto.Signature;
pub const SecretKey = crypto.SecretKey;

test {
    _ = crypto;
    _ = identity;
    _ = git;
    _ = net;
    _ = quic;
    _ = pkg;
}
