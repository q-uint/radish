//! radish - a radicle client and node.
//!
//! Ordered so a module comes after everything it depends on.
pub const codec = @import("codec.zig");
pub const safepath = @import("safepath.zig");
pub const githash = @import("githash.zig");
pub const dial = @import("dial.zig");
pub const crypto = @import("crypto/mod.zig");
pub const identity = @import("identity/mod.zig");
pub const quic = @import("quic/mod.zig");
pub const git = @import("git/mod.zig");
pub const net = @import("net/mod.zig");
pub const pkg = @import("pkg/mod.zig");

test {
    _ = codec;
    _ = safepath;
    _ = githash;
    _ = dial;
    _ = crypto;
    _ = identity;
    _ = quic;
    _ = git;
    _ = net;
    _ = pkg;
}
