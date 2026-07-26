//! Git object layer: libgit2 bindings, our helpers, storage, and the git wire
//! protocol (pkt-line + protocol-v2 client).
pub const git2 = @import("git2.zig");
pub const objects = @import("git.zig");
pub const storage = @import("storage.zig");
pub const pktline = @import("pktline.zig");
pub const protocol = @import("protocol.zig");
