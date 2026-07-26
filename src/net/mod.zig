//! Talking to a radicle-node: framing codec, wire protocol, gossip, fetch.
pub const codec = @import("codec.zig");
pub const protocol = @import("protocol.zig");
pub const wire = @import("wire.zig");
pub const announce = @import("announce.zig");
pub const fetch = @import("fetch.zig");
