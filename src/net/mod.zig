//! Talking to a radicle-node: framing codec, wire protocol, gossip, fetch.
pub const codec = @import("../codec.zig");
pub const protocol = @import("protocol.zig");
pub const dial = @import("dial.zig");
pub const wire = @import("wire.zig");
pub const announce = @import("announce.zig");
pub const fetch = @import("fetch.zig");
pub const seeds = @import("seeds.zig");
pub const node = @import("node.zig");
pub const gossip = @import("gossip.zig");
pub const gitstream = @import("gitstream.zig");

test {
    _ = codec;
    _ = protocol;
    _ = dial;
    _ = wire;
    _ = announce;
    _ = fetch;
    _ = seeds;
    _ = node;
    _ = gossip;
    _ = gitstream;
}
