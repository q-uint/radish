//! Talking to a radicle-node: framing codec, wire protocol, gossip, fetch.
pub const codec = @import("../codec.zig");
pub const protocol = @import("protocol.zig");
pub const wire = @import("wire.zig");
pub const announce = @import("announce.zig");
pub const fetch = @import("fetch.zig");
pub const upload = @import("upload.zig");
pub const seeds = @import("seeds.zig");
pub const node = @import("node.zig");
pub const gossip = @import("gossip.zig");
pub const gitstream = @import("gitstream.zig");
pub const clone = @import("clone.zig");

test {
    _ = codec;
    _ = protocol;
    _ = wire;
    _ = announce;
    _ = fetch;
    _ = upload;
    _ = seeds;
    _ = node;
    _ = gossip;
    _ = gitstream;
    _ = clone;
    _ = @import("node_test.zig");
    _ = @import("upload_test.zig");
}
