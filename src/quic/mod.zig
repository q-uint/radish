//! QUIC (RFC 9000/9001/9002).
//!
//! Independent of `net/`: QUIC knows nothing about node ids, gossip, or
//! radicle. Radicle 2.x reaches it through iroh, but the transport stands on
//! its own and is verified against the RFCs' published test vectors.
pub const crypto = @import("crypto.zig");
pub const packet = @import("packet.zig");
pub const frame = @import("frame.zig");

test {
    _ = crypto;
    _ = packet;
    _ = frame;
}
