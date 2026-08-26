//! QUIC (RFC 9000/9001/9002).
//!
//! Independent of `net/`: QUIC knows nothing about node ids, gossip, or
//! radicle. Radicle 2.x reaches it through iroh, but the transport stands on
//! its own and is verified against the RFCs' published test vectors.
pub const crypto = @import("crypto.zig");
pub const packet = @import("packet.zig");
pub const frame = @import("frame.zig");
pub const tls = @import("tls.zig");
pub const handshake = @import("handshake.zig");
pub const client = @import("client.zig");
pub const probe = @import("probe.zig");
pub const testdata = @import("testdata.zig");

test {
    _ = crypto;
    _ = packet;
    _ = frame;
    _ = tls;
    _ = handshake;
    _ = client;
    _ = probe;
    _ = &probe.run;
}
