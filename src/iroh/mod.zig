//! iroh, the layer radicle 2.x reaches a peer through: the records that say
//! where a node id can be found, and (later) the relay that carries packets
//! when no direct path works. The QUIC underneath is `quic/`.
pub const dns = @import("dns.zig");
pub const pkarr = @import("pkarr.zig");
pub const addr = @import("addr.zig");
pub const resolve = @import("resolve.zig");
pub const testdata = @import("testdata.zig");

test {
    _ = dns;
    _ = pkarr;
    _ = addr;
    _ = resolve;
}
