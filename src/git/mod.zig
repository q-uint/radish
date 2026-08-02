//! Git object layer: object helpers, storage, and the git wire protocol
//! (pkt-line + protocol-v2 client). Pack indexing and checkout come from the
//! toolchain's own git implementation (see build.zig `gitpack`).
pub const objects = @import("git.zig");
pub const storage = @import("storage.zig");
pub const pktline = @import("pktline.zig");
pub const protocol = @import("protocol.zig");

test {
    _ = objects;
    _ = storage;
    _ = pktline;
    _ = protocol;
}
