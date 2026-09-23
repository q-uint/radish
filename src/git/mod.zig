//! Git object layer: object helpers, storage, and the git wire protocol
//! (pkt-line + protocol-v2 client). Pack indexing and checkout come from the
//! toolchain's own git implementation (see build.zig `gitpack`).
pub const objects = @import("git.zig");
pub const checkout = @import("checkout.zig");
pub const odb = @import("odb.zig");
pub const pack = @import("pack.zig");
pub const uploadpack = @import("uploadpack.zig");
pub const walk = @import("walk.zig");
pub const storage = @import("storage.zig");
pub const pktline = @import("pktline.zig");
pub const protocol = @import("protocol.zig");

test {
    _ = objects;
    _ = checkout;
    _ = odb;
    _ = pack;
    _ = uploadpack;
    _ = walk;
    _ = storage;
    _ = pktline;
    _ = protocol;
    _ = @import("storage_test.zig");
    _ = @import("odb_test.zig");
    _ = @import("checkout_test.zig");
    _ = @import("pack_test.zig");
    _ = @import("uploadpack_test.zig");
    _ = @import("walk_test.zig");
}
