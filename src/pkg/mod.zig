//! Resolving radicle dependencies for a Zig package.
pub const zon = @import("zon.zig");
pub const manifest = @import("manifest.zig");
pub const rewrite = @import("rewrite.zig");

test {
    _ = zon;
    _ = manifest;
    _ = rewrite;
}
