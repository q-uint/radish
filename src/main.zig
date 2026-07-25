const std = @import("std");
const radish = @import("radish");

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const nid = radish.NodeId.fromPublicKey(@splat(0));
    const s = try nid.encode(arena);
    std.debug.print("radish node id: {s}\n", .{s});
}
