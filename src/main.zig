const std = @import("std");
const radish = @import("radish");

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    if (args.len >= 5 and std.mem.eql(u8, args[1], "ping")) {
        return ping(init, args[2], args[3], args[4]);
    }

    std.debug.print(
        \\radish - a radicle client
        \\
        \\usage:
        \\  radish ping <host> <port> <node-id>   dial a node, handshake, ping/pong
        \\
    , .{});
}

fn ping(init: std.process.Init, host: []const u8, port_str: []const u8, nid_str: []const u8) !void {
    const arena = init.arena.allocator();
    const port = try std.fmt.parseInt(u16, port_str, 10);
    const nid = try radish.NodeId.parse(arena, nid_str);

    const zeroes = radish.wire.ping(init.io, arena, host, port, nid, 8) catch |e| {
        std.debug.print("ping failed: {s}\n", .{@errorName(e)});
        return e;
    };
    std.debug.print("pong from {s} ({d} zero bytes)\n", .{ nid_str, zeroes });
}
