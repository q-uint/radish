const std = @import("std");
const radish = @import("radish");

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    if (args.len >= 5 and std.mem.eql(u8, args[1], "handshake")) {
        return handshake(init, args[2], args[3], args[4]);
    }

    std.debug.print(
        \\radish - a radicle client
        \\
        \\usage:
        \\  radish handshake <host> <port> <node-id>   dial a node, Noise_XK handshake
        \\
    , .{});
}

fn handshake(init: std.process.Init, host: []const u8, port_str: []const u8, nid_str: []const u8) !void {
    const arena = init.arena.allocator();
    const port = try std.fmt.parseInt(u16, port_str, 10);
    const nid = try radish.NodeId.parse(arena, nid_str);

    var session = radish.wire.connect(init.io, host, port, nid) catch |e| {
        std.debug.print("handshake failed: {s}\n", .{@errorName(e)});
        return e;
    };
    defer session.close();
    std.debug.print("handshake OK with {s} at {s}:{d}\n", .{ nid_str, host, port });
}
