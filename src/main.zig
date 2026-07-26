const std = @import("std");
const radish = @import("radish");

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    if (args.len >= 5 and std.mem.eql(u8, args[1], "ping")) {
        return ping(init, args[2], args[3], args[4]);
    }

    if (args.len >= 5 and std.mem.eql(u8, args[1], "announce")) {
        const alias = if (args.len >= 6) args[5] else "radish";
        return announce(init, args[2], args[3], args[4], alias);
    }

    if (args.len >= 5 and std.mem.eql(u8, args[1], "subscribe")) {
        const max: usize = if (args.len >= 6) try std.fmt.parseInt(usize, args[5], 10) else 200;
        return subscribe(init, args[2], args[3], args[4], max);
    }

    if (args.len >= 6 and std.mem.eql(u8, args[1], "fetch-probe")) {
        return fetchProbe(init, args[2], args[3], args[4], args[5]);
    }

    if (args.len >= 7 and std.mem.eql(u8, args[1], "clone")) {
        return clone(init, args[2], args[3], args[4], args[5], args[6]);
    }

    std.debug.print(
        \\radish - a radicle client
        \\
        \\usage:
        \\  radish ping        <host> <port> <node-id>              dial a node, handshake, ping/pong
        \\  radish announce    <host> <port> <node-id> [alias]      send a signed NodeAnnouncement
        \\  radish subscribe   <host> <port> <node-id> [frames]     listen to gossip: nodes + inventory
        \\  radish fetch-probe <host> <port> <node-id> <rid>        open a git stream, read the v2 advert
        \\  radish clone       <host> <port> <node-id> <rid> <dir>  clone a repo into <dir> (bare)
        \\
    , .{});
}

fn clone(init: std.process.Init, host: []const u8, port_str: []const u8, nid_str: []const u8, rid_str: []const u8, dir: []const u8) !void {
    const arena = init.arena.allocator();
    const port = try std.fmt.parseInt(u16, port_str, 10);
    const nid = try radish.NodeId.parse(arena, nid_str);

    std.debug.print("cloning {s} from {s} into {s}...\n", .{ rid_str, nid_str, dir });
    const result = radish.net.fetch.clone(init.io, arena, host, port, nid, rid_str, dir) catch |e| {
        std.debug.print("clone failed: {s}\n", .{@errorName(e)});
        return e;
    };
    std.debug.print("cloned {s}: {d} refs, {d} pack bytes -> {s}\n", .{ rid_str, result.refs, result.pack_bytes, dir });
}

const FetchProbePrinter = struct {
    git_bytes: usize = 0,
    git_frames: usize = 0,

    pub fn onGit(self: *FetchProbePrinter, data: []const u8) void {
        self.git_frames += 1;
        self.git_bytes += data.len;
        std.debug.print("git frame ({d} bytes):\n{f}\n", .{ data.len, std.zig.fmtString(data) });
    }

    pub fn onControl(_: *FetchProbePrinter, ctrl: radish.net.protocol.ControlType, target: u64) void {
        std.debug.print("control {s} stream={d}\n", .{ @tagName(ctrl), target });
    }
};

fn fetchProbe(init: std.process.Init, host: []const u8, port_str: []const u8, nid_str: []const u8, rid_str: []const u8) !void {
    const arena = init.arena.allocator();
    const port = try std.fmt.parseInt(u16, port_str, 10);
    const nid = try radish.NodeId.parse(arena, nid_str);

    var printer = FetchProbePrinter{};
    std.debug.print("fetch-probe {s} from {s}...\n", .{ rid_str, nid_str });
    const frames = radish.net.wire.fetchProbe(init.io, arena, host, port, nid, rid_str, 20, &printer) catch |e| {
        std.debug.print("fetch-probe failed: {s}\n", .{@errorName(e)});
        return e;
    };
    std.debug.print(
        "\ndone: {d} frames, {d} git frames, {d} git bytes\n",
        .{ frames, printer.git_frames, printer.git_bytes },
    );
}

fn ping(init: std.process.Init, host: []const u8, port_str: []const u8, nid_str: []const u8) !void {
    const arena = init.arena.allocator();
    const port = try std.fmt.parseInt(u16, port_str, 10);
    const nid = try radish.NodeId.parse(arena, nid_str);

    const zeroes = radish.net.wire.ping(init.io, arena, host, port, nid, 8) catch |e| {
        std.debug.print("ping failed: {s}\n", .{@errorName(e)});
        return e;
    };
    std.debug.print("pong from {s} ({d} zero bytes)\n", .{ nid_str, zeroes });
}

fn announce(init: std.process.Init, host: []const u8, port_str: []const u8, nid_str: []const u8, alias: []const u8) !void {
    const arena = init.arena.allocator();
    const port = try std.fmt.parseInt(u16, port_str, 10);
    const nid = try radish.NodeId.parse(arena, nid_str);

    var seed: [32]u8 = undefined;
    init.io.random(&seed);
    const key = try radish.SecretKey.fromSeed(seed);
    const our_nid = try key.nodeId().encode(arena);
    std.debug.print("announcing as {s} (alias {s})\n", .{ our_nid, alias });

    const zeroes = radish.net.wire.sendAnnouncement(init.io, arena, host, port, nid, key, alias) catch |e| {
        std.debug.print("announce failed: {s}\n", .{@errorName(e)});
        return e;
    };
    std.debug.print("accepted: pong from {s} ({d} zero bytes)\n", .{ nid_str, zeroes });
}

const GossipPrinter = struct {
    arena: std.mem.Allocator,
    nodes: usize = 0,
    inventories: usize = 0,
    rids: usize = 0,

    pub fn onMessage(self: *GossipPrinter, msg: radish.net.protocol.Message) void {
        switch (msg) {
            .node_announced => |n| {
                self.nodes += 1;
                const id = radish.NodeId.fromPublicKey(n.node).encode(self.arena) catch return;
                std.debug.print("node  {s}  alias={s} agent={s}\n", .{ id, n.alias, n.agent });
            },
            .inventory_announced => |inv| {
                self.inventories += 1;
                const id = radish.NodeId.fromPublicKey(inv.node).encode(self.arena) catch return;
                std.debug.print("inv   {s}  {d} repos\n", .{ id, inv.inventory.len });
                for (inv.inventory) |oid| {
                    self.rids += 1;
                    const rid = radish.RepoId.fromOid(oid).encode(self.arena) catch continue;
                    std.debug.print("        {s}\n", .{rid});
                }
            },
            else => {},
        }
    }
};

fn subscribe(init: std.process.Init, host: []const u8, port_str: []const u8, nid_str: []const u8, max: usize) !void {
    const arena = init.arena.allocator();
    const port = try std.fmt.parseInt(u16, port_str, 10);
    const nid = try radish.NodeId.parse(arena, nid_str);

    var printer = GossipPrinter{ .arena = arena };
    std.debug.print("subscribing to {s} (up to {d} frames)...\n", .{ nid_str, max });
    const frames = radish.net.wire.subscribe(init.io, arena, host, port, nid, max, &printer) catch |e| {
        std.debug.print("subscribe failed: {s}\n", .{@errorName(e)});
        return e;
    };
    std.debug.print(
        "\ndone: {d} frames, {d} nodes, {d} inventories, {d} repos\n",
        .{ frames, printer.nodes, printer.inventories, printer.rids },
    );
}
