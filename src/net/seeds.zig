//! Finding who holds a repo, from two independent sources: gossip inventory
//! announcements (who advertises it on the network) and a local clone's
//! namespaces (whose refs we actually have on disk).

const std = @import("std");
const protocol = @import("protocol.zig");
const rid = @import("../identity/rid.zig");
const storage = @import("../git/storage.zig");

/// Where to start when the caller names no node. Discovery cannot bootstrap
/// itself: Noise_XK needs the responder's node id before the first byte, and
/// the routing table is only built from gossip once connected. So one entry
/// point is unavoidable. Tried in order, so radish's own seed comes first;
/// the rest are the ones heartwood ships.
/// Source: radicle node/config.rs RADICLE_NODE_BOOTSTRAP_{IRIS,ROSA}.
pub const BOOTSTRAP = [_][]const u8{
    "rad.0x51.dev:8776:z6Mkhh3TfBZeGW4z4uufMp7caXoBf2wcpDWDrRsELqWqmT6Y", // My public node.
    "iris.radicle.network:8776:z6MkrLMMsiPWUcNPHcRajuMi9mDfYckSoJyPwwnknocNYPm7",
    "rosa.radicle.network:8776:z6Mkmqogy2qEM2ummccUthFEaaHvyYmYBYh3dbe9W4ebScxo",
};

/// Collects the nodes whose inventory announcements include `want`. Gossip is a
/// push stream with no "who seeds X" query, so this observes announcements as
/// they arrive rather than asking: a node that stays quiet during the window is
/// simply not seen. Duplicates are dropped; a node re-announcing is one seed.
pub const Collector = struct {
    allocator: std.mem.Allocator,
    want: [20]u8,
    found: std.ArrayList([32]u8) = .empty,
    inventories: usize = 0,

    pub fn init(allocator: std.mem.Allocator, want: rid.RepoId) Collector {
        return .{ .allocator = allocator, .want = want.oid };
    }

    pub fn deinit(self: *Collector) void {
        self.found.deinit(self.allocator);
    }

    pub fn onMessage(self: *Collector, msg: protocol.Message) void {
        const inv = switch (msg) {
            .inventory_announced => |i| i,
            else => return,
        };
        self.inventories += 1;
        for (inv.inventory) |oid| {
            if (!std.mem.eql(u8, &oid, &self.want)) continue;
            self.add(inv.node) catch {};
            break;
        }
    }

    fn add(self: *Collector, node: [32]u8) !void {
        for (self.found.items) |seen| {
            if (std.mem.eql(u8, &seen, &node)) return;
        }
        try self.found.append(self.allocator, node);
    }

    pub fn seeds(self: *const Collector) []const [32]u8 {
        return self.found.items;
    }
};

/// One discovered peer: its node id plus the addresses it advertised. Hosts
/// are copied out of the decode scratch, which the next frame overwrites.
pub const Peer = struct {
    node: [32]u8,
    alias: []u8,
    addrs: [][]u8,
};

/// Watches for both halves of "where can I fetch `want`": the inventory
/// announcements naming who holds it, and the node announcements carrying an
/// address to reach them at. A seed is only usable once both have arrived, and
/// they arrive in no particular order, so this keeps them until they meet.
pub const Locator = struct {
    seeds: Collector,
    peers: PeerCollector,

    pub fn init(allocator: std.mem.Allocator, want: rid.RepoId) Locator {
        return .{
            .seeds = Collector.init(allocator, want),
            .peers = PeerCollector.init(allocator),
        };
    }

    pub fn deinit(self: *Locator) void {
        self.seeds.deinit();
        self.peers.deinit();
    }

    pub fn onMessage(self: *Locator, msg: protocol.Message) void {
        self.seeds.onMessage(msg);
        self.peers.onMessage(msg);
    }

    /// A node that announced `want` and published a dialable address, or null
    /// while nothing has satisfied both. Nodes advertising no address are
    /// skipped: they hold the repo but cannot be reached.
    pub fn located(self: *const Locator) ?Located {
        for (self.seeds.seeds()) |nid| {
            for (self.peers.peers()) |p| {
                if (!std.mem.eql(u8, &p.node, &nid)) continue;
                if (p.addrs.len == 0) continue;
                return .{ .node = nid, .addr = p.addrs[0] };
            }
        }
        return null;
    }
};

/// A seed that both holds the repo and said where to reach it.
pub const Located = struct {
    node: [32]u8,
    /// `host:port`, as `formatAddress` renders it.
    addr: []const u8,
};

/// Collects the nodes seen in NodeAnnouncements, with the addresses each
/// advertises. This is the protocol's only peer-discovery channel: addresses
/// travel in NodeAnnouncement and nowhere else. As with `Collector`, gossip is
/// a replay of what the node has stored, so this observes rather than queries.
pub const PeerCollector = struct {
    allocator: std.mem.Allocator,
    found: std.ArrayList(Peer) = .empty,

    pub fn init(allocator: std.mem.Allocator) PeerCollector {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *PeerCollector) void {
        for (self.found.items) |p| {
            for (p.addrs) |a| self.allocator.free(a);
            self.allocator.free(p.addrs);
            self.allocator.free(p.alias);
        }
        self.found.deinit(self.allocator);
    }

    pub fn onMessage(self: *PeerCollector, msg: protocol.Message) void {
        const ann = switch (msg) {
            .node_announced => |n| n,
            else => return,
        };
        for (self.found.items) |p| {
            if (std.mem.eql(u8, &p.node, &ann.node)) return;
        }
        self.record(ann) catch {};
    }

    fn record(self: *PeerCollector, ann: protocol.NodeAnnounced) !void {
        var addrs: std.ArrayList([]u8) = .empty;
        errdefer {
            for (addrs.items) |a| self.allocator.free(a);
            addrs.deinit(self.allocator);
        }
        for (ann.addresses()) |addr| {
            try addrs.append(self.allocator, try formatAddress(self.allocator, addr));
        }
        const alias = try self.allocator.dupe(u8, ann.alias);
        errdefer self.allocator.free(alias);
        try self.found.append(self.allocator, .{
            .node = ann.node,
            .alias = alias,
            .addrs = try addrs.toOwnedSlice(self.allocator),
        });
    }

    pub fn peers(self: *const PeerCollector) []const Peer {
        return self.found.items;
    }
};

const ONION_B32 = "abcdefghijklmnopqrstuvwxyz234567";

/// Renders a v3 onion service name from its 32-byte Ed25519 public key, which
/// is what the wire carries. The name is base32(key ++ checksum ++ version),
/// so printing the raw key (as hex or otherwise) yields something that is not
/// a dialable address.
/// Source: Tor rend-spec-v3 section 6, "Encoding onion addresses".
fn onionName(key: []const u8, out: *[56]u8) void {
    var h = std.crypto.hash.sha3.Sha3_256.init(.{});
    h.update(".onion checksum");
    h.update(key);
    h.update(&[_]u8{3});
    var digest: [32]u8 = undefined;
    h.final(&digest);

    var raw: [35]u8 = undefined;
    @memcpy(raw[0..32], key);
    raw[32] = digest[0];
    raw[33] = digest[1];
    raw[34] = 3;

    // 35 bytes -> 56 base32 chars, no padding needed (35*8 == 56*5).
    for (out, 0..) |*c, i| {
        const bit = i * 5;
        const byte = bit / 8;
        const shift = bit % 8;
        var v: u16 = @as(u16, raw[byte]) << 8;
        if (byte + 1 < raw.len) v |= raw[byte + 1];
        c.* = ONION_B32[(v >> @intCast(11 - shift)) & 0x1f];
    }
}

/// Renders an address as `host:port`, in the form it would be dialed.
fn formatAddress(allocator: std.mem.Allocator, addr: protocol.Address) ![]u8 {
    return switch (addr.kind) {
        .ipv4 => std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}:{d}", .{
            addr.host[0], addr.host[1], addr.host[2], addr.host[3], addr.port,
        }),
        .ipv6 => std.fmt.allocPrint(allocator, "[{x}]:{d}", .{ addr.host, addr.port }),
        .dns, .i2p => std.fmt.allocPrint(allocator, "{s}:{d}", .{ addr.host, addr.port }),
        .onion => blk: {
            if (addr.host.len != 32) break :blk std.fmt.allocPrint(allocator, "<bad onion>:{d}", .{addr.port});
            var name: [56]u8 = undefined;
            onionName(addr.host, &name);
            break :blk std.fmt.allocPrint(allocator, "{s}.onion:{d}", .{ name, addr.port });
        },
        _ => std.fmt.allocPrint(allocator, "<unknown kind {d}>:{d}", .{ @backingInt(addr.kind), addr.port }),
    };
}

/// The remotes in a local clone: namespaces whose refs are on disk. This
/// answers a different question than gossip does, and needs no network.
pub fn localRemotes(
    io: std.Io,
    gpa: std.mem.Allocator,
    path: []const u8,
) ![][]u8 {
    var repo = try storage.Repository.open(io, gpa, path);
    defer repo.deinit();
    return repo.remotes(gpa);
}

const testing = std.testing;

fn oidOf(b: u8) [20]u8 {
    return @splat(b);
}

test "collects only nodes announcing the wanted rid" {
    const want = rid.RepoId.fromOid(oidOf(1));
    var c = Collector.init(testing.allocator, want);
    defer c.deinit();

    const node_a: [32]u8 = @splat(0xAA);
    const node_b: [32]u8 = @splat(0xBB);

    c.onMessage(.{ .inventory_announced = .{
        .node = node_a,
        .inventory = &.{ oidOf(9), oidOf(1) },
        .timestamp = 0,
    } });
    // Holds other repos, but not the one asked for.
    c.onMessage(.{ .inventory_announced = .{
        .node = node_b,
        .inventory = &.{oidOf(9)},
        .timestamp = 0,
    } });

    try testing.expectEqual(@as(usize, 1), c.seeds().len);
    try testing.expectEqualSlices(u8, &node_a, &c.seeds()[0]);
    try testing.expectEqual(@as(usize, 2), c.inventories);
}

// Nodes re-announce periodically, so the same seed arrives many times in one
// subscribe window. Counting those as distinct seeds would inflate the answer.
test "a node re-announcing is counted once" {
    const want = rid.RepoId.fromOid(oidOf(1));
    var c = Collector.init(testing.allocator, want);
    defer c.deinit();

    const node: [32]u8 = @splat(0xAA);
    const inv: protocol.Message = .{ .inventory_announced = .{
        .node = node,
        .inventory = &.{oidOf(1)},
        .timestamp = 0,
    } };
    c.onMessage(inv);
    c.onMessage(inv);

    try testing.expectEqual(@as(usize, 1), c.seeds().len);
}

fn announcement(node: [32]u8, alias: []const u8, addrs: []const protocol.Address) protocol.Message {
    var ann: protocol.NodeAnnounced = .{
        .node = node,
        .alias = alias,
        .agent = "test",
        .timestamp = 0,
        .addr_count = @intCast(addrs.len),
    };
    for (addrs, 0..) |a, i| ann.addr_storage[i] = a;
    return .{ .node_announced = ann };
}

// The wire carries the 32-byte service key; the dialable name is base32 over
// key ++ checksum ++ version. Vector: the onion iris.radicle.network announces
// over gossip, cross-checked against the address in a node's `connect` config.
test "onion addresses render as their v3 name" {
    var key: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key, "4451288068cc956b128c7e06b4f1c0631d23aaf74d23bccc4c77c4ea748c17a5");

    const got = try formatAddress(testing.allocator, .{ .kind = .onion, .host = &key, .port = 54677 });
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(
        "irisradizskwweumpydlj4oammoshkxxjur3ztcmo7cou5emc6s5lfid.onion:54677",
        got,
    );
}

test "collects peers with their advertised addresses" {
    var c = PeerCollector.init(testing.allocator);
    defer c.deinit();

    c.onMessage(announcement(@splat(0xAA), "one", &.{
        .{ .kind = .dns, .host = "seed.example", .port = 8776 },
        .{ .kind = .ipv4, .host = &.{ 10, 0, 0, 7 }, .port = 8776 },
    }));

    try testing.expectEqual(@as(usize, 1), c.peers().len);
    const p = c.peers()[0];
    try testing.expectEqualStrings("one", p.alias);
    try testing.expectEqual(@as(usize, 2), p.addrs.len);
    try testing.expectEqualStrings("seed.example:8776", p.addrs[0]);
    try testing.expectEqualStrings("10.0.0.7:8776", p.addrs[1]);
}

// Addresses borrow the decode scratch buffer, which the next frame overwrites,
// so a peer that outlives one frame must own its strings.
test "peer addresses survive the frame they arrived in" {
    var c = PeerCollector.init(testing.allocator);
    defer c.deinit();

    var host = "seed.example".*;
    c.onMessage(announcement(@splat(0xAA), "one", &.{
        .{ .kind = .dns, .host = &host, .port = 8776 },
    }));
    @memset(&host, 'x');

    try testing.expectEqualStrings("seed.example:8776", c.peers()[0].addrs[0]);
}

test "a node re-announcing is one peer" {
    var c = PeerCollector.init(testing.allocator);
    defer c.deinit();

    const msg = announcement(@splat(0xAA), "one", &.{
        .{ .kind = .dns, .host = "seed.example", .port = 8776 },
    });
    c.onMessage(msg);
    c.onMessage(msg);

    try testing.expectEqual(@as(usize, 1), c.peers().len);
}

// A seed is usable only when both halves have arrived: the inventory saying
// it holds the repo, and a node announcement saying where to reach it. They
// arrive in either order, so neither alone is enough.
test "locator waits for both the inventory and an address" {
    const want = rid.RepoId.fromOid(oidOf(1));
    var l = Locator.init(testing.allocator, want);
    defer l.deinit();

    const node: [32]u8 = @splat(0xAA);

    // Address first, no inventory yet.
    l.onMessage(announcement(node, "seed", &.{
        .{ .kind = .dns, .host = "seed.example", .port = 8776 },
    }));
    try testing.expectEqual(@as(?Located, null), l.located());

    l.onMessage(.{ .inventory_announced = .{
        .node = node,
        .inventory = &.{oidOf(1)},
        .timestamp = 0,
    } });

    const got = l.located().?;
    try testing.expectEqualSlices(u8, &node, &got.node);
    try testing.expectEqualStrings("seed.example:8776", got.addr);
}

test "locator ignores a holder that published no address" {
    const want = rid.RepoId.fromOid(oidOf(1));
    var l = Locator.init(testing.allocator, want);
    defer l.deinit();

    const node: [32]u8 = @splat(0xAA);
    l.onMessage(announcement(node, "unreachable", &.{}));
    l.onMessage(.{ .inventory_announced = .{
        .node = node,
        .inventory = &.{oidOf(1)},
        .timestamp = 0,
    } });

    try testing.expectEqual(@as(?Located, null), l.located());
}

test "locator ignores a reachable node that lacks the repo" {
    const want = rid.RepoId.fromOid(oidOf(1));
    var l = Locator.init(testing.allocator, want);
    defer l.deinit();

    l.onMessage(announcement(@splat(0xBB), "other", &.{
        .{ .kind = .dns, .host = "other.example", .port = 8776 },
    }));
    l.onMessage(.{ .inventory_announced = .{
        .node = @splat(0xBB),
        .inventory = &.{oidOf(9)},
        .timestamp = 0,
    } });

    try testing.expectEqual(@as(?Located, null), l.located());
}

test "node announcements are not seeds" {
    const want = rid.RepoId.fromOid(oidOf(1));
    var c = Collector.init(testing.allocator, want);
    defer c.deinit();

    c.onMessage(.{ .node_announced = .{
        .node = @splat(0xAA),
        .alias = "a",
        .agent = "b",
        .timestamp = 0,
    } });

    try testing.expectEqual(@as(usize, 0), c.seeds().len);
    try testing.expectEqual(@as(usize, 0), c.inventories);
}
