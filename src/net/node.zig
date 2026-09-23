//! Answering inbound connections: the responder half of the wire.
//!
//! `wire.zig` dials out; this accepts. A session greets the way heartwood's
//! `initial()` does (node announcement, inventory announcement, subscribe),
//! then answers what arrives. It does not yet store gossip or route, so a
//! Subscribe gets the greeting and nothing to replay.
//! Source: radicle-protocol service.rs initial / handle Ping.

const std = @import("std");
const noise = @import("../crypto/noise.zig");
const signature = @import("../crypto/signature.zig");
const pktline = @import("../git/pktline.zig");
const storage = @import("../git/storage.zig");
const rid = @import("../identity/rid.zig");
const protocol = @import("protocol.zig");
const announce = @import("announce.zig");
const upload = @import("upload.zig");

/// What a node needs to answer a peer.
pub const Config = struct {
    /// The node's secret seed; its public half is the node id peers know us by.
    seed: [32]u8,
    alias: []const u8,
    /// Where our repositories live, to serve objects out of.
    store: ?*storage.Storage = null,
    /// The signed inventory frame to greet with, from `inventoryFrame`. Empty
    /// announces nothing, which is what a node holding nothing should say.
    inventory: []const u8 = &.{},
    /// Frames one session will answer before it is dropped.
    max_frames: usize = 1000,
};

/// How long a signed inventory is reused before it is rebuilt with a fresh
/// timestamp. Well inside the day a peer waits before evicting us.
/// Source: RIP-0001 Pruning.
pub const INVENTORY_REFRESH_MS: u64 = 60 * 60 * 1000;

/// A signed inventory announcement and how many repositories it names.
pub const Inventory = struct {
    /// The gossip frame, caller-owned.
    frame: []u8,
    count: usize,
};

/// Signs the inventory announcement a node greets peers with; caller owns the
/// frame. An empty inventory signs to a frame like any other, since the
/// message states a node's whole inventory and so retracts an earlier one.
/// Rebuild on `INVENTORY_REFRESH_MS`, not per session.
/// Source: RIP-0001 Inventory Announcements, Pruning.
pub fn inventoryFrame(
    allocator: std.mem.Allocator,
    store: *storage.Storage,
    seed: [32]u8,
    now_ms: u64,
) !Inventory {
    const ids = try store.inventory(allocator);
    defer allocator.free(ids);

    const oids = try allocator.alloc([20]u8, ids.len);
    defer allocator.free(oids);
    for (ids, oids) |id, *oid| oid.* = id.oid;

    var msg_buf: std.ArrayList(u8) = .empty;
    defer msg_buf.deinit(allocator);
    const signed = try announce.sign(allocator, announce.InventoryAnnouncement{
        .inventory = oids,
        .timestamp = now_ms,
    }, try signature.SecretKey.fromSeed(seed), &msg_buf);
    return .{ .frame = try signed.encodeFrame(allocator), .count = ids.len };
}

/// What a session did, for the caller to report. Counting rather than logging
/// keeps this testable without capturing output.
pub const SessionStats = struct {
    frames: usize = 0,
    pings: usize = 0,
    subscribes: usize = 0,
    announcements: usize = 0,
    /// Fetches served, and fetches we refused to serve.
    fetches: usize = 0,
    refused: usize = 0,
};

/// Drives one already-handshaked session to completion: sends the greeting,
/// then answers frames until the peer goes away or `max_frames` is reached.
/// Split from the socket loop so it runs off in-memory buffers.
pub fn serveOver(
    allocator: std.mem.Allocator,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    cfg: Config,
    now_ms: u64,
) !SessionStats {
    try greet(allocator, w, cfg, now_ms);

    var stats: SessionStats = .{};
    var scratch: [protocol.MAX_FRAME_PAYLOAD]u8 = undefined;
    var oids: [protocol.INVENTORY_LIMIT][20]u8 = undefined;

    var held: Held = .{};
    defer held.deinit(allocator);
    // A refusal is told once per stream.
    var refused: ?u64 = null;

    while (stats.frames < cfg.max_frames) : (stats.frames += 1) {
        const frame = protocol.readRawFrame(r, &scratch) catch |e| switch (e) {
            error.EndOfStream => break,
            // A peer that sends us garbage is not worth staying connected to,
            // which is what heartwood does with "peer misbehaved".
            else => return e,
        };
        switch (frame) {
            .gossip => |payload| {
                const msg = protocol.decodeMessage(payload, &oids) catch continue;
                switch (msg) {
                    .ping => |p| {
                        stats.pings += 1;
                        try pong(allocator, w, p.ponglen);
                    },
                    .node_announced, .inventory_announced => stats.announcements += 1,
                    .other => |t| {
                        if (t == .subscribe) stats.subscribes += 1;
                    },
                    .pong => {},
                }
            },
            // The whole fetch runs inside this arm: `upload` reads the frames
            // that follow off the same socket.
            .git => |g| {
                if (refused) |id| if (id == g.stream.value) continue;
                if (!try fetchFor(allocator, r, w, cfg, g, &held, &stats)) {
                    refused = g.stream.value;
                }
            },
            // `open` needs no answer: the stream exists once a frame names it.
            .control, .unknown => {},
        }
    }
    return stats;
}

/// What storage holds, read once per session rather than per frame.
const Held = struct {
    ids: ?[]rid.RepoId = null,

    fn of(self: *Held, gpa: std.mem.Allocator, store: *storage.Storage) ![]rid.RepoId {
        if (self.ids) |ids| return ids;
        self.ids = try store.inventory(gpa);
        return self.ids.?;
    }

    fn deinit(self: *Held, gpa: std.mem.Allocator) void {
        if (self.ids) |ids| gpa.free(ids);
    }
};

/// Answers one inbound fetch, or refuses it with an ERR pkt-line rather than a
/// dropped connection. False when it was refused.
fn fetchFor(
    allocator: std.mem.Allocator,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    cfg: Config,
    frame: anytype,
    held: *Held,
    stats: *SessionStats,
) !bool {
    const repo = openRequested(allocator, cfg, held, frame.payload) catch |e| {
        stats.refused += 1;
        try refuse(allocator, w, frame.stream, @errorName(e));
        return false;
    };
    defer repo.deinit();

    stats.fetches += 1;
    upload.serve(allocator, r, w, frame.stream, repo) catch |e| switch (e) {
        // The peer hanging up mid-fetch ends the fetch, not the session.
        error.EndOfStream => {},
        else => return e,
    };
    return true;
}

/// The repository the intro line names, if it is one we announce. heartwood
/// asks its policies the same question at the same point.
/// Source: radicle-node worker.rs, `is_authorized`.
fn openRequested(
    allocator: std.mem.Allocator,
    cfg: Config,
    held: *Held,
    intro: []const u8,
) !*storage.Repository {
    const store = cfg.store orelse return error.NoStorage;
    const req = try protocol.parseGitUploadPackLine(intro);
    if (!req.version_2) return error.ProtocolVersionUnsupported;

    const id = try rid.RepoId.parse(req.rid);
    for (try held.of(allocator, store)) |h| {
        if (std.mem.eql(u8, &h.oid, &id.oid)) return store.repository(allocator, id);
    }
    return error.RepositoryNotFound;
}

/// Tells the peer why it gets nothing, in the one shape a git client reads as
/// a refusal, and framed the way it would have read the advertisement.
fn refuse(
    allocator: std.mem.Allocator,
    w: *std.Io.Writer,
    stream: protocol.StreamId,
    message: []const u8,
) !void {
    var line: [128]u8 = undefined;
    const text = std.fmt.bufPrint(&line, "ERR {s}\n", .{message}) catch return;

    var buf: [160]u8 = undefined;
    const pkt = try pktline.bufWrite(&buf, text);
    const out = try protocol.encodeGitFrame(allocator, stream, pkt);
    defer allocator.free(out);
    try w.writeAll(out);
    try w.flush();
}

/// Binds `port` and serves inbound connections one at a time, until
/// `max_sessions` have been handled. Owns the inventory frame that every
/// greeting sends, rebuilding it when it goes stale rather than per session.
pub fn listen(
    io: std.Io,
    allocator: std.mem.Allocator,
    port: u16,
    config: Config,
    max_sessions: usize,
    handler: anytype,
) !usize {
    const addr = try std.Io.net.IpAddress.resolve(io, "0.0.0.0", port);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);

    var cfg = config;
    // Ours to free; `config.inventory` is the caller's and is only read.
    var owned: ?[]u8 = null;
    defer if (owned) |frame| allocator.free(frame);
    // Silent until we hold something; after that, empty retracts.
    var announced = cfg.inventory.len > 0;
    var signed_at_ms: u64 = 0;

    var served: usize = 0;
    while (served < max_sessions) : (served += 1) {
        var stream = server.accept(io) catch |e| switch (e) {
            error.ConnectionAborted => continue,
            else => return e,
        };
        defer stream.close(io);

        if (cfg.store) |store| refresh: {
            const now_ms: u64 = @intCast(@divTrunc(std.Io.Clock.now(.real, io).nanoseconds, std.time.ns_per_ms));
            if (now_ms -| signed_at_ms < INVENTORY_REFRESH_MS) break :refresh;

            // Before the attempt, so a root we cannot read is not rescanned
            // per connection.
            signed_at_ms = now_ms;

            // The frame we already hold is still true, so a failed rescan is
            // not a reason to drop the peer we just accepted.
            const inv = inventoryFrame(allocator, store, cfg.seed, now_ms) catch |e| {
                handler.onRefreshFailed(e);
                break :refresh;
            };

            if (owned) |frame| allocator.free(frame);
            owned = inv.frame;
            announced = announced or inv.count > 0;
            cfg.inventory = if (announced) inv.frame else &.{};
        }

        const stats = accept(io, allocator, &stream, cfg) catch |e| {
            handler.onSessionFailed(e);
            continue;
        };
        handler.onSession(stats);
    }
    return served;
}

/// Completes the responder handshake on `stream`, then serves the session.
fn accept(
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: *std.Io.net.Stream,
    cfg: Config,
) !SessionStats {
    const key = try signature.SecretKey.fromSeed(cfg.seed);
    var eph_seed: [32]u8 = undefined;
    try io.randomSecure(&eph_seed);
    const ephemeral = try noise.KeyPair.generateDeterministic(eph_seed);
    // noise.KeyPair carries the seed as its secret, matching how the initiator
    // builds one; the node id is the Ed25519 public key over that seed.
    const static: noise.KeyPair = .{ .secret_key = cfg.seed, .public_key = key.nodeId().key };
    var res = noise.Responder.init(static, ephemeral);

    var wbuf: [4096]u8 = undefined;
    var rbuf: [protocol.MAX_FRAME_PAYLOAD]u8 = undefined;
    var sw = stream.writer(io, &wbuf);
    var sr = stream.reader(io, &rbuf);
    const w = &sw.interface;
    const r = &sr.interface;

    // XK: read `e, es` (32), write `e, ee` (32), read `s, se` (48: a 32-byte
    // static key plus its 16-byte tag, then an empty encrypted payload). The
    // peer's static key falls out of message 3, which is how we learn who
    // dialed us.
    var msg: [128]u8 = undefined;
    try r.readSliceAll(msg[0..noise.MSG1_LEN]);
    try res.readMsg1(msg[0..noise.MSG1_LEN]);

    const n2 = res.writeMsg2(&msg);
    try w.writeAll(msg[0..n2]);
    try w.flush();

    try r.readSliceAll(msg[0..noise.MSG3_LEN]);
    _ = try res.readMsg3(msg[0..noise.MSG3_LEN]);
    _ = res.split();

    const now_ms: u64 = @intCast(@divTrunc(std.Io.Clock.now(.real, io).nanoseconds, std.time.ns_per_ms));
    return serveOver(allocator, r, w, cfg, now_ms);
}

/// The three messages heartwood sends on every new connection.
fn greet(
    allocator: std.mem.Allocator,
    w: *std.Io.Writer,
    cfg: Config,
    now_ms: u64,
) !void {
    const key = try signature.SecretKey.fromSeed(cfg.seed);

    var msg_buf: std.ArrayList(u8) = .empty;
    defer msg_buf.deinit(allocator);
    const signed = try announce.sign(allocator, announce.NodeAnnouncement{
        .timestamp = now_ms,
        .alias = cfg.alias,
    }, key, &msg_buf);
    const ann = try signed.encodeFrame(allocator);
    defer allocator.free(ann);
    try w.writeAll(ann);

    // The same bytes for every peer, so our inventory does not churn through
    // the network under a new timestamp per connection.
    if (cfg.inventory.len > 0) try w.writeAll(cfg.inventory);

    const sub = &protocol.subscribe_all_frame;
    try w.writeAll(sub);
    try w.flush();
}

/// Answers a Ping. A request for more zeroes than a Pong can carry is ignored
/// rather than honoured, which is what heartwood does with it.
/// Source: radicle-protocol service.rs, `handle_message` Ping.
fn pong(allocator: std.mem.Allocator, w: *std.Io.Writer, ponglen: u16) !void {
    if (ponglen > protocol.MAX_PONG_ZEROES) return;
    const frame = try protocol.encodePongFrame(allocator, ponglen);
    defer allocator.free(frame);
    try w.writeAll(frame);
    try w.flush();
}

const testing = std.testing;

fn testConfig() Config {
    return .{ .seed = @splat(7), .alias = "radish", .max_frames = 10 };
}

test "greets with a signed announcement and a subscribe" {
    var out: [8192]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    var r = std.Io.Reader.fixed(&.{});

    const stats = try serveOver(testing.allocator, &r, &w, testConfig(), 1);
    try testing.expectEqual(@as(usize, 0), stats.frames);

    // Both frames are on the gossip stream and decode cleanly.
    var sent = std.Io.Reader.fixed(w.buffered());
    var scratch: [protocol.MAX_FRAME_PAYLOAD]u8 = undefined;
    var oids: [8][20]u8 = undefined;
    const first = try protocol.decodeFrameStreaming(&sent, &scratch, &oids);
    try testing.expectEqualStrings("radish", first.node_announced.alias);
    const second = try protocol.decodeFrameStreaming(&sent, &scratch, &oids);
    try testing.expectEqual(protocol.MessageType.subscribe, second.other);
}

// A node that does not answer pings is dropped as unresponsive after
// STALE_CONNECTION_TIMEOUT, so a pong is what keeps a session alive. A ponglen
// above MAX_PONG_ZEROES cannot be encoded as a Pong at all, so answering that
// one would mean sending a malformed frame.
test "answers a ping with a matching pong, but ignores one asking for too many zeroes" {
    var scratch: [protocol.MAX_FRAME_PAYLOAD]u8 = undefined;
    var oids: [8][20]u8 = undefined;

    for ([_]u16{ 4, protocol.MAX_PONG_ZEROES + 1 }) |ponglen| {
        var out: [8192]u8 = undefined;
        var w = std.Io.Writer.fixed(&out);

        const ping = try protocol.encodePingFrame(testing.allocator, .{ .ponglen = ponglen, .zeroes = 0 });
        defer testing.allocator.free(ping);
        var r = std.Io.Reader.fixed(ping);

        const stats = try serveOver(testing.allocator, &r, &w, testConfig(), 1);
        try testing.expectEqual(@as(usize, 1), stats.pings);

        // Skip the greeting, then look for a reply behind it.
        var sent = std.Io.Reader.fixed(w.buffered());
        _ = try protocol.decodeFrameStreaming(&sent, &scratch, &oids);
        _ = try protocol.decodeFrameStreaming(&sent, &scratch, &oids);
        if (ponglen <= protocol.MAX_PONG_ZEROES) {
            const reply = try protocol.decodeFrameStreaming(&sent, &scratch, &oids);
            try testing.expectEqual(ponglen, reply.pong.zeroes);
        } else {
            try testing.expectError(error.EndOfStream, protocol.decodeFrameStreaming(&sent, &scratch, &oids));
        }
    }
}

test "counts a peer's subscribe" {
    var out: [16384]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);

    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    const sub = &protocol.subscribe_all_frame;
    try input.appendSlice(testing.allocator, sub);

    var r = std.Io.Reader.fixed(input.items);
    const stats = try serveOver(testing.allocator, &r, &w, testConfig(), 1);
    try testing.expectEqual(@as(usize, 1), stats.subscribes);
    try testing.expectEqual(@as(usize, 1), stats.frames);
}

/// A directory `Storage` will count: named for a RID, holding both halves of
/// a pack.
fn fakeRepo(dir: std.Io.Dir, name: []const u8) !void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    try dir.createDirPath(testing.io, try std.fmt.bufPrint(&buf, "{s}/objects/pack", .{name}));
    for ([_][]const u8{ "pack", "idx" }) |ext| {
        const path = try std.fmt.bufPrint(&buf, "{s}/objects/pack/pack-fixture.{s}", .{ name, ext });
        (try dir.createFile(testing.io, path, .{})).close(testing.io);
    }
}

// The greeting claims what we hold, and a peer can check the claim: the frame
// verifies under our own key.
test "the greeting carries a signed inventory of what storage holds" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = path_buf[0..try tmp.dir.realPath(testing.io, &path_buf)];

    var store = try storage.Storage.open(testing.io, gpa, root);
    defer store.deinit();

    // An empty root still signs to a frame; `listen` is what decides that one
    // naming nothing is silence rather than a retraction.
    const empty = try inventoryFrame(gpa, &store, testConfig().seed, 1);
    defer gpa.free(empty.frame);
    try testing.expectEqual(@as(usize, 0), empty.count);

    try fakeRepo(tmp.dir, "z42hL2jL4XNk6K8oHQaSWfMgCL7ji");
    const inv = try inventoryFrame(gpa, &store, testConfig().seed, 1);
    defer gpa.free(inv.frame);
    try testing.expectEqual(@as(usize, 1), inv.count);

    var cfg = testConfig();
    cfg.store = &store;
    cfg.inventory = inv.frame;

    var out: [8192]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    var r = std.Io.Reader.fixed(&.{});
    _ = try serveOver(gpa, &r, &w, cfg, 1);

    var sent = std.Io.Reader.fixed(w.buffered());
    var scratch: [protocol.MAX_FRAME_PAYLOAD]u8 = undefined;
    var oids: [8][20]u8 = undefined;
    _ = try protocol.decodeFrameStreaming(&sent, &scratch, &oids); // node announcement
    const second = try protocol.decodeFrameStreaming(&sent, &scratch, &oids);
    try testing.expectEqual(@as(usize, 1), second.inventory_announced.inventory.len);
    try testing.expect(second.inventory_announced.verified());
}

// Peers keep the newest announcement and relay it, so an unchanged inventory
// must sign to the identical frame, or every connection puts a new message on
// the network for no change. Moving the clock is the refresh that keeps us
// from expiring out of their tables, and that must produce different bytes.
test "an unchanged inventory re-signs identically until its timestamp moves" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = path_buf[0..try tmp.dir.realPath(testing.io, &path_buf)];

    try fakeRepo(tmp.dir, "z42hL2jL4XNk6K8oHQaSWfMgCL7ji");

    var store = try storage.Storage.open(testing.io, gpa, root);
    defer store.deinit();

    const a = (try inventoryFrame(gpa, &store, testConfig().seed, 1000)).frame;
    defer gpa.free(a);
    const b = (try inventoryFrame(gpa, &store, testConfig().seed, 1000)).frame;
    defer gpa.free(b);
    const later = (try inventoryFrame(gpa, &store, testConfig().seed, 2000)).frame;
    defer gpa.free(later);

    try testing.expectEqualSlices(u8, a, b);
    try testing.expect(!std.mem.eql(u8, a, later));
}
