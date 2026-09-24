//! Integration tests for `node.zig` that need a storage root on disk. The
//! in-memory session tests stay in node.zig itself.
const std = @import("std");
const fixture = @import("../testfixture.zig");
const storage = @import("../git/storage.zig");
const node = @import("node.zig");
const protocol = @import("protocol.zig");

const testing = std.testing;
const alloc = testing.allocator;

fn testConfig() node.Config {
    return .{ .seed = @splat(7), .alias = "radish", .max_frames = 10 };
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
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = path_buf[0..try tmp.dir.realPath(testing.io, &path_buf)];

    var store = try storage.Storage.open(testing.io, alloc, root);
    defer store.deinit();

    // An empty root still signs to a frame; `listen` is what decides that one
    // naming nothing is silence rather than a retraction.
    const empty = try node.inventoryFrame(alloc, &store, testConfig().seed, 1);
    defer alloc.free(empty.frame);
    try testing.expectEqual(@as(usize, 0), empty.count);

    const nid = try fixture.nidForSeed(alloc, 7);
    defer alloc.free(nid);
    const doc_bytes = try fixture.identityDoc(alloc, nid, false);
    defer alloc.free(doc_bytes);
    const seeded = try fixture.seedRepo(alloc, root, doc_bytes);
    defer alloc.free(seeded);

    const inv = try node.inventoryFrame(alloc, &store, testConfig().seed, 1);
    defer alloc.free(inv.frame);
    try testing.expectEqual(@as(usize, 1), inv.count);

    var cfg = testConfig();
    cfg.store = &store;
    cfg.inventory = inv.frame;

    var out: [8192]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    var r = std.Io.Reader.fixed(&.{});
    _ = try node.serveOver(alloc, &r, &w, cfg, 1);

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
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = path_buf[0..try tmp.dir.realPath(testing.io, &path_buf)];

    try fakeRepo(tmp.dir, "z42hL2jL4XNk6K8oHQaSWfMgCL7ji");

    var store = try storage.Storage.open(testing.io, alloc, root);
    defer store.deinit();

    const a = (try node.inventoryFrame(alloc, &store, testConfig().seed, 1000)).frame;
    defer alloc.free(a);
    const b = (try node.inventoryFrame(alloc, &store, testConfig().seed, 1000)).frame;
    defer alloc.free(b);
    const later = (try node.inventoryFrame(alloc, &store, testConfig().seed, 2000)).frame;
    defer alloc.free(later);

    try testing.expectEqualSlices(u8, a, b);
    try testing.expect(!std.mem.eql(u8, a, later));
}
