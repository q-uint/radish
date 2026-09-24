//! A fetch as a peer drives one: radicle frames in, radicle frames out, with
//! `node.serveOver` demultiplexing and `upload.zig` bridging the git bytes.
//! The request bytes are the ones `fetch.zig` would put on the wire, so the
//! two halves are tested against each other.
const std = @import("std");
const fixture = @import("../testfixture.zig");
const pktline = @import("../git/pktline.zig");
const storage = @import("../git/storage.zig");
const rid = @import("../identity/rid.zig");
const node = @import("node.zig");
const protocol = @import("protocol.zig");

const testing = std.testing;
const alloc = testing.allocator;

/// The stream a real fetch opens, which is what the answer has to come back on.
const GIT_STREAM = protocol.StreamId.git_out.nth(1);

const DOC = "{\"payload\":{\"xyz.radicle.project\":{\"defaultBranch\":\"main\"," ++
    "\"description\":\"d\",\"name\":\"n\"}},\"delegates\":[\"did:key:" ++
    "z6MkireRatUThvd3qzfKht1S44wpm4FEWSSa4PRMTSQZ3voM\"],\"threshold\":1}";

/// A storage root holding one fixture repository, named by its RID the way
/// `Storage` expects to find it. Returns the RID and the commit at `refs/rad/id`.
const Held = struct { id: rid.RepoId, root: []const u8, tip: []const u8 };

fn holding(s: *fixture.Scratch) !Held {
    const tip = try s.repo.commit("main", "embeds/radicle.json", DOC);
    try s.repo.radId(tip);
    const bare = try s.repo.finish();

    const id = rid.RepoId.fromDoc(DOC);
    const name = try id.encodeBare(alloc);
    defer alloc.free(name);

    const parent = std.fs.path.dirname(bare).?;
    var dir = try std.Io.Dir.cwd().openDir(testing.io, parent, .{});
    defer dir.close(testing.io);
    try dir.rename(std.fs.path.basename(bare), dir, name, testing.io);

    return .{ .id = id, .root = parent, .tip = tip };
}

/// The frames a fetching peer sends: the stream opens, the intro names the
/// repository, and each git request rides in its own frame.
fn requestFrames(id: rid.RepoId, parts: []const []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);

    const open = try protocol.encodeControlFrame(alloc, .open, GIT_STREAM);
    defer alloc.free(open);
    try out.appendSlice(alloc, open);

    const name = try id.encodeBare(alloc);
    defer alloc.free(name);
    const intro = try protocol.gitUploadPackLine(alloc, name);
    defer alloc.free(intro);
    try appendGit(&out, intro);

    for (parts) |p| try appendGit(&out, p);
    return out.toOwnedSlice(alloc);
}

fn appendGit(out: *std.ArrayList(u8), payload: []const u8) !void {
    const frame = try protocol.encodeGitFrame(alloc, GIT_STREAM, payload);
    defer alloc.free(frame);
    try out.appendSlice(alloc, frame);
}

/// One pkt-line, or a flush for the empty string.
fn pkt(out: *std.ArrayList(u8), payload: []const u8) !void {
    if (payload.len == 0) return out.appendSlice(alloc, pktline.Marker.flush.wire());
    var buf: [256]u8 = undefined;
    try out.appendSlice(alloc, try pktline.bufWrite(&buf, payload));
}

/// What one session answered: `git` is every git byte it sent, unframed.
const Answer = struct {
    stats: node.SessionStats,
    git: []u8,

    fn deinit(self: Answer) void {
        alloc.free(self.git);
    }
};

/// Serves `frames` out of the storage at `root`, as `listen` would once the
/// handshake is behind it.
fn answer(root: []const u8, frames: []const u8) !Answer {
    var store = try storage.Storage.open(testing.io, alloc, root);
    defer store.deinit();

    // Off the stack: a pack of any size lands in here.
    const out = try alloc.alloc(u8, 1 << 20);
    defer alloc.free(out);
    var w = std.Io.Writer.fixed(out);
    var r = std.Io.Reader.fixed(frames);

    const cfg: node.Config = .{
        .seed = @splat(7),
        .alias = "radish",
        .max_frames = 10,
        .store = &store,
    };
    return .{
        .stats = try node.serveOver(alloc, &r, &w, cfg, 1),
        .git = try gitBytes(w.buffered()),
    };
}

/// Every git byte the server sent back, unframed, in order. Frames that are
/// not the git stream's (the greeting is three of them) are dropped.
fn gitBytes(raw: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);

    var r = std.Io.Reader.fixed(raw);
    var scratch: [protocol.MAX_FRAME_PAYLOAD]u8 = undefined;
    while (true) {
        const frame = protocol.readRawFrame(&r, &scratch) catch break;
        switch (frame) {
            .git => |g| try out.appendSlice(alloc, g.payload),
            else => {},
        }
    }
    return out.toOwnedSlice(alloc);
}

test "a peer's fetch is answered on its own git stream" {
    const s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);
    const held = try holding(s);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(alloc);
    try pkt(&body, "command=ls-refs\n");
    try pkt(&body, "object-format=sha1\n");
    try body.appendSlice(alloc, pktline.Marker.delim.wire());
    try pkt(&body, "ref-prefix refs/rad/id\n");
    try pkt(&body, "");

    var want: [64]u8 = undefined;
    try pkt(&body, "command=fetch\n");
    try body.appendSlice(alloc, pktline.Marker.delim.wire());
    try pkt(&body, try std.fmt.bufPrint(&want, "want {s}\n", .{held.tip}));
    try pkt(&body, "done\n");
    try pkt(&body, "");
    // Nothing more to ask, which is how a v2 conversation ends.
    try pkt(&body, "");

    const frames = try requestFrames(held.id, &.{body.items});
    defer alloc.free(frames);

    const got = try answer(held.root, frames);
    defer got.deinit();
    try testing.expectEqual(@as(usize, 1), got.stats.fetches);
    try testing.expectEqual(@as(usize, 0), got.stats.refused);

    // The advertisement, the ref the prefix asked for, and a pack behind the
    // packfile header: a fetch answered, not merely a stream accepted.
    try testing.expect(std.mem.indexOf(u8, got.git, "version 2\n") != null);
    try testing.expect(std.mem.indexOf(u8, got.git, "refs/rad/id\n") != null);
    try testing.expect(std.mem.indexOf(u8, got.git, "packfile\n") != null);
    try testing.expect(std.mem.indexOf(u8, got.git, "\x01PACK") != null);
    try testing.expect(std.mem.indexOf(u8, got.git, held.tip) != null);
}

// Holding a private repository must look exactly like not holding it. If the
// two refusals differ in any byte, the difference confirms the repository
// exists, which is the one thing its owner asked us not to say.
test "a private repository is refused indistinguishably from an absent one" {
    const s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);

    const nid = try fixture.nidForSeed(alloc, 9);
    defer alloc.free(nid);
    const private_doc = try fixture.identityDoc(alloc, nid, true);
    defer alloc.free(private_doc);

    const tip = try s.repo.commit("main", "embeds/radicle.json", private_doc);
    try s.repo.radId(tip);
    const bare = try s.repo.finish();

    const held = rid.RepoId.fromDoc(private_doc);
    const name = try held.encodeBare(alloc);
    defer alloc.free(name);
    const parent = std.fs.path.dirname(bare).?;
    var dir = try std.Io.Dir.cwd().openDir(testing.io, parent, .{});
    defer dir.close(testing.io);
    try dir.rename(std.fs.path.basename(bare), dir, name, testing.io);

    const private_frames = try requestFrames(held, &.{});
    defer alloc.free(private_frames);
    const private_answer = try answer(parent, private_frames);
    defer private_answer.deinit();

    // A RID of a repository this root has never held.
    const absent = try rid.RepoId.parse("rad:z42hL2jL4XNk6K8oHQaSWfMgCL7ji");
    const absent_frames = try requestFrames(absent, &.{});
    defer alloc.free(absent_frames);
    const absent_answer = try answer(parent, absent_frames);
    defer absent_answer.deinit();

    try testing.expectEqual(@as(usize, 0), private_answer.stats.fetches);
    try testing.expectEqual(@as(usize, 1), private_answer.stats.refused);
    try testing.expectEqualSlices(u8, absent_answer.git, private_answer.git);
    try testing.expectEqual(absent_answer.stats, private_answer.stats);
}

// A repository we do not announce is not one a peer gets to name: the
// inventory is the whole of what we have said we serve.
test "a fetch for an unannounced repository is refused, not served" {
    const s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);
    const held = try holding(s);

    // Same shape of request, a different repository.
    const other = try rid.RepoId.parse("rad:z42hL2jL4XNk6K8oHQaSWfMgCL7ji");
    const frames = try requestFrames(other, &.{});
    defer alloc.free(frames);

    const got = try answer(held.root, frames);
    defer got.deinit();
    try testing.expectEqual(@as(usize, 0), got.stats.fetches);
    try testing.expectEqual(@as(usize, 1), got.stats.refused);
    try testing.expect(std.mem.indexOf(u8, got.git, "ERR RepositoryNotFound") != null);
}
