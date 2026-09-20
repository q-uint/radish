//! Integration tests for `uploadpack.zig`. Requests go in as the bytes our own
//! client in `protocol.zig` would send, and the packfile that comes back is
//! handed to real `git` to index.
const std = @import("std");
const gitpack = @import("gitpack");
const pktline = @import("pktline.zig");
const storage = @import("storage.zig");
const uploadpack = @import("uploadpack.zig");
const fixture = @import("testfixture.zig");

const testing = std.testing;
const alloc = testing.allocator;

/// The pkt-lines a client sends, concatenated. Caller owns the result.
fn request(parts: []const []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    for (parts) |p| {
        if (p.len == 0) {
            try out.appendSlice(alloc, pktline.Marker.flush.wire());
        } else if (std.mem.eql(u8, p, "\x01")) {
            try out.appendSlice(alloc, pktline.Marker.delim.wire());
        } else {
            var head: [4]u8 = undefined;
            _ = try std.fmt.bufPrint(&head, "{x:0>4}", .{p.len + 4});
            try out.appendSlice(alloc, &head);
            try out.appendSlice(alloc, p);
        }
    }
    return out.toOwnedSlice(alloc);
}

/// Every pkt-line the server wrote, in order. Data slices borrow `raw`.
fn responses(raw: []const u8) ![]pktline.Line {
    var out: std.ArrayList(pktline.Line) = .empty;
    errdefer out.deinit(alloc);
    var rest = raw;
    while (rest.len >= 4) {
        const r = try pktline.parse(rest);
        try out.append(alloc, r.line);
        rest = rest[r.consumed..];
    }
    return out.toOwnedSlice(alloc);
}

const Served = struct {
    raw: []u8,
    lines: []pktline.Line,

    fn deinit(self: *Served) void {
        alloc.free(self.lines);
        alloc.free(self.raw);
    }

    /// The payloads after the capability advertisement, which every
    /// conversation opens with and no test is about.
    fn body(self: *const Served) []pktline.Line {
        for (self.lines, 0..) |line, i| {
            if (line == .marker and line.marker == .flush) return self.lines[i + 1 ..];
        }
        return &.{};
    }
};

fn serve(repo: *storage.Repository, req: []const u8) !Served {
    var r = std.Io.Reader.fixed(req);
    var buf: [1 << 20]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try uploadpack.serve(alloc, &r, &w, repo);

    const raw = try alloc.dupe(u8, w.buffered());
    errdefer alloc.free(raw);
    return .{ .raw = raw, .lines = try responses(raw) };
}

fn openFixture(s: *fixture.Scratch) !*storage.Repository {
    const bare = try s.repo.finish();
    return storage.Repository.open(testing.io, alloc, bare);
}

const NID = "z6Mkrqyt3CCmZxNWAa4ZLm6esfuNqiCRyX6paGVMdvP14J7a";

/// Reassembles the sideband pack out of a response, writes it beside the
/// fixture and lets git judge it. Returns how many objects git found.
fn indexed(s: *fixture.Scratch, name: []const u8, got: *const Served) !usize {
    const body = got.body();
    try testing.expectEqualStrings("packfile\n", body[0].data);

    var packfile: std.ArrayList(u8) = .empty;
    defer packfile.deinit(alloc);
    for (body[1..]) |line| {
        if (line != .data) continue;
        try testing.expectEqual(@as(u8, 1), line.data[0]);
        try packfile.appendSlice(alloc, line.data[1..]);
    }

    const path = try std.fmt.allocPrint(alloc, "{s}/{s}", .{ s.repo.root, name });
    defer alloc.free(path);
    try std.Io.Dir.cwd().writeFile(testing.io, .{ .sub_path = path, .data = packfile.items });
    return fixture.indexPack(alloc, path);
}

test "ls-refs advertises every ref, or only those under a prefix a peer named" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);
    const head = try s.repo.commit("main", "a.txt", "one\n");
    try s.repo.radId(head);
    try s.repo.namespaceRef(NID, "refs/heads/main", head);

    var repo = try openFixture(s);
    defer repo.deinit();

    // No prefix means everything, which for a radicle fetch is the point: the
    // namespaces are where every remote's work lives.
    const all = try request(&.{ "command=ls-refs\n", "\x01", "" });
    defer alloc.free(all);
    var every = try serve(repo, all);
    defer every.deinit();

    var names: std.ArrayList([]const u8) = .empty;
    defer names.deinit(alloc);
    for (every.body()) |line| {
        if (line != .data) continue;
        try names.append(alloc, std.mem.trimEnd(u8, line.data, "\n")[41..]);
    }
    try testing.expectEqual(@as(usize, 2), names.items.len);
    try testing.expectEqualStrings("refs/namespaces/" ++ NID ++ "/refs/heads/main", names.items[0]);
    try testing.expectEqualStrings("refs/rad/id", names.items[1]);

    const under = try request(&.{ "command=ls-refs\n", "\x01", "ref-prefix refs/rad/\n", "" });
    defer alloc.free(under);
    var some = try serve(repo, under);
    defer some.deinit();

    const body = some.body();
    try testing.expectEqual(@as(usize, 2), body.len); // one ref, then flush
    const expected = try std.fmt.allocPrint(alloc, "{s} refs/rad/id\n", .{head});
    defer alloc.free(expected);
    try testing.expectEqualStrings(expected, body[0].data);
}

test "fetch sends a packfile git can index, and a have narrows it" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);
    const base = try s.repo.commit("main", "a.txt", "one\n");
    const head = try s.repo.commit("main", "b.txt", "two\n");

    var repo = try openFixture(s);
    defer repo.deinit();

    const want = try std.fmt.allocPrint(alloc, "want {s}\n", .{head});
    defer alloc.free(want);
    const have = try std.fmt.allocPrint(alloc, "have {s}\n", .{base});
    defer alloc.free(have);

    const asked = try request(&.{ "command=fetch\n", "\x01", want, "done\n", "" });
    defer alloc.free(asked);
    const narrower = try request(&.{ "command=fetch\n", "\x01", want, have, "done\n", "" });
    defer alloc.free(narrower);

    var full = try serve(repo, asked);
    defer full.deinit();
    var narrowed = try serve(repo, narrower);
    defer narrowed.deinit();

    // A peer that has the base already is not sent it again, which is the
    // whole point of reading its have lines. Both packs still stand on their
    // own, which only real git can say.
    try testing.expect(narrowed.raw.len < full.raw.len);
    try testing.expect(try indexed(s, "full.pack", &full) > 0);
    try testing.expect(try indexed(s, "narrowed.pack", &narrowed) > 0);
}

// Without `done` the peer is still negotiating, so it gets told what we have
// in common rather than a pack it did not finish asking for. The round must
// end there: saying `ready` would promise a packfile in this same response,
// and a peer that heard it would read on for one.
test "fetch without done ends after acknowledgements, promising nothing" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);
    const head = try s.repo.commit("main", "a.txt", "one\n");

    var repo = try openFixture(s);
    defer repo.deinit();

    const want = try std.fmt.allocPrint(alloc, "want {s}\n", .{head});
    defer alloc.free(want);
    const have = try std.fmt.allocPrint(alloc, "have {s}\n", .{head});
    defer alloc.free(have);

    const req = try request(&.{ "command=fetch\n", "\x01", want, have, "" });
    defer alloc.free(req);
    var got = try serve(repo, req);
    defer got.deinit();

    const body = got.body();
    try testing.expectEqualStrings("acknowledgments\n", body[0].data);
    try testing.expect(std.mem.startsWith(u8, body[1].data, "ACK "));
    // The ACK, then the flush that closes the round, and nothing after it.
    try testing.expectEqual(@as(usize, 3), body.len);
    try testing.expectEqual(pktline.Marker.flush, body[2].marker);
}

// Each is decided before a byte of answer is written, so the peer gets a word
// rather than a connection that closes on it without one. The last is the
// exception: a peer that hung up has no one left to tell.
test "a request we cannot answer is refused in words, unless the peer is gone" {
    var s = try fixture.scratch(alloc);
    defer fixture.destroy(alloc, s);
    _ = try s.repo.commit("main", "a.txt", "one\n");

    var repo = try openFixture(s);
    defer repo.deinit();

    const cases = [_]struct {
        parts: []const []const u8 = &.{},
        raw: []const u8 = "",
        expect: []const u8, // empty: no answer at all
    }{
        .{
            .parts = &.{
                "command=fetch\n",
                "\x01",
                "want 0123456789abcdef0123456789abcdef01234567\n",
                "done\n",
                "",
            },
            .expect = "ERR ObjectMissing\n",
        },
        .{
            .parts = &.{ "command=push\n", "\x01", "" },
            .expect = "ERR UnknownCommand\n",
        },
        .{ .raw = "+123", .expect = "ERR BadLength\n" },
        // A command, and then nothing where its arguments should be.
        .{ .raw = "0012command=fetch\n", .expect = "" },
    };

    for (cases) |c| {
        const req = if (c.raw.len > 0) try alloc.dupe(u8, c.raw) else try request(c.parts);
        defer alloc.free(req);
        var got = try serve(repo, req);
        defer got.deinit();

        if (c.expect.len == 0) {
            try testing.expectEqual(@as(usize, 0), got.body().len);
        } else {
            try testing.expectEqualStrings(c.expect, got.body()[0].data);
        }
    }
}
