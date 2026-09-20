//! The server half of git protocol v2, which is what answers a fetch.
//! `protocol.zig` is the client this mirrors, and the two are tested against
//! each other's shapes.
//!
//! The transport's own opening line (`git-upload-pack <rid>` in 1.x) is not
//! ours: whoever read it already picked the repository, and `serve` starts at
//! the capability advertisement.
//! Source: gitprotocol-v2.
const std = @import("std");
const gitpack = @import("gitpack");
const pack = @import("pack.zig");
const pktline = @import("pktline.zig");
const protocol = @import("protocol.zig");
const storage = @import("storage.zig");
const walk = @import("walk.zig");

/// What a request can be refused for, on top of the framing errors `pktline`
/// raises.
pub const Error = error{
    UnknownCommand,
    MalformedRequest,
};

/// Sideband channel numbers. Only the pack travels on 1; we send no progress.
const band_pack = 1;

/// Arguments a peer may name. Bounded by both count and bytes, since one line
/// may be 64K on its own. Past a bound the request is refused rather than
/// trimmed: prefixes are a union and wants are a set, so dropping one of
/// either would answer a narrower question than the peer asked.
const max_prefixes = 1024;
const max_prefix_bytes = 1 << 16;
const max_oids = 65536;

/// Answers requests on `r` until the peer stops asking. One repository for the
/// whole conversation, since that is what the transport already selected.
pub fn serve(
    gpa: std.mem.Allocator,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    repo: *storage.Repository,
) !void {
    try advertise(w);

    // Off the stack: a pkt-line is 64K, and this runs per connection.
    const line_buf = try gpa.alloc(u8, pktline.MAX_DATA);
    defer gpa.free(line_buf);

    while (true) {
        var wrote = false;
        const more = handle(gpa, r, w, repo, line_buf, &wrote) catch |e| switch (e) {
            // The peer hung up, which is how a conversation usually ends.
            error.EndOfStream => return,
            error.ObjectMissing,
            error.MalformedRequest,
            error.UnknownCommand,
            error.BadLength,
            error.LineTooLong,
            => {
                // Only while the peer is still reading pkt-lines: past the
                // packfile line an ERR would be pack bytes to it.
                if (wrote) return e;
                try fail(w, @errorName(e));
                return;
            },
            else => return e,
        };
        if (!more) return;
        try w.flush();
    }
}

/// One request: the command, then whatever it reads and answers with. False
/// once the peer stops asking. `wrote` says whether the answer has started.
fn handle(
    gpa: std.mem.Allocator,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    repo: *storage.Repository,
    buf: []u8,
    wrote: *bool,
) !bool {
    const command = (try nextCommand(r, buf)) orelse return false;
    switch (command) {
        .ls_refs => try lsRefs(gpa, r, w, repo, buf, wrote),
        .fetch => try fetch(gpa, r, w, repo, buf, wrote),
    }
    return true;
}

/// The one way to report a refusal that a peer will read as one.
/// Source: gitprotocol-common, "ERR <message>".
fn fail(w: *std.Io.Writer, message: []const u8) !void {
    var line: [128]u8 = undefined;
    try pktline.write(w, try std.fmt.bufPrint(&line, "ERR {s}\n", .{message}));
    try w.flush();
}

/// What we speak, which the peer reads before it asks for anything.
fn advertise(w: *std.Io.Writer) !void {
    try pktline.write(w, "version 2\n");
    // The same line the client half sends: it names this implementation,
    // not either side of it.
    try pktline.write(w, protocol.AGENT);
    try pktline.write(w, "ls-refs\n");
    try pktline.write(w, "fetch\n");
    try pktline.write(w, "object-format=sha1\n");
    try w.writeAll(pktline.Marker.flush.wire());
    try w.flush();
}

const Command = enum { ls_refs, fetch };

/// Reads up to the next `command=` line, or null if the peer is done. Anything
/// before it is a capability the peer is announcing, which we have no use for.
fn nextCommand(r: *std.Io.Reader, buf: []u8) !?Command {
    while (true) {
        switch (try pktline.read(r, buf)) {
            // A flush between requests is the peer done talking.
            .marker => |m| if (m == .flush) return null,
            .data => |d| {
                const value = std.mem.trimEnd(u8, d, "\n");
                if (!std.mem.startsWith(u8, value, "command=")) continue;
                const name = value["command=".len..];
                if (std.mem.eql(u8, name, "ls-refs")) return .ls_refs;
                if (std.mem.eql(u8, name, "fetch")) return .fetch;
                return error.UnknownCommand;
            },
        }
    }
}

/// Advertises the refs the peer asked for, or all of them when it named no
/// prefix. `symrefs` and `peel` are accepted and not acted on: we publish no
/// symbolic refs, and nothing here is an annotated tag.
fn lsRefs(
    gpa: std.mem.Allocator,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    repo: *storage.Repository,
    buf: []u8,
    wrote: *bool,
) !void {
    var prefixes: std.ArrayList([]const u8) = .empty;
    defer {
        for (prefixes.items) |p| gpa.free(p);
        prefixes.deinit(gpa);
    }
    var prefix_bytes: usize = 0;

    while (true) {
        switch (try pktline.read(r, buf)) {
            .marker => |m| if (m == .flush) break else continue,
            .data => |d| {
                const arg = std.mem.trimEnd(u8, d, "\n");
                if (!std.mem.startsWith(u8, arg, "ref-prefix ")) continue;
                const prefix = arg["ref-prefix ".len..];
                prefix_bytes += prefix.len;
                if (prefixes.items.len == max_prefixes or prefix_bytes > max_prefix_bytes)
                    return error.MalformedRequest;
                try prefixes.append(gpa, try gpa.dupe(u8, prefix));
            },
        }
    }

    const refs = try repo.listRefs(gpa, prefixes.items);
    defer {
        for (refs) |ref| gpa.free(ref.name);
        gpa.free(refs);
    }

    // The request is read by now, so its buffer is free to spell the answer.
    wrote.* = true;
    for (refs) |ref| {
        const text = try std.fmt.bufPrint(buf, "{x} {s}\n", .{ ref.oid.slice(), ref.name });
        try pktline.write(w, text);
    }
    try w.writeAll(pktline.Marker.flush.wire());
}

const Request = struct {
    wants: std.ArrayList(gitpack.Oid) = .empty,
    haves: std.ArrayList(gitpack.Oid) = .empty,
    done: bool = false,

    fn deinit(self: *Request, gpa: std.mem.Allocator) void {
        self.wants.deinit(gpa);
        self.haves.deinit(gpa);
    }
};

/// Sends the objects behind the peer's wants that its haves do not already
/// cover. Without `done` the peer is still negotiating, so it gets
/// acknowledgements and another round instead of a pack.
fn fetch(
    gpa: std.mem.Allocator,
    r: *std.Io.Reader,
    w: *std.Io.Writer,
    repo: *storage.Repository,
    buf: []u8,
    wrote: *bool,
) !void {
    var req = try readFetch(gpa, r, buf);
    defer req.deinit(gpa);

    if (!req.done) {
        wrote.* = true;
        return acknowledge(w, repo, req);
    }

    const oids = try walk.missing(gpa, &repo.odb, req.wants.items, req.haves.items);
    defer gpa.free(oids);

    wrote.* = true;
    try pktline.write(w, "packfile\n");

    // The pack goes out as it is produced. Nothing here is proportional to the
    // pack; what memory the send costs is one object at a time, inside
    // `pack.write`.
    const band_buf = try gpa.alloc(u8, pktline.MAX_BAND_DATA);
    defer gpa.free(band_buf);
    var sideband = Sideband.init(w, band_buf);
    try pack.write(gpa, &sideband.writer, &repo.odb, oids);
    try sideband.writer.flush();

    try w.writeAll(pktline.Marker.flush.wire());
}

/// Turns everything written to it into sideband pkt-lines, so a pack can be
/// sent while it is still being built.
const Sideband = struct {
    writer: std.Io.Writer,
    out: *std.Io.Writer,

    fn init(out: *std.Io.Writer, buffer: []u8) Sideband {
        return .{
            .writer = .{ .vtable = &.{ .drain = drain }, .buffer = buffer },
            .out = out,
        };
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *Sideband = @alignCast(@fieldParentPtr("writer", w));
        self.emit(w.buffer[0..w.end]) catch return error.WriteFailed;
        w.end = 0;

        const head = data[0 .. data.len - 1];
        const pattern = data[head.len];
        var written: usize = 0;
        for (head) |bytes| {
            self.emit(bytes) catch return error.WriteFailed;
            written += bytes.len;
        }
        for (0..splat) |_| {
            self.emit(pattern) catch return error.WriteFailed;
            written += pattern.len;
        }
        return written;
    }

    /// One band line per chunk, since a pkt-line cannot carry more. Nothing is
    /// written for no bytes: an empty pkt-line is a flush, which would end the
    /// packfile section early.
    fn emit(self: *Sideband, bytes: []const u8) !void {
        var rest = bytes;
        while (rest.len > 0) {
            const n = @min(rest.len, pktline.MAX_BAND_DATA);
            try pktline.writeBand(self.out, band_pack, rest[0..n]);
            rest = rest[n..];
        }
    }
};

fn readFetch(gpa: std.mem.Allocator, r: *std.Io.Reader, buf: []u8) !Request {
    var req: Request = .{};
    errdefer req.deinit(gpa);

    while (true) {
        switch (try pktline.read(r, buf)) {
            .marker => |m| if (m == .flush) break else continue,
            .data => |d| {
                const arg = std.mem.trimEnd(u8, d, "\n");
                if (std.mem.eql(u8, arg, "done")) {
                    req.done = true;
                } else if (std.mem.startsWith(u8, arg, "want ")) {
                    if (req.wants.items.len == max_oids) return error.MalformedRequest;
                    try req.wants.append(gpa, try parseOid(arg["want ".len..]));
                } else if (std.mem.startsWith(u8, arg, "have ")) {
                    // A have we drop only makes the pack bigger, so the cap
                    // trims here rather than refusing.
                    if (req.haves.items.len == max_oids) continue;
                    try req.haves.append(gpa, try parseOid(arg["have ".len..]));
                }
            },
        }
    }
    return req;
}

/// Tells the peer which of its haves we hold, so the next round can narrow
/// what it asks for.
///
/// Deliberately never `ready`: that word commits us to continuing the same
/// response with the packfile section, and a peer told `ready` will read on
/// for it. Ending the round instead costs a round trip and asks the peer to
/// come back with `done`.
fn acknowledge(w: *std.Io.Writer, repo: *storage.Repository, req: Request) !void {
    try pktline.write(w, "acknowledgments\n");

    var line: [64]u8 = undefined;
    var common: usize = 0;
    for (req.haves.items) |oid| {
        if (!(repo.hasObject(oid) catch false)) continue;
        common += 1;
        try pktline.write(w, try std.fmt.bufPrint(&line, "ACK {x}\n", .{oid.slice()}));
    }
    if (common == 0) try pktline.write(w, "NAK\n");
    try w.writeAll(pktline.Marker.flush.wire());
}

fn parseOid(hex: []const u8) !gitpack.Oid {
    return gitpack.Oid.parse(.sha1, hex) catch error.MalformedRequest;
}

