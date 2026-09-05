//! Git protocol v2 client (gitprotocol-v2), spoken over a fetch Session.
//! Drives `ls-refs` and `fetch` and demultiplexes the sideband packfile.
//! radicle-node requires v2, so this client is hand-rolled; the returned
//! packfile is indexed by the toolchain's own git plumbing.
//!
//! Request/response shapes verified against a live radicle-node 1.9.1 fetch:
//!   -> command=ls-refs\n agent=..\n DELIM symrefs\n peel\n ref-prefix ..\n FLUSH
//!   <- <oid> <refname>\n ... FLUSH
//!   -> command=fetch\n agent=..\n DELIM ofs-delta\n want <oid>\n ... done\n FLUSH
//!   <- packfile\n then sideband: \x01 pack data, \x02 progress, \x03 error
const std = @import("std");
const pktline = @import("pktline.zig");

pub const AGENT = "agent=radish/0.0.0\n";

/// Read buffer for pkt-line responses: one max-length pkt-line plus its 4-byte
/// header must always fit, or `PktReader` cannot make progress.
const MAX_PKT_BUF = pktline.MAX_DATA + 4;

/// This client is transport-agnostic: `session` is any value exposing
///   readGit([]u8) !usize   writeGit([]const u8) !void
///   sendIntro() !void      intro_sent: bool
/// (net/fetch.Session runs it over Noise, net/gitstream.Session over QUIC.)
pub const Ref = struct {
    oid: [40]u8, // hex
    name: []const u8, // owned by the RefList arena
};

pub const RefList = struct {
    arena: std.heap.ArenaAllocator,
    refs: []Ref,

    pub fn deinit(self: *RefList) void {
        self.arena.deinit();
    }
};

/// Reads pkt-lines from a session, buffering a single frame's worth at a time.
fn PktReader(comptime S: type) type {
    return struct {
        session: S,
        buf: []u8,
        len: usize = 0,
        pos: usize = 0,

        const Self = @This();

        fn refill(self: *Self) !void {
            if (self.pos > 0) {
                std.mem.copyForwards(u8, self.buf[0 .. self.len - self.pos], self.buf[self.pos..self.len]);
                self.len -= self.pos;
                self.pos = 0;
            }
            if (self.len == self.buf.len) return error.PktLineTooLong;
            const n = try self.session.readGit(self.buf[self.len..]);
            if (n == 0) return error.EndOfStream;
            self.len += n;
        }

        /// Data slices borrow the internal buffer; valid until the next call.
        fn next(self: *Self) !pktline.Line {
            while (true) {
                const avail = self.buf[self.pos..self.len];
                if (avail.len >= 4) {
                    const r = pktline.parse(avail) catch |e| switch (e) {
                        error.ShortBuffer => {
                            try self.refill();
                            continue;
                        },
                        else => return e,
                    };
                    self.pos += r.consumed;
                    return r.line;
                }
                try self.refill();
            }
        }
    };
}

/// Frames `payload` as a pkt-line and sends it. Our request lines are all
/// small (commands, oids, ref-prefixes); the local buffer bounds them.
fn writePkt(session: anytype, payload: []const u8) !void {
    var buf: [512]u8 = undefined;
    const line = try pktline.writeData(&buf, payload);
    try session.writeGit(line);
}

/// On first use, sends the intro and consumes the v2 capability advertisement
/// (a run of pkt-lines ended by a flush) that the server sends on connect.
fn ensureReady(session: anytype) !void {
    if (session.intro_sent) return;
    try session.sendIntro();
    var rbuf: [8192]u8 = undefined;
    var reader = PktReader(@TypeOf(session)){ .session = session, .buf = &rbuf };
    while (true) switch (try reader.next()) {
        .marker => |m| if (m == .flush) return,
        .data => {},
    };
}

/// Runs `ls-refs` for the given ref-prefixes and returns the advertised refs.
pub fn lsRefs(allocator: std.mem.Allocator, session: anytype, prefixes: []const []const u8) !RefList {
    try ensureReady(session);

    var wbuf: [512]u8 = undefined;
    try writePkt(session, "command=ls-refs\n");
    try writePkt(session, AGENT);
    try session.writeGit(pktline.Marker.delim.wire());
    try writePkt(session, "symrefs\n");
    try writePkt(session, "peel\n");
    for (prefixes) |p| {
        const line = try std.fmt.bufPrint(wbuf[0..], "ref-prefix {s}\n", .{p});
        try writePkt(session, line);
    }
    try session.writeGit(pktline.Marker.flush.wire());

    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    var list: std.ArrayList(Ref) = .empty;

    var rbuf: [MAX_PKT_BUF]u8 = undefined;
    var reader = PktReader(@TypeOf(session)){ .session = session, .buf = &rbuf };
    while (true) {
        const line = try reader.next();
        switch (line) {
            .marker => |m| if (m == .flush) break,
            .data => |d| {
                // "<oid> <refname>[ symref-target:..][ peeled:..]\n"
                const trimmed = std.mem.trimEnd(u8, d, "\n");
                const sp = std.mem.indexOfScalar(u8, trimmed, ' ') orelse continue;
                if (sp != 40) continue;
                var ref: Ref = .{ .oid = undefined, .name = undefined };
                @memcpy(&ref.oid, trimmed[0..40]);
                const rest = trimmed[sp + 1 ..];
                const name_end = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
                ref.name = try a.dupe(u8, rest[0..name_end]);
                try list.append(a, ref);
            },
        }
    }
    return .{ .arena = arena, .refs = try list.toOwnedSlice(a) };
}

/// Sends `fetch` wanting every oid in `wants`, then reads the sideband
/// response, writing raw packfile bytes to `pack_out`. Progress (band 2) is
/// discarded; band 3 is an error.
pub fn fetchPack(
    session: anytype,
    wants: []const [40]u8,
    pack_out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
) !void {
    try ensureReady(session);

    var wbuf: [512]u8 = undefined;
    try writePkt(session, "command=fetch\n");
    try writePkt(session, AGENT);
    try session.writeGit(pktline.Marker.delim.wire());
    try writePkt(session, "ofs-delta\n");
    for (wants) |oid| {
        const line = try std.fmt.bufPrint(wbuf[0..], "want {s}\n", .{oid});
        try writePkt(session, line);
    }
    try writePkt(session, "done\n");
    try session.writeGit(pktline.Marker.flush.wire());

    var rbuf: [MAX_PKT_BUF]u8 = undefined;
    var reader = PktReader(@TypeOf(session)){ .session = session, .buf = &rbuf };
    var in_packfile = false;
    while (true) {
        const line = reader.next() catch |e| switch (e) {
            error.EndOfStream => break,
            else => return e,
        };
        switch (line) {
            .marker => |m| if (m == .flush) {
                if (in_packfile) break;
            },
            .data => |d| {
                if (!in_packfile) {
                    // Section header before the packfile ("packfile\n").
                    if (std.mem.eql(u8, std.mem.trimEnd(u8, d, "\n"), "packfile")) in_packfile = true;
                    continue;
                }
                if (d.len == 0) continue;
                switch (d[0]) {
                    1 => try pack_out.appendSlice(allocator, d[1..]), // pack data
                    2 => {}, // progress
                    3 => return error.RemoteError,
                    else => {},
                }
            },
        }
    }
}
