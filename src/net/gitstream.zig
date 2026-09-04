//! Git protocol v2 over a QUIC stream, which is what the `radicle/git/1` ALPN
//! carries: the node bridges the stream straight into its fetch machinery, so
//! there is no radicle framing around the git bytes, unlike 1.x.
//!
//! The initiator speaks first, with the same `git-upload-pack` line 1.x sends
//! inside its git frames.
//! Source: radicle-node/src/runtime.rs GitProtocolHandler, run_git_worker.
const std = @import("std");

const gossip = @import("gossip.zig");
const protocol = @import("protocol.zig");
const quic = @import("../quic/mod.zig");

/// Room for one request's pkt-lines before they go out together. A fetch names
/// every ref it wants, so this is sized for a repo with a lot of them.
const request_buffer = 64 * 1024;

/// A session in the shape `git/protocol.zig` drives: `sendIntro`, `writeGit`,
/// `readGit`, and `intro_sent`.
pub const Session = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    conn: *quic.conn.Conn,
    /// The repo being fetched, which the intro line names.
    rid: []const u8,
    intro_sent: bool = false,
    /// Pending request bytes. A request is many small pkt-lines, and a packet
    /// per line stalls on the sender's window every `Sender.max_chunks` of
    /// them, so they travel together.
    pending: []u8,
    pending_len: usize = 0,

    /// Dials `host` on the git ALPN and returns a session ready to speak git.
    pub fn connect(
        io: std.Io,
        allocator: std.mem.Allocator,
        conn: *quic.conn.Conn,
        opts: quic.conn.Options,
        rid: []const u8,
    ) !Session {
        var with_alpn = opts;
        with_alpn.alpn = gossip.alpn_git;
        try conn.establish(io, with_alpn);
        return .{
            .io = io,
            .allocator = allocator,
            .conn = conn,
            .rid = rid,
            .pending = try allocator.alloc(u8, request_buffer),
        };
    }

    pub fn sendIntro(self: *Session) !void {
        const intro = try protocol.gitUploadPackLine(self.allocator, self.rid);
        defer self.allocator.free(intro);
        try self.writeGit(intro);
        self.intro_sent = true;
    }

    /// Queues git bytes. They go out on the next read, which is where the
    /// request/response protocol needs them to have landed.
    pub fn writeGit(self: *Session, data: []const u8) !void {
        if (data.len > self.pending.len) return error.RequestTooLong;
        if (self.pending_len + data.len > self.pending.len) try self.flushGit();
        @memcpy(self.pending[self.pending_len..][0..data.len], data);
        self.pending_len += data.len;
    }

    fn flushGit(self: *Session) !void {
        if (self.pending_len == 0) return;
        try self.conn.send(self.pending[0..self.pending_len], false);
        self.pending_len = 0;
    }

    /// Reads up to `buf.len` git bytes, sending whatever is queued first and
    /// then pumping until some arrive. Returns 0 at the end of the stream.
    pub fn readGit(self: *Session, buf: []u8) !usize {
        try self.flushGit();

        // Bytes already in hand come first, however the connection ended: a
        // close travels in the same packet as the stream data before it.
        while (self.conn.readable().len == 0) {
            if (self.conn.streamDone()) return 0;
            if (self.conn.peerClose()) |close| {
                // A close in place of a FIN ends the stream too, but only a
                // clean one: an aborted fetch reported as EOF would hand the
                // caller a truncated pack as if it were whole.
                if (close.error_code != 0) return error.PeerClosed;
                return 0;
            }
            switch (try self.conn.service()) {
                // Both re-test the loop above: a close is not the end while
                // there are still bytes it arrived with.
                .arrived, .closed => {},
                // Quiet is not the end: a node enumerating objects for a
                // packfile says nothing for a while. Only its own idle timeout
                // settles that the connection is gone.
                .silent => if (self.conn.stalled()) return error.StreamStalled,
            }
        }

        const have = self.conn.readable();
        const n = @min(buf.len, have.len);
        @memcpy(buf[0..n], have[0..n]);
        self.conn.consume(n);
        return n;
    }
};

const testing = std.testing;
const fakepeer = @import("../quic/fakepeer.zig");

/// The RID `identity/rid.zig` round-trips. Nothing here sends it, but an
/// invented one would still be a lie.
const test_rid = "rad:z42hL2jL4XNk6K8oHQaSWfMgCL7ji";

/// A session over `d`, with `pending` for the bytes it queues.
fn testSession(d: *fakepeer.Dialed, pending: []u8) Session {
    return .{
        .io = testing.io,
        .allocator = testing.allocator,
        .conn = d.conn,
        .rid = test_rid,
        .pending = pending,
    };
}

test "a close ends the stream after its bytes, and only when it was clean" {
    var buf: [64]u8 = undefined;
    var pending: [256]u8 = undefined;

    {
        const d = try fakepeer.Dialed.init(testing.io, 1000);
        defer d.deinit();
        var s = testSession(d, &pending);
        try d.peer.sendStreamAndClose("PACK-tail", false, 0, "done");

        try testing.expectEqual(@as(usize, 9), try s.readGit(&buf));
        try testing.expectEqualStrings("PACK-tail", buf[0..9]);
        // Only now is the close the end of the stream.
        try testing.expectEqual(@as(usize, 0), try s.readGit(&buf));
    }
    {
        const d = try fakepeer.Dialed.init(testing.io, 1000);
        defer d.deinit();
        var s = testSession(d, &pending);
        try d.peer.sendStreamAndClose("half a pa", false, 0x3, "aborted");

        try testing.expectEqual(@as(usize, 9), try s.readGit(&buf));
        // A truncated pack reported as a clean end is what this must not be.
        try testing.expectError(error.PeerClosed, s.readGit(&buf));
    }
}

test "a FIN ends the stream without waiting for a timeout" {
    const d = try fakepeer.Dialed.init(testing.io, 1000);
    defer d.deinit();
    var pending: [256]u8 = undefined;
    var s = testSession(d, &pending);

    try d.peer.sendStream("refs", true);

    var buf: [64]u8 = undefined;
    try testing.expectEqual(@as(usize, 4), try s.readGit(&buf));
    // Reached through `streamDone`, so no receive timeout is spent on it: at
    // this connection's 20ms timeout, a wait would take the idle timeout.
    try testing.expectEqual(@as(usize, 0), try s.readGit(&buf));
}

test "silence past what the peer said it would wait stalls the read" {
    // 100ms advertised, so the silence runs out in a few receive timeouts
    // rather than in the 30 seconds a real peer asks for.
    const d = try fakepeer.Dialed.init(testing.io, 100);
    defer d.deinit();
    var pending: [256]u8 = undefined;
    var s = testSession(d, &pending);

    var buf: [64]u8 = undefined;
    try testing.expectError(error.StreamStalled, s.readGit(&buf));
}
