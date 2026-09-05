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

    /// Why a stalled stream stopped: whatever the last datagram went wrong
    /// with, since `service` records those rather than raising them, and only
    /// `StreamStalled` when nothing did.
    fn failure(self: *Session) anyerror {
        return self.conn.lastError() orelse error.StreamStalled;
    }

    /// Frees the request buffer. The connection is the caller's.
    pub fn deinit(self: *Session) void {
        self.allocator.free(self.pending);
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
            // A reset is the peer abandoning what it was sending, so what
            // arrived is a fragment however much of it there is.
            if (self.conn.streamReset()) return error.PeerResetStream;
            // A stateless reset says the peer no longer knows this connection,
            // so nothing more will ever arrive on it.
            if (self.conn.wasReset()) return error.StatelessReset;
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
                .silent => if (self.conn.stalled()) return self.failure(),
            }
            // A peer that keeps the connection alive while sending nothing
            // leaves `stalled` false forever, so the stream gets its own
            // deadline.
            if (self.conn.streamStalled()) return self.failure();
        }

        const have = self.conn.readable();
        const n = @min(buf.len, have.len);
        @memcpy(buf[0..n], have[0..n]);
        self.conn.consume(n);
        return n;
    }
};

const testing = std.testing;
const codec = @import("../codec.zig");
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

test "a stream longer than the window arrives once the reader drains" {
    const d = try fakepeer.Dialed.init(testing.io, 1000);
    defer d.deinit();
    var pending: [256]u8 = undefined;
    var s = testSession(d, &pending);

    // Three windows' worth, which a packfile passes in the first megabyte.
    const chunk_len = 1200;
    const total = chunk_len * (3 * quic.client.default_window / chunk_len);
    var chunk: [chunk_len]u8 = undefined;

    var sent: u64 = 0;
    var read: u64 = 0;
    var buf: [chunk_len]u8 = undefined;
    while (sent < total) {
        // Every byte says which offset it belongs at, so a gap or a repeat
        // shows up as a mismatch rather than as a short read.
        for (&chunk, 0..) |*b, i| b.* = @truncate(sent + i);
        try d.peer.sendStream(&chunk, false);
        sent += chunk_len;

        var got: usize = 0;
        while (got < chunk_len) {
            const n = try s.readGit(buf[got..]);
            try testing.expect(n > 0);
            for (buf[got..][0..n], 0..) |b, i| {
                try testing.expectEqual(@as(u8, @truncate(read + got + i)), b);
            }
            got += n;
        }
        read += got;
    }
    try testing.expectEqual(total, read);
}

test "a stream survives the peer updating keys mid-transfer" {
    const d = try fakepeer.Dialed.init(testing.io, 1000);
    defer d.deinit();
    var pending: [256]u8 = undefined;
    var s = testSession(d, &pending);

    var buf: [64]u8 = undefined;
    try d.peer.sendStream("before", false);
    try testing.expectEqual(@as(usize, 6), try s.readGit(&buf));
    try testing.expectEqualStrings("before", buf[0..6]);

    // Nothing announces this but the Key Phase bit on the next packet.
    d.peer.updateKeys();
    try d.peer.sendStream("after", false);
    try testing.expectEqual(@as(usize, 5), try s.readGit(&buf));
    try testing.expectEqualStrings("after", buf[0..5]);

    // Our own keys moved too, so the phase we send is the one the peer now
    // expects to see acknowledged.
    try testing.expect(d.conn.hs.key_phase);

    // And a second update, which is only allowed once the first completed.
    d.peer.updateKeys();
    try d.peer.sendStream("third", false);
    try testing.expectEqual(@as(usize, 5), try s.readGit(&buf));
    try testing.expectEqualStrings("third", buf[0..5]);
    try testing.expect(!d.conn.hs.key_phase);
}

test "a stateless reset ends the stream, and no goodbye goes back" {
    const d = try fakepeer.Dialed.init(testing.io, 1000);
    defer d.deinit();
    var pending: [256]u8 = undefined;
    var s = testSession(d, &pending);

    var buf: [64]u8 = undefined;
    try d.peer.sendStream("half a pa", false);
    try testing.expectEqual(@as(usize, 9), try s.readGit(&buf));

    // Nothing about it opens, and only the token tells it from noise.
    try d.peer.sendUnopenable(fakepeer.FakePeer.reset_token);
    try testing.expectError(error.StatelessReset, s.readGit(&buf));
    try testing.expect(d.conn.wasReset());

    // The peer holds nothing to release, so nothing answers the reset and
    // closing says no goodbye. What is queued is the acknowledgement of the
    // stream bytes, from before any of this.
    d.conn.close();
    var frames: [512]u8 = undefined;
    while (d.peer.receiveFramesIn(&frames, 20)) |payload| {
        var it = quic.frame.Iterator.init(payload);
        while (try it.next()) |f| try testing.expect(f != .connection_close);
    } else |_| {}
}

test "datagrams that will not open cannot hold the stream open" {
    // Short timeout: the point is that it is reached at all.
    const d = try fakepeer.Dialed.init(testing.io, 100);
    defer d.deinit();
    var pending: [256]u8 = undefined;
    var s = testSession(d, &pending);

    // Noise, with no token to make it a reset. Nothing here counts as the peer
    // still being there, so the deadline still arrives and says why.
    for (0..8) |_| try d.peer.sendUnopenable(null);
    var buf: [64]u8 = undefined;
    try testing.expectError(error.AuthenticationFailed, s.readGit(&buf));
}

test "a packet sealed before a key update still opens after it" {
    const d = try fakepeer.Dialed.init(testing.io, 1000);
    defer d.deinit();
    var pending: [256]u8 = undefined;
    var s = testSession(d, &pending);

    var buf: [64]u8 = undefined;
    const before_keys = d.peer.keys;
    const before_phase = d.peer.key_phase;

    d.peer.updateKeys();
    try d.peer.sendStream("new", false);
    try testing.expectEqual(@as(usize, 3), try s.readGit(&buf));
    try testing.expectEqualStrings("new", buf[0..3]);

    // A packet from the generation just replaced, arriving after the update.
    d.peer.keys = before_keys;
    d.peer.key_phase = before_phase;
    try d.peer.sendStream("old", false);
    try testing.expectEqual(@as(usize, 3), try s.readGit(&buf));
    try testing.expectEqualStrings("old", buf[0..3]);
}

test "a reset ends the stream as a fragment, after the bytes that did arrive" {
    const d = try fakepeer.Dialed.init(testing.io, 1000);
    defer d.deinit();
    var pending: [256]u8 = undefined;
    var s = testSession(d, &pending);

    var frames: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&frames);
    try quic.frame.writeStream(&w, .{ .id = 0, .offset = 0, .data = "half a pa", .fin = false });
    // RESET_STREAM: id, application error code, final size.
    try codec.writeVarint(&w, @backingInt(quic.frame.Type.reset_stream));
    try codec.writeVarint(&w, 0);
    try codec.writeVarint(&w, 7);
    try codec.writeVarint(&w, 9);
    try d.peer.sendFrames(w.buffered());

    var buf: [64]u8 = undefined;
    try testing.expectEqual(@as(usize, 9), try s.readGit(&buf));
    try testing.expectError(error.PeerResetStream, s.readGit(&buf));
}

// The id in a RESET_STREAM is read, so one about a stream we never opened is
// not our transfer being abandoned mid-pack.
test "a reset naming another stream leaves ours running" {
    const d = try fakepeer.Dialed.init(testing.io, 1000);
    defer d.deinit();
    var pending: [256]u8 = undefined;
    var s = testSession(d, &pending);

    var frames: [32]u8 = undefined;
    var w = std.Io.Writer.fixed(&frames);
    // RESET_STREAM on stream 4: id, application error code, final size.
    try codec.writeVarint(&w, @backingInt(quic.frame.Type.reset_stream));
    try codec.writeVarint(&w, 4);
    try codec.writeVarint(&w, 7);
    try codec.writeVarint(&w, 9);
    try d.peer.sendFrames(w.buffered());
    // Read past the reset to reach this, so it has been handled by then.
    try d.peer.sendStream("refs", true);

    var buf: [64]u8 = undefined;
    try testing.expectEqual(@as(usize, 4), try s.readGit(&buf));
    try testing.expect(!d.conn.streamReset());
    try testing.expectEqual(@as(usize, 0), try s.readGit(&buf));
}

test "a peer saying it is blocked gets a grant it has not earned" {
    const d = try fakepeer.Dialed.init(testing.io, 1000);
    defer d.deinit();

    // Nothing has been read, so no grant is due on the reader's account and
    // none would go out on its own.
    var out: [512]u8 = undefined;
    try testing.expect(!d.conn.hs.stream.wantsGrant());
    try testing.expectEqual(@as(?usize, null), try d.conn.hs.sealMaxData(&out));

    var frames: [32]u8 = undefined;
    var w = std.Io.Writer.fixed(&frames);
    try codec.writeVarint(&w, @backingInt(quic.frame.Type.data_blocked));
    try codec.writeVarint(&w, 0);
    try d.peer.sendFrames(w.buffered());
    _ = try d.conn.service();

    // The frame is ack-eliciting, so an ACK comes first and the grant follows.
    var seen_max_data = false;
    for (0..4) |_| {
        const payload = d.peer.receiveFrames(&out) catch break;
        var it = quic.frame.Iterator.init(payload);
        while (it.next() catch break) |f| {
            if (f == .max_data) seen_max_data = true;
        }
        if (seen_max_data) break;
    }
    try testing.expect(seen_max_data);
    // Answered and cleared, so asking again takes another frame.
    try testing.expect(!d.conn.hs.grant_asked);
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
