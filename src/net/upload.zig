//! Answering a fetch on a 1.x git stream: the responder half of `fetch.zig`.
//!
//! Git bytes arrive wrapped in radicle git frames and leave the same way, so
//! what `uploadpack.serve` wants (a reader and a writer of plain git protocol
//! v2) is built here, over the socket the session already holds.
//!
//! Nothing is sent on the control stream when the fetch ends. The peer learns
//! the pack is whole from git's own framing, and it is the side that opened
//! the stream that gets to close it.
//! Source: radicle-node worker.rs, which hands the same two halves to
//! `git upload-pack`.
const std = @import("std");
const protocol = @import("protocol.zig");
const storage = @import("../git/storage.zig");
const uploadpack = @import("../git/uploadpack.zig");

/// One whole frame, since a frame may declare that much and is read in one go.
const FRAME_BUF: usize = protocol.MAX_FRAME_PAYLOAD;
/// Small: reassembly happens in `FRAME_BUF`, and a pkt-line is read straight
/// into upload-pack's own buffer.
const READ_BUF: usize = 4096;
/// A frame's worth, so a full buffer leaves as one frame rather than two.
const WRITE_BUF: usize = protocol.MAX_FRAME_PAYLOAD;

/// One git stream, as raw git bytes in both directions. `reader` ends when the
/// peer closes the stream; `writer` frames what is written on the peer's id.
///
/// Frames that are not this stream's keep arriving while a fetch is in flight;
/// they are counted and dropped. Gossip we miss is gossip the peer will send
/// again, and a fetch is not the moment to answer it.
pub const Stream = struct {
    sock_r: *std.Io.Reader,
    sock_w: *std.Io.Writer,
    id: protocol.StreamId,
    /// What is left of the frame being handed out; borrows `frame_buf`.
    pending: []const u8 = &.{},
    frame_buf: []u8,
    skipped: usize = 0,
    reader: std.Io.Reader,
    writer: std.Io.Writer,

    /// Borrows all three buffers, and must not be copied once built: both
    /// halves find their way back here from the address of a field.
    pub fn init(
        sock_r: *std.Io.Reader,
        sock_w: *std.Io.Writer,
        id: protocol.StreamId,
        frame_buf: []u8,
        read_buf: []u8,
        write_buf: []u8,
    ) Stream {
        return .{
            .sock_r = sock_r,
            .sock_w = sock_w,
            .id = id,
            .frame_buf = frame_buf,
            .reader = .{
                .vtable = &.{ .stream = read },
                .buffer = read_buf,
                .seek = 0,
                .end = 0,
            },
            .writer = .{ .vtable = &.{ .drain = drain, .flush = flush }, .buffer = write_buf },
        };
    }

    fn read(
        r: *std.Io.Reader,
        w: *std.Io.Writer,
        limit: std.Io.Limit,
    ) std.Io.Reader.StreamError!usize {
        const self: *Stream = @alignCast(@fieldParentPtr("reader", r));
        if (self.pending.len == 0) {
            self.pending = self.nextPayload() catch |e| switch (e) {
                error.EndOfStream => return error.EndOfStream,
                else => return error.ReadFailed,
            };
        }
        // Never more than the caller has room for, which is what keeps the
        // write below from failing.
        const n = limit.minInt(self.pending.len);
        try w.writeAll(self.pending[0..n]);
        self.pending = self.pending[n..];
        return n;
    }

    /// The next payload on our stream. A close or an eof naming it is the peer
    /// done talking; anything else on the connection is not ours to answer
    /// here.
    fn nextPayload(self: *Stream) ![]const u8 {
        while (true) {
            switch (try protocol.readRawFrame(self.sock_r, self.frame_buf)) {
                .git => |g| {
                    if (g.stream.value != self.id.value) {
                        self.skipped += 1;
                        continue;
                    }
                    return g.payload;
                },
                .control => |c| {
                    if (c.target != self.id.value) continue;
                    if (c.ctrl == .close or c.ctrl == .eof) return error.EndOfStream;
                },
                else => self.skipped += 1,
            }
        }
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *Stream = @alignCast(@fieldParentPtr("writer", w));
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

    /// Ours empties into the socket's, so a flush has to carry through to it:
    /// upload-pack flushes when it wants the peer to have the bytes.
    fn flush(w: *std.Io.Writer) std.Io.Writer.Error!void {
        const self: *Stream = @alignCast(@fieldParentPtr("writer", w));
        self.emit(w.buffer[0..w.end]) catch return error.WriteFailed;
        w.end = 0;
        try self.sock_w.flush();
    }

    /// One frame per chunk, up to what a frame can carry. Nothing is written
    /// for no bytes: an empty git frame says nothing, and the peer would have
    /// to read past it anyway.
    fn emit(self: *Stream, bytes: []const u8) !void {
        var rest = bytes;
        while (rest.len > 0) {
            const n = @min(rest.len, protocol.MAX_FRAME_PAYLOAD);
            try protocol.writeGitFrameHeader(self.sock_w, self.id, n);
            try self.sock_w.writeAll(rest[0..n]);
            rest = rest[n..];
        }
    }
};

/// Serves one fetch on `id`, starting at the capability advertisement: the
/// caller has read the intro line out of the first git frame, and with it
/// decided which repository this is and that we will serve it.
pub fn serve(
    gpa: std.mem.Allocator,
    sock_r: *std.Io.Reader,
    sock_w: *std.Io.Writer,
    id: protocol.StreamId,
    repo: *storage.Repository,
) !void {
    const bufs = try gpa.alloc(u8, FRAME_BUF + READ_BUF + WRITE_BUF);
    defer gpa.free(bufs);

    var stream = Stream.init(
        sock_r,
        sock_w,
        id,
        bufs[0..FRAME_BUF],
        bufs[FRAME_BUF..][0..READ_BUF],
        bufs[FRAME_BUF + READ_BUF ..][0..WRITE_BUF],
    );
    return uploadpack.serve(gpa, &stream.reader, &stream.writer, repo);
}
