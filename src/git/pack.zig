//! Writing a pack, which is what serving a fetch sends. Every object goes out
//! as a base rather than a delta: the result is a valid pack that the peer
//! indexes the same way, at the cost of the bytes a delta would have saved.
//! Source: gitformat-pack.
const std = @import("std");
const gitpack = @import("gitpack");
const odb = @import("odb.zig");

const Sha1 = std.crypto.hash.Sha1;

const signature = "PACK";
const format_version = 2;

/// The most an entry header takes: four bits of the length in the type byte,
/// then seven per byte for what is left of a u64.
const max_entry_header = 1 + 10;

/// Writes the objects `oids` names as a pack, in the order given. The trailer
/// hashes everything before it, which is how the peer knows the stream arrived
/// whole.
pub fn write(
    gpa: std.mem.Allocator,
    out: *std.Io.Writer,
    o: *odb.Odb,
    oids: []const gitpack.Oid,
) !void {
    // Everything goes through the hash on its way out, so the compressor can
    // write to the peer directly instead of into a copy we would only hash
    // and forward.
    var sink_buf: [4096]u8 = undefined;
    var sink = Hashing.init(out, &sink_buf);
    const w = &sink.writer;

    var header: [12]u8 = undefined;
    @memcpy(header[0..4], signature);
    std.mem.writeInt(u32, header[4..8], format_version, .big);
    std.mem.writeInt(u32, header[8..12], @intCast(oids.len), .big);
    try w.writeAll(&header);

    // One window for the whole pack, since the compressor is rebuilt per entry
    // but never needs history across them.
    const window = try gpa.alloc(u8, std.compress.flate.max_window_len);
    defer gpa.free(window);

    for (oids) |oid| {
        const obj = try o.read(gpa, oid);
        defer obj.deinit(gpa);

        var entry: [max_entry_header]u8 = undefined;
        try w.writeAll(entry[0..entryHeader(&entry, obj.type, obj.data.len)]);

        var z = try std.compress.flate.Compress.init(w, window, .zlib, .default);
        try z.writer.writeAll(obj.data);
        try z.finish();
    }

    try w.flush();
    // The trailer is the one thing the hash does not cover.
    try out.writeAll(&sink.hash.finalResult());
}

/// Hashes every byte on its way to `out`. A pack's trailer covers everything
/// before it, and the bytes come from a compressor we do not otherwise see
/// into.
const Hashing = struct {
    writer: std.Io.Writer,
    out: *std.Io.Writer,
    hash: Sha1,

    fn init(out: *std.Io.Writer, buffer: []u8) Hashing {
        return .{
            .writer = .{ .vtable = &.{ .drain = drain }, .buffer = buffer },
            .out = out,
            .hash = Sha1.init(.{}),
        };
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *Hashing = @alignCast(@fieldParentPtr("writer", w));
        try self.emit(w.buffer[0..w.end]);
        w.end = 0;

        const head = data[0 .. data.len - 1];
        const pattern = data[head.len];
        var written: usize = 0;
        for (head) |bytes| {
            try self.emit(bytes);
            written += bytes.len;
        }
        for (0..splat) |_| {
            try self.emit(pattern);
            written += pattern.len;
        }
        return written;
    }

    fn emit(self: *Hashing, bytes: []const u8) std.Io.Writer.Error!void {
        if (bytes.len == 0) return;
        self.hash.update(bytes);
        try self.out.writeAll(bytes);
    }
};

/// The type and uncompressed length, low bits first: four of them share the
/// type byte, then seven per continuation byte.
fn entryHeader(out: []u8, kind: odb.Type, len: usize) usize {
    out[0] = (@as(u8, @backingInt(kind)) << 4) | @as(u8, @intCast(len & 0xf));
    var rest = len >> 4;
    if (rest == 0) return 1;
    out[0] |= 0x80;

    var n: usize = 1;
    while (true) : (n += 1) {
        const byte: u8 = @intCast(rest & 0x7f);
        rest >>= 7;
        if (rest == 0) {
            out[n] = byte;
            return n + 1;
        }
        out[n] = byte | 0x80;
    }
}

const testing = std.testing;

// The header round-trips through the reader that has to parse it, since the
// two encodings are the only thing binding a written pack to a readable one.
test "an entry header says the type and length odb reads back" {
    const cases = [_]struct { kind: odb.Type, len: usize }{
        .{ .kind = .commit, .len = 0 },
        .{ .kind = .blob, .len = 15 }, // the largest that fits the type byte
        .{ .kind = .tree, .len = 16 }, // the smallest that does not
        .{ .kind = .blob, .len = 2047 },
        .{ .kind = .tag, .len = 1 << 30 },
    };

    for (cases) |c| {
        var buf: [max_entry_header]u8 = undefined;
        const n = entryHeader(&buf, c.kind, c.len);

        var r = std.Io.Reader.fixed(buf[0..n]);
        const first: packed struct { len: u4, type: u3, more: bool } = @bitCast(try r.takeByte());
        const rest = if (first.more) try r.takeLeb128(u64) else 0;

        try testing.expectEqual(c.kind, @as(odb.Type, @fromBackingInt(first.type)));
        try testing.expectEqual(c.len, @as(u64, first.len) | (rest << 4));
        try testing.expectEqual(@as(usize, 0), r.buffered().len);
    }
}
