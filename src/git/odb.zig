//! Reading an object out of a pack by oid. gitpack keeps its own object
//! database private, so this is ours: the index gives an offset, the entry
//! there gives a type and deflated bytes, and a delta is applied over whatever
//! it points at.
//! Source: gitformat-pack.
const std = @import("std");
const gitpack = @import("gitpack");

pub const Error = error{
    BadPackIndex,
    BadPack,
    ObjectMissing,
    ObjectTooLarge,
    DeltaTooDeep,
    InvalidDelta,
};

/// What an object is once its deltas are resolved. The two delta encodings are
/// how an entry is stored, never what it means.
pub const Type = enum(u3) {
    commit = 1,
    tree = 2,
    blob = 3,
    tag = 4,

    /// The word that goes in the "<type> <len>\x00" an oid is taken over.
    pub fn name(self: Type) []const u8 {
        return @tagName(self);
    }
};

pub const Object = struct {
    type: Type,
    /// The caller's to free.
    data: []u8,

    pub fn deinit(self: Object, gpa: std.mem.Allocator) void {
        gpa.free(self.data);
    }
};

const idx_magic = "\xFFtOc";
const fanout_off = 8;
const oids_off = fanout_off + 256 * 4;

/// The largest object we will build, and the largest delta we will hold to
/// build one. Every length here is a claim the pack makes before it backs the
/// claim up, so a header naming a size it does not have would otherwise buy an
/// allocation of whatever it asked for.
pub const max_object = 1 << 26;
pub const max_delta = 1 << 22;

/// A v2 index and the pack it belongs to, borrowed for as long as this lives.
pub const Odb = struct {
    format: gitpack.Oid.Format,
    pack: *std.Io.File.Reader,
    idx: *std.Io.File.Reader,

    /// Long enough for anything git writes, short enough that a pack pointing
    /// at itself ends rather than runs out of stack.
    const max_depth = 50;

    pub fn read(self: *Odb, gpa: std.mem.Allocator, oid: gitpack.Oid) !Object {
        const at = (try self.offsetOf(oid)) orelse return error.ObjectMissing;
        return self.readAt(gpa, at, 0);
    }

    /// What `oid` is, without inflating a byte of it. A delta never changes
    /// the type, so this follows the chain to a base, but only through entry
    /// headers: a caller that will not walk a blob's content need not pay to
    /// find out it is one.
    pub fn typeOf(self: *Odb, oid: gitpack.Oid) !Type {
        const at = (try self.offsetOf(oid)) orelse return error.ObjectMissing;
        return self.typeAt(at, 0);
    }

    fn typeAt(self: *Odb, offset: u64, depth: usize) anyerror!Type {
        if (depth > max_depth) return error.DeltaTooDeep;
        try self.pack.seekTo(offset);
        switch (try self.entry()) {
            .base => |b| return b.type,
            .ofs => |d| {
                if (d.back > offset) return error.BadPack;
                return self.typeAt(offset - d.back, depth + 1);
            },
            .ref => |d| {
                const at = (try self.offsetOf(d.base)) orelse return error.ObjectMissing;
                return self.typeAt(at, depth + 1);
            },
        }
    }

    /// Where `oid`'s entry starts, or null when the pack does not hold it.
    pub fn offsetOf(self: *Odb, oid: gitpack.Oid) !?u64 {
        const n = try self.count();
        const i = (try self.indexOf(oid, n)) orelse return null;
        return try self.offsetAt(i, n);
    }

    /// Objects in the pack, which is the last fan-out bucket: every entry has
    /// a first byte of 0xff or less.
    fn count(self: *Odb) !u32 {
        const r = &self.idx.interface;
        try self.idx.seekTo(0);
        if (!std.mem.eql(u8, try r.take(4), idx_magic)) return error.BadPackIndex;
        if (try r.takeInt(u32, .big) != 2) return error.BadPackIndex;
        try self.idx.seekTo(fanout_off + 255 * 4);
        return r.takeInt(u32, .big);
    }

    /// Binary search of the sorted oid table. fan_out[b] counts the oids whose
    /// first byte is at most b, so the candidates sit in [fan_out[b-1], fan_out[b]).
    fn indexOf(self: *Odb, oid: gitpack.Oid, n: u32) !?u32 {
        const r = &self.idx.interface;
        const key = oid.slice()[0];
        var lo: u32 = 0;
        if (key > 0) {
            try self.idx.seekTo(fanout_off + (@as(u64, key) - 1) * 4);
            lo = try r.takeInt(u32, .big);
        }
        try self.idx.seekTo(fanout_off + @as(u64, key) * 4);
        var hi = try r.takeInt(u32, .big);
        if (hi > n) return error.BadPackIndex;

        const width = oid.slice().len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            try self.idx.seekTo(oids_off + @as(u64, mid) * width);
            switch (std.mem.order(u8, try r.take(width), oid.slice())) {
                .lt => lo = mid + 1,
                .gt => hi = mid,
                .eq => return mid,
            }
        }
        return null;
    }

    /// The offset for entry `i`. The four-byte table holds it directly unless
    /// its top bit is set, which makes the rest an index into the eight-byte
    /// table that follows, for packs past 2 GiB.
    fn offsetAt(self: *Odb, i: u32, n: u32) !u64 {
        const r = &self.idx.interface;
        const width = self.format.byteLength();
        const offsets = oids_off + @as(u64, n) * (width + 4);
        try self.idx.seekTo(offsets + @as(u64, i) * 4);
        const short = try r.takeInt(u32, .big);
        if (short & 0x80000000 == 0) return short;

        try self.idx.seekTo(offsets + @as(u64, n) * 4 + @as(u64, short & 0x7fffffff) * 8);
        return r.takeInt(u64, .big);
    }

    /// `anyerror` because this and `deltify` call each other: an inferred set
    /// cannot close over a cycle.
    fn readAt(self: *Odb, gpa: std.mem.Allocator, offset: u64, depth: usize) anyerror!Object {
        if (depth > max_depth) return error.DeltaTooDeep;
        try self.pack.seekTo(offset);
        switch (try self.entry()) {
            .base => |b| return .{ .type = b.type, .data = try self.inflate(gpa, b.len) },
            // The delta before the base: its bytes start here, and reading the
            // base moves the pack away.
            .ofs => |d| {
                const delta = try self.inflateDelta(gpa, d.len);
                defer gpa.free(delta);
                if (d.back > offset) return error.BadPack;
                return self.deltify(gpa, offset - d.back, delta, depth);
            },
            .ref => |d| {
                const delta = try self.inflateDelta(gpa, d.len);
                defer gpa.free(delta);
                const at = (try self.offsetOf(d.base)) orelse return error.ObjectMissing;
                return self.deltify(gpa, at, delta, depth);
            },
        }
    }

    /// The object `delta` describes against the base at `at`. A delta never
    /// changes the type, so the base's is the answer.
    fn deltify(
        self: *Odb,
        gpa: std.mem.Allocator,
        at: u64,
        delta: []const u8,
        depth: usize,
    ) anyerror!Object {
        const base = try self.readAt(gpa, at, depth + 1);
        defer base.deinit(gpa);
        return .{ .type = base.type, .data = try apply(gpa, base.data, delta) };
    }

    const Entry = union(enum) {
        base: struct { type: Type, len: u64 },
        /// A base this many bytes earlier in the pack.
        ofs: struct { back: u64, len: u64 },
        ref: struct { base: gitpack.Oid, len: u64 },
    };

    /// An entry header: a type and the uncompressed length, low bits first.
    fn entry(self: *Odb) !Entry {
        const r = &self.pack.interface;
        const first: packed struct { len: u4, type: u3, more: bool } = @bitCast(try r.takeByte());
        const rest = if (first.more) try r.takeLeb128(u64) else 0;
        const len = @as(u64, first.len) |
            (std.math.shlExact(u64, rest, 4) catch return error.BadPack);

        return switch (first.type) {
            1, 2, 3, 4 => .{ .base = .{ .type = @fromBackingInt(@intCast(first.type)), .len = len } },
            6 => .{ .ofs = .{ .back = try backOffset(r), .len = len } },
            7 => .{ .ref = .{ .base = try gitpack.Oid.readBytes(self.format, r), .len = len } },
            else => error.BadPack,
        };
    }

    /// A delta stays live while the base under it is read, so a chain holds
    /// one per level rather than one at a time. Held to far less than
    /// `max_object`: a delta bigger than what it rebuilds is not something
    /// git would have written.
    fn inflateDelta(self: *Odb, gpa: std.mem.Allocator, len: u64) ![]u8 {
        if (len > max_delta) return error.ObjectTooLarge;
        return self.inflate(gpa, len);
    }

    fn inflate(self: *Odb, gpa: std.mem.Allocator, len: u64) ![]u8 {
        if (len > max_object) return error.ObjectTooLarge;
        const n: usize = @intCast(len);
        var out: std.Io.Writer.Allocating = .init(gpa);
        errdefer out.deinit();
        try out.ensureTotalCapacity(n + std.compress.flate.max_window_len);
        var d: std.compress.flate.Decompress = .init(&self.pack.interface, .zlib, &.{});
        try d.reader.streamExact(&out.writer, n);
        return out.toOwnedSlice();
    }
};

/// The distance back to a delta's base, which is its own encoding: each byte
/// carries seven bits, and every continuation adds one so no value has two
/// spellings. Source: gitformat-pack.
fn backOffset(r: *std.Io.Reader) !u64 {
    var b = try r.takeByte();
    var value: u64 = b & 0x7f;
    while (b & 0x80 != 0) {
        b = try r.takeByte();
        value = (std.math.add(u64, value, 1) catch return error.BadPack) << 7;
        value |= b & 0x7f;
    }
    return value;
}

/// Applies a delta: the base's length, the result's, then instructions that
/// either copy a run out of the base or insert literal bytes.
/// Source: gitformat-pack.
fn apply(gpa: std.mem.Allocator, base: []const u8, delta: []const u8) ![]u8 {
    var r = std.Io.Reader.fixed(delta);
    if (try r.takeLeb128(u64) != base.len) return error.InvalidDelta;
    const declared = try r.takeLeb128(u64);
    if (declared > max_object) return error.ObjectTooLarge;
    const size: usize = @intCast(declared);

    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    try out.ensureTotalCapacity(size);

    while (r.takeByte() catch null) |inst| {
        if (inst & 0x80 != 0) {
            // Each flag says whether that byte of the offset or the size is
            // present; the absent ones are zero.
            var at: u64 = 0;
            inline for (0..4) |i| {
                if (inst & (@as(u8, 1) << i) != 0) {
                    at |= @as(u64, try r.takeByte()) << (8 * i);
                }
            }
            var run: u64 = 0;
            inline for (0..3) |i| {
                if (inst & (@as(u8, 0x10) << i) != 0) {
                    run |= @as(u64, try r.takeByte()) << (8 * i);
                }
            }
            // Zero means the largest a three-byte size cannot spell.
            if (run == 0) run = 0x10000;
            if (at + run > base.len) return error.InvalidDelta;
            try out.writer.writeAll(base[@intCast(at)..][0..@intCast(run)]);
        } else if (inst != 0) {
            try out.writer.writeAll(try r.take(inst));
        } else {
            // Reserved, and git refuses it rather than guessing.
            return error.InvalidDelta;
        }
    }
    if (out.written().len != size) return error.InvalidDelta;
    return out.toOwnedSlice();
}
