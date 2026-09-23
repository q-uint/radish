//! Reading an object by oid out of wherever the repository put it. gitpack
//! keeps its own object database private, so this is ours: a pack index gives
//! an offset, the entry there gives a type and deflated bytes, and a delta is
//! applied over whatever it points at. An object no pack holds is read from
//! `objects/ab/cdef...` instead.
//!
//! Both halves are needed for a repository `rad` wrote: its only packing is
//! `git gc --auto`, which leaves loose objects alone until there are thousands
//! and adds a pack per fetch until there are dozens.
//! Source: gitformat-pack, gitformat-loose; radicle-node worker/garbage.rs.
const std = @import("std");
const gitpack = @import("gitpack");

pub const Error = error{
    BadPackIndex,
    BadPack,
    BadLooseObject,
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

/// One pack and the v2 index beside it, borrowed for as long as this lives.
/// Everything the index alone can answer is here; what an entry means is the
/// `Odb`'s, since a delta may reach out of the pack it is stored in.
pub const Pack = struct {
    pack: *std.Io.File.Reader,
    idx: *std.Io.File.Reader,

    /// Where `oid`'s entry starts, or null when this pack does not hold it.
    pub fn offsetOf(self: Pack, format: gitpack.Oid.Format, oid: gitpack.Oid) !?u64 {
        const n = try self.count();
        const i = (try self.indexOf(oid, n)) orelse return null;
        return try self.offsetAt(format, i, n);
    }

    /// Objects in the pack, which is the last fan-out bucket: every entry has
    /// a first byte of 0xff or less.
    fn count(self: Pack) !u32 {
        const r = &self.idx.interface;
        try self.idx.seekTo(0);
        if (!std.mem.eql(u8, try r.take(4), idx_magic)) return error.BadPackIndex;
        if (try r.takeInt(u32, .big) != 2) return error.BadPackIndex;
        try self.idx.seekTo(fanout_off + 255 * 4);
        return r.takeInt(u32, .big);
    }

    /// Binary search of the sorted oid table. fan_out[b] counts the oids whose
    /// first byte is at most b, so the candidates sit in [fan_out[b-1], fan_out[b]).
    fn indexOf(self: Pack, oid: gitpack.Oid, n: u32) !?u32 {
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
    fn offsetAt(self: Pack, format: gitpack.Oid.Format, i: u32, n: u32) !u64 {
        const r = &self.idx.interface;
        const width = format.byteLength();
        const offsets = oids_off + @as(u64, n) * (width + 4);
        try self.idx.seekTo(offsets + @as(u64, i) * 4);
        const short = try r.takeInt(u32, .big);
        if (short & 0x80000000 == 0) return short;

        try self.idx.seekTo(offsets + @as(u64, n) * 4 + @as(u64, short & 0x7fffffff) * 8);
        return r.takeInt(u64, .big);
    }

    const Entry = union(enum) {
        base: struct { type: Type, len: u64 },
        /// A base this many bytes earlier in the same pack.
        ofs: struct { back: u64, len: u64 },
        ref: struct { base: gitpack.Oid, len: u64 },
    };

    /// An entry header, read from wherever the pack is positioned: a type and
    /// the uncompressed length, low bits first.
    fn entry(self: Pack, format: gitpack.Oid.Format) !Entry {
        const r = &self.pack.interface;
        const first: packed struct { len: u4, type: u3, more: bool } = @bitCast(try r.takeByte());
        const rest = if (first.more) try r.takeLeb128(u64) else 0;
        const len = @as(u64, first.len) |
            (std.math.shlExact(u64, rest, 4) catch return error.BadPack);

        return switch (first.type) {
            1, 2, 3, 4 => .{ .base = .{ .type = @fromBackingInt(@intCast(first.type)), .len = len } },
            6 => .{ .ofs = .{ .back = try backOffset(r), .len = len } },
            7 => .{ .ref = .{ .base = try gitpack.Oid.readBytes(format, r), .len = len } },
            else => error.BadPack,
        };
    }

    /// A delta stays live while the base under it is read, so a chain holds
    /// one per level rather than one at a time. Held to far less than
    /// `max_object`: a delta bigger than what it rebuilds is not something
    /// git would have written.
    fn inflateDelta(self: Pack, gpa: std.mem.Allocator, len: u64) ![]u8 {
        if (len > max_delta) return error.ObjectTooLarge;
        return self.inflate(gpa, len);
    }

    fn inflate(self: Pack, gpa: std.mem.Allocator, len: u64) ![]u8 {
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

/// Where loose objects are read from. `window` is the decompressor's history
/// and must be at least `max_window_len`; it is borrowed, so a repository
/// allocates one rather than every read paying for its own.
pub const Loose = struct {
    io: std.Io,
    /// The repository directory, the one holding `objects/`.
    dir: std.Io.Dir,
    window: []u8,
};

pub const Odb = struct {
    format: gitpack.Oid.Format,
    /// Every pack in the repository, searched in order. A repository whose
    /// objects have never been collected has none.
    packs: []const Pack,
    /// Absent when nothing may be read loose, which is what a repository
    /// radish packed itself looks like.
    loose: ?Loose = null,

    /// Long enough for anything git writes, short enough that a pack pointing
    /// at itself ends rather than runs out of stack.
    const max_depth = 50;

    /// Which pack holds an entry, and where in it.
    const At = struct { pack: usize, offset: u64 };

    pub fn read(self: *Odb, gpa: std.mem.Allocator, oid: gitpack.Oid) !Object {
        return self.readOid(gpa, oid, 0);
    }

    /// What `oid` is, without inflating a byte of it. A delta never changes
    /// the type, so this follows the chain to a base, but only through entry
    /// headers: a caller that will not walk a blob's content need not pay to
    /// find out it is one. A loose object says so in its own header.
    pub fn typeOf(self: *Odb, oid: gitpack.Oid) !Type {
        return self.typeOfOid(oid, 0);
    }

    /// Whether the repository holds `oid` at all, which an index answers
    /// without decoding pack data and a loose object by existing.
    pub fn has(self: *Odb, oid: gitpack.Oid) !bool {
        if (try self.locate(oid) != null) return true;
        const l = self.loose orelse return false;
        var file = openLoose(l, oid) orelse return false;
        file.close(l.io);
        return true;
    }

    /// `anyerror` because this and `readAt` call each other through a ref
    /// delta: an inferred set cannot close over a cycle.
    fn readOid(self: *Odb, gpa: std.mem.Allocator, oid: gitpack.Oid, depth: usize) anyerror!Object {
        if (depth > max_depth) return error.DeltaTooDeep;
        if (try self.locate(oid)) |at| return self.readAt(gpa, at, depth);
        return (try self.readLoose(gpa, oid)) orelse error.ObjectMissing;
    }

    fn typeOfOid(self: *Odb, oid: gitpack.Oid, depth: usize) anyerror!Type {
        if (depth > max_depth) return error.DeltaTooDeep;
        if (try self.locate(oid)) |at| return self.typeAt(at, depth);
        return (try self.looseType(oid)) orelse error.ObjectMissing;
    }

    fn typeAt(self: *Odb, at: At, depth: usize) anyerror!Type {
        if (depth > max_depth) return error.DeltaTooDeep;
        const p = self.packs[at.pack];
        try p.pack.seekTo(at.offset);
        switch (try p.entry(self.format)) {
            .base => |b| return b.type,
            .ofs => |d| {
                if (d.back > at.offset) return error.BadPack;
                return self.typeAt(.{ .pack = at.pack, .offset = at.offset - d.back }, depth + 1);
            },
            // An oid, so the base may be in another pack or not packed at all.
            .ref => |d| return self.typeOfOid(d.base, depth + 1),
        }
    }

    /// Where `oid`'s entry is, or null when no pack holds it.
    fn locate(self: *Odb, oid: gitpack.Oid) !?At {
        for (self.packs, 0..) |p, i| {
            if (try p.offsetOf(self.format, oid)) |offset| {
                return .{ .pack = i, .offset = offset };
            }
        }
        return null;
    }

    fn readAt(self: *Odb, gpa: std.mem.Allocator, at: At, depth: usize) anyerror!Object {
        if (depth > max_depth) return error.DeltaTooDeep;
        const p = self.packs[at.pack];
        try p.pack.seekTo(at.offset);
        switch (try p.entry(self.format)) {
            .base => |b| return .{ .type = b.type, .data = try p.inflate(gpa, b.len) },
            // The delta before the base: its bytes start here, and reading the
            // base moves the pack away.
            .ofs => |d| {
                const delta = try p.inflateDelta(gpa, d.len);
                defer gpa.free(delta);
                if (d.back > at.offset) return error.BadPack;
                const base = try self.readAt(
                    gpa,
                    .{ .pack = at.pack, .offset = at.offset - d.back },
                    depth + 1,
                );
                return deltified(gpa, base, delta);
            },
            .ref => |d| {
                const delta = try p.inflateDelta(gpa, d.len);
                defer gpa.free(delta);
                const base = try self.readOid(gpa, d.base, depth + 1);
                return deltified(gpa, base, delta);
            },
        }
    }

    /// A loose object, or null when the repository has no such file: one zlib
    /// stream holding `"<type> <len>\x00"` and then the bytes.
    /// Source: gitformat-loose.
    fn readLoose(self: *Odb, gpa: std.mem.Allocator, oid: gitpack.Oid) !?Object {
        const l = self.loose orelse return null;
        var file = openLoose(l, oid) orelse return null;
        defer file.close(l.io);

        var buf: [4096]u8 = undefined;
        var fr = file.reader(l.io, &buf);
        var d: std.compress.flate.Decompress = .init(&fr.interface, .zlib, l.window);
        const head = try looseHeader(&d.reader);

        const n: usize = @intCast(head.len);
        var out: std.Io.Writer.Allocating = .init(gpa);
        errdefer out.deinit();
        try out.ensureTotalCapacity(n);
        d.reader.streamExact(&out.writer, n) catch return error.BadLooseObject;
        return .{ .type = head.type, .data = try out.toOwnedSlice() };
    }

    /// The type a loose object declares, without inflating past its header.
    fn looseType(self: *Odb, oid: gitpack.Oid) !?Type {
        const l = self.loose orelse return null;
        var file = openLoose(l, oid) orelse return null;
        defer file.close(l.io);

        var buf: [4096]u8 = undefined;
        var fr = file.reader(l.io, &buf);
        var d: std.compress.flate.Decompress = .init(&fr.interface, .zlib, l.window);
        return (try looseHeader(&d.reader)).type;
    }
};

/// `objects/ab/cdef...`, or null when nothing is there. An object we cannot
/// open is one the repository does not hold, which is what a caller does with
/// a missing file anyway.
fn openLoose(l: Loose, oid: gitpack.Oid) ?std.Io.File {
    const s = oid.slice();
    var buf: [std.fs.max_name_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(&buf, "objects/{x}/{x}", .{ s[0..1], s[1..] }) catch return null;
    return l.dir.openFile(l.io, path, .{}) catch null;
}

const LooseHeader = struct { type: Type, len: u64 };

fn looseHeader(r: *std.Io.Reader) !LooseHeader {
    const line = r.takeDelimiterInclusive(0) catch return error.BadLooseObject;
    var parts = std.mem.splitScalar(u8, line[0 .. line.len - 1], ' ');
    const kind = std.meta.stringToEnum(Type, parts.first()) orelse return error.BadLooseObject;
    const digits = parts.next() orelse return error.BadLooseObject;
    if (parts.next() != null) return error.BadLooseObject;

    const len = std.fmt.parseInt(u64, digits, 10) catch return error.BadLooseObject;
    if (len > max_object) return error.ObjectTooLarge;
    return .{ .type = kind, .len = len };
}

/// The object `delta` describes against `base`, which this takes over. A delta
/// never changes the type, so the base's is the answer.
fn deltified(gpa: std.mem.Allocator, base: Object, delta: []const u8) !Object {
    defer base.deinit(gpa);
    return .{ .type = base.type, .data = try apply(gpa, base.data, delta) };
}

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
