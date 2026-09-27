//! Just enough DNS wire format (RFC 1035 s4) for a pkarr record: read the
//! answers out of a message, and build one holding TXT records.
//!
//! A pkarr packet is a signed DNS reply, so this never sends or receives
//! anything; it only encodes and decodes the bytes the signature covers.
const std = @import("std");

pub const Error = error{ Malformed, NoSpaceLeft, ValueTooLong };

/// A domain name in text form, dot separated, root written as "".
pub const max_name = 255;
/// One label between the dots.
pub const max_label = 63;

pub const TYPE_TXT: u16 = 16;
pub const CLASS_IN: u16 = 1;

const header_len = 12;
/// Header flags for a reply: QR set, everything else zero, which is what
/// `simple_dns::Packet::new_reply` writes and so what iroh signs.
const flags_reply: u16 = 0x8000;

pub const Answer = struct {
    /// Points into the buffer handed to `next`, valid until the next call.
    name: []const u8,
    kind: u16,
    class: u16,
    ttl: u32,
    /// Points into the message.
    rdata: []const u8,
};

/// Walks the answer section. Questions are skipped, and the authority and
/// additional sections are ignored: a pkarr packet carries neither.
pub const Reader = struct {
    msg: []const u8,
    pos: usize,
    left: u16,

    pub fn init(msg: []const u8) Error!Reader {
        if (msg.len < header_len) return error.Malformed;
        const questions = std.mem.readInt(u16, msg[4..6], .big);
        const answers = std.mem.readInt(u16, msg[6..8], .big);

        var pos: usize = header_len;
        var scratch: [max_name]u8 = undefined;
        for (0..questions) |_| {
            pos = (try readName(msg, pos, &scratch)).next;
            // QTYPE and QCLASS.
            if (pos + 4 > msg.len) return error.Malformed;
            pos += 4;
        }
        return .{ .msg = msg, .pos = pos, .left = answers };
    }

    /// The next answer, or null at the end. `name_buf` must hold `max_name`.
    pub fn next(self: *Reader, name_buf: []u8) Error!?Answer {
        if (self.left == 0) return null;
        self.left -= 1;

        const name = try readName(self.msg, self.pos, name_buf);
        var pos = name.next;
        if (pos + 10 > self.msg.len) return error.Malformed;

        const kind = std.mem.readInt(u16, self.msg[pos..][0..2], .big);
        const class = std.mem.readInt(u16, self.msg[pos + 2 ..][0..2], .big);
        const ttl = std.mem.readInt(u32, self.msg[pos + 4 ..][0..4], .big);
        const rdlen = std.mem.readInt(u16, self.msg[pos + 8 ..][0..2], .big);
        pos += 10;

        if (pos + rdlen > self.msg.len) return error.Malformed;
        const rdata = self.msg[pos..][0..rdlen];
        self.pos = pos + rdlen;

        return .{ .name = name.text, .kind = kind, .class = class, .ttl = ttl, .rdata = rdata };
    }
};

const NameRead = struct {
    text: []const u8,
    /// Where the record continues, which is past the first pointer rather than
    /// past wherever that pointer led.
    next: usize,
};

/// Decodes a name into `out`, following compression pointers. A pointer must
/// lead strictly backwards, which is what RFC 1035 s4.1.4 intends and what
/// makes a loop impossible.
fn readName(msg: []const u8, start: usize, out: []u8) Error!NameRead {
    var pos = start;
    var n: usize = 0;
    var after: ?usize = null;

    while (true) {
        if (pos >= msg.len) return error.Malformed;
        const len = msg[pos];

        if (len & 0xc0 == 0xc0) {
            if (pos + 2 > msg.len) return error.Malformed;
            const off = (@as(usize, len & 0x3f) << 8) | msg[pos + 1];
            if (off >= pos) return error.Malformed;
            if (after == null) after = pos + 2;
            pos = off;
            continue;
        }
        if (len & 0xc0 != 0) return error.Malformed; // reserved label type
        pos += 1;
        if (len == 0) break;
        if (len > max_label or pos + len > msg.len) return error.Malformed;

        if (n != 0) {
            if (n + 1 > out.len) return error.NoSpaceLeft;
            out[n] = '.';
            n += 1;
        }
        if (n + len > out.len) return error.NoSpaceLeft;
        @memcpy(out[n..][0..len], msg[pos..][0..len]);
        n += len;
        pos += len;
    }
    return .{ .text = out[0..n], .next = after orelse pos };
}

/// The character-strings inside TXT rdata. A TXT record is a sequence of
/// length-prefixed strings, and iroh writes exactly one per record.
pub const TxtIterator = struct {
    rdata: []const u8,
    pos: usize = 0,

    pub fn next(self: *TxtIterator) Error!?[]const u8 {
        if (self.pos >= self.rdata.len) return null;
        const len = self.rdata[self.pos];
        const start = self.pos + 1;
        if (start + len > self.rdata.len) return error.Malformed;
        self.pos = start + len;
        return self.rdata[start..][0..len];
    }
};

pub fn txtStrings(rdata: []const u8) TxtIterator {
    return .{ .rdata = rdata };
}

/// Writes a reply holding TXT records. Records under a name already written
/// are compressed to a pointer, which is what keeps a set of records under one
/// long `_iroh.<z32>` name inside pkarr's 1000 byte budget.
pub const Builder = struct {
    buf: []u8,
    pos: usize = 0,
    answers: u16 = 0,
    /// The first name written, and where. Borrowed, so it must outlive the
    /// builder.
    first: ?struct { name: []const u8, off: u16 } = null,

    pub fn init(buf: []u8) Error!Builder {
        if (buf.len < header_len) return error.NoSpaceLeft;
        @memset(buf[0..header_len], 0);
        std.mem.writeInt(u16, buf[2..4], flags_reply, .big);
        return .{ .buf = buf, .pos = header_len };
    }

    pub fn addTxt(self: *Builder, name: []const u8, ttl: u32, value: []const u8) Error!void {
        if (value.len > 255) return error.ValueTooLong;
        try self.writeName(name);

        const fixed = 10 + 1 + value.len; // type, class, ttl, rdlen, then the string
        if (self.pos + fixed > self.buf.len) return error.NoSpaceLeft;

        std.mem.writeInt(u16, self.buf[self.pos..][0..2], TYPE_TXT, .big);
        std.mem.writeInt(u16, self.buf[self.pos + 2 ..][0..2], CLASS_IN, .big);
        std.mem.writeInt(u32, self.buf[self.pos + 4 ..][0..4], ttl, .big);
        std.mem.writeInt(u16, self.buf[self.pos + 8 ..][0..2], @intCast(1 + value.len), .big);
        self.buf[self.pos + 10] = @intCast(value.len);
        @memcpy(self.buf[self.pos + 11 ..][0..value.len], value);
        self.pos += fixed;

        self.answers += 1;
    }

    /// The message, with the answer count filled in.
    pub fn finish(self: *Builder) []u8 {
        std.mem.writeInt(u16, self.buf[6..8], self.answers, .big);
        return self.buf[0..self.pos];
    }

    fn writeName(self: *Builder, name: []const u8) Error!void {
        if (self.first) |f| {
            if (std.mem.eql(u8, f.name, name)) {
                if (self.pos + 2 > self.buf.len) return error.NoSpaceLeft;
                std.mem.writeInt(u16, self.buf[self.pos..][0..2], 0xc000 | f.off, .big);
                self.pos += 2;
                return;
            }
        }

        const off = self.pos;
        if (name.len > max_name) return error.NoSpaceLeft;
        var it = std.mem.splitScalar(u8, name, '.');
        while (it.next()) |label| {
            if (label.len == 0) continue; // a trailing dot is the root, written below
            if (label.len > max_label) return error.Malformed;
            if (self.pos + 1 + label.len > self.buf.len) return error.NoSpaceLeft;
            self.buf[self.pos] = @intCast(label.len);
            @memcpy(self.buf[self.pos + 1 ..][0..label.len], label);
            self.pos += 1 + label.len;
        }
        if (self.pos + 1 > self.buf.len) return error.NoSpaceLeft;
        self.buf[self.pos] = 0;
        self.pos += 1;

        // Only an offset a pointer can reach is worth remembering.
        if (self.first == null and off <= 0x3fff) {
            self.first = .{ .name = name, .off = @intCast(off) };
        }
    }
};

const testing = std.testing;

test "round trip two records under one name" {
    const name = "_iroh.snd196153e58acupm43b7k4773a94brd3u415ne7nf1cowpe9exy";
    var buf: [512]u8 = undefined;
    var b = try Builder.init(&buf);
    try b.addTxt(name, 30, "relay=https://euw1-1.relay.n0.iroh.link./");
    try b.addTxt(name, 30, "addr=192.0.2.1:4433");
    const msg = b.finish();

    // The second name costs two bytes, not the full 57.
    try testing.expect(msg.len < header_len + 2 * (name.len + 2 + 10 + 41));

    var r = try Reader.init(msg);
    var name_buf: [max_name]u8 = undefined;

    const first = (try r.next(&name_buf)).?;
    try testing.expectEqualStrings(name, first.name);
    try testing.expectEqual(TYPE_TXT, first.kind);
    try testing.expectEqual(CLASS_IN, first.class);
    try testing.expectEqual(@as(u32, 30), first.ttl);
    var it = txtStrings(first.rdata);
    try testing.expectEqualStrings("relay=https://euw1-1.relay.n0.iroh.link./", (try it.next()).?);
    try testing.expectEqual(@as(?[]const u8, null), try it.next());

    const second = (try r.next(&name_buf)).?;
    try testing.expectEqualStrings(name, second.name);
    var it2 = txtStrings(second.rdata);
    try testing.expectEqualStrings("addr=192.0.2.1:4433", (try it2.next()).?);

    try testing.expectEqual(@as(?Answer, null), try r.next(&name_buf));
}

test "questions are skipped" {
    // One question for "a.b" A IN, then one TXT answer pointing back at it.
    const msg = [_]u8{
        0x00, 0x00, 0x80, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        1, 'a', 1, 'b', 0, // question name
        0x00, 0x01, 0x00, 0x01, // A IN
        0xc0, 0x0c, // pointer to offset 12
        0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, // TXT IN ttl 30
        0x00, 0x03, 0x02, 'h',  'i',
    };
    var r = try Reader.init(&msg);
    var name_buf: [max_name]u8 = undefined;
    const a = (try r.next(&name_buf)).?;
    try testing.expectEqualStrings("a.b", a.name);
    var it = txtStrings(a.rdata);
    try testing.expectEqualStrings("hi", (try it.next()).?);
}

test "forward pointer rejected" {
    const msg = [_]u8{
        0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0x20, // points forward, past itself
        0x00, 0x10,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x1e,
        0x00, 0x00,
    };
    var r = try Reader.init(&msg);
    var name_buf: [max_name]u8 = undefined;
    try testing.expectError(error.Malformed, r.next(&name_buf));
}

test "truncated rdata rejected" {
    const msg = [_]u8{
        0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, // root name
        0x00,
        0x10,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x1e,
        0x00,
        0x08,
        'n',
        'o',
    };
    var r = try Reader.init(&msg);
    var name_buf: [max_name]u8 = undefined;
    try testing.expectError(error.Malformed, r.next(&name_buf));
}

test "value longer than a character-string rejected" {
    var buf: [512]u8 = undefined;
    var b = try Builder.init(&buf);
    const long: [256]u8 = @splat('x');
    try testing.expectError(error.ValueTooLong, b.addTxt("x", 30, &long));
}
