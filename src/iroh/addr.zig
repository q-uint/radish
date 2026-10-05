//! The `_iroh` records inside a pkarr packet: what a key publishes about where
//! it can be reached.
//!
//! A resolver asks for `_iroh.<z32 endpoint id>.<origin>` and gets TXT strings
//! of the form `key=value` (RFC 1464): `relay`, `addr`, and `user-data`.
//! Source: iroh-dns-1.0.3/src/{attrs,endpoint_info,pkarr}.rs.
const std = @import("std");

const dns = @import("dns.zig");
const pkarr = @import("pkarr.zig");
const node_id = @import("../identity/node_id.zig");
const zbase32 = @import("../crypto/zbase32.zig");

pub const Error = error{ NotAnIrohRecord, UnknownAttr } || dns.Error;

/// The label every iroh record sits under.
pub const label = "_iroh";

/// `_iroh.<z32>`, which is as long as a name gets before an origin is added.
pub const max_record_name = label.len + 1 + zbase32.encoded_key_len;

/// The attributes iroh publishes. The wire spelling is kebab-case, which only
/// `user-data` notices.
pub const Attr = enum {
    relay,
    addr,
    user_data,

    pub fn parse(s: []const u8) ?Attr {
        if (std.mem.eql(u8, s, "relay")) return .relay;
        if (std.mem.eql(u8, s, "addr")) return .addr;
        if (std.mem.eql(u8, s, "user-data")) return .user_data;
        return null;
    }

    pub fn text(self: Attr) []const u8 {
        return switch (self) {
            .relay => "relay",
            .addr => "addr",
            .user_data => "user-data",
        };
    }
};

pub const Entry = struct {
    attr: Attr,
    /// Points into the packet.
    value: []const u8,
};

/// `_iroh.<z32>`, the name a record carries inside a packet.
pub fn recordName(buf: []u8, key: node_id.NodeId) ![]const u8 {
    var z: [zbase32.encoded_key_len]u8 = undefined;
    return std.fmt.bufPrint(buf, "{s}.{s}", .{ label, try zbase32.encodeBuf(&z, &key.key) });
}

/// `_iroh.<z32>.<origin>`, the name a resolver asks a DNS server for.
pub fn queryName(buf: []u8, key: node_id.NodeId, origin: []const u8) ![]const u8 {
    var z: [zbase32.encoded_key_len]u8 = undefined;
    return std.fmt.bufPrint(buf, "{s}.{s}.{s}", .{
        label,
        try zbase32.encodeBuf(&z, &key.key),
        origin,
    });
}

/// The endpoint id in `_iroh.<z32>...`, for the DNS path where the name is all
/// the caller has. In a pkarr packet the signing key is authoritative instead,
/// so `Iterator` never calls this.
pub fn idFromName(name: []const u8) Error!node_id.NodeId {
    var it = std.mem.splitScalar(u8, name, '.');
    const first = it.next() orelse return error.NotAnIrohRecord;
    if (!std.ascii.eqlIgnoreCase(first, label)) return error.NotAnIrohRecord;
    const z = it.next() orelse return error.NotAnIrohRecord;

    var key: [zbase32.key_len]u8 = undefined;
    const decoded = zbase32.decodeBuf(&key, z) catch return error.NotAnIrohRecord;
    if (decoded.len != zbase32.key_len) return error.NotAnIrohRecord;
    return node_id.NodeId.fromPublicKey(key);
}

/// Walks a record's `_iroh` attributes. Hold it by pointer: an `Entry` borrows
/// the packet, and the name it matches against lives in the iterator.
///
/// The endpoint id is the key that signed the packet, never the one spelled in
/// the name, so a record can only ever speak for itself.
pub const Iterator = struct {
    reader: dns.Reader,
    /// The only name that counts: `_iroh.<z32>` inside a packet, or the fully
    /// qualified name a resolver was asked for.
    want: [dns.max_name]u8,
    want_len: usize,
    name_buf: [dns.max_name]u8 = undefined,
    txt: ?dns.TxtIterator = null,
    /// Whether a record named plainly `_iroh`, relative to the packet's own
    /// zone, counts. Only a signed packet may say so: there the signature ties
    /// the record to the key however it is named. In a DNS answer the name is
    /// the only thing tying a record to the id asked about, and anyone able to
    /// add an `_iroh` record to the reply could otherwise put words in its
    /// mouth.
    allow_bare: bool = false,

    pub fn next(self: *Iterator) Error!?Entry {
        while (true) {
            if (self.txt) |*strings| {
                if (try strings.next()) |s| {
                    // An attribute iroh has not taught us about is skipped
                    // rather than fatal: iroh rejects the whole record, but a
                    // reader gains nothing by refusing the rest of what it can
                    // understand.
                    const eq = std.mem.indexOfScalar(u8, s, '=') orelse continue;
                    const attr = Attr.parse(s[0..eq]) orelse continue;
                    return .{ .attr = attr, .value = s[eq + 1 ..] };
                }
                self.txt = null;
            }

            const answer = try self.reader.next(&self.name_buf) orelse return null;
            if (answer.kind != .txt or answer.class != .in) continue;
            if (!self.matches(answer.name)) continue;
            self.txt = dns.txtStrings(answer.rdata);
        }
    }

    /// The comparison ignores case because a resolver is free to vary it in
    /// flight.
    fn matches(self: *const Iterator, name: []const u8) bool {
        if (std.ascii.eqlIgnoreCase(name, self.want[0..self.want_len])) return true;
        return self.allow_bare and std.ascii.eqlIgnoreCase(name, label);
    }
};

/// Reads `packet`, whose signature `pkarr` has already checked. The name it
/// looks for is the signing key's, so the packet can only speak for itself.
pub fn iterate(packet: pkarr.SignedPacket) Error!Iterator {
    var name_buf: [max_record_name]u8 = undefined;
    const want = recordName(&name_buf, node_id.NodeId.fromPublicKey(packet.key)) catch unreachable;
    var it = try iterateMessage(packet.packet, want);
    it.allow_bare = true;
    return it;
}

/// Reads any DNS message for records under `want`. This is the resolver's way
/// in, where nothing is signed and the name asked for is what identifies the
/// answer.
pub fn iterateMessage(msg: []const u8, want: []const u8) Error!Iterator {
    if (want.len > dns.max_name) return error.NotAnIrohRecord;
    var it: Iterator = .{
        .reader = try dns.Reader.init(msg),
        .want = undefined,
        .want_len = want.len,
    };
    @memcpy(it.want[0..want.len], want);
    return it;
}

/// Everything one record says, collected. The slices point into the packet, so
/// this lives no longer than the bytes it was read from.
pub const Addr = struct {
    id: node_id.NodeId,
    relays: [][]const u8,
    addrs: [][]const u8,
    user_data: ?[]const u8,

    pub fn parse(allocator: std.mem.Allocator, packet: pkarr.SignedPacket) !Addr {
        var it = try iterate(packet);
        return collect(allocator, node_id.NodeId.fromPublicKey(packet.key), &it);
    }

    /// Drains `it` into one address. `id` is the caller's: a signed packet
    /// names its own key, a DNS answer names whoever was asked about.
    pub fn collect(allocator: std.mem.Allocator, id: node_id.NodeId, it: *Iterator) !Addr {
        var relays: std.ArrayList([]const u8) = .empty;
        errdefer relays.deinit(allocator);
        var addrs: std.ArrayList([]const u8) = .empty;
        errdefer addrs.deinit(allocator);
        var user_data: ?[]const u8 = null;

        while (try it.next()) |entry| switch (entry.attr) {
            .relay => try relays.append(allocator, entry.value),
            .addr => try addrs.append(allocator, entry.value),
            // Last wins, as with a repeated key in any `key=value` set.
            .user_data => user_data = entry.value,
        };

        // Taken one at a time: `toOwnedSlice` empties the list, so the errdefer
        // above no longer covers what it handed over.
        const relay_slice = try relays.toOwnedSlice(allocator);
        errdefer allocator.free(relay_slice);
        const addr_slice = try addrs.toOwnedSlice(allocator);

        return .{
            .id = id,
            .relays = relay_slice,
            .addrs = addr_slice,
            .user_data = user_data,
        };
    }

    /// Whether the record said anything about this key at all.
    pub fn isEmpty(self: Addr) bool {
        return self.relays.len == 0 and self.addrs.len == 0 and self.user_data == null;
    }

    pub fn deinit(self: *Addr, allocator: std.mem.Allocator) void {
        allocator.free(self.relays);
        allocator.free(self.addrs);
        self.* = undefined;
    }
};

const testing = std.testing;
const signature = @import("../crypto/signature.zig");

/// Signs `values` as one record under `name`, the way a publisher would.
fn record(out: []u8, packet_buf: []u8, secret: signature.SecretKey, name: []const u8, values: []const []const u8) ![]u8 {
    var b = try dns.Builder.init(packet_buf);
    for (values) |v| try b.addTxt(name, 30, v);
    return pkarr.sign(out, secret, b.finish(), 1);
}

fn testKey(seed: u8) !signature.SecretKey {
    return signature.SecretKey.fromSeed(@splat(seed));
}

test "reads what a record says" {
    const secret = try testKey(11);
    const id = node_id.NodeId.fromPublicKey(secret.publicKey());

    var name_buf: [max_record_name]u8 = undefined;
    const name = try recordName(&name_buf, id);

    var packet_buf: [pkarr.max_packet]u8 = undefined;
    var out: [pkarr.max_signed]u8 = undefined;
    const bytes = try record(&out, &packet_buf, secret, name, &.{
        "relay=https://euw1-1.relay.n0.iroh.link./",
        "addr=192.0.2.1:4433",
        "addr=[2001:db8::1]:4433",
        "user-data=radish",
    });

    var addr = try Addr.parse(testing.allocator, try pkarr.SignedPacket.parse(bytes));
    defer addr.deinit(testing.allocator);

    try testing.expectEqualSlices(u8, &id.key, &addr.id.key);
    try testing.expectEqual(@as(usize, 1), addr.relays.len);
    try testing.expectEqualStrings("https://euw1-1.relay.n0.iroh.link./", addr.relays[0]);
    try testing.expectEqual(@as(usize, 2), addr.addrs.len);
    try testing.expectEqualStrings("192.0.2.1:4433", addr.addrs[0]);
    try testing.expectEqualStrings("[2001:db8::1]:4433", addr.addrs[1]);
    try testing.expectEqualStrings("radish", addr.user_data.?);
}

test "a bare _iroh name counts, another key's name does not" {
    const secret = try testKey(12);

    var packet_buf: [pkarr.max_packet]u8 = undefined;
    var out: [pkarr.max_signed]u8 = undefined;
    const bytes = try record(&out, &packet_buf, secret, label, &.{"addr=192.0.2.1:4433"});
    var addr = try Addr.parse(testing.allocator, try pkarr.SignedPacket.parse(bytes));
    defer addr.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), addr.addrs.len);

    // Signed by one key, named after another: the name is what loses, since
    // the id comes from the signature.
    var other_name: [max_record_name]u8 = undefined;
    const other = try recordName(&other_name, node_id.NodeId.fromPublicKey((try testKey(13)).publicKey()));
    const bytes2 = try record(&out, &packet_buf, secret, other, &.{"addr=192.0.2.1:4433"});
    var addr2 = try Addr.parse(testing.allocator, try pkarr.SignedPacket.parse(bytes2));
    defer addr2.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), addr2.addrs.len);
}

test "a bare _iroh in a dns answer is ignored" {
    // Same record, read the two ways. Under a signature the bare name is the
    // key's own zone-relative record, and in a DNS answer it is whatever the
    // resolver felt like adding, so only the fully qualified name counts.
    const secret = try testKey(15);
    const id = node_id.NodeId.fromPublicKey(secret.publicKey());

    var packet_buf: [pkarr.max_packet]u8 = undefined;
    var out: [pkarr.max_signed]u8 = undefined;
    const bytes = try record(&out, &packet_buf, secret, label, &.{"addr=192.0.2.1:4433"});
    const packet = try pkarr.SignedPacket.parse(bytes);

    var signed = try Addr.parse(testing.allocator, packet);
    defer signed.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), signed.addrs.len);

    var name_buf: [max_record_name + 32]u8 = undefined;
    const queried = try queryName(&name_buf, id, "dns.iroh.link");
    var it = try iterateMessage(packet.packet, queried);
    var unsigned = try Addr.collect(testing.allocator, id, &it);
    defer unsigned.deinit(testing.allocator);
    try testing.expect(unsigned.isEmpty());
}

test "an attribute we do not know is skipped, not fatal" {
    const secret = try testKey(14);
    var name_buf: [max_record_name]u8 = undefined;
    const name = try recordName(&name_buf, node_id.NodeId.fromPublicKey(secret.publicKey()));

    var packet_buf: [pkarr.max_packet]u8 = undefined;
    var out: [pkarr.max_signed]u8 = undefined;
    const bytes = try record(&out, &packet_buf, secret, name, &.{
        "future=whatever",
        "novalue",
        "addr=192.0.2.1:4433",
    });

    var addr = try Addr.parse(testing.allocator, try pkarr.SignedPacket.parse(bytes));
    defer addr.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), addr.addrs.len);
}

test "an attribute round trips through its wire spelling" {
    for ([_]Attr{ .relay, .addr, .user_data }) |a| {
        try testing.expectEqual(a, Attr.parse(a.text()).?);
    }
    try testing.expectEqual(@as(?Attr, null), Attr.parse("user_data"));
}

test "names a resolver asks for" {
    const id = try node_id.NodeId.parse("z6MkrLMMsiPWUcNPHcRajuMi9mDfYckSoJyPwwnknocNYPm7");
    var buf: [max_record_name + 32]u8 = undefined;

    try testing.expectEqualStrings(
        "_iroh.snd196153e58acupm43b7k4773a94brd3u415ne7nf1cowpe9exy.dns.iroh.link",
        try queryName(&buf, id, "dns.iroh.link"),
    );
    try testing.expectEqualStrings(
        "_iroh.snd196153e58acupm43b7k4773a94brd3u415ne7nf1cowpe9exy",
        try recordName(&buf, id),
    );
}

test "the id in a name round trips, and a foreign name is refused" {
    const id = try node_id.NodeId.parse("z6MkrLMMsiPWUcNPHcRajuMi9mDfYckSoJyPwwnknocNYPm7");
    var buf: [max_record_name + 32]u8 = undefined;

    const parsed = try idFromName(try queryName(&buf, id, "dns.iroh.link"));
    try testing.expectEqualSlices(u8, &id.key, &parsed.key);

    try testing.expectError(error.NotAnIrohRecord, idFromName("_dns.abc.example"));
    try testing.expectError(error.NotAnIrohRecord, idFromName("_iroh"));
    try testing.expectError(error.NotAnIrohRecord, idFromName("_iroh.notz32"));
}
