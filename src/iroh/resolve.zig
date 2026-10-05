//! Finding where a node id can be reached.
//!
//! Two sources, and they are not equally good. A pkarr relay hands back the
//! record as its owner signed it, so `lookup` verifies the ed25519 signature
//! and trusts nobody: a hostile relay can withhold an answer or serve a stale
//! one, but it cannot invent an address. Plain DNS hands back the same records
//! with the signature stripped off, so `lookupUnsigned` believes whatever the
//! resolver says. DNS is unauthenticated by design and iroh's zone is not
//! DNSSEC signed, so that answer is a hint, not a fact.
//!
//! Either way an address is only ever a hint about *where*, never about *who*:
//! the TLS handshake that follows makes the peer prove it holds the key we
//! asked about (RFC 7250 raw public keys).
//! Source: iroh-1.0.3/src/address_lookup/{dns,pkarr}.rs, pkarr design/relays.md.
const std = @import("std");

const addr = @import("addr.zig");
const dns = @import("dns.zig");
const node_id = @import("../identity/node_id.zig");
const pkarr = @import("pkarr.zig");
const zbase32 = @import("../crypto/zbase32.zig");

pub const Error = error{
    NoAnswer,
    /// Nobody has published for this key, whichever source was asked.
    NoRecord,
    Truncated,
    NameError,
    ServerFailure,
    RelayRefused,
    /// A newer record is already stored under this key.
    Stale,
    RateLimited,
} || dns.Error;

/// n0's relay and the domain their records hang under.
pub const n0_relay = "https://dns.iroh.link/pkarr";
pub const n0_origin = "dns.iroh.link";

/// Radicle's own, which is where a 2.x node publishes and looks up. Both are
/// live. There is no DNS origin to go with them: the node's iroh preset
/// registers a pkarr publisher and resolver and nothing else.
/// Source: heartwood ng, crates/radicle-node/src/iroh.rs `presets::Radicle`.
pub const radicle_relays = [_][]const u8{
    "https://1.eu.dns.iroh.radicle.network/pkarr",
    "https://1.us.dns.iroh.radicle.network/pkarr",
};

/// What we tell a DNS server we can receive. Not an RFC value: RFC 6891 s6.2.3
/// only says advertise what you can actually take, and treat anything under
/// 512 as 512. 1232 is the DNS flag day 2020 number, the 1280-byte IPv6
/// minimum MTU less 40 for the IPv6 header and 8 for UDP, so a reply never
/// fragments. Still above the 1000 bytes a pkarr record may hold.
pub const max_reply = 1232;

/// Where a lookup went, which decides what the answer is worth.
pub const Source = enum {
    /// A record the key signed, checked here.
    signed,
    /// A resolver's word for it.
    dns,
};

pub const Result = struct {
    addr: addr.Addr,
    source: Source,
    /// Microseconds since the epoch, from the record. Only a signed record has
    /// one, and it is what tells a newer record from an older.
    timestamp: ?u64,

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        self.addr.deinit(allocator);
    }
};

pub const Options = struct {
    /// Tried in order, because a record is stored per relay and either may be
    /// the one holding it. Radicle's by default: a 2.x node publishes to these
    /// two and to nothing else, so n0's relay cannot answer for a radicle peer.
    relays: []const []const u8 = &radicle_relays,
    /// Bytes of record we will hold. A relay may not send more than this.
    max_record: usize = pkarr.max_payload,
    /// A relay stores a record into the mainline DHT before it answers, which
    /// is a lookup across the internet and takes as long as it takes. Generous
    /// therefore, but never unbounded: a relay that goes quiet must not hang
    /// its caller forever.
    timeout_ms: u64 = 30_000,
};

/// Runs `f` with a deadline, since `std.http.Client` takes no timeout of its
/// own. Cancelling really does cut a blocked connect short rather than waiting
/// it out, so `error.Timeout` arrives when it says it will.
fn withDeadline(
    io: std.Io,
    ms: u64,
    comptime f: anytype,
    args: std.meta.ArgsTuple(@TypeOf(f)),
) @typeInfo(@TypeOf(f)).@"fn".return_type.? {
    const Returned = @typeInfo(@TypeOf(f)).@"fn".return_type.?;
    const Outcome = union(enum) { done: Returned, expired: void };

    var buf: [2]Outcome = undefined;
    var select: std.Io.Select(Outcome) = .init(io, &buf);
    select.async(.done, f, args);
    select.async(.expired, expire, .{ io, ms });

    const first = try select.await();
    // Whichever lost is told to stop, and this returns once it has.
    _ = select.cancel();
    return switch (first) {
        .done => |result| result,
        .expired => error.Timeout,
    };
}

fn expire(io: std.Io, ms: u64) void {
    io.sleep(.fromNanoseconds(@intCast(ms * std.time.ns_per_ms)), .awake) catch {};
}

/// Fetches `id`'s record from a pkarr relay and verifies it. The relay is only
/// trusted to hand over bytes: the signature is what makes them true, so this
/// is safe over a connection to a server we have no reason to believe.
///
/// `record` holds the bytes the result borrows, so it must outlive the result.
pub fn lookup(
    io: std.Io,
    allocator: std.mem.Allocator,
    record: []u8,
    id: node_id.NodeId,
    opts: Options,
) !Result {
    const payload = try fetch(io, allocator, record, id, opts);
    const packet = try pkarr.SignedPacket.fromPayload(id.key, payload);

    var it = try addr.iterate(packet);
    var found = try addr.Addr.collect(allocator, id, &it);
    errdefer found.deinit(allocator);
    try requireAddresses(found);

    return .{ .addr = found, .source = .signed, .timestamp = packet.timestamp };
}

/// GETs `<relay>/<z32>`, returning the signature, timestamp and packet the
/// relay stores. Nothing here believes any of it. `lookup` verifies.
/// First relay with an answer wins, so the error returned is the last one's.
/// Source: pkarr design/relays.md.
pub fn fetch(
    io: std.Io,
    allocator: std.mem.Allocator,
    out: []u8,
    id: node_id.NodeId,
    opts: Options,
) ![]u8 {
    var last: anyerror = error.NoRecord;
    for (opts.relays) |relay| {
        return withDeadline(io, opts.timeout_ms, fetchOnce, .{ io, allocator, out, id, relay, opts }) catch |e| {
            last = e;
            continue;
        };
    }
    return last;
}

fn fetchOnce(
    io: std.Io,
    allocator: std.mem.Allocator,
    out: []u8,
    id: node_id.NodeId,
    relay: []const u8,
    opts: Options,
) anyerror![]u8 {
    var z: [zbase32.encoded_key_len]u8 = undefined;
    var url_buf: [256]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "{s}/{s}", .{
        relay,
        try zbase32.encodeBuf(&z, &id.key),
    });

    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();

    const limit = @min(out.len, opts.max_record);
    var body: std.Io.Writer = .fixed(out[0..limit]);
    const res = try client.fetch(.{
        .location = .{ .url = url },
        .response_writer = &body,
    });

    try fetchStatus(res.status);
    return body.buffered();
}

fn fetchStatus(status: std.http.Status) Error!void {
    return switch (status) {
        .ok => {},
        // 404 is a key nobody has published for, not a transport failure.
        .not_found => error.NoRecord,
        else => error.RelayRefused,
    };
}

/// PUTs a signed record to every relay, the way a node does. One acceptance is
/// enough to call it published.
///
/// A relay refusing a record is the only outside check that what we encode is
/// what pkarr specifies.
/// Source: pkarr design/relays.md.
pub fn publish(io: std.Io, allocator: std.mem.Allocator, record: []const u8, opts: Options) !void {
    var last: anyerror = error.RelayRefused;
    var stored = false;
    for (opts.relays) |relay| {
        withDeadline(io, opts.timeout_ms, publishOnce, .{ io, allocator, record, relay }) catch |e| {
            last = e;
            continue;
        };
        stored = true;
    }
    if (!stored) return last;
}

fn publishOnce(
    io: std.Io,
    allocator: std.mem.Allocator,
    record: []const u8,
    relay: []const u8,
) anyerror!void {
    const packet = try pkarr.SignedPacket.parse(record);

    var z: [zbase32.encoded_key_len]u8 = undefined;
    var url_buf: [256]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "{s}/{s}", .{
        relay,
        try zbase32.encodeBuf(&z, &packet.key),
    });

    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();

    const res = try client.fetch(.{
        .location = .{ .url = url },
        .method = .PUT,
        .payload = pkarr.payloadOf(record),
    });

    return publishStatus(res.status);
}

fn publishStatus(status: std.http.Status) Error!void {
    return switch (status) {
        .no_content, .ok => {},
        // Something newer is stored, or our clock went backwards.
        .conflict => error.Stale,
        .too_many_requests => error.RateLimited,
        else => error.RelayRefused,
    };
}

/// Microseconds since the unix epoch, which is what a record's timestamp
/// counts and the only thing ordering one record against another.
pub fn nowMicros(io: std.Io) u64 {
    const ns = std.Io.Timestamp.now(io, .real).nanoseconds;
    return @intCast(@divFloor(ns, std.time.ns_per_us));
}

/// Asks a DNS server for the same records, unsigned. Named so a caller cannot
/// reach for it by accident: what comes back is the resolver's word, and the
/// `Result` says so.
///
/// `reply` holds the datagram the result borrows.
pub fn lookupUnsigned(
    io: std.Io,
    allocator: std.mem.Allocator,
    reply: []u8,
    id: node_id.NodeId,
    opts: DnsOptions,
) !Result {
    var name_buf: [dns.max_name]u8 = undefined;
    const name = try addr.queryName(&name_buf, id, opts.origin);

    // A name that does not exist is the same answer as a name with nothing
    // under it, and as the relay's 404. One name for it, whichever source.
    const msg = ask(io, reply, name, opts) catch |e| switch (e) {
        error.NameError => return error.NoRecord,
        else => return e,
    };
    var it = try addr.iterateMessage(msg, name);
    var found = try addr.Addr.collect(allocator, id, &it);
    errdefer found.deinit(allocator);
    try requireAddresses(found);

    return .{ .addr = found, .source = .dns, .timestamp = null };
}

/// A record saying nothing about the key is the same answer as no record, and
/// must not read as "reachable at no address". The relay spells that 404, a DNS
/// server spells it NOERROR with no answers.
fn requireAddresses(found: addr.Addr) Error!void {
    if (found.isEmpty()) return error.NoRecord;
}

pub const DnsOptions = struct {
    /// Where to ask. Nothing here reads the system configuration, so a caller
    /// picks, and `systemServer` is the usual answer.
    server: std.Io.net.IpAddress,
    origin: []const u8 = n0_origin,
    timeout_ms: u64 = 3000,
    /// A datagram can vanish without anyone minding, so ask more than once.
    attempts: usize = 3,
};

/// Sends one question and returns the reply, which borrows `reply`.
pub fn ask(io: std.Io, reply: []u8, name: []const u8, opts: DnsOptions) ![]u8 {
    var query_buf: [dns.max_name + 64]u8 = undefined;

    var local = switch (opts.server) {
        .ip4 => try std.Io.net.IpAddress.resolve(io, "0.0.0.0", 0),
        .ip6 => try std.Io.net.IpAddress.resolve(io, "::", 0),
    };
    const sock = try local.bind(io, .{ .mode = .dgram });
    defer sock.close(io);

    // Never advertise more than we can hold. A server takes this at its word,
    // and a reply that overruns `reply` is cut by the kernel, which sets no TC
    // bit for the reader to notice it by.
    const advertised: u16 = @intCast(@min(reply.len, max_reply));
    const budget_ns = opts.timeout_ms * std.time.ns_per_ms;

    var attempt: usize = 0;
    while (attempt < opts.attempts) : (attempt += 1) {
        // A fresh id per attempt, so a late answer to the previous one cannot
        // pass for this one.
        var id_bytes: [2]u8 = undefined;
        try io.randomSecure(&id_bytes);
        const id = std.mem.readInt(u16, &id_bytes, .big);

        const query = try dns.writeQuery(&query_buf, id, name, .txt, advertised);
        try sock.send(io, &opts.server, query);

        // Read until this question's answer turns up or the budget runs out.
        // Anything else - a late reply to the previous attempt, a datagram
        // from somewhere else entirely - is dropped, not counted as an answer
        // and not allowed to burn an attempt.
        const started = std.Io.Timestamp.now(io, .awake);
        while (true) {
            const spent = std.Io.Timestamp.now(io, .awake).nanoseconds -| started.nanoseconds;
            if (spent >= budget_ns) break;
            const left: u64 = @intCast(budget_ns - spent);

            const got = sock.receiveTimeout(io, reply, .{ .duration = .{
                .raw = .fromNanoseconds(@intCast(left)),
                .clock = .awake,
            } }) catch |e| switch (e) {
                error.Timeout => break,
                else => return e,
            };

            // The kernel discarded the tail, so what is here is a fragment of
            // an answer rather than a short one.
            if (got.flags.trunc) return error.Truncated;
            // Weak, since a datagram's source is forgeable, but free. Only the
            // signature in `lookup` actually settles who said this.
            if (!got.from.eql(&opts.server)) continue;

            const r = dns.Reader.init(got.data) catch continue;
            if (!r.isResponse() or r.id != id) continue;
            if (r.truncated()) return error.Truncated;
            try rcodeError(r.rcode());
            return got.data;
        }
    }
    return error.NoAnswer;
}

/// A response code (RFC 1035 s4.1.1), as far as a lookup cares.
fn rcodeError(code: u4) Error!void {
    return switch (code) {
        0 => {},
        3 => error.NameError,
        else => error.ServerFailure,
    };
}

/// The first nameserver std finds. It falls back to 127.0.0.1, so this cannot
/// fail for want of a configured server.
pub fn systemServer(io: std.Io) !std.Io.net.IpAddress {
    const rc = try std.Io.net.HostName.ResolvConf.init(io);
    return rc.nameservers_buffer[0];
}

const testing = std.testing;
const signature = @import("../crypto/signature.zig");
const testdata = @import("testdata.zig");

test "the publish path is compiled even though nothing calls it yet" {
    // Zig analyses a function only once something refers to it.
    _ = &publish;
    _ = &nowMicros;
}

test "a record a relay accepted, stored and served back" {
    const record = testdata.hex(testdata.fixture_record);

    // Parsing verifies the signature, so this fails if anything about our
    // bencode, our timestamp or our DNS packet differs from what was signed.
    const packet = try pkarr.SignedPacket.parse(&record);
    try testing.expectEqual(testdata.fixture_timestamp, packet.timestamp);

    // The key in the record is the one our own seed derives, so the committed
    // seed and the committed bytes belong to each other.
    const secret = try signature.SecretKey.fromSeed(testdata.hex(testdata.fixture_seed));
    try testing.expectEqualSlices(u8, &secret.publicKey(), &packet.key);

    var found = try addr.Addr.parse(testing.allocator, packet);
    defer found.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), found.addrs.len);
    try testing.expectEqualStrings("192.0.2.1:4433", found.addrs[0]);
    try testing.expectEqual(@as(usize, 0), found.relays.len);
}

test "a lookup asks for the name the record lives under" {
    const id = try node_id.NodeId.parse("z6MkrLMMsiPWUcNPHcRajuMi9mDfYckSoJyPwwnknocNYPm7");
    var buf: [dns.max_name]u8 = undefined;
    try testing.expectEqualStrings(
        "_iroh.snd196153e58acupm43b7k4773a94brd3u415ne7nf1cowpe9exy.dns.iroh.link",
        try addr.queryName(&buf, id, n0_origin),
    );
}

test "a relay payload is verified against the key it was asked for" {
    const secret = try signature.SecretKey.fromSeed(@splat(21));
    const id = node_id.NodeId.fromPublicKey(secret.publicKey());

    var name_buf: [addr.max_record_name]u8 = undefined;
    var packet_buf: [pkarr.max_packet]u8 = undefined;
    var b = try dns.Builder.init(&packet_buf);
    try b.addTxt(try addr.recordName(&name_buf, id), 30, "addr=192.0.2.1:4433");

    var signed: [pkarr.max_signed]u8 = undefined;
    const record = try pkarr.sign(&signed, secret, b.finish(), 7);

    // What a relay returns: the record without its leading key.
    const payload = pkarr.payloadOf(record);
    const packet = try pkarr.SignedPacket.fromPayload(id.key, payload);
    try testing.expectEqual(@as(u64, 7), packet.timestamp);

    // The same bytes offered as another key's record do not verify, which is
    // what makes a relay safe to fetch from.
    const other = node_id.NodeId.fromPublicKey((try signature.SecretKey.fromSeed(@splat(22))).publicKey());
    try testing.expectError(error.BadSignature, pkarr.SignedPacket.fromPayload(other.key, payload));
}

test "a dns reply is read the same way a packet is" {
    const id = try node_id.NodeId.parse("z6MkrLMMsiPWUcNPHcRajuMi9mDfYckSoJyPwwnknocNYPm7");
    var name_buf: [dns.max_name]u8 = undefined;
    const name = try addr.queryName(&name_buf, id, n0_origin);

    var msg: [1024]u8 = undefined;
    var b = try dns.Builder.init(&msg);
    try b.addTxt(name, 30, "relay=https://euw1-1.relay.n0.iroh.link./");
    try b.addTxt(name, 30, "addr=192.0.2.1:4433");
    const reply = b.finish();

    var it = try addr.iterateMessage(reply, name);
    var result = try addr.Addr.collect(testing.allocator, id, &it);
    defer result.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), result.relays.len);
    try testing.expectEqualStrings("192.0.2.1:4433", result.addrs[0]);
}
