const std = @import("std");
const radish = @import("radish");

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    if (args.len >= 5 and std.mem.eql(u8, args[1], "ping")) {
        return ping(init, Target.from(args[2], args[3], args[4]) orelse return usage());
    }

    if (args.len >= 5 and std.mem.eql(u8, args[1], "announce")) {
        const alias = if (args.len >= 6) args[5] else "radish";
        return announce(init, Target.from(args[2], args[3], args[4]) orelse return usage(), alias);
    }

    if (args.len >= 5 and std.mem.eql(u8, args[1], "subscribe")) {
        const max: usize = if (args.len >= 6) try std.fmt.parseInt(usize, args[5], 10) else 200;
        return subscribe(init, Target.from(args[2], args[3], args[4]) orelse return usage(), max);
    }

    if (args.len >= 6 and std.mem.eql(u8, args[1], "fetch-probe")) {
        return fetchProbe(init, Target.from(args[2], args[3], args[4]) orelse return usage(), args[5]);
    }

    if (args.len >= 3 and std.mem.eql(u8, args[1], "seeds")) {
        var opts = SeedsOpts{ .rid = args[2] };
        var i: usize = 3;
        while (i < args.len) : (i += 1) {
            const next = if (i + 1 < args.len) args[i + 1] else null;
            if (std.mem.eql(u8, args[i], "--dir")) {
                opts.dir = next orelse return usage();
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--from")) {
                // host:port:node-id, since Noise_XK cannot dial without all
                // three: the node id is a handshake pre-message, not a lookup.
                opts.from = next orelse return usage();
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--frames")) {
                opts.frames = std.fmt.parseInt(usize, next orelse return usage(), 10) catch return usage();
                i += 1;
            } else return usage();
        }
        if (opts.from == null and opts.dir == null) return usage();
        return seeds(init, opts);
    }

    if (args.len >= 3 and std.mem.eql(u8, args[1], "serve")) {
        const port = std.fmt.parseInt(u16, args[2], 10) catch return usage();
        const sessions: usize = if (args.len >= 4)
            std.fmt.parseInt(usize, args[3], 10) catch return usage()
        else
            std.math.maxInt(usize);
        return serve(init, port, sessions);
    }

    // Radicle 2.x, which shares nothing with the commands above but storage.
    if (args.len >= 5 and std.mem.eql(u8, args[1], "quic")) {
        const port = std.fmt.parseInt(u16, args[4], 10) catch return usage();
        if (std.mem.eql(u8, args[2], "ping")) {
            return quicPing(init, args[3], port);
        }
        if (std.mem.eql(u8, args[2], "fetch-probe") and args.len >= 6) {
            return quicFetchProbe(init, args[3], port, args[5]);
        }
        if (std.mem.eql(u8, args[2], "clone") and args.len >= 7) {
            var require = false;
            for (args[7..]) |a| {
                if (std.mem.eql(u8, a, "--require-verified")) require = true;
            }
            return quicClone(init, args[3], port, args[5], args[6], require);
        }
        if (std.mem.eql(u8, args[2], "capture")) {
            const max: usize = if (args.len >= 6)
                std.fmt.parseInt(usize, args[5], 10) catch return usage()
            else
                10;
            return quicCapture(init, args[3], port, max);
        }
        if (std.mem.eql(u8, args[2], "subscribe")) {
            const max: usize = if (args.len >= 6)
                std.fmt.parseInt(usize, args[5], 10) catch return usage()
            else
                200;
            return quicSubscribe(init, args[3], port, max);
        }
        if (std.mem.eql(u8, args[2], "probe")) {
            const alpn = if (args.len >= 6) args[5] else "h3";
            const sni = if (args.len >= 7) args[6] else null;
            return quicProbe(init, args[3], port, alpn, sni);
        }
        return usage();
    }

    if (args.len >= 3 and std.mem.eql(u8, args[1], "peers")) {
        var frames: usize = 200;
        if (args.len >= 5 and std.mem.eql(u8, args[3], "--frames")) {
            frames = std.fmt.parseInt(usize, args[4], 10) catch return usage();
        }
        return peers(init, args[2], frames);
    }

    if (args.len >= 3 and std.mem.eql(u8, args[1], "fetch-deps")) {
        var from: ?[]const u8 = null;
        var dir: []const u8 = ".rad-deps";
        var i: usize = 3;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--from") and i + 1 < args.len) {
                i += 1;
                from = args[i];
            } else dir = args[i];
        }
        return fetchDeps(init, args[2], from, dir);
    }

    if (args.len >= 7 and std.mem.eql(u8, args[1], "clone")) {
        var require = false;
        for (args[7..]) |a| {
            if (std.mem.eql(u8, a, "--require-verified")) require = true;
        }
        const t = Target.from(args[2], args[3], args[4]) orelse return usage();
        return clone(init, t, args[5], args[6], require);
    }

    return usage();
}

fn usage() void {
    std.debug.print(
        \\radish - a radicle client
        \\
        \\usage:
        \\  radish ping        <host> <port> <node-id>              dial a node, handshake, ping/pong
        \\  radish announce    <host> <port> <node-id> [alias]      send a signed NodeAnnouncement
        \\  radish subscribe   <host> <port> <node-id> [frames]     listen to gossip: nodes + inventory
        \\  radish fetch-probe <host> <port> <node-id> <rid>        open a git stream, read the v2 advert
        \\  radish clone       <host> <port> <node-id> <rid> <dir>  clone a repo into <dir> (bare)
        \\    --require-verified                                    exit non-zero if any remote fails verification
        \\  radish seeds       <rid>                                who holds a repo; needs --from or --dir
        \\    --dir <path>                                          remotes in a local clone (no network)
        \\    --from <host>:<port>:<node-id>                        seeds announcing it over gossip
        \\    --frames <n>                                          gossip frames to observe (default 200)
        \\  radish peers       <host>:<port>:<node-id>              nodes seen announcing themselves
        \\    --frames <n>                                          gossip frames to observe (default 200)
        \\  radish fetch-deps  <manifest> [dir]                     resolve `.rad` deps (default .rad-deps)
        \\    --from <host>:<port>:<node-id>                        fetch from this node instead of
        \\                                                          locating a seed over gossip
        \\  radish serve       <port> [sessions]                    answer inbound connections
        \\
        \\radicle 2.x, over QUIC:
        \\  radish quic ping   <host> <port>                        handshake, then a gossip ping/pong
        \\  radish quic subscribe <host> <port> [messages]          listen to gossip (default 200)
        \\  radish quic fetch-probe <host> <port> <rid>             open the git ALPN, list refs
        \\  radish quic clone  <host> <port> <rid> <dir>            clone a repo into <dir> (bare)
        \\    --require-verified                                    exit non-zero if any remote fails verification
        \\  radish quic capture <host> <port> [messages]            record datagrams as hex fixtures
        \\  radish quic probe  <host> <port> [alpn] [sni]           send an Initial, read the reply
        \\                                                          (default alpn h3). Only raw public
        \\                                                          keys are offered, so a public
        \\                                                          server closes on the certificate
        \\
    , .{});
}

fn clone(init: std.process.Init, t: Target, rid_str: []const u8, dir: []const u8, require_verified: bool) !void {
    const arena = init.arena.allocator();
    const nid = try t.nodeId();

    std.debug.print("cloning {s} from {s} into {s}...\n", .{ rid_str, t.nid, dir });
    var result = radish.net.clone.overNoise(init.io, arena, t.host, t.port, nid, rid_str, dir) catch |e| {
        std.debug.print("clone failed: {s}\n", .{@errorName(e)});
        return e;
    };
    defer result.deinit(arena);
    return report(result, rid_str, dir, require_verified);
}

/// What a clone came to, whichever transport carried it.
fn report(
    result: radish.net.clone.CloneResult,
    rid_str: []const u8,
    dir: []const u8,
    require_verified: bool,
) !void {
    std.debug.print("cloned {s}: {d} refs, {d} pack bytes -> {s}\n", .{ rid_str, result.refs, result.pack_bytes, dir });

    for (result.report.verified) |remote| std.debug.print("  verified {s}\n", .{remote});
    for (result.report.failed) |f| std.debug.print("  UNVERIFIED {s}: {s}\n", .{ f.nid, @errorName(f.err) });
    if (result.report.failed.len > 0) {
        std.debug.print("\n{d} of {d} remotes could not be verified\n", .{
            result.report.failed.len,
            result.report.failed.len + result.report.verified.len,
        });
        // Verification is a report, not a filter: the refs stay on disk either
        // way (heartwood's validate does the same). The flag only decides
        // whether an unverified remote is worth a non-zero exit.
        if (require_verified) return error.UnverifiedRemotes;
    }
}

const FetchProbePrinter = struct {
    git_bytes: usize = 0,
    git_frames: usize = 0,

    pub fn onGit(self: *FetchProbePrinter, data: []const u8) void {
        self.git_frames += 1;
        self.git_bytes += data.len;
        std.debug.print("git frame ({d} bytes):\n{f}\n", .{ data.len, std.zig.fmtString(data) });
    }

    pub fn onControl(_: *FetchProbePrinter, ctrl: radish.net.protocol.ControlType, target: u64) void {
        std.debug.print("control {s} stream={d}\n", .{ @tagName(ctrl), target });
    }
};

fn fetchProbe(init: std.process.Init, t: Target, rid_str: []const u8) !void {
    const arena = init.arena.allocator();
    const nid = try t.nodeId();

    var printer = FetchProbePrinter{};
    std.debug.print("fetch-probe {s} from {s}...\n", .{ rid_str, t.nid });
    const frames = radish.net.wire.fetchProbe(init.io, arena, t.host, t.port, nid, rid_str, 20, &printer) catch |e| {
        std.debug.print("fetch-probe failed: {s}\n", .{@errorName(e)});
        return e;
    };
    std.debug.print(
        "\ndone: {d} frames, {d} git frames, {d} git bytes\n",
        .{ frames, printer.git_frames, printer.git_bytes },
    );
}

fn ping(init: std.process.Init, t: Target) !void {
    const arena = init.arena.allocator();
    const nid = try t.nodeId();

    const zeroes = radish.net.wire.ping(init.io, arena, t.host, t.port, nid, 8) catch |e| {
        std.debug.print("ping failed: {s}\n", .{@errorName(e)});
        return e;
    };
    std.debug.print("pong from {s} ({d} zero bytes)\n", .{ t.nid, zeroes });
}

fn announce(init: std.process.Init, t: Target, alias: []const u8) !void {
    const arena = init.arena.allocator();
    const nid = try t.nodeId();

    var seed: [32]u8 = undefined;
    try init.io.randomSecure(&seed);
    const key = try radish.SecretKey.fromSeed(seed);
    const our_nid = try key.nodeId().encode(arena);
    std.debug.print("announcing as {s} (alias {s})\n", .{ our_nid, alias });

    const zeroes = radish.net.wire.sendAnnouncement(init.io, arena, t.host, t.port, nid, key, alias) catch |e| {
        std.debug.print("announce failed: {s}\n", .{@errorName(e)});
        return e;
    };
    std.debug.print("accepted: pong from {s} ({d} zero bytes)\n", .{ t.nid, zeroes });
}

const GossipPrinter = struct {
    arena: std.mem.Allocator,
    nodes: usize = 0,
    inventories: usize = 0,
    rids: usize = 0,
    unsigned: usize = 0,
    undecodable: usize = 0,

    /// A relayed announcement is signed by the node it describes, not by the
    /// peer that passed it on, so an unverified one is worth nothing.
    fn mark(self: *GossipPrinter, ok: bool) []const u8 {
        if (ok) return "";
        self.unsigned += 1;
        return " UNSIGNED";
    }

    pub fn onMessage(self: *GossipPrinter, msg: radish.net.protocol.Message) void {
        switch (msg) {
            .node_announced => |n| {
                self.nodes += 1;
                const id = radish.NodeId.fromPublicKey(n.node).encode(self.arena) catch return;
                std.debug.print("node  {s}  alias={s} agent={s} ts={d} addrs={d}{s}\n", .{
                    id,
                    n.alias,
                    n.agent,
                    n.timestamp,
                    n.addr_count,
                    self.mark(n.verified()),
                });
            },
            .inventory_announced => |inv| {
                self.inventories += 1;
                const id = radish.NodeId.fromPublicKey(inv.node).encode(self.arena) catch return;
                std.debug.print("inv   {s}  {d} repos{s}\n", .{
                    id,
                    inv.inventory.len,
                    self.mark(inv.verified()),
                });
                for (inv.inventory) |oid| {
                    self.rids += 1;
                    const rid = radish.RepoId.fromOid(oid).encode(self.arena) catch continue;
                    std.debug.print("        {s}\n", .{rid});
                }
            },
            // Named, not dropped: knowing which kinds a node sends is half of
            // what a subscribe run is for.
            .other => |t| std.debug.print("other message type {d}\n", .{@backingInt(t)}),
            else => {},
        }
    }

    /// A message this build cannot read is still news: it names a field or an
    /// address kind we do not know yet.
    pub fn onUndecodable(self: *GossipPrinter, err: anyerror) void {
        self.undecodable += 1;
        std.debug.print("undecodable message: {s}\n", .{@errorName(err)});
    }
};

/// Resolves the `.rad` dependencies in a build.zig.zon: clone each repo, verify
/// it really is the RID that was asked for, resolve the canonical branch, and
/// check that commit out into `out_dir/<name>`. A POC; see the README for what
/// it cannot do.
fn fetchDeps(init: std.process.Init, manifest_path: []const u8, from: ?[]const u8, out_dir: []const u8) !void {
    const arena = init.arena.allocator();
    // Only used when the caller named a node; otherwise each dependency is
    // located over gossip, since different repos may live on different seeds.
    const explicit: ?Target = if (from) |f| Target.parse(f) orelse return usage() else null;

    const source = try std.Io.Dir.cwd().readFileAllocOptions(
        init.io,
        manifest_path,
        arena,
        .unlimited,
        .of(u8),
        0,
    );
    const deps = try radish.pkg.manifest.radDeps(arena, source);
    if (deps.len == 0) {
        std.debug.print("no .rad dependencies in {s}\n", .{manifest_path});
        return;
    }

    var edits: std.ArrayList(radish.pkg.rewrite.Set) = .empty;

    for (deps) |dep| {
        std.debug.print("\n{s}: rad:{s}\n", .{ dep.name, dep.rid });

        const dest_name = try std.fmt.allocPrint(arena, "{s}/{s}", .{ out_dir, dep.name });
        // The package root is where build.zig lives, which is the checkout
        // itself unless the manifest named a subdirectory.
        const root = if (dep.subdir) |sub|
            try std.fmt.allocPrint(arena, "{s}/{s}", .{ dest_name, sub })
        else
            dest_name;

        // Hash what is already on disk before touching it. Re-cloning first
        // would overwrite a locally modified dependency and report the tree it
        // just wrote, which checks nothing.
        if (dep.rad_hash) |want| {
            if (hashOf(init.io, arena, root)) |got| {
                if (std.mem.eql(u8, want, got)) {
                    std.debug.print("  rad_hash ok (cached)\n", .{});
                    try edits.append(arena, .{ .dep = dep.name, .field = "path", .value = root });
                    continue;
                }
                std.debug.print("  local tree does not match rad_hash, refetching\n", .{});
            } else |_| {}
        }

        // Clone into a bare repo beside the checkout, since the pack and refs
        // are what verification reads.
        const bare = try std.fmt.allocPrint(arena, "{s}/{s}.git", .{ out_dir, dep.name });
        std.Io.Dir.cwd().deleteTree(init.io, bare) catch {};
        const rid_str = try std.fmt.allocPrint(arena, "rad:{s}", .{dep.rid});

        // --from wins, then the manifest's `.node`, then discovery. A pinned
        // node that is down is a preference we cannot honour, not an error, so
        // it falls back rather than failing the build.
        var result = blk: {
            if (explicit orelse manifestNode(dep)) |pinned| {
                if (cloneFrom(init, pinned, rid_str, bare)) |r| break :blk r else |e| {
                    if (explicit != null) return e;
                    std.debug.print("  {s} unreachable ({s}), locating a seed\n", .{ pinned.host, @errorName(e) });
                    std.Io.Dir.cwd().deleteTree(init.io, bare) catch {};
                }
            }
            const found = try locate(init, rid_str, 500);
            break :blk cloneFrom(init, found, rid_str, bare) catch |e| {
                std.debug.print("  clone failed: {s}\n", .{@errorName(e)});
                return e;
            };
        };
        defer result.deinit(arena);

        // A dependency must not come from an unverified remote, unlike a plain
        // clone where verification is only reported.
        if (result.report.failed.len > 0) {
            for (result.report.failed) |f| {
                std.debug.print("  UNVERIFIED {s}: {s}\n", .{ f.nid, @errorName(f.err) });
            }
            return error.UnverifiedRemotes;
        }

        var repo = try radish.git.storage.Repository.open(init.io, arena, bare);
        defer repo.deinit();

        // A pinned rev still has to be one a delegate published, so it is
        // checked against the same namespaces canonicalHead reads.
        const head = if (dep.rev) |rev| blk: {
            const want = radish.git.storage.parseOid(rev) catch return error.BadRev;
            if (!try repo.revPublishedByDelegate(arena, want)) return error.RevUnauthorized;
            break :blk want;
        } else try repo.canonicalHead(arena);
        std.Io.Dir.cwd().deleteTree(init.io, dest_name) catch {};
        var dest = try std.Io.Dir.cwd().createDirPathOpen(init.io, dest_name, .{});
        defer dest.close(init.io);
        try repo.checkoutTo(arena, dest, head);

        var oid_hex: [40]u8 = undefined;
        _ = std.fmt.bufPrint(&oid_hex, "{x}", .{head.slice()}) catch unreachable;
        std.debug.print("  verified {d} remote(s), checked out {s}\n", .{
            result.report.verified.len,
            oid_hex,
        });

        const rel_build = if (dep.subdir) |s|
            try std.fmt.allocPrint(arena, "{s}/build.zig", .{s})
        else
            "build.zig";
        const has_build = if (dest.statFile(init.io, rel_build, .{})) |_| true else |_| false;
        std.debug.print("  package root: {s}{s}\n", .{
            root,
            if (has_build) "" else "  (no build.zig here)",
        });

        const hash = try hashOf(init.io, arena, root);

        if (dep.rad_hash) |want| {
            if (!std.mem.eql(u8, want, hash)) {
                std.debug.print("  rad_hash mismatch\n    want {s}\n    got  {s}\n", .{ want, hash });
                return error.RadHashMismatch;
            }
            std.debug.print("  rad_hash ok\n", .{});
        }

        try edits.append(arena, .{ .dep = dep.name, .field = "path", .value = root });
        try edits.append(arena, .{ .dep = dep.name, .field = "rad_hash", .value = hash });
    }

    // Zig needs a location and has no `rad` variant, so `.rad` is the source of
    // truth and `.path` is generated. Writing it back keeps the manifest usable
    // by `zig build` without the user maintaining it by hand.
    const updated = try radish.pkg.rewrite.apply(arena, source, edits.items);
    try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = manifest_path, .data = updated });
    std.debug.print("\nupdated {s}\n", .{manifest_path});
}

const ServePrinter = struct {
    sessions: usize = 0,

    pub fn onSession(self: *ServePrinter, stats: radish.net.node.SessionStats) void {
        self.sessions += 1;
        std.debug.print("session: {d} frames, {d} pings, {d} subscribes, {d} announcements\n", .{
            stats.frames, stats.pings, stats.subscribes, stats.announcements,
        });
    }

    pub fn onSessionFailed(_: *ServePrinter, err: anyerror) void {
        std.debug.print("session failed: {s}\n", .{@errorName(err)});
    }
};

/// Connection settings for a live 2.x exchange: a fresh key share and
/// connection id, which RFC 9000 s7.2 wants unpredictable, and the fixed
/// identity so the node keeps seeing the same peer. `quic probe` overrides the
/// fresh parts, since a recorded exchange has to replay.
fn quicDial(init: std.process.Init, host: []const u8, port: u16) !radish.quic.conn.Options {
    const arena = init.arena.allocator();
    var seed: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, radish.quic.testdata.fixed_identity_seed);

    // Allocated, not a local: the options outlive this function.
    const dcid = try arena.alloc(u8, 8);
    try init.io.randomSecure(dcid);

    var opts: radish.quic.conn.Options = .{
        .host = host,
        .port = port,
        .alpn = radish.net.gossip.alpn_gossip,
        .secret = undefined,
        .random = undefined,
        .dcid = dcid,
        .identity = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed),
    };
    try init.io.randomSecure(&opts.secret);
    try init.io.randomSecure(&opts.random);
    return opts;
}

/// The node id a set of options presents.
fn quicNodeId(arena: std.mem.Allocator, opts: radish.quic.conn.Options) ![]u8 {
    return radish.NodeId.fromPublicKey(opts.identity.public_key.toBytes()).encode(arena);
}

/// A radicle 2.x ping: the QUIC handshake, then one gossip message each way.
fn quicPing(init: std.process.Init, host: []const u8, port: u16) !void {
    const quic = radish.quic;
    const arena = init.arena.allocator();
    const opts = try quicDial(init, host, port);
    std.debug.print("quic ping {s}:{d} as {s}\n", .{ host, port, try quicNodeId(arena, opts) });

    const c = try arena.create(quic.conn.Conn);
    defer c.close();
    const pong = radish.net.gossip.ping(init.io, arena, c, opts, 8) catch |e| {
        std.debug.print("quic ping failed: {s}\n", .{@errorName(e)});
        if (c.peerClose()) |close| {
            std.debug.print("  peer closed: 0x{x} {s}\n", .{ close.error_code, close.reason() });
        }
        if (c.lastError()) |last| std.debug.print("  last error: {s}\n", .{@errorName(last)});
        return e;
    };

    if (c.accepted()) |a| if (a.peer_key) |k| {
        std.debug.print("peer node id: {s}\n", .{
            try radish.NodeId.fromPublicKey(k).encode(arena),
        });
    };
    std.debug.print("pong: {d} zeroes\n", .{pong.zeroes});
}

/// Subscribes to a 2.x node's gossip and prints what arrives, the counterpart
/// of `radish subscribe`.
fn quicSubscribe(init: std.process.Init, host: []const u8, port: u16, max: usize) !void {
    const quic = radish.quic;
    const arena = init.arena.allocator();
    const opts = try quicDial(init, host, port);
    std.debug.print("quic subscribe {s}:{d} as {s}\n", .{ host, port, try quicNodeId(arena, opts) });

    var printer = GossipPrinter{ .arena = arena };
    const c = try arena.create(quic.conn.Conn);
    defer c.close();
    const seen = radish.net.gossip.subscribe(init.io, arena, c, opts, max, &printer) catch |e| {
        std.debug.print("quic subscribe failed: {s}\n", .{@errorName(e)});
        if (c.peerClose()) |close| {
            std.debug.print("  peer closed: 0x{x} {s}\n", .{ close.error_code, close.reason() });
        }
        return e;
    };

    std.debug.print(
        "\n{d} message(s): {d} nodes, {d} inventories, {d} repos, {d} unsigned, {d} undecodable\n",
        .{
            seen,
            printer.nodes,
            printer.inventories,
            printer.rids,
            printer.unsigned,
            printer.undecodable,
        },
    );
    // A peer that ends the run says why, and "why" is often the whole story
    // when nothing arrived.
    if (c.peerClose()) |close| {
        std.debug.print("peer closed: 0x{x} {s}\n", .{ close.error_code, close.reason() });
    }
}

/// Records a gossip exchange: every datagram that arrives, as hex, one per
/// line, for pasting into `quic/testdata.zig`. The key share and connection id
/// are the fixed ones, so the recording replays.
fn quicCapture(init: std.process.Init, host: []const u8, port: u16, max: usize) !void {
    const quic = radish.quic;
    const arena = init.arena.allocator();
    const dcid = quic.testdata.hex(quic.testdata.fixed_dcid);

    var opts = try quicDial(init, host, port);
    opts.secret = quic.testdata.hex(quic.testdata.fixed_x25519_secret);
    opts.random = quic.testdata.hex(quic.testdata.fixed_hello_random);
    opts.dcid = &dcid;

    var buf: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writer(init.io, &buf);
    opts.capture = &out.interface;

    var printer = GossipPrinter{ .arena = arena };
    const c = try arena.create(quic.conn.Conn);
    defer c.close();
    // However the capture ends, the reason belongs with the recording.
    defer if (c.peerClose()) |close| {
        std.debug.print("peer closed: 0x{x} {s}\n", .{ close.error_code, close.reason() });
    };
    _ = try radish.net.gossip.subscribe(init.io, arena, c, opts, max, &printer);
    try out.interface.flush();
}

/// Opens the git ALPN, sends the upload-pack intro, and lists the refs the
/// node advertises: the 2.x counterpart of `radish fetch-probe`.
fn quicFetchProbe(init: std.process.Init, host: []const u8, port: u16, rid: []const u8) !void {
    const quic = radish.quic;
    const arena = init.arena.allocator();
    const opts = try quicDial(init, host, port);
    std.debug.print("quic fetch-probe {s}:{d} {s}\n", .{ host, port, rid });

    const c = try arena.create(quic.conn.Conn);
    defer c.close();
    var session = radish.net.gitstream.Session.connect(
        init.io,
        arena,
        c,
        opts,
        rid,
    ) catch |e| {
        std.debug.print("fetch-probe failed: {s}\n", .{@errorName(e)});
        if (c.peerClose()) |close| {
            std.debug.print("  peer closed: 0x{x} {s}\n", .{ close.error_code, close.reason() });
        }
        return e;
    };
    defer session.deinit();

    var refs = radish.git.protocol.lsRefs(arena, &session, &.{"refs/"}) catch |e| {
        std.debug.print("ls-refs failed: {s}\n", .{@errorName(e)});
        if (c.peerClose()) |close| {
            std.debug.print("  peer closed: 0x{x} {s}\n", .{ close.error_code, close.reason() });
        }
        return e;
    };
    defer refs.deinit();

    for (refs.refs) |ref| std.debug.print("{s}  {s}\n", .{ ref.oid, ref.name });
    std.debug.print("\n{d} ref(s)\n", .{refs.refs.len});
}

/// Clones over the git ALPN: the 2.x counterpart of `radish clone`, and the
/// same storage and verification once the bytes are in.
fn quicClone(
    init: std.process.Init,
    host: []const u8,
    port: u16,
    rid: []const u8,
    dir: []const u8,
    require_verified: bool,
) !void {
    const quic = radish.quic;
    const arena = init.arena.allocator();
    const opts = try quicDial(init, host, port);
    std.debug.print("quic clone {s} from {s}:{d} into {s}...\n", .{ rid, host, port, dir });

    const c = try arena.create(quic.conn.Conn);
    defer c.close();
    var result = radish.net.clone.overQuic(init.io, arena, c, opts, rid, dir) catch |e| {
        std.debug.print("clone failed: {s}\n", .{@errorName(e)});
        if (c.lastError()) |last| std.debug.print("  last datagram: {s}\n", .{@errorName(last)});
        if (c.peerClose()) |close| {
            std.debug.print("  peer closed: 0x{x} {s}\n", .{ close.error_code, close.reason() });
        }
        return e;
    };
    defer result.deinit(arena);
    return report(result, rid, dir, require_verified);
}

/// One QUIC first flight against a live server. The x25519 key is fixed, so a
/// recorded reply replays byte for byte; that also means the exchange has no
/// forward secrecy, which is fine for a probe of public traffic.
fn quicProbe(init: std.process.Init, host: []const u8, port: u16, alpn: []const u8, sni: ?[]const u8) !void {
    const quic = radish.quic;
    const arena = init.arena.allocator();
    const dcid = quic.testdata.hex(quic.testdata.fixed_dcid);

    var opts = try quicDial(init, host, port);
    opts.alpn = alpn;
    opts.server_name = sni;
    // Fixed, so a recorded reply replays byte for byte.
    opts.secret = quic.testdata.hex(quic.testdata.fixed_x25519_secret);
    opts.random = quic.testdata.hex(quic.testdata.fixed_hello_random);
    opts.dcid = &dcid;

    std.debug.print("quic probe {s}:{d} alpn={s} as {s}\n", .{
        host,
        port,
        alpn,
        try quicNodeId(arena, opts),
    });

    // Every buffer the connection reports from lives in here, so it stays put.
    const c = try arena.create(quic.conn.Conn);
    c.open(init.io, opts) catch |e| {
        std.debug.print("probe failed: {s}\n", .{@errorName(e)});
        return e;
    };
    defer c.close();
    c.handshake() catch |e| {
        std.debug.print("probe failed: {s}\n", .{@errorName(e)});
        return e;
    };

    std.debug.print("sent {d} bytes, received {d} in {d} datagram(s)\n", .{ c.sent, c.received, c.datagrams });
    // Partial progress is worth printing: a peer that answers the ServerHello
    // and then closes still yields secrets and a reason.
    if (c.accepted()) |a| if (a.handshake != null) {
        std.debug.print("cipher suite 0x{x:0>4}\n", .{a.cipher_suite});
        std.debug.print("server connection id: {x}\n", .{a.scid()});
        if (a.handshake) |h| {
            std.debug.print("client handshake secret: {x}\n", .{h.client});
            std.debug.print("server handshake secret: {x}\n", .{h.server});
        }
        if (a.alpn_len > 0) std.debug.print("alpn: {s}\n", .{a.alpn()});
        if (a.peer_key) |k| std.debug.print("peer node id: {s}{s}\n", .{
            try radish.NodeId.fromPublicKey(k).encode(arena),
            if (a.peer_verified) "" else " (unverified)",
        });
    };
    if (c.confirmed()) {
        std.debug.print("handshake confirmed\n", .{});
    } else if (c.flight_out) {
        std.debug.print("our flight sent, no HANDSHAKE_DONE\n", .{});
    }
    if (c.peerClose()) |close| {
        std.debug.print("peer closed: 0x{x}", .{close.error_code});
        if (radish.quic.frame.cryptoAlert(close.error_code)) |alert| {
            // A CRYPTO_ERROR carries the TLS alert in its low byte, which is
            // the part that says what the peer objected to.
            std.debug.print(" CRYPTO_ERROR, TLS alert {d}", .{alert});
            if (std.enums.tagName(std.crypto.tls.Alert.Description, @fromBackingInt(@intCast(alert)))) |name| {
                std.debug.print(" ({s})", .{name});
            }
        } else if (radish.quic.frame.transportErrorName(close.error_code)) |name| {
            std.debug.print(" {s}", .{name});
        }
        if (close.frame_type) |t| std.debug.print(", triggered by frame 0x{x}", .{t});
        std.debug.print("\n", .{});
        if (close.reason_len > 0) std.debug.print("  reason: {s}\n", .{close.reason()});
    }
    if (c.last_err) |e| {
        std.debug.print("could not complete the handshake: {s}\n", .{@errorName(e)});
    }
    std.debug.print("\nreply datagram ({d} bytes):\n{x}\n", .{ c.last.len, c.last });
}

/// Answers inbound connections. The identity is generated per run, so peers
/// cannot find this node again across restarts; a stored key is the next piece
/// of work.
fn serve(init: std.process.Init, port: u16, sessions: usize) !void {
    const arena = init.arena.allocator();

    // randomSecure everywhere a key is derived: `random` degrades to a weaker
    // source on entropy failure instead of reporting it.
    var seed: [32]u8 = undefined;
    try init.io.randomSecure(&seed);
    const key = try radish.SecretKey.fromSeed(seed);
    const nid = try key.nodeId().encode(arena);

    var printer = ServePrinter{};
    std.debug.print("listening on 0.0.0.0:{d} as {s}\n", .{ port, nid });
    const served = radish.net.node.listen(init.io, arena, port, seed, "radish", sessions, &printer) catch |e| {
        std.debug.print("serve failed: {s}\n", .{@errorName(e)});
        return e;
    };
    std.debug.print("\nserved {d} sessions\n", .{served});
}

/// The dependency's pinned `.node`, or null when it names none or names one
/// that does not parse. A malformed pin falls back to discovery rather than
/// failing, since it is only a preference.
fn manifestNode(dep: radish.pkg.manifest.RadDep) ?Target {
    const spec = dep.node orelse return null;
    return Target.parse(spec);
}

fn cloneFrom(
    init: std.process.Init,
    t: Target,
    rid_str: []const u8,
    bare: []const u8,
) !radish.net.clone.CloneResult {
    const arena = init.arena.allocator();
    const nid = try t.nodeId();
    return radish.net.clone.overNoise(init.io, arena, t.host, t.port, nid, rid_str, bare);
}

/// Asks a bootstrap node who seeds `rid`, and returns the first seed that both
/// holds it and published an address. Discovery needs an entry point of its
/// own, so the bootstrap list is tried in order until one answers.
fn locate(init: std.process.Init, rid_str: []const u8, frames: usize) !Target {
    const arena = init.arena.allocator();
    const want = try radish.RepoId.parse(rid_str);

    for (radish.net.seeds.BOOTSTRAP) |entry| {
        const boot = Target.parse(entry) orelse continue;
        const boot_nid = boot.nodeId() catch continue;

        var locator = radish.net.seeds.Locator.init(arena, want);
        defer locator.deinit();

        _ = radish.net.wire.subscribe(init.io, boot.host, boot.port, boot_nid, frames, &locator) catch |e| {
            std.debug.print("  {s}: {s}\n", .{ boot.host, @errorName(e) });
            continue;
        };

        const found = locator.located() orelse {
            std.debug.print("  {s}: no seed announced it\n", .{boot.host});
            continue;
        };
        const id = try radish.NodeId.fromPublicKey(found.node).encode(arena);
        const spec = try std.fmt.allocPrint(arena, "{s}:{s}", .{ found.addr, id });
        // An address that will not parse is this bootstrap node's answer being
        // unusable, not the end of the search.
        const target = Target.parse(spec) orelse {
            std.debug.print("  {s}: {s} is not a dial target\n", .{ boot.host, found.addr });
            continue;
        };
        std.debug.print("  found {s} at {s} (via {s})\n", .{ id, found.addr, boot.host });
        return target;
    }
    return error.NoSeedFound;
}

/// The tree hash of the directory at `path`.
fn hashOf(io: std.Io, arena: std.mem.Allocator, path: []const u8) ![]u8 {
    var dir = try std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
    defer dir.close(io);
    return radish.pkg.treehash.hashDir(arena, io, dir);
}

/// A dial target, `host:port:node-id`. All three are required: Noise_XK mixes
/// the node id into the handshake before the first byte, so it cannot be
/// looked up from the connection.
const Target = struct {
    host: []const u8,
    port: u16,
    nid: []const u8,

    /// From the colon form, `host:port:node-id`.
    fn parse(spec: []const u8) ?Target {
        var it = std.mem.splitScalar(u8, spec, ':');
        const host = it.next() orelse return null;
        const port_str = it.next() orelse return null;
        const nid = it.next() orelse return null;
        return from(host, port_str, nid);
    }

    /// From three positional arguments, as the older commands take them.
    fn from(host: []const u8, port_str: []const u8, nid: []const u8) ?Target {
        if (host.len == 0 or nid.len == 0) return null;
        return .{
            .host = host,
            .port = std.fmt.parseInt(u16, port_str, 10) catch return null,
            .nid = nid,
        };
    }

    /// The parsed node id, which every command needs before dialing.
    fn nodeId(self: Target) !radish.NodeId {
        return radish.NodeId.parse(self.nid);
    }
};

/// Lists the nodes seen announcing themselves, with the addresses each
/// advertises. Discovery is bounded by what `from` has stored and relays.
fn peers(init: std.process.Init, from: []const u8, frames: usize) !void {
    const arena = init.arena.allocator();
    const target = Target.parse(from) orelse return usage();
    const nid = try target.nodeId();

    var collector = radish.net.seeds.PeerCollector.init(arena);
    defer collector.deinit();

    std.debug.print("watching {s} for peers (up to {d} frames)...\n", .{ target.host, frames });
    const read = radish.net.wire.subscribe(init.io, target.host, target.port, nid, frames, &collector) catch |e| {
        std.debug.print("subscribe failed: {s}\n", .{@errorName(e)});
        return e;
    };

    for (collector.peers()) |p| {
        const id = radish.NodeId.fromPublicKey(p.node).encode(arena) catch continue;
        std.debug.print("peer  {s}  alias={s}\n", .{ id, p.alias });
        for (p.addrs) |a| std.debug.print("        {s}\n", .{a.text});
    }
    std.debug.print("\n{d} peers seen in {d} frames\n", .{ collector.peers().len, read });
}

const SeedsOpts = struct {
    rid: []const u8,
    dir: ?[]const u8 = null,
    from: ?[]const u8 = null,
    frames: usize = 200,
};

/// The two sources answer different questions and neither is a substitute for
/// the other: `--dir` is whose refs we hold, `--from` is who advertises the
/// repo right now. Gossip is a push stream with no "who seeds X" query, so its
/// answer is a lower bound over the observed window, never a complete list.
fn seeds(init: std.process.Init, opts: SeedsOpts) !void {
    const arena = init.arena.allocator();

    if (opts.dir) |path| {
        const remotes = radish.net.seeds.localRemotes(init.io, arena, path) catch |e| {
            std.debug.print("could not read {s}: {s}\n", .{ path, @errorName(e) });
            return e;
        };
        for (remotes) |r| std.debug.print("local {s}\n", .{r});
        std.debug.print("{d} remotes on disk in {s}\n", .{ remotes.len, path });
    }

    const from = opts.from orelse return;
    if (opts.dir != null) std.debug.print("\n", .{});

    const target = Target.parse(from) orelse return usage();
    const nid = try target.nodeId();
    const want = try radish.RepoId.parse(opts.rid);

    var collector = radish.net.seeds.Collector.init(arena, want);
    defer collector.deinit();

    std.debug.print("watching {s} for seeds of {s} (up to {d} frames)...\n", .{ target.host, opts.rid, opts.frames });
    const read = radish.net.wire.subscribe(init.io, target.host, target.port, nid, opts.frames, &collector) catch |e| {
        std.debug.print("subscribe failed: {s}\n", .{@errorName(e)});
        return e;
    };

    for (collector.seeds()) |node| {
        const id = radish.NodeId.fromPublicKey(node).encode(arena) catch continue;
        std.debug.print("seed  {s}\n", .{id});
    }
    std.debug.print(
        "{d} seeds seen in {d} frames ({d} inventories)\n",
        .{ collector.seeds().len, read, collector.inventories },
    );
}

fn subscribe(init: std.process.Init, t: Target, max: usize) !void {
    const arena = init.arena.allocator();
    const nid = try t.nodeId();

    var printer = GossipPrinter{ .arena = arena };
    std.debug.print("subscribing to {s} (up to {d} frames)...\n", .{ t.nid, max });
    const frames = radish.net.wire.subscribe(init.io, t.host, t.port, nid, max, &printer) catch |e| {
        std.debug.print("subscribe failed: {s}\n", .{@errorName(e)});
        return e;
    };
    std.debug.print(
        "\ndone: {d} frames, {d} nodes, {d} inventories, {d} repos\n",
        .{ frames, printer.nodes, printer.inventories, printer.rids },
    );
}
