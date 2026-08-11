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

    if (args.len >= 3 and std.mem.eql(u8, args[1], "peers")) {
        var frames: usize = 200;
        if (args.len >= 5 and std.mem.eql(u8, args[3], "--frames")) {
            frames = std.fmt.parseInt(usize, args[4], 10) catch return usage();
        }
        return peers(init, args[2], frames);
    }

    if (args.len >= 4 and std.mem.eql(u8, args[1], "fetch-deps")) {
        return fetchDeps(init, args[2], args[3], if (args.len >= 5) args[4] else ".rad-deps");
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
        \\  radish fetch-deps  <manifest> <host>:<port>:<node-id> [dir]
        \\                                                          resolve `.rad` deps (default .rad-deps)
        \\
    , .{});
}

fn clone(init: std.process.Init, t: Target, rid_str: []const u8, dir: []const u8, require_verified: bool) !void {
    const arena = init.arena.allocator();
    const nid = try t.nodeId(arena);

    std.debug.print("cloning {s} from {s} into {s}...\n", .{ rid_str, t.nid, dir });
    var result = radish.net.fetch.clone(init.io, arena, t.host, t.port, nid, rid_str, dir) catch |e| {
        std.debug.print("clone failed: {s}\n", .{@errorName(e)});
        return e;
    };
    defer result.deinit(arena);
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
    const nid = try t.nodeId(arena);

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
    const nid = try t.nodeId(arena);

    const zeroes = radish.net.wire.ping(init.io, arena, t.host, t.port, nid, 8) catch |e| {
        std.debug.print("ping failed: {s}\n", .{@errorName(e)});
        return e;
    };
    std.debug.print("pong from {s} ({d} zero bytes)\n", .{ t.nid, zeroes });
}

fn announce(init: std.process.Init, t: Target, alias: []const u8) !void {
    const arena = init.arena.allocator();
    const nid = try t.nodeId(arena);

    var seed: [32]u8 = undefined;
    init.io.random(&seed);
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

    pub fn onMessage(self: *GossipPrinter, msg: radish.net.protocol.Message) void {
        switch (msg) {
            .node_announced => |n| {
                self.nodes += 1;
                const id = radish.NodeId.fromPublicKey(n.node).encode(self.arena) catch return;
                std.debug.print("node  {s}  alias={s} agent={s}\n", .{ id, n.alias, n.agent });
            },
            .inventory_announced => |inv| {
                self.inventories += 1;
                const id = radish.NodeId.fromPublicKey(inv.node).encode(self.arena) catch return;
                std.debug.print("inv   {s}  {d} repos\n", .{ id, inv.inventory.len });
                for (inv.inventory) |oid| {
                    self.rids += 1;
                    const rid = radish.RepoId.fromOid(oid).encode(self.arena) catch continue;
                    std.debug.print("        {s}\n", .{rid});
                }
            },
            else => {},
        }
    }
};

/// Resolves the `.rad` dependencies in a build.zig.zon: clone each repo, verify
/// it really is the RID that was asked for, resolve the canonical branch, and
/// check that commit out into `out_dir/<name>`.
///
/// POC. See README for the limitations, the main one being that Zig cannot
/// consume the result automatically: its dependency location is a closed union
/// of `url` and `path`, so a `.rad` field is parsed by us and ignored by Zig.
fn fetchDeps(init: std.process.Init, manifest_path: []const u8, from: []const u8, out_dir: []const u8) !void {
    const arena = init.arena.allocator();
    const target = Target.parse(from) orelse return usage();
    const nid = try target.nodeId(arena);

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

        var result = radish.net.fetch.clone(init.io, arena, target.host, target.port, nid, rid_str, bare) catch |e| {
            std.debug.print("  clone failed: {s}\n", .{@errorName(e)});
            return e;
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
    fn nodeId(self: Target, arena: std.mem.Allocator) !radish.NodeId {
        return radish.NodeId.parse(arena, self.nid);
    }
};

/// Lists the nodes seen announcing themselves, with the addresses each
/// advertises. Discovery is bounded by what `from` has stored and relays.
fn peers(init: std.process.Init, from: []const u8, frames: usize) !void {
    const arena = init.arena.allocator();
    const target = Target.parse(from) orelse return usage();
    const nid = try target.nodeId(arena);

    var collector = radish.net.seeds.PeerCollector.init(arena);
    defer collector.deinit();

    std.debug.print("watching {s} for peers (up to {d} frames)...\n", .{ target.host, frames });
    const read = radish.net.wire.subscribe(init.io, arena, target.host, target.port, nid, frames, &collector) catch |e| {
        std.debug.print("subscribe failed: {s}\n", .{@errorName(e)});
        return e;
    };

    for (collector.peers()) |p| {
        const id = radish.NodeId.fromPublicKey(p.node).encode(arena) catch continue;
        std.debug.print("peer  {s}  alias={s}\n", .{ id, p.alias });
        for (p.addrs) |a| std.debug.print("        {s}\n", .{a});
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
    const nid = try target.nodeId(arena);
    const want = try radish.RepoId.parse(arena, opts.rid);

    var collector = radish.net.seeds.Collector.init(arena, want);
    defer collector.deinit();

    std.debug.print("watching {s} for seeds of {s} (up to {d} frames)...\n", .{ target.host, opts.rid, opts.frames });
    const read = radish.net.wire.subscribe(init.io, arena, target.host, target.port, nid, opts.frames, &collector) catch |e| {
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
    const nid = try t.nodeId(arena);

    var printer = GossipPrinter{ .arena = arena };
    std.debug.print("subscribing to {s} (up to {d} frames)...\n", .{ t.nid, max });
    const frames = radish.net.wire.subscribe(init.io, arena, t.host, t.port, nid, max, &printer) catch |e| {
        std.debug.print("subscribe failed: {s}\n", .{@errorName(e)});
        return e;
    };
    std.debug.print(
        "\ndone: {d} frames, {d} nodes, {d} inventories, {d} repos\n",
        .{ frames, printer.nodes, printer.inventories, printer.rids },
    );
}
