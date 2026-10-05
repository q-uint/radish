const std = @import("std");
const radish = @import("radish");

const cli = radish.args;
const Arg = cli.Arg;
const Flag = cli.Flag;

const NodeId = radish.identity.NodeId;
const RepoId = radish.identity.RepoId;

/// Shared so a description is written once and reads the same everywhere.
const host_help = "hostname or address of the node";
const port_help = "TCP port, usually 8776";
const node_id_help = "the node's z6Mk... identity";
const rid_help = "repository id, rad:z...";
const seed_help = "a seed, as host:port:node-id";
const repo_help = "path to a bare repo: a dir of objects/ and refs/";
const dir_help = "path for the bare repo, created if missing";
const manifest_help = "path to a build.zig.zon";

const Ping = struct {
    pub const about = "dial a node, handshake, ping/pong";
    host: Arg([]const u8, host_help),
    port: Arg(u16, port_help),
    node_id: Arg(NodeId, node_id_help),
};

const Announce = struct {
    pub const about = "send a signed NodeAnnouncement";
    host: Arg([]const u8, host_help),
    port: Arg(u16, port_help),
    node_id: Arg(NodeId, node_id_help),
    alias: Arg([]const u8, "the name to announce ourselves under") = .{ .value = "radish" },
};

const Subscribe = struct {
    pub const about = "listen to gossip: nodes and inventory";
    host: Arg([]const u8, host_help),
    port: Arg(u16, port_help),
    node_id: Arg(NodeId, node_id_help),
    flags: struct {
        frames: Flag(usize, "gossip frames to observe") = .{ .value = 200 },
    } = .{},
};

const FetchProbe = struct {
    pub const about = "open a git stream, read the v2 advertisement";
    host: Arg([]const u8, host_help),
    port: Arg(u16, port_help),
    node_id: Arg(NodeId, node_id_help),
    rid: Arg(RepoId, rid_help),
};

const Clone = struct {
    pub const about = "clone a repo into <dir> (bare)";
    host: Arg([]const u8, host_help),
    port: Arg(u16, port_help),
    node_id: Arg(NodeId, node_id_help),
    rid: Arg(RepoId, rid_help),
    dir: Arg([]const u8, dir_help),
    flags: struct {
        require_verified: Flag(bool, "exit non-zero if any remote fails verification") = .{ .value = false },
    } = .{},
};

const Seeds = struct {
    pub const about = "who holds a repo; needs --from or --dir";
    rid: Arg(RepoId, rid_help),
    flags: struct {
        dir: Flag(?[]const u8, "remotes in a local clone (no network)") = .{ .value = null },
        from: Flag(?[]const u8, seed_help) = .{ .value = null },
        frames: Flag(usize, "gossip frames to observe") = .{ .value = 200 },
    } = .{},
};

const Peers = struct {
    pub const about = "nodes seen announcing themselves";
    from: Arg([]const u8, seed_help),
    flags: struct {
        frames: Flag(usize, "gossip frames to observe") = .{ .value = 200 },
    } = .{},
};

const Resolve = struct {
    pub const about = "where a node id says it can be reached";
    node_id: Arg(NodeId, node_id_help),
    flags: struct {
        relay: Flag(?[]const u8, "pkarr relay to ask, default radicle's two") =
            .{ .value = null },
        dns: Flag(bool, "ask DNS instead, whose answer is unsigned") =
            .{ .value = false },
        origin: Flag([]const u8, "domain the records hang under, with --dns") =
            .{ .value = radish.iroh.resolve.n0_origin },
        server: Flag(?[]const u8, "DNS server to ask, default /etc/resolv.conf") =
            .{ .value = null },
    } = .{},
};

const FetchDeps = struct {
    pub const about = "resolve `.rad` deps in a build.zig.zon";
    manifest: Arg([]const u8, manifest_help),
    dir: Arg([]const u8, "where each dependency is checked out") = .{ .value = ".rad-deps" },
    flags: struct {
        from: Flag(?[]const u8, "fetch from this node instead of a seed") = .{ .value = null },
    } = .{},
};

const Serve = struct {
    pub const about = "answer inbound connections out of <storage>";
    port: Arg(u16, port_help),
    sessions: Arg(?usize, "stop after this many; unbounded by default") = .{ .value = null },
    storage: Arg(?[]const u8, "a root of <rid> repositories to serve") = .{ .value = null },
};

const UploadPack = struct {
    pub const about = "serve one git v2 fetch on stdin/stdout";
    repo: Arg([]const u8, repo_help),
};

const VerifyPack = struct {
    pub const about = "check every pack against its own checksums";
    repo: Arg([]const u8, repo_help),
};

const QuicPing = struct {
    pub const about = "handshake, then a gossip ping/pong";
    host: Arg([]const u8, host_help),
    port: Arg(u16, port_help),
};

const QuicSubscribe = struct {
    pub const about = "listen to gossip";
    host: Arg([]const u8, host_help),
    port: Arg(u16, port_help),
    flags: struct {
        messages: Flag(usize, "gossip messages to observe") = .{ .value = 200 },
    } = .{},
};

const QuicFetchProbe = struct {
    pub const about = "open the git ALPN, list refs";
    host: Arg([]const u8, host_help),
    port: Arg(u16, port_help),
    rid: Arg(RepoId, rid_help),
};

const QuicClone = struct {
    pub const about = "clone a repo into <dir> (bare)";
    host: Arg([]const u8, host_help),
    port: Arg(u16, port_help),
    rid: Arg(RepoId, rid_help),
    dir: Arg([]const u8, dir_help),
    flags: struct {
        require_verified: Flag(bool, "exit non-zero if any remote fails verification") = .{ .value = false },
        profile: Flag(bool, "print connection counters on exit") = .{ .value = false },
    } = .{},
};

const QuicCapture = struct {
    pub const about = "record datagrams as hex fixtures";
    host: Arg([]const u8, host_help),
    port: Arg(u16, port_help),
    flags: struct {
        messages: Flag(usize, "datagrams to record") = .{ .value = 10 },
    } = .{},
};

const QuicProbe = struct {
    pub const about = "send an Initial, read the reply";
    host: Arg([]const u8, host_help),
    port: Arg(u16, port_help),
    alpn: Arg([]const u8, "only raw public keys are offered, so a public server closes") = .{ .value = "h3" },
    sni: Arg(?[]const u8, "server name to send, if any") = .{ .value = null },
};

const commands = .{
    .{ .name = "ping", .Args = Ping, .run = ping },
    .{ .name = "announce", .Args = Announce, .run = announce },
    .{ .name = "subscribe", .Args = Subscribe, .run = subscribe },
    .{ .name = "fetch-probe", .Args = FetchProbe, .run = fetchProbe },
    .{ .name = "clone", .Args = Clone, .run = clone },
    .{ .name = "seeds", .Args = Seeds, .run = seeds },
    .{ .name = "peers", .Args = Peers, .run = peers },
    .{ .name = "resolve", .Args = Resolve, .run = resolve },
    .{ .name = "fetch-deps", .Args = FetchDeps, .run = fetchDeps },
    .{ .name = "serve", .Args = Serve, .run = serve },
    .{ .name = "upload-pack", .Args = UploadPack, .run = uploadPack },
    .{ .name = "verify-pack", .Args = VerifyPack, .run = verifyPack },
};

const quic_commands = .{
    .{ .name = "ping", .Args = QuicPing, .run = quicPing },
    .{ .name = "subscribe", .Args = QuicSubscribe, .run = quicSubscribe },
    .{ .name = "fetch-probe", .Args = QuicFetchProbe, .run = quicFetchProbe },
    .{ .name = "clone", .Args = QuicClone, .run = quicClone },
    .{ .name = "capture", .Args = QuicCapture, .run = quicCapture },
    .{ .name = "probe", .Args = QuicProbe, .run = quicProbe },
};

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(arena);
    if (argv.len < 2 or wantsHelp(argv[1..2])) return usage();

    // Radicle 2.x, which shares nothing with the commands above but storage.
    if (std.mem.eql(u8, argv[1], "quic")) {
        if (argv.len < 3) return usage();
        return dispatch(quic_commands, "radish quic ", init, argv[2], argv[3..]);
    }
    return dispatch(commands, "radish ", init, argv[1], argv[2..]);
}

/// Runs the command `name` out of `table`, or prints the whole usage when
/// nothing matches. A command that matches but will not parse prints its own
/// line rather than every other command's.
fn dispatch(
    comptime table: anytype,
    comptime prefix: []const u8,
    init: std.process.Init,
    name: []const u8,
    rest: []const []const u8,
) !void {
    inline for (table) |c| {
        if (std.mem.eql(u8, name, c.name)) {
            if (wantsHelp(rest)) return printHelp(c.Args, prefix ++ c.name);

            var diag: cli.Diagnostic = .{};
            const parsed = cli.parse(c.Args, rest, &diag) catch |e| {
                var buf: [256]u8 = undefined;
                var w = std.Io.Writer.fixed(&buf);
                diag.report(e, &w) catch {};
                std.debug.print("{s}{s}: {s}\n", .{ prefix, c.name, w.buffered() });
                printUsage(c.Args, prefix ++ c.name);
                // A misspelled argument is the user's mistake, not a crash:
                // returning the error would dump a stack trace over the help.
                std.process.exit(2);
            };
            return c.run(init, parsed);
        }
    }
    return usage();
}

fn wantsHelp(argv: []const []const u8) bool {
    for (argv) |a| {
        if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) return true;
    }
    return false;
}

fn printUsage(comptime Args: type, comptime name: []const u8) void {
    var buf: [1024]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    cli.usage(Args, name, &w) catch {};
    std.debug.print("{s}", .{w.buffered()});
}

fn printHelp(comptime Args: type, comptime name: []const u8) void {
    var buf: [2048]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    cli.help(Args, name, &w) catch {};
    std.debug.print("{s}", .{w.buffered()});
}

fn usage() void {
    std.debug.print("radish - a radicle client\n\nusage:\n", .{});
    inline for (commands) |c| printUsage(c.Args, "radish " ++ c.name);
    std.debug.print("\nradicle 2.x, over QUIC:\n", .{});
    inline for (quic_commands) |c| printUsage(c.Args, "radish quic " ++ c.name);
}

/// The three arguments every 1.x command dials with.
fn targetOf(a: anytype) Target {
    return .{ .host = a.host.value, .port = a.port.value, .nid = a.node_id.value };
}

fn clone(init: std.process.Init, cmd: Clone) !void {
    const t = targetOf(cmd);
    const rid_str = cmd.rid.value;
    const dir = cmd.dir.value;
    const require_verified = cmd.flags.require_verified.value;
    const arena = init.arena.allocator();
    const nid = t.nid;

    std.debug.print("cloning {f} from {f} into {s}...\n", .{ rid_str, t.nid, dir });
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
    rid_str: RepoId,
    dir: []const u8,
    require_verified: bool,
) !void {
    std.debug.print("cloned {f}: {d} refs, {d} pack bytes -> {s}\n", .{ rid_str, result.refs, result.pack_bytes, dir });
    if (result.damaged_packs > 0) {
        std.debug.print("  DAMAGED: {d} pack index(es) unreadable, objects may be missing\n", .{
            result.damaged_packs,
        });
    }

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

fn fetchProbe(init: std.process.Init, cmd: FetchProbe) !void {
    const t = targetOf(cmd);
    const rid_str = cmd.rid.value;
    const arena = init.arena.allocator();
    const nid = t.nid;

    var printer = FetchProbePrinter{};
    std.debug.print("fetch-probe {f} from {f}...\n", .{ rid_str, t.nid });
    const frames = radish.net.wire.fetchProbe(init.io, arena, t.host, t.port, nid, rid_str, 20, &printer) catch |e| {
        std.debug.print("fetch-probe failed: {s}\n", .{@errorName(e)});
        return e;
    };
    std.debug.print(
        "\ndone: {d} frames, {d} git frames, {d} git bytes\n",
        .{ frames, printer.git_frames, printer.git_bytes },
    );
}

fn ping(init: std.process.Init, cmd: Ping) !void {
    const t = targetOf(cmd);
    const arena = init.arena.allocator();
    const nid = t.nid;

    const zeroes = radish.net.wire.ping(init.io, arena, t.host, t.port, nid, 8) catch |e| {
        std.debug.print("ping failed: {s}\n", .{@errorName(e)});
        return e;
    };
    std.debug.print("pong from {f} ({d} zero bytes)\n", .{ t.nid, zeroes });
}

fn announce(init: std.process.Init, cmd: Announce) !void {
    const t = targetOf(cmd);
    const alias = cmd.alias.value;
    const arena = init.arena.allocator();
    const nid = t.nid;

    var seed: [32]u8 = undefined;
    try init.io.randomSecure(&seed);
    const key = try radish.crypto.SecretKey.fromSeed(seed);
    const our_nid = radish.identity.NodeId.fromPublicKey(key.publicKey());
    std.debug.print("announcing as {f} (alias {s})\n", .{ our_nid, alias });

    const zeroes = radish.net.wire.sendAnnouncement(init.io, arena, t.host, t.port, nid, key, alias) catch |e| {
        std.debug.print("announce failed: {s}\n", .{@errorName(e)});
        return e;
    };
    std.debug.print("accepted: pong from {f} ({d} zero bytes)\n", .{ t.nid, zeroes });
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
                const id = radish.identity.NodeId.fromPublicKey(n.node).encode(self.arena) catch return;
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
                const id = radish.identity.NodeId.fromPublicKey(inv.node).encode(self.arena) catch return;
                std.debug.print("inv   {s}  {d} repos{s}\n", .{
                    id,
                    inv.inventory.len,
                    self.mark(inv.verified()),
                });
                for (inv.inventory) |oid| {
                    self.rids += 1;
                    const rid = radish.identity.RepoId.fromOid(oid).encode(self.arena) catch continue;
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
fn fetchDeps(init: std.process.Init, cmd: FetchDeps) !void {
    const manifest_path = cmd.manifest.value;
    const from = cmd.flags.from.value;
    const out_dir = cmd.dir.value;
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

        // A pinned rev names one commit, so a checkout already there is the
        // one it names and the network has nothing to add. Without a pin the
        // branch may have moved, so it is always fetched.
        if (dep.rev != null and hasCheckout(init.io, root)) {
            std.debug.print("  pinned rev already checked out\n", .{});
            try edits.append(arena, .{ .dep = dep.name, .field = "path", .value = root });
            continue;
        }

        // Clone into a bare repo beside the checkout, since the pack and refs
        // are what verification reads.
        const bare = try std.fmt.allocPrint(arena, "{s}/{s}.git", .{ out_dir, dep.name });
        std.Io.Dir.cwd().deleteTree(init.io, bare) catch {};
        // The manifest is text, so this is where a `.rad` entry is checked.
        const rid = radish.identity.RepoId.parse(dep.rid) catch {
            std.debug.print("  '{s}' is not a repository id\n", .{dep.rid});
            return error.BadRid;
        };

        // --from wins, then the manifest's `.node`, then discovery. A pinned
        // node that is down is a preference we cannot honour, not an error, so
        // it falls back rather than failing the build.
        var result = blk: {
            if (explicit orelse manifestNode(dep)) |pinned| {
                if (cloneFrom(init, pinned, rid, bare)) |r| break :blk r else |e| {
                    if (explicit != null) return e;
                    std.debug.print("  {s} unreachable ({s}), locating a seed\n", .{ pinned.host, @errorName(e) });
                    std.Io.Dir.cwd().deleteTree(init.io, bare) catch {};
                }
            }
            const found = try locate(init, rid, 500);
            break :blk cloneFrom(init, found, rid, bare) catch |e| {
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

        std.debug.print("  verified {d} remote(s), checked out {x}\n", .{
            result.report.verified.len,
            head.slice(),
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

        try edits.append(arena, .{ .dep = dep.name, .field = "path", .value = root });
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
        std.debug.print(
            "session: {d} frames, {d} pings, {d} subscribes, {d} announcements, {d} fetches, {d} refused\n",
            .{
                stats.frames,        stats.pings,   stats.subscribes,
                stats.announcements, stats.fetches, stats.refused,
            },
        );
    }

    pub fn onSessionFailed(_: *ServePrinter, err: anyerror) void {
        std.debug.print("session failed: {s}\n", .{@errorName(err)});
    }

    pub fn onRefreshFailed(_: *ServePrinter, err: anyerror) void {
        std.debug.print("inventory refresh failed: {s}\n", .{@errorName(err)});
    }
};

/// Connection settings for a live 2.x exchange: a fresh key share and
/// connection id, which RFC 9000 s7.2 wants unpredictable, and the fixed
/// identity so the node keeps seeing the same peer. `quic probe` overrides the
/// fresh parts, since a recorded exchange has to replay.
fn quicDial(init: std.process.Init, host: []const u8, port: u16) !radish.quic.endpoint.Options {
    const arena = init.arena.allocator();
    var seed: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, radish.quic.testdata.fixed_identity_seed);

    // Allocated, not a local: the options outlive this function.
    const dcid = try arena.alloc(u8, 8);
    try init.io.randomSecure(dcid);

    // Allocated for the same reason, and large: a full receive window.
    const bufs = try arena.create(radish.quic.endpoint.DefaultStorage);
    var opts: radish.quic.endpoint.Options = .{
        .host = host,
        .port = port,
        .alpn = radish.net.gossip.alpn_gossip,
        .bufs = bufs.buffers(),
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
fn quicNodeId(opts: radish.quic.endpoint.Options) radish.identity.NodeId {
    return radish.identity.NodeId.fromPublicKey(opts.identity.public_key.toBytes());
}

/// A radicle 2.x ping: the QUIC handshake, then one gossip message each way.
fn quicPing(init: std.process.Init, cmd: QuicPing) !void {
    const host = cmd.host.value;
    const port = cmd.port.value;
    const quic = radish.quic;
    const arena = init.arena.allocator();
    const opts = try quicDial(init, host, port);
    std.debug.print("quic ping {s}:{d} as {f}\n", .{ host, port, quicNodeId(opts) });

    const c = try arena.create(quic.endpoint.Endpoint);
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
        std.debug.print("peer node id: {f}\n", .{
            radish.identity.NodeId.fromPublicKey(k),
        });
    };
    std.debug.print("pong: {d} zeroes\n", .{pong.zeroes});
}

/// Subscribes to a 2.x node's gossip and prints what arrives, the counterpart
/// of `radish subscribe`.
fn quicSubscribe(init: std.process.Init, cmd: QuicSubscribe) !void {
    const host = cmd.host.value;
    const port = cmd.port.value;
    const max = cmd.flags.messages.value;
    const quic = radish.quic;
    const arena = init.arena.allocator();
    const opts = try quicDial(init, host, port);
    std.debug.print("quic subscribe {s}:{d} as {f}\n", .{ host, port, quicNodeId(opts) });

    var printer = GossipPrinter{ .arena = arena };
    const c = try arena.create(quic.endpoint.Endpoint);
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
fn quicCapture(init: std.process.Init, cmd: QuicCapture) !void {
    const host = cmd.host.value;
    const port = cmd.port.value;
    const max = cmd.flags.messages.value;
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
    const c = try arena.create(quic.endpoint.Endpoint);
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
fn quicFetchProbe(init: std.process.Init, cmd: QuicFetchProbe) !void {
    const host = cmd.host.value;
    const port = cmd.port.value;
    const rid = cmd.rid.value;
    const quic = radish.quic;
    const arena = init.arena.allocator();
    const opts = try quicDial(init, host, port);
    std.debug.print("quic fetch-probe {s}:{d} {f}\n", .{ host, port, rid });

    const c = try arena.create(quic.endpoint.Endpoint);
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
fn quicClone(init: std.process.Init, cmd: QuicClone) !void {
    const host = cmd.host.value;
    const port = cmd.port.value;
    const rid = cmd.rid.value;
    const dir = cmd.dir.value;
    const require_verified = cmd.flags.require_verified.value;
    const show_profile = cmd.flags.profile.value;
    const quic = radish.quic;
    const arena = init.arena.allocator();
    const opts = try quicDial(init, host, port);
    std.debug.print("quic clone {f} from {s}:{d} into {s}...\n", .{ rid, host, port, dir });

    const c = try arena.create(quic.endpoint.Endpoint);
    defer c.close();
    const started = (quic.endpoint.Clock{ .awake = {} }).nowMs(init.io);
    // Printed whether or not the clone worked: a failure is when the counters
    // are most worth seeing.
    defer if (show_profile) printProfile(init, c, started);

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

fn printProfile(init: std.process.Init, c: *radish.quic.endpoint.Endpoint, started_ms: u64) void {
    var buf: [1024]u8 = undefined;
    var w = std.Io.File.stderr().writer(init.io, &buf);
    const elapsed = (radish.quic.endpoint.Clock{ .awake = {} }).nowMs(init.io) -| started_ms;
    c.profiled().report(&w.interface, elapsed) catch return;
    w.interface.flush() catch {};
}

/// One QUIC first flight against a live server. The x25519 key is fixed, so a
/// recorded reply replays byte for byte; that also means the exchange has no
/// forward secrecy, which is fine for a probe of public traffic.
fn quicProbe(init: std.process.Init, cmd: QuicProbe) !void {
    const host = cmd.host.value;
    const port = cmd.port.value;
    const alpn = cmd.alpn.value;
    const sni = cmd.sni.value;
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

    std.debug.print("quic probe {s}:{d} alpn={s} as {f}\n", .{
        host,
        port,
        alpn,
        quicNodeId(opts),
    });

    // Every buffer the connection reports from lives in here, so it stays put.
    const c = try arena.create(quic.endpoint.Endpoint);
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
        if (a.peer_key) |k| std.debug.print("peer node id: {f}{s}\n", .{
            radish.identity.NodeId.fromPublicKey(k),
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
fn serve(init: std.process.Init, cmd: Serve) !void {
    const port = cmd.port.value;
    const sessions = cmd.sessions.value orelse std.math.maxInt(usize);
    const root = cmd.storage.value;
    const arena = init.arena.allocator();

    // randomSecure everywhere a key is derived: `random` degrades to a weaker
    // source on entropy failure instead of reporting it.
    var seed: [32]u8 = undefined;
    try init.io.randomSecure(&seed);
    const key = try radish.crypto.SecretKey.fromSeed(seed);
    const nid = radish.identity.NodeId.fromPublicKey(key.publicKey());

    var store: ?radish.git.storage.Storage = null;
    defer if (store) |*s| s.deinit();
    if (root) |path| {
        store = radish.git.storage.Storage.open(init.io, arena, path) catch |e| {
            std.debug.print("cannot read storage at {s}: {s}\n", .{ path, @errorName(e) });
            return e;
        };
        const ids = try store.?.inventory(arena);
        std.debug.print("serving {d} repositories from {s}\n", .{ ids.len, path });
    }

    var printer = ServePrinter{};
    std.debug.print("listening on 0.0.0.0:{d} as {f}\n", .{ port, nid });
    const cfg: radish.net.node.Config = .{
        .seed = seed,
        .alias = "radish",
        .store = if (store) |*s| s else null,
    };
    const served = radish.net.node.listen(init.io, arena, port, cfg, sessions, &printer) catch |e| {
        std.debug.print("serve failed: {s}\n", .{@errorName(e)});
        return e;
    };
    std.debug.print("\nserved {d} sessions\n", .{served});
}

/// Checks every pack in `repo` against the checksums it carries. Reads both
/// files whole, which is why it is a command rather than part of opening a
/// repository.
fn verifyPack(init: std.process.Init, cmd: VerifyPack) !void {
    const path = cmd.repo.value;
    var repo = radish.git.storage.Repository.open(init.io, init.gpa, path) catch |e| {
        std.debug.print("cannot open {s}: {s}\n", .{ path, @errorName(e) });
        return e;
    };
    defer repo.deinit();

    var bad = repo.damaged_packs;
    if (repo.damaged_packs > 0) {
        std.debug.print("{d} pack index(es) would not parse and were skipped\n", .{repo.damaged_packs});
    }

    for (repo.odb.packs, 0..) |pack, i| {
        if (pack.verify()) {
            std.debug.print("  pack {d}: ok\n", .{i});
        } else |e| {
            bad += 1;
            std.debug.print("  pack {d}: {s}\n", .{ i, @errorName(e) });
        }
    }

    std.debug.print("{d} pack(s) checked, {d} bad\n", .{ repo.odb.packs.len, bad });
    if (bad > 0) return error.PackDamaged;
}

/// Serves one git protocol v2 fetch over stdin/stdout, which is how real `git`
/// runs an upload-pack: `git -c protocol.version=2 clone --upload-pack 'radish
/// upload-pack' <repo> <dir>`. No transport intro line is read here, since the
/// repository arrives on the command line the way `git upload-pack` takes it.
fn uploadPack(init: std.process.Init, cmd: UploadPack) !void {
    const path = cmd.repo.value;
    const gpa = init.gpa;
    var repo = radish.git.storage.Repository.open(init.io, gpa, path) catch |e| {
        std.debug.print("cannot open {s}: {s}\n", .{ path, @errorName(e) });
        return e;
    };
    defer repo.deinit();
    if (repo.damaged_packs > 0) {
        std.debug.print("warning: {d} pack index(es) in {s} are unreadable\n", .{
            repo.damaged_packs,
            path,
        });
    }

    // Streaming: stdio is a pipe here, which has no position to seek to. The
    // write side holds one pkt-line, so a sideband line never splits a syscall.
    var in_buf: [4096]u8 = undefined;
    var out_buf: [radish.git.pktline.MAX_LINE]u8 = undefined;
    var in = std.Io.File.stdin().readerStreaming(init.io, &in_buf);
    var out = std.Io.File.stdout().writerStreaming(init.io, &out_buf);

    try radish.git.uploadpack.serve(gpa, &in.interface, &out.interface, repo);
    try out.interface.flush();
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
    rid_str: RepoId,
    bare: []const u8,
) !radish.net.clone.CloneResult {
    const arena = init.arena.allocator();
    const nid = t.nid;
    return radish.net.clone.overNoise(init.io, arena, t.host, t.port, nid, rid_str, bare);
}

/// Asks a bootstrap node who seeds `rid`, and returns the first seed that both
/// holds it and published an address. Discovery needs an entry point of its
/// own, so the bootstrap list is tried in order until one answers.
fn locate(init: std.process.Init, want: RepoId, frames: usize) !Target {
    const arena = init.arena.allocator();

    for (radish.net.seeds.BOOTSTRAP) |entry| {
        const boot = Target.parse(entry) orelse continue;
        const boot_nid = boot.nid;

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
        const id = radish.identity.NodeId.fromPublicKey(found.node);
        const spec = try std.fmt.allocPrint(arena, "{s}:{f}", .{ found.addr, id });
        // An address that will not parse is this bootstrap node's answer being
        // unusable, not the end of the search.
        const target = Target.parse(spec) orelse {
            std.debug.print("  {s}: {s} is not a dial target\n", .{ boot.host, found.addr });
            continue;
        };
        std.debug.print("  found {f} at {s} (via {s})\n", .{ id, found.addr, boot.host });
        return target;
    }
    return error.NoSeedFound;
}

/// The tree hash of the directory at `path`.
/// Whether `path` holds a checkout already. Only ever asked of a pinned rev,
/// where a directory that is there is the one the pin names.
fn hasCheckout(io: std.Io, path: []const u8) bool {
    var dir = std.Io.Dir.cwd().openDir(io, path, .{}) catch return false;
    dir.close(io);
    return true;
}

/// A dial target, `host:port:node-id`. All three are required: Noise_XK mixes
/// the node id into the handshake before the first byte, so it cannot be
/// looked up from the connection.
const Target = struct {
    host: []const u8,
    port: u16,
    nid: radish.identity.NodeId,

    /// From the colon form, `host:port:node-id`.
    fn parse(spec: []const u8) ?Target {
        var it = std.mem.splitScalar(u8, spec, ':');
        const host = it.next() orelse return null;
        const port_str = it.next() orelse return null;
        const nid = it.next() orelse return null;
        if (host.len == 0) return null;
        return .{
            .host = host,
            .port = std.fmt.parseInt(u16, port_str, 10) catch return null,
            .nid = radish.identity.NodeId.parse(nid) catch return null,
        };
    }
};

/// Lists the nodes seen announcing themselves, with the addresses each
/// advertises. Discovery is bounded by what `from` has stored and relays.
fn peers(init: std.process.Init, cmd: Peers) !void {
    const from = cmd.from.value;
    const frames = cmd.flags.frames.value;
    const arena = init.arena.allocator();
    const target = Target.parse(from) orelse return usage();
    const nid = target.nid;

    var collector = radish.net.seeds.PeerCollector.init(arena);
    defer collector.deinit();

    std.debug.print("watching {s} for peers (up to {d} frames)...\n", .{ target.host, frames });
    const read = radish.net.wire.subscribe(init.io, target.host, target.port, nid, frames, &collector) catch |e| {
        std.debug.print("subscribe failed: {s}\n", .{@errorName(e)});
        return e;
    };

    for (collector.peers()) |p| {
        const id = radish.identity.NodeId.fromPublicKey(p.node);
        std.debug.print("peer  {f}  alias={s}\n", .{ id, p.alias });
        for (p.addrs) |a| std.debug.print("        {s}\n", .{a.text});
    }
    std.debug.print("\n{d} peers seen in {d} frames\n", .{ collector.peers().len, read });
}

/// Nothing published is an answer, not a crash, so it says one line and exits
/// rather than unwinding into a stack trace. Anything else really did go
/// wrong, and the trace is worth having.
fn lookupFailed(id: NodeId, e: anyerror) anyerror {
    if (e == error.NoRecord) {
        std.debug.print("{f}\n  no record published\n", .{id});
        std.process.exit(1);
    }
    std.debug.print("lookup failed: {s}\n", .{@errorName(e)});
    return e;
}

/// Looks a node id up in the records its own key publishes. The signed route
/// is the default. `--dns` asks a resolver instead, which is faster to answer
/// and worth nothing without the signature, so what it returns is labelled.
fn resolve(init: std.process.Init, cmd: Resolve) !void {
    const iroh = radish.iroh;
    const arena = init.arena.allocator();
    const id = cmd.node_id.value;

    // Both buffers hold what the result borrows, so they outlive the printing.
    var record: [iroh.pkarr.max_payload]u8 = undefined;
    var reply: [iroh.resolve.max_reply]u8 = undefined;

    var result = blk: {
        if (cmd.flags.dns.value) {
            const server = if (cmd.flags.server.value) |s|
                try std.Io.net.IpAddress.resolve(init.io, s, 53)
            else
                iroh.resolve.systemServer(init.io) catch |e| {
                    std.debug.print("no nameserver: {s}\n", .{@errorName(e)});
                    return e;
                };
            break :blk iroh.resolve.lookupUnsigned(init.io, arena, &reply, id, .{
                .server = server,
                .origin = cmd.flags.origin.value,
            }) catch |e| return lookupFailed(id, e);
        }
        var one: [1][]const u8 = undefined;
        var opts: iroh.resolve.Options = .{};
        if (cmd.flags.relay.value) |r| {
            one[0] = r;
            opts.relays = &one;
        }
        break :blk iroh.resolve.lookup(init.io, arena, &record, id, opts) catch |e|
            return lookupFailed(id, e);
    };
    defer result.deinit(arena);

    std.debug.print("{f}\n", .{id});
    switch (result.source) {
        .signed => std.debug.print(
            "  signed by the node's own key, verified here, published {d} us since the epoch\n",
            .{result.timestamp.?},
        ),
        .dns => std.debug.print("  UNSIGNED: a resolver's word, not the key's\n", .{}),
    }
    for (result.addr.relays) |r| std.debug.print("  relay  {s}\n", .{r});
    for (result.addr.addrs) |a| std.debug.print("  addr   {s}\n", .{a});
    if (result.addr.user_data) |d| std.debug.print("  data   {s}\n", .{d});
    // radish dials UDP directly and does not speak the iroh relay protocol.
    if (result.addr.addrs.len == 0) std.debug.print("  not dialable: relay only\n", .{});
}

const SeedsOpts = struct {
    rid: RepoId,
    dir: ?[]const u8 = null,
    from: ?[]const u8 = null,
    frames: usize = 200,
};

/// The two sources answer different questions and neither is a substitute for
/// the other: `--dir` is whose refs we hold, `--from` is who advertises the
/// repo right now. Gossip is a push stream with no "who seeds X" query, so its
/// answer is a lower bound over the observed window, never a complete list.
fn seeds(init: std.process.Init, cmd: Seeds) !void {
    // Neither source means nothing to look in, which the parser cannot catch:
    // it checks one argument at a time, and this is a rule about two.
    if (cmd.flags.dir.value == null and cmd.flags.from.value == null) {
        std.debug.print("radish seeds: needs --dir or --from\n", .{});
        printHelp(Seeds, "radish seeds");
        std.process.exit(2);
    }

    const opts: SeedsOpts = .{
        .rid = cmd.rid.value,
        .dir = cmd.flags.dir.value,
        .from = cmd.flags.from.value,
        .frames = cmd.flags.frames.value,
    };
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
    const nid = target.nid;
    const want = opts.rid;

    var collector = radish.net.seeds.Collector.init(arena, want);
    defer collector.deinit();

    std.debug.print("watching {s} for seeds of {f} (up to {d} frames)...\n", .{ target.host, opts.rid, opts.frames });
    const read = radish.net.wire.subscribe(init.io, target.host, target.port, nid, opts.frames, &collector) catch |e| {
        std.debug.print("subscribe failed: {s}\n", .{@errorName(e)});
        return e;
    };

    for (collector.seeds()) |node| {
        const id = radish.identity.NodeId.fromPublicKey(node);
        std.debug.print("seed  {f}\n", .{id});
    }
    std.debug.print(
        "{d} seeds seen in {d} frames ({d} inventories)\n",
        .{ collector.seeds().len, read, collector.inventories },
    );
}

fn subscribe(init: std.process.Init, cmd: Subscribe) !void {
    const t = targetOf(cmd);
    const max = cmd.flags.frames.value;
    const arena = init.arena.allocator();
    const nid = t.nid;

    var printer = GossipPrinter{ .arena = arena };
    std.debug.print("subscribing to {f} (up to {d} frames)...\n", .{ t.nid, max });
    const frames = radish.net.wire.subscribe(init.io, t.host, t.port, nid, max, &printer) catch |e| {
        std.debug.print("subscribe failed: {s}\n", .{@errorName(e)});
        return e;
    };
    std.debug.print(
        "\ndone: {d} frames, {d} nodes, {d} inventories, {d} repos\n",
        .{ frames, printer.nodes, printer.inventories, printer.rids },
    );
}
