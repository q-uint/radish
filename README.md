# Radish

A [Radicle](https://radicle.xyz) client and node, in Zig. Early work in
progress, verified against Heartwood, the RFCs, `git`, and a live radicle-node.

Radicle 1.x runs over Noise/TCP. 2.0 moves to QUIC via
[iroh](https://iroh.computer), and the two do not interoperate. Radish
implements 1.x in `src/net/` and is experimenting with 2.x in `src/quic/`;
storage, identities, sigrefs and COBs are shared.

Radish is seeded on the radicle network as [`rad:z4VSyUhaBGUJQrFdS7nWULf1dJdos`](https://rad.0x51.dev/nodes/rad.0x51.dev/rad:z4VSyUhaBGUJQrFdS7nWULf1dJdos), so it can clone itself:

```
radish clone rad.0x51.dev 8776 z6Mkhh3TfBZeGW4z4uufMp7caXoBf2wcpDWDrRsELqWqmT6Y \
  rad:z4VSyUhaBGUJQrFdS7nWULf1dJdos radish.git --require-verified
```

Clones are verified, not just downloaded: every remote's `rad/sigrefs` signature
is checked against its node id, each signed oid must be present in the packfile,
and each ref on disk must be signed at the oid it points to. Verification reports
rather than filters, matching heartwood's `validate`.

## CLI

```
radish ping        <host> <port> <node-id>              handshake + ping/pong
radish announce    <host> <port> <node-id> [alias]      send a signed NodeAnnouncement
radish subscribe   <host> <port> <node-id> [frames]     listen to gossip (nodes + inventory)
radish fetch-probe <host> <port> <node-id> <rid>        open a git stream, read the v2 advertisement
radish clone       <host> <port> <node-id> <rid> <dir>  clone a repo into <dir> (bare), verifying each remote
  --require-verified                                    exit non-zero if any remote fails verification
  --profile                                             print connection counters on exit
radish seeds       <rid>                                who holds a repo; needs --from or --dir
  --dir <path>                                          remotes in a local clone (no network)
  --from <host>:<port>:<node-id>                        seeds announcing it over gossip
  --frames <n>                                          gossip frames to observe (default 200)
radish peers       <host>:<port>:<node-id>              nodes seen announcing themselves, with addresses
  --frames <n>                                          gossip frames to observe (default 200)
radish fetch-deps  <manifest> [dir]                     resolve `.rad` dependencies (default .rad-deps)
  --from <host>:<port>:<node-id>                        fetch from this node instead of locating a seed
radish serve       <port> [sessions]                    answer inbound connections (one at a time)
radish quic ping   <host> <port>                        2.x: handshake, then a gossip ping/pong
radish quic subscribe <host> <port> [messages]          2.x: listen to gossip (default 200)
radish quic clone  <host> <port> <rid> <dir>            2.x: clone a repo into <dir> (bare)
  --require-verified                                    exit non-zero if any remote fails verification
  --profile                                             print connection counters on exit
radish quic probe  <host> <port> [alpn] [sni]           2.x: send an Initial, read the reply
```

## Zig packages over Radicle (proof of concept)

A Zig dependency can be named by RID instead of a URL, authenticated end to end.
`fetch-deps` clones each one, checks it really is the repo that was asked for,
resolves the identity document's `defaultBranch` from a delegate's namespace, and
checks that commit out.

Write only `.rad`:

```
.dependencies = .{
    .radish = .{
        .rad = "z4VSyUhaBGUJQrFdS7nWULf1dJdos",
    },
},
```

then run:

```
radish fetch-deps build.zig.zon
zig build
```

`fetch-deps` rewrites the manifest in place, preserving comments and formatting:

```
.radish = .{
    .rad = "z4VSyUhaBGUJQrFdS7nWULf1dJdos",
    .path = ".rad-deps/radish",
    .rad_hash = "radtree-1-fa8889c5...",
},
```

With no node named, radish asks a bootstrap seed who announces the RID. Name one
to avoid leaning on the public bootstraps:

```
.radish = .{
    .rad = "z4VSyUhaBGUJQrFdS7nWULf1dJdos",
    .node = "rad.0x51.dev:8776:z6Mkhh3TfBZeGW4z4uufMp7caXoBf2wcpDWDrRsELqWqmT6Y",
},
```

`.node` is a preference and falls back to discovery if unreachable; `--from`
overrides both and does not fall back. Pin an exact commit with `.rev`, or omit
it to follow `defaultBranch`.

### Limitations

- Zig requires `url` or `path`, so `.rad` cannot stand alone, and it will not
  hash a path dependency. Hence the generated `.path` and `.rad_hash`, which
  radish checks and Zig ignores. Native support needs a `rad` variant of Zig's
  location union.
- Discovery needs an entry point. The bootstrap seeds in `net/seeds.zig` are
  hardcoded.
- Without `.rev`, delegates publishing different heads for `defaultBranch` fails
  rather than picking one.
- No transitive dependencies, no lockfile. A matching `.rad_hash` skips the
  network; anything else is re-cloned in full.

## Radish is NOT a good network citizen

Easy to point at seeds you do not run, so, explicitly:

- Every connection uses a throwaway identity, and `serve` regenerates its key per
  run. Rate limits and bans do not accumulate against a rotating identity.
- Radish drains gossip and disconnects. It relays nothing and seeds nothing.
- Locating a seed costs a full subscribe per dependency, spent whether or not the
  RID turns up.

Prefer `.node` or `--from` to point at a seed you run, and do not put
`fetch-deps` in a loop.

## QUIC (2.x)

Independent of `src/net/`, and pinned to RFC 9001 Appendix A and RFC 8448
vectors, and completed against a live radicle 2.x node: packet protection, long
and short headers, the frames a handshake needs, and mutual authentication with
raw public keys, through to HANDSHAKE_DONE. A public server refuses raw public
keys, so the peer has to be iroh; `nix build .#radicle-ng` provides one.

One stream runs on top, with flow control, key updates, RFC 9002 loss recovery
and NewReno. 2.x gossip runs over it, reusing the 1.x message codec, and so does
git protocol v2: the `radicle/git/1` ALPN carries git bytes unframed, so cloning
is the same ls-refs, packfile, index and verify as 1.x over a different session.
A 12 MB packfile clones and verifies against a local node.

Not started: the server side, which is also what sends a stateless reset.

## Build

Requires a Zig 0.17-dev toolchain; a Nix flake pins it.

```
nix develop --command zig build test
nix develop --command zig build
```

The pack indexer is the Zig toolchain's own `git.zig`, compiled from source as a
module. Stock 0.17-dev writes a zeroed CRC32 table that real `git` rejects, so
the flake pins a branch carrying the fix ([ziglang/zig#36328]). Override with
`-Dgitpack=/path/to/git.zig`, or drop the pin once it lands upstream.

[ziglang/zig#36328]: https://codeberg.org/ziglang/zig/pulls/36328

## References

Each function cites the section it implements. These are the documents:

- [Radicle Protocol Guide](https://docs.radicle.xyz/guides/protocol) - node ids, RIDs, the identity document, `refs/rad/*`, gossip.
- [radicle/heartwood](https://codeberg.org/radicle/heartwood) - reference implementation, and ground truth for byte layouts.
- [Collaborative Objects RFC](https://github.com/radicle-dev/radicle-link/blob/master/docs/rfc/0662-collaborative-objects.adoc)
- [Noise Protocol Framework](https://noiseprotocol.org/noise.html) - the `XK` pattern radicle names; see `noise.zig` for how radicle diverges.
- git: [gitprotocol-v2](https://git-scm.com/docs/gitprotocol-v2), [-pack](https://git-scm.com/docs/gitprotocol-pack), [-common](https://git-scm.com/docs/gitprotocol-common), [gitformat-pack](https://git-scm.com/docs/gitformat-pack).
- Encodings: [did:key](https://w3c-ccg.github.io/did-method-key/), [multibase](https://github.com/multiformats/multibase), [multicodec](https://github.com/multiformats/multicodec/blob/master/table.csv), [base58](https://datatracker.ietf.org/doc/html/draft-msporny-base58), [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032).
- QUIC: [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000), [9001](https://www.rfc-editor.org/rfc/rfc9001), [9002](https://www.rfc-editor.org/rfc/rfc9002); TLS 1.3: [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446), [8448](https://www.rfc-editor.org/rfc/rfc8448).
- [iroh](https://iroh.computer) - what Radicle 2.0 uses; [docs](https://docs.iroh.computer).

## License

[MIT](LICENSE)
