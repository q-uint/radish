# Radish

A [Radicle](https://radicle.xyz) client and node, in Zig.

Early work in progress. Every layer is verified against authoritative sources (Heartwood source, RFCs, `git`, and a live radicle-node).

Radish is seeded on the radicle network as [`rad:z4VSyUhaBGUJQrFdS7nWULf1dJdos`](https://rad.0x51.dev/nodes/rad.0x51.dev/rad:z4VSyUhaBGUJQrFdS7nWULf1dJdos), so it can clone itself:

```
radish clone rad.0x51.dev 8776 z6Mkhh3TfBZeGW4z4uufMp7caXoBf2wcpDWDrRsELqWqmT6Y \
  rad:z4VSyUhaBGUJQrFdS7nWULf1dJdos radish.git --require-verified
```

Radish dials a live radicle-node over the `Noise_XK` handshake, exchanges gossip (ping/pong, signed announcements, subscriptions), and clones repositories through a hand-rolled git protocol v2 client. Identity and encoding are built from the ground up: base58btc, `did:key` node ids, Radicle canonical JSON with NFC normalization via a forked [zg](https://codeberg.org/atman/zg), and identity documents whose canonical blob hash is the RID.

Clones are verified, not just downloaded. Every remote's `rad/sigrefs` signature is checked against its node id, each signed oid must be present in the packfile, and each ref on disk must be signed at the oid it points to. The RID is the identity doc's hash at `refs/rad/root`, read only from remotes that actually signed that root, so a seed cannot serve one repository under another's name. Verification reports rather than filters, matching heartwood's `validate`, since non-delegate contributors are legitimate remotes.

## CLI

```
radish ping        <host> <port> <node-id>              handshake + ping/pong
radish announce    <host> <port> <node-id> [alias]      send a signed NodeAnnouncement
radish subscribe   <host> <port> <node-id> [frames]     listen to gossip (nodes + inventory)
radish fetch-probe <host> <port> <node-id> <rid>        open a git stream, read the v2 advertisement
radish clone       <host> <port> <node-id> <rid> <dir>  clone a repo into <dir> (bare), verifying each remote
  --require-verified                                    exit non-zero if any remote fails verification
radish seeds       <rid>                                who holds a repo; needs --from or --dir
  --dir <path>                                          remotes in a local clone (no network)
  --from <host>:<port>:<node-id>                        seeds announcing it over gossip
  --frames <n>                                          gossip frames to observe (default 200)
radish peers       <host>:<port>:<node-id>              nodes seen announcing themselves, with addresses
  --frames <n>                                          gossip frames to observe (default 200)
radish fetch-deps  <manifest> <host>:<port>:<node-id> [dir]
                                                        resolve `.rad` dependencies (default .rad-deps)
```

## Zig packages over Radicle (proof of concept)

A Zig dependency can be named by RID instead of a URL. `fetch-deps` clones each
one, checks it really is the repo that was asked for, resolves the identity
document's `defaultBranch` from a delegate's namespace, and checks that commit
out.

Write only `.rad`; `fetch-deps` fills in the rest and rewrites the manifest in
place, preserving comments and formatting.

```
.dependencies = .{
    .radish = .{
        .rad = "z4VSyUhaBGUJQrFdS7nWULf1dJdos",
    },
},
```

```
radish fetch-deps build.zig.zon rad.0x51.dev:8776:z6Mkhh3TfBZeGW4z4uufMp7caXoBf2wcpDWDrRsELqWqmT6Y
zig build
```

leaves the dependency resolved and buildable:

```
.radish = .{
    .rad = "z4VSyUhaBGUJQrFdS7nWULf1dJdos",
    .path = ".rad-deps/radish",
    .rad_hash = "radtree-1-fa8889c5...",
},
```

Unlike a `url` dependency, the bytes are authenticated: the RID is the hash of
the identity document, so a seed cannot serve a different repo under the same
name, every remote's refs must be signed by that remote, and the resolved commit
must be one a delegate published. Pin an exact commit with `.rev`, or omit it to
follow the identity document's `defaultBranch`.

### Limitations

This is a proof of concept, not a package manager. In particular:

- **Zig still needs `.path`, and it cannot be hashed.** Unknown fields in a
  manifest are ignored, but a dependency must carry a location (`dependency
  requires location field, one of 'url' or 'path'`), so `.rad` cannot stand
  alone. `fetch-deps` generates the `.path`, which keeps it out of the user's
  hands, but Zig then refuses a `.hash` on it (`path-based dependencies are not
  hashed`) because it only hashes what it fetches itself. Hence `.rad_hash`,
  which radish checks and Zig ignores. Native support would mean a `rad` variant
  of Zig's location union, which is a change to Zig itself.
- **You must supply a node to talk to.** A RID says what, never where. Noise_XK
  needs the node id before the first byte, and the routing table is built from
  gossip, so a known entry point is unavoidable. `radish seeds --from` can tell
  you who announces a RID, but that lookup is not wired into `fetch-deps`.
- **Delegates must agree.** Without `.rev`, if delegates publish different heads
  for `defaultBranch`, resolution fails rather than picking one.
- **No transitive dependencies** and no lockfile. A dependency whose `.rad_hash`
  matches is reused, but anything else is re-cloned in full.

`.rad_hash` is checked against the tree already on disk before anything is
fetched, so a locally modified dependency is reported and refetched rather than
silently overwritten. A matching tree skips the network entirely.

`.rev` may name any commit a delegate published, including one behind the
branch head. Ancestry comes from the pack rather than from walking parents,
which gitpack exposes no way to do: the clone requests whole refs, so the pack
holds exactly what the fetched tips reach, and every tip is checked against a
delegate's sigrefs.

## Build

Requires a Zig 0.17-dev toolchain; a Nix flake pins it.

```
nix develop --command zig build test
nix develop --command zig build
```

The pack indexer is the Zig toolchain's own `git.zig`, compiled from source as a module rather than linked from the compiler. Stock 0.17-dev writes a zeroed CRC32 table that real `git` rejects, so the flake also pins a source-only checkout of a branch carrying the fix ([ziglang/zig#36328]) and points the module at it; the toolchain itself stays a prebuilt release. Override the path with `-Dgitpack=/path/to/git.zig`, or drop the pin once the fix lands upstream.

[ziglang/zig#36328]: https://codeberg.org/ziglang/zig/pulls/36328

## References

See [REFERENCES.md](REFERENCES.md) for the Radicle protocol docs and the standards behind each encoding.

## License

[MIT](LICENSE)
