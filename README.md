# Radish

A [Radicle](https://radicle.xyz) client and node, in Zig.

Early work in progress. Every layer is verified against authoritative sources
(Heartwood source, RFCs, `git`, and a live radicle-node).

Identity and encoding:

- `base58` - base58btc (multibase `z`)
- `NodeId` - Ed25519 public key as `did:key:z6Mk...`
- `RepoId` - repository identifier `rad:z...`
- `canonical` - Radicle canonical JSON (NFC-normalized, sorted keys, integer-only)
- `Doc` - identity document; its canonical git-blob hash is the RID
- `sigrefs` - signed refs (`rad/sigrefs`)
- `unicode` - NFC via a forked [zg](https://codeberg.org/atman/zg)

Wire protocol (spoken to a live node):

- `noise` - the `Noise_XK` handshake radicle uses (Edwards25519 DH)
- `codec` / `protocol` - QUIC-varint framing, streams, gossip messages
- `wire` - dial a node: ping/pong, signed `NodeAnnouncement`, gossip `Subscribe`
- `announce` - encode and sign gossip announcements
- `dial` - resolve a node address: IP literals, or a hostname via DNS
- `git.protocol` - hand-rolled git protocol v2 client (ls-refs, fetch, sideband)
- `fetch` - clone a repo: git stream, v2 fetch, packfile indexed and written to a bare repo

Storage (reading what we cloned, pure Zig via the toolchain's git plumbing):

- `storage` - the clone layout: one content-named pack plus loose refs
- identity docs read from `refs/rad/id:embeds/radicle.json`
- per-remote verification: each `rad/sigrefs` signature is checked against its node id, and every oid it signs must be present in the pack, so a peer cannot advertise refs it never sent objects for

## CLI

```
radish ping        <host> <port> <node-id>              handshake + ping/pong
radish announce    <host> <port> <node-id> [alias]      send a signed NodeAnnouncement
radish subscribe   <host> <port> <node-id> [frames]     listen to gossip (nodes + inventory)
radish fetch-probe <host> <port> <node-id> <rid>        open a git stream, read the v2 advertisement
radish clone       <host> <port> <node-id> <rid> <dir>  clone a repo into <dir> (bare), verifying each remote
```

## Build

Requires a Zig 0.17-dev toolchain; a Nix flake pins it.

```
nix develop --command zig build test
nix develop --command zig build run
```

## References

See [REFERENCES.md](REFERENCES.md) for the Radicle protocol docs and the
standards behind each encoding.

## License

[MIT](LICENSE)
