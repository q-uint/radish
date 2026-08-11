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
```

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
