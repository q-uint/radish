# Radish

A [Radicle](https://radicle.xyz) client and node, in Zig.

Early work in progress. The identity and encoding layer is implemented and
tested against authoritative Radicle Heartwood vectors:

- `base58` - base58btc (multibase `z`)
- `NodeId` - Ed25519 public key as `did:key:z6Mk...`
- `RepoId` - repository identifier `rad:z...`
- `canonical` - Radicle canonical JSON (NFC-normalized, sorted keys, integer-only)
- `Doc` - identity document; its canonical git-blob hash is the RID
- `unicode` - NFC via a forked [zg](https://codeberg.org/dude_the_builder/zg)

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
