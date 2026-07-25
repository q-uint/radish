# References

## Radicle

- [Radicle Protocol Guide](https://docs.radicle.xyz/guides/protocol) - canonical spec: Node IDs, RIDs, identity document, `refs/rad/*`, gossip.
- [Radicle Protocol Overview - Heartwood Release (HackMD)](https://hackmd.io/@radicle/rJ2UH54P6) - narrative architecture overview.
- [radicle/heartwood](https://codeberg.org/radicle/heartwood) - reference implementation (Rust). Ground truth for byte layouts and test vectors. See `radicle/src/crypto.rs`, `radicle/src/identity/`, `radicle-node`.
- [heartwood/HACKING.md](https://codeberg.org/radicle/heartwood/blob/master/HACKING.md) - build/architecture notes.

Key facts:
- Node ID == Peer ID == Public Key: an Ed25519 key rendered as `did:key:z6Mk...`.
  Payload = multicodec `0xed01` ++ 32-byte key, multibase base58btc (`z`).
- RID: `rad:` ++ multibase base58btc (`z`) of the 20-byte git SHA-1 of the
  canonical identity-document blob. No multicodec prefix (unlike Node ID).
  Only base58btc is accepted on decode; other multibase tags are rejected.
  Source: heartwood `crates/radicle-core/src/repo.rs` (`RepoId`),
  `crates/radicle/src/identity/doc.rs` (`Doc::encode`, canonical JSON).
- Git blob oid: SHA-1 of `"blob " ++ len ++ "\0" ++ content`.
- Canonical JSON (radicle variant of Canonical JSON):
  - object keys sorted by their serialized UTF-8 bytes; compact separators,
    no insignificant whitespace.
  - every string fragment NFC-normalized before writing (needs a Unicode NFC
    table - the one non-trivial dependency for the doc slice).
  - control chars U+0000..U+001F escaped per RFC 8259 (`\"` `\\` `\b` `\f`
    `\n` `\r` `\t`, else `\u00xx`), hex lower-case. This DIFFERS from Canonical
    JSON proper, which does not escape control chars.
  Source: heartwood `crates/radicle/src/canonical/formatter.rs`.

## Underlying standards

- [did:key method](https://w3c-ccg.github.io/did-method-key/) - `did:key:z6Mk...` construction; Ed25519 test vectors.
- [Multibase](https://github.com/multiformats/multibase) - the `z` = base58btc prefix.
- [Multicodec table](https://github.com/multiformats/multicodec/blob/master/table.csv) - `ed25519-pub = 0xed`, varint-encoded to `0xed 0x01`.
- [base58 (Bitcoin alphabet)](https://datatracker.ietf.org/doc/html/draft-msporny-base58) - alphabet, algorithm, and the test vectors in `base58.zig`.

## Test vector provenance

- base58 vectors: draft-msporny-base58 Section 5 (Test Vectors).
- Node ID / did:key vectors: heartwood `crates/radicle/src/identity/did.rs` (`test_did_vectors`, `test_did_encode_decode`).
