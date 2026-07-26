# References

## Radicle

- [Radicle Protocol Guide](https://docs.radicle.xyz/guides/protocol) - the spec: Node IDs, RIDs, identity document, `refs/rad/*`, gossip.
- [Radicle Protocol Overview - Heartwood Release (HackMD)](https://hackmd.io/@radicle/rJ2UH54P6) - narrative architecture overview.
- [radicle/heartwood](https://codeberg.org/radicle/heartwood) - reference implementation (Rust); ground truth for byte layouts and vectors.
  - `crates/radicle/src/crypto.rs` - keys, signatures.
  - `crates/radicle/src/identity/doc.rs` - identity `Doc`, canonical encoding, `embeds/radicle.json` storage.
  - `crates/radicle-core/src/repo.rs` - `RepoId` (RID).
  - `crates/radicle/src/canonical/formatter.rs` - canonical JSON.
  - `crates/radicle/src/storage/refs.rs` - `Refs`/`SignedRefs` (sigrefs).
- [heartwood/HACKING.md](https://codeberg.org/radicle/heartwood/blob/master/HACKING.md) - build/architecture notes.
- [Collaborative Objects RFC](https://github.com/radicle-dev/radicle-link/blob/master/docs/rfc/0662-collaborative-objects.adoc) - COB design.

## Wire protocol

- [radicle/heartwood `crates/radicle-protocol`](https://codeberg.org/radicle/heartwood/src/branch/master/crates/radicle-protocol) - framing, streams, gossip messages, the fetch handshake (ground truth for byte layouts).
  - `src/wire/frame.rs` - `StreamId`, `StreamType`, `Control`, frame encode/decode.
  - `src/wire/message.rs` - `Address`, `NodeAnnouncement`, gossip message encode/decode.
  - `src/service/{message,filter}.rs` - `Subscribe`, bloom `Filter`.
  - `crates/radicle-node/src/worker/upload_pack.rs` - the `git-upload-pack` request header the node expects.
- [Noise Protocol Framework](https://noiseprotocol.org/noise.html) - the `XK` pattern radicle names (radicle diverges: Edwards25519 DH, see `noise.zig`).
- [RFC 9000 s16](https://www.rfc-editor.org/rfc/rfc9000#section-16) - QUIC variable-length integers (the framing varints).

## Git protocol

- [gitprotocol-pack](https://git-scm.com/docs/gitprotocol-pack) - the `git-upload-pack /repo\0...` request and pack negotiation.
- [gitprotocol-v2](https://git-scm.com/docs/gitprotocol-v2) - protocol v2 (`ls-refs`, `fetch`) - what radicle-node requires.
- [gitprotocol-common](https://git-scm.com/docs/gitprotocol-common) - pkt-line framing.
- [gitformat-pack](https://git-scm.com/docs/gitformat-pack) - packfile format.

## Underlying standards

- [did:key method](https://w3c-ccg.github.io/did-method-key/)
- [Multibase](https://github.com/multiformats/multibase)
- [Multicodec table](https://github.com/multiformats/multicodec/blob/master/table.csv)
- [base58 (Bitcoin alphabet)](https://datatracker.ietf.org/doc/html/draft-msporny-base58)
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) - Ed25519 signature test vectors.

## Test vector provenance

- base58: draft-msporny-base58 Section 5.
- Node ID / did:key: heartwood `identity/did.rs` (`test_did_vectors`, `test_did_encode_decode`).
- Ed25519 sign/verify: RFC 8032 Section 7.1 TEST 2.
- Canonical JSON: golden bytes from heartwood's `CanonicalFormatter`.
