# Changelog

## v0.1.0 (unreleased)

First tagged release. Covers plan Stages 0–6, ADR-0001 (tokens as
files), and ADR-0002 (encrypted per-pubkey folders + paid-transfer
factory). All client-side flows are reachable through Finder /
`std::fs` and verified against a `docker/standalone.yml` shard.

### Mount modes

- `--mount-mode=root` (default) — oracular bundle entry as a file
  tree, backed by the on-chain `Fs` agent (ADR pre-dating this
  codebase; written in the original plan).
- `--mount-mode=wallets` (ADR-0001) — synthetic per-wallet tree with
  denominated-bill `.token` files; drag-rename to transfer REV.
- `--mount-mode=extension` (ADR-0002) — encrypted per-pubkey folders
  (SELF/RECV envelope crypto client-side), contract-folder plug-ins,
  paid-transfer factory. Opt-in on-chain settlement via
  `--chain-factory`; disk-persistent `ListingStore`; cross-daemon
  listing discovery via a per-owner on-chain manifest; synthetic
  `/<uuid>/.info` surface for inspecting a listing's price + filename
  before buying.

### Supporting infrastructure

- Linux mount backend via `fuser 0.16` on `/dev/fuse` alongside the
  existing macOS fuse-t path. Shared `Filesystem` trait.
- `FactoryClient` encapsulating sign+propose+`get_data_at_name` for
  on-chain mint / rmdir / purchase deploys.
- `NodeClient::get_data_at_name` wrapper + `deploy_id_name` /
  `string_channel_name` helpers.
- `f1r3drive-crypto` crate: AES-256-GCM + ECIES envelope, Blake2b
  key fingerprinting, keystore at `<state_dir>/keys/`.
- `f1r3drive-identity` crate: load-or-create
  `<state_dir>/identity.{key,pub}` with half-written recovery.
- `f1r3drive-wallet` crate: REV address derivation, denomination
  decomposition, balance cache.
- `f1r3drive-ext` crate: Finder Sync extension gRPC transport
  (parity with the Java f1r3drive).

### Testing

- 340+ unit tests across the workspace, all green.
- `cargo test -p f1r3drive-rho --lib paid_transfer` — 24 unit tests
  on snippet composition + reply decoding.
- `cargo test -p f1r3drive --test e2e_paid_transfer -- --ignored` — 5
  shard-side tests covering mint → purchase → decrypt + owner-check
  rmdir reply shapes.
- `cargo test -p f1r3drive --test e2e_extension_mount -- --ignored` —
  8 integration tests spawning real daemons under `--mount-mode=
  extension` and exercising ADR-0002 behaviours through `std::fs`.
- `cargo test -p f1r3drive --test e2e_balance -- --ignored` and
  `e2e_mount -- --ignored` — existing root + wallet mount coverage.

### Known limitations

See [`docs/limitations.md`](docs/limitations.md). Key v0.1 cuts:

- Nested `readdir` beyond the mount root in `--mount-mode=root` not
  wired (requires an upstream Fs-agent handler).
- Keystore GC on edit/unlink not implemented (bounded orphan growth,
  32 bytes/orphan).
- 64 MiB per-blob read cap in `ChainBlobStore`; larger blobs would
  need chunked reads.
- Buyer-side paid-transfer requires a funded vault; failed deploys
  surface as `EIO`.
- macOS Finder Extension + Windows support are v2.
