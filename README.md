# f1r3drive-rust

A Rust FUSE filesystem that mounts F1r3fly blockchain state as a local
filesystem. Open files in `/Volumes/f1r3drive`, write them, close them —
the bytes land in a consensus-replicated on-chain file store.

A re-implementation of
[F1R3FLY-io/f1r3drive](https://github.com/F1R3FLY-io/f1r3drive)
(originally Java/JNR-FUSE) built on the native file I/O layer in
[F1R3FLY-io/f1r3node-rust](https://github.com/F1R3FLY-io/f1r3node-rust).

## Status: v0.1

- All ten workspace crates compile clean; `cargo clippy --workspace
  --all-targets -- -D warnings` passes.
- 340+ unit tests across the workspace. Three shard-side integration
  suites gated behind `#[ignore]` + a running standalone shard
  (`f1r3node-rust/docker/standalone.yml`): paid-transfer flow (5
  tests), extension-mount via `std::fs` on the mountpoint (8 tests),
  balance + wallet mount smoke (several).
- Daemon mounts on macOS via `fuse-t` (no kext) and on Linux via
  `fuser` (`/dev/fuse` kernel protocol). The shared `Filesystem`
  trait lives in `libfuse-t-rs` and both backends drive the same
  implementation.
- Three mount modes:
  - **`root`** (default): oracular bundle entry as a file tree,
    backed by the on-chain `Fs` agent. Writes = signed deploys +
    optional auto-propose.
  - **`wallets`** (ADR-0001): synthetic per-wallet tree with
    `.tokens/` subdirs that enumerate on-chain balance as
    denominated bills. Drag-rename a `.token` across folders to
    transfer REV.
  - **`extension`** (ADR-0002): encrypted per-pubkey folders with
    SELF/RECV envelope crypto client-side, contract-folder
    plug-ins, paid-transfer factory. Identity bootstrapped from
    `~/.f1r3drive/identity.{key,pub}` on first run. On-chain
    factory execution is opt-in via `--chain-factory`.

## Architecture

```
┌─────────────────────────┐
│ FUSE op (kernel → libfuse-t)
└─────────────────────────┘
            │
            ▼
┌─────────────────────────┐
│ libfuse-t-sys / libfuse-t-rs  (safe Rust wrapper around libfuse-t)
└─────────────────────────┘
            │
            ▼  Filesystem trait, path-oriented
┌─────────────────────────┐
│ F1r3Fs                        (compiles each op into a Rholang snippet)
└─────────────────────────┘
            │
            ▼  Rholang term + signing
┌─────────────────────────┐
│ f1r3drive-rho   f1r3drive-client   (snippet codec, deploy signing)
└─────────────────────────┘
            │
            ▼  tonic gRPC
┌─────────────────────────┐
│  f1r3node                      (on-chain Fs/File/Dir agents)
└─────────────────────────┘
```

- **Reads** (`getattr`, `lookup`, `readdir`, `read`) use
  `ExploratoryDeploy` — read-only, no block proposal.
- **Writes** (`write`, `truncate`, `chmod`, `unlink`, `rmdir`, `rename`)
  submit a signed deploy via `DoDeploy` and (unless `--manual-propose`
  is set) issue `Propose` to seal a block.

Each FUSE op compiles to a small Rholang program that looks up the
on-chain `Fs` agent at URN
`rho:id:zphjgsfy13h1k85isc8rtwtgt3t9zzt5pjd5ihykfmyapfc4wt3x5h`, opens
the target file in the requested mode, performs the verb, and leaves
the reply on the deploy's return channel.

## Workspace layout

| Crate | Purpose |
|---|---|
| `crates/f1r3drive` | Binary: CLI + daemon entry point. |
| `crates/f1r3drive-fs` | Shared `Filesystem` impls: `F1r3Fs` (root mode), `WalletFs` (wallets mode), `ExtensionFs` (extension mode). Blob stores, factory client, contract-folder registry. |
| `crates/f1r3drive-rho` | Rholang snippet generation + reply decoding; paid-transfer factory contract; FSERR codes. |
| `crates/f1r3drive-client` | `tonic` gRPC client, deploy signing (secp256k1 ECDSA DER), key loading, `get_data_at_name`. |
| `crates/f1r3drive-proto` | `tonic`-generated protobuf, vendored from `f1r3node-rust/models/`. |
| `crates/f1r3drive-crypto` | SELF/RECV envelope format (AES-256-GCM + ECIES), symmetric keystore. |
| `crates/f1r3drive-identity` | Local identity bootstrap at `<state_dir>/identity.{key,pub}`. |
| `crates/f1r3drive-wallet` | REV address derivation, denomination model, balance cache. |
| `crates/f1r3drive-ext` | Finder-extension gRPC transport (`generic.FinderSyncExtensionService`). |
| `crates/libfuse-t-sys` | Raw FFI bindings to libfuse-t's high-level C API (macOS). |
| `crates/libfuse-t-rs` | Safe Rust wrapper around `libfuse-t-sys`; also hosts the shared `Filesystem` trait. |

## Platforms (v0.1)

- **macOS** via [`fuse-t`](https://github.com/macos-fuse-t/fuse-t).
  fuse-t has no kernel extension — it embeds an NFSv4 server that
  bridges to the libfuse C API, and we drive that from Rust via the
  `libfuse-t-sys` / `libfuse-t-rs` crates we ship here.

- **Linux** via `fuser 0.16` driving `/dev/fuse` directly. The
  `linux_mount` module in `f1r3drive-fs` translates fuser's
  inode-based callbacks into the shared path-based `Filesystem`
  trait that both backends implement.

- **Windows** is explicitly out of scope; the Java f1r3drive supports
  it via WinFsp and that port is a v2 item.

- **macOS Finder extension** (status badges, context menus) is deferred
  to v2 — the FUSE mount works the same as any external volume in
  Finder without it.

## Prerequisites

- Rust toolchain (see `rust-toolchain.toml` — nightly-2026-02-09, same
  as f1r3node-rust).
- Running f1r3node accessible over gRPC. See
  [f1r3node-rust/docker](https://github.com/F1R3FLY-io/f1r3node-rust/tree/main/docker)
  for a local shard.
- **macOS:** `brew install --cask fuse-t`
  ([install docs](https://github.com/macos-fuse-t/fuse-t)).

## Quick start

```shell
# 1. Boot a shard (from a sibling f1r3node-rust checkout):
docker compose -f ../f1r3node-rust/docker/shard.yml up -d

# 2. Save your deployer key:
mkdir -p ~/.keys
printf '0x%s' <YOUR_HEX_KEY> > ~/.keys/dev.hex

# 3. Mount:
mkdir -p /tmp/f1r3mnt
cargo run -p f1r3drive -- \
    --key-file ~/.keys/dev.hex \
    --host 127.0.0.1 --port 40401 \
    --mount-source root \
    /tmp/f1r3mnt
```

Then from another terminal:

```shell
ls /tmp/f1r3mnt
cat /tmp/f1r3mnt/some-file
echo hello > /tmp/f1r3mnt/new-file
```

To unmount, SIGINT the daemon or `umount /tmp/f1r3mnt`.

## Extension mode (ADR-0002)

The newest surface. Mounts a per-user tree of encrypted files
addressed by secp256k1 public key, with a plug-in registry for
"contract folders" — v0.1 ships one: *Paid transfer*.

```shell
# No key file needed — identity is self-provisioned at
# ~/.f1r3drive/identity.{key,pub} on first run.
mkdir -p /tmp/ext
cargo run -p f1r3drive -- \
    --mount-mode extension \
    --host 127.0.0.1 --port 40401 \
    /tmp/ext
```

The mount looks like:

```
/tmp/ext/
├── <my-pubkey-130hex>/                   my own folder (read + write)
│   ├── .tokens/<denom>-REV.<i>.token     bills (balance view)
│   ├── Paid transfer/                    factory folder
│   └── <plaintext-filenames>             encrypted blobs
├── <other-pubkey-130hex>/                tracked peers (empty readdir)
└── <uuid-of-listing>/                    minted listings
    └── .info                             JSON: owner, price, filename
```

Workflow:

```shell
# Alice drops a file she wants to sell for 10 REV:
echo "the manuscript" > "/tmp/ext/<my-pubkey>/Paid transfer/10REV-manuscript.txt"
# → a new /<uuid> folder appears at root, encrypted copy stored
# → inspect via `cat /tmp/ext/<uuid>/.info`

# Transfer a file to Bob (SELF→RECV re-wrap, client-side):
mv "/tmp/ext/<my-pubkey>/notes.txt" "/tmp/ext/<bob-pubkey>/notes.txt"
# Bob sees `notes.txt` in his folder on next readdir, decrypted via
# his own private key.

# Burn a listing:
rmdir "/tmp/ext/<uuid>"
```

Pass `--chain-factory` (plus a `--key-file` or `--private-key`) to
route Paid-transfer mint + rmdir + purchase deploys through the
on-chain Rholang factory. Without it, listings live purely in the
daemon's local state (good for offline / development).

Pass `--chain-blobs` separately to persist regular encrypted blobs
on-chain via the `Fs` agent instead of the default in-process
store. Independent of `--chain-factory`.

Pass `--track-pubkey <hex>` (repeatable) to surface tracked peers'
listings at root via their on-chain manifest.

## CLI

Flag parity with the Java f1r3drive, plus Rust-side additions:

| Flag | Default | Purpose |
|---|---|---|
| `--host` | `127.0.0.1` | Validator host for writes. |
| `--port` | `40401` | Validator gRPC port. |
| `--observer-host` | `--host` | *(parity, no behavior yet)* |
| `--observer-port` | `--port` | *(parity, no behavior yet)* |
| `--key-file <path>` | — | Signing key (hex or 32 raw bytes). |
| `--private-key <hex>` | — | Signing key inline. Mutually exclusive with `--key-file`. |
| `--address <hex>` | — | *(parity, derived from key)* |
| `--shard-id <id>` | `root` | Shard baked into every signed deploy. |
| `--manual-propose` | off | Don't auto-propose after writes. |
| `--read-only` | off | Force RO even with a key loaded. |
| `--mount-mode <root/wallets/extension>` | `root` | Top-level filesystem shape. |
| `--mount-source <name>` | `root` | (`--mount-mode=root`) Bundle entry exposed as the mount root. |
| `--fs-urn <urn>` | genesis URN | Override the on-chain `Fs` agent URN. |
| `--state-dir <path>` | `$HOME/.f1r3drive` | (extension) Where identity + listing-store state lives. |
| `--track-pubkey <hex>` | — | (extension, repeatable) Render a tracked peer in `readdir /`. |
| `--chain-blobs` | off | (extension) Persist encrypted blobs on-chain via the `Fs` agent. |
| `--chain-factory` | off | (extension) Route Paid-transfer mint/rmdir/purchase through the on-chain Rholang factory. |
| `--track-address <addr>` | — | (`--mount-mode=wallets`, repeatable) Surface a REV address as a locked wallet directory. |
| `--unlock-key-file <path>` | — | (`--mount-mode=wallets`, repeatable) Pre-unlock a wallet directory from a key file. |
| `--balance-ttl <dur>` | `5s` | (`--mount-mode=wallets`) `.tokens/` balance cache TTL. |
| `--extension-grpc-port <port>` | `40411` | Finder-extension gRPC port; 0 disables. |
| `--attr-timeout <dur>` | `1s` | Attribute cache TTL. |
| `--entry-timeout <dur>` | `1s` | Entry cache TTL. |
| `--volume-name <name>` | `f1r3drive` | Finder volume name (macOS). |
| `--allow-other` | off | `-o allow_other` on Linux mount. |
| `--debug` | off | Trace-level logging. |

## Testing

```shell
# Unit tests (no shard required, ~340 tests across the workspace):
cargo test --workspace --lib

# Shard-side integration suites (bring up `docker/standalone.yml` first,
# then):
cargo test -p f1r3drive --test e2e_paid_transfer    -- --ignored
cargo test -p f1r3drive --test e2e_extension_mount  -- --ignored
cargo test -p f1r3drive --test e2e_balance          -- --ignored
cargo test -p f1r3drive --test e2e_mount            -- --ignored
```

See [`docs/testing.md`](docs/testing.md) for details on the fixtures
+ environment variables that override the node endpoint.

## Known limitations

See [`docs/limitations.md`](docs/limitations.md) for the full list.
Highlights:

- Nested `readdir` beyond the mount root in `--mount-mode=root` isn't
  wired yet (requires an upstream Fs-agent handler).
- Mutating-deploy reply visibility is admission-only outside the
  paid-transfer factory. In practice admission + propose errors
  propagate as `EIO`; silent partial writes are rare but not
  currently caught by the client.
- Keystore GC on edit/unlink not implemented; 32 bytes/orphan.
- 64 MiB per-blob read cap in `ChainBlobStore`.
- macOS `read_dir` / `std::fs::read` on the mount require "Network
  Volumes" access in Privacy & Security (fuse-t ships NFSv4 under
  the hood). `getattr` doesn't need it.

## License

Apache-2.0.
