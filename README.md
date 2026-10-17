# f1r3drive-rust

A Rust FUSE filesystem that mounts F1r3fly blockchain state as a local
filesystem. Open files in `/Volumes/f1r3drive`, write them, close them —
the bytes land in a consensus-replicated on-chain file store.

A re-implementation of
[F1R3FLY-io/f1r3drive](https://github.com/F1R3FLY-io/f1r3drive)
(originally Java/JNR-FUSE) built on the native file I/O layer in
[F1R3FLY-io/f1r3node-rust](https://github.com/F1R3FLY-io/f1r3node-rust).

## Status: v1-ready on macOS

- All six workspace crates compile clean; `cargo clippy -D warnings`
  passes.
- 37 passing tests across unit + two mount smoke tests; two live-shard
  tests gated behind `--ignored` ready for use once a shard is up.
- Daemon mounts on macOS via `fuse-t` (no kext). Linux support is
  present in the Rholang + client crates but the FUSE mount layer is
  macOS-only in v1 (see *Platforms* below).

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
| `crates/f1r3drive-fs` | `libfuse_t_rs::Filesystem` impl; translates FUSE ops to Rholang snippets. |
| `crates/f1r3drive-rho` | Rholang snippet generation + reply decoding; mirrors the FSERR codes. |
| `crates/f1r3drive-client` | `tonic` gRPC client, deploy signing (secp256k1 ECDSA DER), key loading. |
| `crates/f1r3drive-proto` | `tonic`-generated protobuf, vendored from `f1r3node-rust/models/`. |
| `crates/libfuse-t-sys` | Raw FFI bindings to libfuse-t's high-level C API. |
| `crates/libfuse-t-rs` | Safe Rust wrapper around `libfuse-t-sys` — the thing `f1r3drive-fs` builds on. |

## Platforms (v1)

- **macOS** via [`fuse-t`](https://github.com/macos-fuse-t/fuse-t).
  fuse-t has no kernel extension — it embeds an NFSv4 server that
  bridges to the libfuse C API, and we drive that from Rust via the
  `libfuse-t-sys` / `libfuse-t-rs` crates we ship here.

- **Linux** support is partially present: the `f1r3drive-rho`,
  `f1r3drive-client`, and `f1r3drive-proto` crates all build and test
  on Linux, but `f1r3drive-fs` and `f1r3drive` are `#[cfg(target_os =
  "macos")]`-gated in v1. The straightforward path is a Linux mount
  backend via `fuser 0.18`'s `/dev/fuse` path; that lands post-v1.

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
| `--mount-source <name>` | `root` | Bundle entry exposed as the mount root. |
| `--fs-urn <urn>` | genesis URN | Override the on-chain `Fs` agent URN. |
| `--attr-timeout <dur>` | `1s` | Attribute cache TTL. |
| `--entry-timeout <dur>` | `1s` | Entry cache TTL. |
| `--volume-name <name>` | `f1r3drive` | Finder volume name (macOS). |
| `--debug` | off | Trace-level logging. |

## Tokens as files

`--mount-mode=wallets` exposes on-chain REV balances as a synthetic
file tree — one directory per wallet, each with a `.tokens/`
subdirectory of zero-byte `<denom>-REV.<i>.token` entries. Drag a
token across wallet directories to initiate an on-chain transfer.
Design: [`docs/architecture/ADR-0001-token-as-file.md`](docs/architecture/ADR-0001-token-as-file.md).

The macOS Finder Sync extension at
[`F1R3FLY-io/f1r3drive-extension`](https://github.com/F1R3FLY-io/f1r3drive-extension)
drives the right-click Change / Combine actions and `f1r3drive://unlock`
deep links via the daemon's loopback gRPC. Install + build steps:
[`docs/finder-extension.md`](docs/finder-extension.md).

## Testing

See [`docs/testing.md`](docs/testing.md). Short version:

```shell
cargo test --workspace                               # unit + smoke
cargo test --test live_shard -- --ignored --nocapture # live-shard e2e
```

## Known limitations

See [`docs/limitations.md`](docs/limitations.md). Highlights:

- Nested `readdir` beyond the mount root isn't wired yet
  (`FtFsError::NotSupported`). Flat bundle trees work; nested dirs come
  with the Dir ops migration.
- Write path reports the input size on success without reading back the
  deploy's `[true, nWritten]` reply. In practice admission + propose
  errors propagate as EIO; silent partial writes should be rare but
  aren't currently caught by the client.
- macOS `read_dir` / `std::fs::read` on the mount require "Network
  Volumes" access in Privacy & Security (fuse-t ships NFSv4 under the
  hood). `getattr` doesn't need it.

## License

Apache-2.0.
