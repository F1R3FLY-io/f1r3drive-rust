# Known limitations

## Filesystem semantics

- **No symlinks, FIFOs, sockets, or device nodes.** The on-chain `Fs`
  agent in `f1r3node-rust` currently only models regular files and
  directories. Symlink support requires new native handlers
  (`fs_symlink`, `fs_readlink`) upstream.
- **No mmap.** FUSE does not expose shared-memory mapping to the daemon
  in a way we can translate to on-chain reads cheaply.
- **No extended attributes beyond mode bits.** `fs_chmod` is the only
  metadata-mutation handler currently exposed; ownership (`fs_chown`)
  is present but returns `FSERR_UNSUPPORTED` in consensus mode.
- **No `mkdir` or file creation.** `openDir(rel, {"path": true})` is
  the Fs-agent path for mkdir-like semantics but is not yet implemented
  upstream (`FSERR_UNSUPPORTED`). `create()` returns `NotSupported`.
- **Nested `readdir` not wired.** Only the mount-root directory can be
  enumerated. Reading / writing / stat'ing nested files works via
  `Dir.openFile(rel)`, but a `readdir` on a subdirectory returns
  `NotSupported`.

## Consistency

- **Writes are deploy-latency bound.** Each mutator FUSE op issues a
  signed deploy and (unless `--manual-propose` is set) a propose, so
  writes typically complete on the order of seconds, bounded by the
  shard's block cadence.
- **Reads reflect the LFB.** `read` and `getattr` go through
  `ExploratoryDeploy`, which runs against the last-finalized-block
  post-state. Writes submitted by the same client may not be visible
  to subsequent reads until the next block finalizes.
- **Write replies are optimistic.** The client reports success based on
  deploy admission + propose. The actual `[true, nWritten]` reply from
  the `Fs` agent isn't fetched back — retrieving it would require a
  `getDataAtName` round-trip against the deploy's unforgeable return
  channel, which is tracked as a post-v1 enhancement.

## Wallets mode (`--mount-mode=wallets`)

- **No persistence of unlocked keys.** Private keys live in-memory in
  the `KeyStore` and drop on daemon restart. Persisting them on disk
  would risk leaking into the oracular bundle, per ADR-0001.
- **No node → daemon push.** Balance changes initiated by *other*
  clients are observed only on the next `.tokens/` readdir refresh
  (default TTL 5s). The daemon doesn't subscribe to any on-chain
  event stream.
- **`SubmitAction(COMBINE, …)` returns an error.** Combining ten
  smaller bills into one larger is not implemented in v1 — matches
  Java f1r3drive. CHANGE (break one bill into ten smaller) works.
- **CHANGE overrides are per-process in-memory.** Any transfer-in/out
  drops the override. A daemon restart drops them all; the next
  readdir falls back to greedy denomination decomposition.
- **No finality tracking surface.** Transfers return success as soon
  as the deploy admits + proposes. A `.pending/` subtree reflecting
  pre-finalization state is a v2 feature.
- **Loopback-only Finder-ext gRPC, no TLS.** Private-key material
  flows into the daemon over `127.0.0.1:40411`. The port is
  addressable only from the local machine; UDS transport is a v2
  fork point if we need to tighten.
- **No multi-signature wallets.** The daemon models single-signer
  secp256k1 only. `cosigners` / `cosigner_threshold` are a cross-cut
  feature with f1r3node-rust that lands post-v1.
- **No non-REV tokens.** The `.tokens/` surface is REV-only.
  Arbitrary vaults need new Fs-agent surface area.

## Platform

- **No Windows support.** The Java f1r3drive uses WinFsp; that port is
  a v2 item.
- **macOS "Network Volumes" permission required for `readdir` / `read`.**
  fuse-t presents the mount via NFSv4 and macOS's TCC gates network
  volume access. Grant your terminal access under *System Settings →
  Privacy & Security → Files and Folders → \<terminal\> → Network
  Volumes*. Without it, `getattr` works but `read_dir` /
  `std::fs::read` fail with EPERM. This is documented in fuse-t's
  README.

## Build

- **macOS**: `brew install --cask fuse-t` is required to build
  `libfuse-t-sys`. `pkg-config` must be able to find `fuse-t.pc`
  (`.cargo/config.toml` handles the common Homebrew prefixes).
- **Linux**: the mount layer is `#[cfg(target_os = "macos")]`-gated,
  so `f1r3drive-fs` and the `f1r3drive` binary don't build on Linux
  yet. All other crates compile.
