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

## Platform

- **macOS and Linux both supported for v0.1.** macOS via `fuse-t`;
  Linux via `fuser 0.16` (`/dev/fuse`). The shared `Filesystem`
  trait lives in `libfuse-t-rs` and both backends drive the same
  implementation.
- **No Windows support.** The Java f1r3drive uses WinFsp; that port is
  a v2 item.
- **No macOS Finder extension in v0.1.** Status badges and context
  menus for `.token` files are a v2 feature; the FUSE mount works the
  same as any external volume in Finder.
- **macOS "Network Volumes" permission required for `readdir` / `read`.**
  fuse-t presents the mount via NFSv4 and macOS's TCC gates network
  volume access. Grant your terminal access under *System Settings →
  Privacy & Security → Files and Folders → \<terminal\> → Network
  Volumes*. Without it, `getattr` works but `read_dir` /
  `std::fs::read` fail with EPERM. This is documented in fuse-t's
  README.

## Extension mode (ADR-0002)

- **Keystore GC not implemented.** Rename-replaces-blob and
  unlink leave the owner's old `K` entry in the on-disk keystore.
  Bounded growth (32 bytes per orphan); doesn't affect correctness.
- **64 MiB per-blob read cap.** `ChainBlobStore::get` requests
  `MAX_READ_BYTES = 64 MiB` in a single `dir_read_file_at`. Larger
  blobs would need chunked reads; not yet wired.
- **Admission-only mutating reply visibility for non-factory paths.**
  `F1r3Fs::run_mutating_snippet` + `ChainBlobStore` return on admission
  + propose success and don't observe the Fs agent's actual reply.
  The paid-transfer factory uses `get_data_at_name` on string
  observation channels; applying that pattern to the rest of the
  mutating surface is a post-v0.1 improvement.
- **Buyer flow needs funded vault.** The buyer's vault must have
  enough REV to cover both the listing price AND phlo for the
  purchase deploy. The daemon doesn't currently pre-check; a failed
  deploy surfaces as `EIO` with a tracing-level diagnostic.

## Build

- **macOS**: `brew install --cask fuse-t` is required to build
  `libfuse-t-sys`. `pkg-config` must be able to find `fuse-t.pc`
  (`.cargo/config.toml` handles the common Homebrew prefixes).
- **Linux**: builds via `fuser` without extra system deps.
