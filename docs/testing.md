# Testing

## Unit + smoke tests (no shard required)

```shell
cargo test --workspace
```

Exercises:

- Rholang snippet generation (`f1r3drive-rho`, 24 tests)
- gRPC deploy signing and reply decoding (`f1r3drive-client`, 6 tests)
- Path dispatch + inode logic (`f1r3drive-fs`, 3 tests)
- `libfuse-t-sys` + `libfuse-t-rs` mount pipelines on macOS (2 smoke tests)

Clippy passes under `-D warnings`:

```shell
cargo clippy --workspace --all-targets -- -D warnings
```

## Live-shard E2E tests

Require a running local f1r3node shard. Marked `#[ignore]` so they
don't gate normal CI.

### 1. Boot a shard

From a sibling checkout of `f1r3node-rust`:

```shell
cd ../f1r3node-rust
docker compose -f docker/shard.yml up -d
```

Wait for the validators to finish genesis — tail the logs until you see
`Casper initialised`:

```shell
docker compose -f docker/shard.yml logs -f rnode.bootstrap
```

### 2. Provision a mount-source bundle entry

Edit the shard's node config to add a `consensus-static-dirs` entry
exposing a writable directory as the logical name `root` (matching the
test's default `--mount-source`):

```hocon
storage {
  consensus-static-dirs = {
    root = { path = "/data/root", mode = "rw" }
  }
}
```

Restart the shard after the config change.

### 3. Run the tests

```shell
cargo test -p f1r3drive --test e2e_mount           -- --ignored --nocapture
cargo test -p f1r3drive --test e2e_balance         -- --ignored --nocapture
cargo test -p f1r3drive --test e2e_extension_mount -- --ignored --test-threads=1
cargo test -p f1r3drive --test e2e_paid_transfer   -- --ignored --nocapture
```

Covers:

- `e2e_mount`: root-mode golden path (stat → write → read → unlink).
- `e2e_balance`: wallet-mode denomination decomposition + drag-rename
  REV transfer.
- `e2e_extension_mount`: eight extension-mode scenarios through
  `std::fs` (own-folder create/write/read, rename, unlink, non-owner
  rmdir denial, drop-into-Paid-transfer mint, owner rmdir).
- `e2e_paid_transfer`: five shard-side paid-transfer tests (mint reply
  shape, mint→purchase→decrypt capstone, owner/non-owner rmdir reply
  shapes). `e2e_extension_mount` must run single-threaded because each
  test spawns its own daemon on a mountpoint.

### 4. (macOS only) Grant "Network Volumes" access

fuse-t presents the mount as an NFS v4 volume. macOS's TCC
(Transparency, Consent, Control) blocks `readdir` and `read` on
network volumes by default. Grant your terminal access under:

*System Settings → Privacy & Security → Files and Folders →
\<your terminal\> → Network Volumes*

Without this permission, the tests still prove mount setup and
`getattr` dispatch work; only `read_dir` and `read` fail with EPERM.

## Manual mount

```shell
mkdir -p /tmp/f1r3mnt
cargo run -p f1r3drive -- \
    --host 127.0.0.1 --port 40401 \
    --key-file ~/.keys/dev.hex \
    /tmp/f1r3mnt
```

Then from another terminal:

```shell
ls /tmp/f1r3mnt
cat /tmp/f1r3mnt/some-file
echo hello > /tmp/f1r3mnt/new-file
```

Unmount with `umount /tmp/f1r3mnt` (macOS) or stop the daemon
(SIGINT/SIGTERM).

## Platform verification

The v0.1 cut is verified green on the following combinations.

### macOS (fuse-t)

- macOS 14.6 (23G80), Darwin arm64 (Apple Silicon).
- fuse-t 1.2.9 via the `macos-fuse-t/homebrew-cask/fuse-t` tap.
- `cargo test --workspace` — all workspace unit + smoke suites green.
- `cargo test -p f1r3drive --test e2e_extension_mount -- --ignored
  --test-threads=1` — 8/8 passing (one daemon spawned per test, each
  under `--mount-mode extension` against a standalone shard).
- `cargo test -p f1r3drive --test e2e_paid_transfer -- --ignored` —
  5/5 passing (mint, rmdir, mint→purchase→decrypt).

fuse-t presents the mount as an NFS v4 volume. The TCC "Network
Volumes" prompt (see §4 above) is required for `readdir` / `read` to
succeed; the e2e harness drives those paths, so if the suites fail
with `EPERM` on first run, grant the terminal that permission and
rerun. No kext install is required — fuse-t is kext-less by design,
which also means no reboot and no SIP toggling between upgrades.

### Linux (fuser)

Native FUSE via the kernel's `/dev/fuse`; the `fuser` crate talks the
libfuse ABI directly. CI (`ubuntu-latest`) runs fmt + clippy + build
+ `cargo test --workspace --all-targets` green on every PR, which
exercises the FUSE op dispatcher's unit matrix and the shared
`Filesystem` trait. The `#[ignore]`-gated e2e suites require a live
f1r3node shard and are driven manually from the commands in §3 above
(not booted inside CI).
