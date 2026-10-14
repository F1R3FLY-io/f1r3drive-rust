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
cargo test --test live_shard -- --ignored --nocapture
```

Two tests run:

- `live_shard_golden_path`: mount → stat → write → read → stat → unlink
- `live_shard_readonly_without_signer`: mount without `--key-file` and
  verify writes are rejected

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
