# Developer Guide

Native development setup for the Rust workspace.

This repository is built with Cargo and system packages only. The live-shard test suites also need Docker and a sibling `f1r3node-rust` checkout. [docs/ci.md](docs/ci.md) describes the CI jobs. [CONTRIBUTING.md](CONTRIBUTING.md) describes the contribution workflow.

## Required Tooling

### macOS

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

brew install --cask fuse-t
brew install protobuf pkg-config coreutils ruby jq
```

fuse-t installs `/usr/local/lib/libfuse-t.dylib` and `/usr/local/lib/pkgconfig/fuse-t.pc`. It has no kernel extension.

### Ubuntu Or Debian

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

sudo apt-get update
sudo apt-get install -y \
  libfuse3-dev \
  pkg-config \
  protobuf-compiler \
  build-essential \
  ruby \
  jq
```

`.github/apt-dependencies.txt` holds the package list that CI installs.

### Fedora Or RHEL

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

sudo dnf install -y \
  fuse3-devel \
  pkgconf-pkg-config \
  protobuf-compiler \
  gcc \
  ruby \
  jq
```

### Cargo Tools

```bash
cargo install cargo-nextest --locked
cargo install cargo-deny --locked
```

## Git Hooks

Install the hooks after cloning:

```bash
./scripts/setup-hooks.sh
```

This sets `core.hooksPath` to `.githooks/`, which provides:

| Hook         | Runs            | Checks                                                                                  |
|--------------|-----------------|-----------------------------------------------------------------------------------------|
| `pre-commit` | On every commit | `cargo fmt --check`, `cargo clippy -D warnings`, `cargo deny check`, tracked key material |
| `commit-msg` | On every commit | Unratified `Co-authored-by` trailers, denied identities, `Claude-Session` trailers      |
| `pre-push`   | On every push   | `cargo clippy`, CI script tests, `cargo nextest run --workspace`, doctests              |

All hooks skip automatically in CI environments. The pre-push hook gives each command 900 seconds. If cargo-deny is not installed, the pre-commit hook skips that check.

`core.hooksPath` replaces `.git/hooks/`. If you keep other hooks there, for example ctags hooks, install with `--copy`.

If the remote already has every ref that you push, the pre-push hook stops and runs no checks.

### Hook Options

```bash
# Commit with skips
SKIP_FMT=1 git commit -m "wip"
SKIP_CLIPPY=1 git commit -m "wip"
SKIP_DENY=1 git commit -m "wip"
SKIP_KEYS=1 git commit -m "wip"
VERBOSE=1 git commit -m "wip"              # Show full output

# Push with skips
QUICK=1 git push                           # Skip doctests
SKIP_TESTS=1 git push                      # Skip Rust tests
SKIP_CLIPPY=1 git push                     # Skip clippy
SKIP_CI_TESTS=1 git push                   # Skip CI script tests
TEST_CRATES="f1r3drive-fs f1r3drive-rho" git push   # Test specific crates only
TEST_RUNNER=cargo git push                 # Use cargo test for A/B comparison
TEST_TIMEOUT=300 git push                  # Adjust the per-command timeout

# Bypass entirely (not recommended)
git commit --no-verify
git push --no-verify
```

### Hook Management

```bash
./scripts/setup-hooks.sh --status   # Show current configuration
./scripts/setup-hooks.sh --copy     # Alternative: copy to .git/hooks/
./scripts/setup-hooks.sh --remove   # Remove hooks
```

## Toolchain

The workspace is pinned in [rust-toolchain.toml](rust-toolchain.toml), the same toolchain as `f1r3node-rust`:

```bash
rustup toolchain install nightly-2026-02-09
rustup show
```

## Environment Notes

`.cargo/config.toml` sets these values for macOS builds:

- `PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/opt/homebrew/lib/pkgconfig`, so the `libfuse-t-sys` build script finds `fuse-t.pc` also inside Nix dev shells.
- An rpath to `/usr/local/lib` for every binary and test, because `libfuse-t.dylib` has the install name `@rpath/libfuse-t.dylib`.

On macOS, `read_dir` and `std::fs::read` on a mount need the **Network Volumes** permission in **System Settings → Privacy & Security**. fuse-t serves the mount over NFSv4.

The pre-push hook needs GNU `timeout`. On macOS, Homebrew `coreutils` installs it as `gtimeout`, and the hook accepts both names.

## Common Workflows

### Build

```bash
cargo build --workspace
cargo build -p f1r3drive --release
```

### Format And Lint

```bash
cargo fmt --all
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo deny check
```

### Test

```bash
cargo nextest run --locked --workspace --no-tests=pass
cargo test --locked --workspace --doc          # nextest does not run doctests
cargo nextest run --locked -p f1r3drive-rho    # One crate
```

The CI script tests need no Rust build:

```bash
bash .github/scripts/check-workflow-invariants.sh
bash .github/scripts/check-ci-docs.sh
bash .github/scripts/test-check-commit-trailers.sh
bash .github/scripts/test-commit-policy-exemptions.sh
bash .github/scripts/test-check-tracked-key-material.sh
bash .github/scripts/test-pre-push-hook.sh
```

### Run Against A Local Shard

From a sibling `f1r3node-rust` checkout:

```bash
# docker/.env is not tracked: copy the development template (public keys, local use only)
cp ../f1r3node-rust/docker/.env.example ../f1r3node-rust/docker/.env

# Standalone (single node). The e2e suites use it.
docker compose -f ../f1r3node-rust/docker/standalone.yml up -d

# Multi-validator shard. f1r3drive-fs/tests/live_shard.rs uses it.
docker compose -f ../f1r3node-rust/docker/shard.yml up -d
```

The live-shard suites are `#[ignore]`-gated. [docs/testing.md](docs/testing.md) lists them and their environment variables.

```bash
cargo test -p f1r3drive --test e2e_paid_transfer -- --ignored
```

## Workspace Layout

[README.md](README.md#workspace-layout) lists the crates. The development files are:

```text
f1r3drive-rust/
├── .githooks/           # pre-commit, commit-msg, pre-push
├── .github/
│   ├── workflows/ci.yml # CI (docs/ci.md)
│   ├── scripts/         # CI checks and their script tests
│   ├── CODEOWNERS
│   ├── denied-identities.txt
│   └── known-dev-keys.txt
├── scripts/setup-hooks.sh
├── deny.toml            # cargo-deny policy
└── rust-toolchain.toml
```

## Troubleshooting

### `library 'fuse-t' not found`

The linker cannot find libfuse-t. Install fuse-t and check the pkg-config file:

```bash
brew install --cask fuse-t
ls /usr/local/lib/libfuse-t.dylib /usr/local/lib/pkgconfig/fuse-t.pc
```

To test only the crates that do not link fuse-t:

```bash
cargo nextest run -p f1r3drive-client -p f1r3drive-rho -p f1r3drive-proto \
  -p f1r3drive-wallet -p f1r3drive-crypto -p f1r3drive-identity
```

### `protoc` Not Found

```bash
which protoc
export PROTOC=$(which protoc)
```

### Mount Reads Fail With `Operation not permitted` On macOS

Give your terminal the **Network Volumes** permission in **System Settings → Privacy & Security**.

### Commit Rejected By `commit-msg`

The hook names the trailer. Remove `Co-authored-by` lines for AI tools and any `Claude-Session` trailer, then commit again. Turn off the co-author attribution setting in your Claude Code `settings.json`.
