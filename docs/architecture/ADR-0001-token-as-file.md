# ADR-0001: Tokens as files

- **Status**: Proposed
- **Date**: 2026-10-17
- **Deciders**: core f1r3drive-rust maintainers
- **Supersedes**: n/a
- **Related**: `../../crates/f1r3drive-proto/proto/FinderSyncExtensionService.proto`

## Context

The Java `F1R3FLY-io/f1r3drive` daemon exposes on-chain REV balances as
a tree of fake, zero-byte files underneath per-wallet directories.
Each file name encodes a denomination (one of 10⁰ … 10¹⁸ REV) and an
index. Dragging such a file between wallet directories triggers a
transfer deploy; right-clicking it in Finder opens a context menu
("Change", "Combine") served by a bundled macOS Finder Sync
extension over loopback gRPC.

We are re-implementing that daemon in Rust on top of `f1r3node-rust`'s
native file-I/O layer. The oracular bundle mount (`--mount-source
root`) already works byte-exact on both platforms. This ADR captures
the design for layering the wallet / token surface on top of it,
without disturbing the oracular path.

## Decision drivers

- The macOS Finder Sync extension (Swift) is already compiled against
  the Java proto shape and shipped. Reusing it as-is costs us one
  verbatim proto file and nothing else; writing our own extension
  costs weeks and burns through Apple's provisioning sign-off cycle
  twice. **Wire compatibility with the existing extension is a hard
  constraint**, not an aspiration.
- The wallet/token semantics (naming, denominations, FUSE op →
  Rholang mapping) are observable to end users and were already
  learned-by-doing on the Java side. Deviating is churn. **File
  naming and FUSE-op semantics mirror the Java daemon exactly for v1**;
  anything that improves on the Java UX gets a separate ADR.
- The daemon's existing FUSE path is thin and OS-portable
  (`libfuse-t-rs` on macOS, `fuser` on Linux). Keeping wallet
  state out of `f1r3drive-fs` preserves that portability — the
  wallet module stays pure Rust with no FUSE deps.

## Decision

### Mount modes

A new `--mount-mode` flag selects the top-level filesystem shape:

- `root` (default, current behavior): mount a single oracular bundle
  entry (`--mount-source root` → `/`). Nothing in this ADR changes.
- `wallets`: mount a synthetic root whose top-level entries are
  wallet directories (locked and unlocked). The `--mount-source`
  flag is ignored in this mode.

Running both modes simultaneously is out of scope for v1 — users who
need both open two mountpoints.

### Directory and file naming (frozen, mirror Java)

| Path                                         | Shape        | Contents / behavior |
|----------------------------------------------|--------------|--------------------|
| `/`                                          | directory    | One entry per known wallet. Read-only; `mkdir` / `create` → EPERM. |
| `/LOCKED-REMOTE-REV-<revAddress>/`           | directory    | Opaque locked wallet. `readdir` returns empty; `getattr` on children → ENOENT. |
| `/<revAddress>/`                             | directory    | Unlocked wallet. Always contains exactly one child: `.tokens`. |
| `/<revAddress>/.tokens/`                     | directory    | Synthetic token view. `readdir` queries balance, decomposes into denominations, emits one `<denom>-REV.<i>.token` per bill. |
| `/<revAddress>/.tokens/<denom>-REV.<i>.token` | regular file | Zero-byte, read-only, permission `0o444`. `open` / `read` / `write` / `truncate` are no-ops (match Java). Rename is the only meaningful mutator. |

`<revAddress>` is the base58-check REV address as derived by
`casper/src/rust/util/rev_address.rs` from the secp256k1 public key.
`<denom>` is one of 19 fixed values: `1`, `10`, `100`, …, `1000000000000000000`
(10⁰ through 10¹⁸, matching `TokenDirectory.java:denominations`).

### Denomination decomposition

Greedy top-down, largest denomination first, exactly like
`TokenDirectory.collectDenominations` in the Java daemon:

```
decompose(balance):
  for d in [10^18, 10^17, ..., 10^1, 10^0]:
    count = balance / d
    emit `count` copies of {denom = d}
    balance -= count * d
```

This is purely cosmetic — the on-chain `TransferDeploy` takes a
`long amount`, not a bag of denominations. If a drag targets a path
whose `<denom>` doesn't divide the on-chain amount cleanly, the
daemon still constructs a single transfer for the file's declared
value; the client-side bills are an invariant of `balance`, not of
individual transfers.

### FUSE op → Rholang mapping

Only ops under `/<revAddress>/.tokens/` or that cross a wallet
boundary carry on-chain meaning. Everything else is either rejected
or served from cache. The table is in evaluation order inside the FS
layer:

| FUSE op                                      | Target path            | Behavior |
|----------------------------------------------|------------------------|----------|
| `getattr`, `lookup` on `/<addr>` or children | wallet subtree         | Served from in-memory wallet registry + balance cache. No deploy. |
| `readdir` on `.tokens/`                      | token dir              | `exploratory_deploy(check_balance(addr))` if cache stale; decompose; emit synthetic entries. No deploy. |
| `open`, `read`, `write`, `truncate`, `chmod` | `*.token`              | No-op (returns success without side effects). Matches `TokenFile.java`. |
| `create`, `mkdir`, `unlink`, `rmdir`         | anywhere in `.tokens/` | EPERM. |
| `rename` within same `.tokens/`              | `*.token` → `*.token`  | EINVAL (indistinguishable from no-op; rejected to surface misuse). |
| `rename` across wallet dirs                  | `/<fromAddr>/.tokens/<denom>-REV.<i>.token` → `/<toAddr>/.tokens/<denom>-REV.<i>.token` | **Transfer**. Signed deploy of `rho:rev:vault` transfer term; eagerly invalidate `fromAddr` + `toAddr` balance cache; return success once admitted + proposed. |
| `rename` into `LOCKED-REMOTE-REV-<addr>`     | locked target          | EACCES in v1. The extension can trigger an `UnlockWalletDirectory` RPC first; retrying after that unlocks the target. |

### Balance cache

Lives in `f1r3drive-wallet::BalanceCache`. Keyed by `RevAddress`,
value is `{ balance: i64, fetched_at: Instant }`. Policy:

- Read path: on `.tokens/` readdir, consult cache; if entry is
  missing or older than `--balance-ttl` (default **5s**), submit the
  `check_balance` snippet and update. Serve stale on fetch error.
- Write path: on successful transfer admit, invalidate from+to
  address immediately so the next readdir refetches post-state.
- No background refresh in v1 — refetch is lazy on access.

The cache is in-process; a daemon restart drops it. That's fine
because `check_balance` is cheap enough that cold starts cost one
exploratory deploy per visible wallet.

### How the daemon learns about state

- **Transfers initiated through the mount**: known because we built
  the deploy — invalidate cache on return from our own
  `run_mutating_snippet`.
- **Transfers from elsewhere** (other clients, direct deploys): the
  daemon only observes them on the next `check_balance` refresh.
  The 5s TTL is the staleness bound. v1 does not subscribe to any
  push notification stream from the node.
- **Finalization status**: v1 reports "transfer admitted" as success.
  v2 may add a `.pending/` subtree reflecting pre-finalization
  deploys and poll `is_finalized` to retire them. ADR deferred.

### Wallet discovery and persistence

- No persistence. The in-memory registry is seeded empty.
- Unlocked wallets are added via the `UnlockWalletDirectory` RPC
  (gRPC server, see below) or a daemon-side CLI flag
  `--unlock-key-file <path>` repeated per wallet.
- Locked wallets are added by `--track-address <revAddress>`
  repeated. These show up as `LOCKED-REMOTE-REV-*` directories so
  the user can see them but not touch them without unlocking.
- Persisting unlocked keys to disk — tempting for UX — leaks private
  keys into the oracular bundle if the user tracks the daemon's own
  state dir. **Explicitly out of scope**. If a user wants
  cross-session persistence they can wire up their own agent / KMS.

### Finder extension gRPC server

- Served by a new `f1r3drive-ext` crate using the generated tonic
  server from `f1r3drive_proto::generic`.
- Bind address: `127.0.0.1:40411` by default (external deploy port +
  10, mirrors Java's offset convention), configurable via
  `--extension-grpc-port`. Loopback only; no TLS.
- Service surface (frozen by `FinderSyncExtensionService.proto`):
  - `SubmitAction(MenuActionRequest)`:
    - `CHANGE`: break one `<denom>-REV.<i>.token` into ten of the
      next-smaller denomination. In Rholang this is purely a client
      presentation (no on-chain mint/burn is needed because the
      underlying balance never changes); update the token
      directory's synthetic view and return success. If the action
      targets `<denom>=1`, return `ErrorResponse { "cannot change
      smallest denomination" }`.
    - `COMBINE`: not implemented in v1; return
      `ErrorResponse { "COMBINE not implemented" }`. The Java daemon
      does the same.
  - `UnlockWalletDirectory(revAddress, privateKey)`:
    - Validate `privateKey` derives to `revAddress` (secp256k1 →
      REV address) via `f1r3drive-wallet::validate_signer`.
    - On success, insert into the in-memory registry so the next
      `readdir /` surfaces `<revAddress>/` instead of
      `LOCKED-REMOTE-REV-<revAddress>/`. Return `EmptyResponse`.
    - On key mismatch, return `ErrorResponse { "key does not match
      address" }`.

### Deep links

- v1: a `--open-url f1r3drive://unlock?revAddress=…&privateKey=…` flag
  on the daemon binary routes the parsed args into the daemon's own
  gRPC extension endpoint over the configured loopback port. This is
  what the eventual macOS app bundle's `Info.plist` URL-scheme
  handler calls out to.
- v1 does **not** register a system URL handler; that lands with the
  Stage 7 Finder-extension work and requires an `.app` bundle.

### Non-goals (v1)

- Persisting unlocked private keys across daemon restarts.
- Push notifications from node → daemon on finality.
- Multi-signature wallets.
- Combining tokens (`COMBINE` menu action).
- Non-REV tokens / arbitrary vaults.

## Consequences

### Positive

- Reuses the shipping macOS extension verbatim. No notarization work.
- Keeps the FUSE op layer thin; wallet state and balance cache stay
  behind a crate boundary and remain Linux/macOS-agnostic.
- Each FUSE op maps to at most one deploy. Latency bound is one
  propose-cycle per transfer; readdir on `.tokens/` is one
  exploratory_deploy (sub-100ms on a local shard).

### Negative

- Wire compat means the proto field names stay camelCase
  (`revAddress`, `privateKey`), which clashes with Rust's snake_case
  convention. Mitigated with `#[allow(non_camel_case_types)]` on the
  generated server mod.
- The daemon ends up running a gRPC server as well as a client. New
  listening port = new attack surface. Loopback-only + no key
  material served over the wire; the `privateKey` field is accepted
  *in*, never emitted *out*. Still, future hardening work should look
  at Unix-domain socket transport (which would also break the Swift
  extension — a v2 fork point).

### Neutral

- The 5s balance-cache TTL is a hand-picked knob. It's exposed as a
  CLI flag so it can be tuned without a rebuild once we have real
  workloads to measure.

## Alternatives considered

- **Design our own extension transport**. Rejected: throws away the
  Swift extension and buys nothing until we're ready to redesign the
  entire context-menu UX.
- **Mount the wallet surface alongside `/root/`** (not instead of).
  Rejected for v1: adds a notion of a mount with mixed-provenance
  entries, which complicates the oracular path and the FUSE
  permission model. Users who want both open two mountpoints.
- **Push on-chain notifications via a long-lived gRPC subscription**
  from node → daemon so the balance cache refreshes eagerly.
  Rejected: node-rust has no such endpoint today, and adding one
  blocks the whole project on a server-side change. 5s TTL is good
  enough for v1.
