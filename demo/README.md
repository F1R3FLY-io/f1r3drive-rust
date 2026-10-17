# demo: pay-for-content vendor

A walkthrough of a vendor contract that releases file content to a
payer in exchange for REV. Maps onto the four user-visible criteria:

1. **Alice deploys a contract** that, when it receives `T` tokens,
   makes a file `A` visible to the payer.
2. **I transfer `T` tokens to Alice** by dragging them from my
   wallet into a folder representing that contract.
3. **The `T` tokens become invisible to me** and **file `A` appears
   somewhere only I can access it**.
4. **I can drag a copy to my desktop.**

The on-chain contract is Rholang (`vendor_contract.rho`); the client
tooling is a small Rust binary (`crates/demo-vendor/`). An
orchestration script (`run-demo.sh`) ties everything together.

## What's in here

| File                              | Role                                          |
|-----------------------------------|-----------------------------------------------|
| `vendor_contract.rho`             | Alice's contract. Serves content on request.  |
| `run-demo.sh`                     | End-to-end walkthrough (steps 0–4).           |
| `../crates/demo-vendor/`          | CLI binary wrapping deploy/transfer/fetch.    |

## Prerequisites

- A running f1r3node at `127.0.0.1:40401` with the standalone-dev
  genesis wallet set (so the validator at `1111Atah…` is funded).
- Stable Rust toolchain (`cargo build` runs out of the workspace
  root).

## One-liner

```shell
./demo/run-demo.sh
```

Expected output (abbreviated):

```
== step 0: mint Alice (fresh key, funded from validator) ==
   Alice REV address: 1111M4oCo5cRxmr14LFde2arWVumNNmuUn985UbaufZwUct3UYPVE
   funding Alice with 1_000_000 REV from the validator (needed for phlo)
== step 1: Alice deploys vendor_contract.rho ==
vendor deployed. channel: @"demo:alice:vendor:v1"
== step 2: payer transfers 100 REV + fetches manifesto.txt ==
[1/3] transfer: 100 REV 1111Atah…→ 1111M4o…
[2/3] fetched: 65 bytes
[3/3] saved to: /tmp/demo-received/manifesto.txt
== step 3: delivered file ==
   content:
      Rholang: process calculus as the user experience. -- Alice, 2026.
== step 4 (manual): drag '/tmp/demo-received/manifesto.txt' to your desktop ==
```

## Mapping the demo to the four criteria

### 1. Alice has deployed a contract

`vendor_contract.rho` registers a persistent `vendor` contract on
the well-known channel `@"demo:alice:vendor:v1"` and seeds a tiny
in-memory library (`manifesto.txt`, `secret.txt`). On a receive it
checks `amount >= 100` and `lib.get(fname) != Nil`, then replies
`(true, content)` or `(false, reason)` on the caller's ack
channel.

```shell
./target/release/demo-vendor deploy-vendor \
    --key-file alice.hex \
    --rho-file demo/vendor_contract.rho
```

### 2. I transfer T tokens by dragging them to a folder representing the contract

The scripted way the demo uses:

```shell
./target/release/demo-vendor transfer \
    --key-file payer.hex \
    --to <alice-rev-address> \
    --amount 100
```

Under the hood this is `f1r3drive-rho::transfer_snippet` →
`rho:vault:system::transfer`, byte-identical to what the
`WalletFs::rename` handler produces when a user drags
`100-REV.<i>.token` from one wallet directory to another in a
mounted wallets-mode tree. The "folder representing the contract"
is Alice's wallet directory `/<alice-addr>/`.

### 3. The T tokens become invisible to me, and a file A appears somewhere only I can access it

- *Invisible to me*: after the transfer, the payer's balance drops
  by `amount + phlo-cost`; the next `readdir .tokens/` renders one
  fewer bill of the matching denomination. Alice's balance
  symmetrically grows.
- *Visible only to me*: the vendor's reply travels on the payer's
  deploy return channel, which is an **unforgeable name** allocated
  per deploy. Only the payer (holder of the deploy's signing key)
  can observe its output. The `buy` subcommand writes the content
  to a local file at `--output` (default `~/Downloads/<file>`),
  owned by the running user with ordinary POSIX permissions.

### 4. I can drag a copy to my desktop

The saved file is a regular file:

```shell
cp /tmp/demo-received/manifesto.txt ~/Desktop/
```

…or in Finder, drag.

## Caveats, pinned

- **Trust model is demo-only.** The vendor contract does not verify
  that the payer actually sent `amount` REV to Alice. In production,
  Alice would (a) hold a dedicated vault, (b) track each payer's
  cumulative deposit, and (c) only release content once that
  cumulative amount reaches the price. See the contract header for
  the full gap. The current contract trusts the amount declared in
  the request message.
- **Price is hardcoded (`>= 100`).** Easy to parameterize but kept
  flat here for a crisp demo.
- **The library is in-memory.** A real vendor would reference files
  from an oracular `Fs`-agent bundle, so Alice can edit her
  catalogue without redeploying the contract.
- **Deploy order matters.** Alice must deploy the vendor *before*
  the payer calls it. `run-demo.sh` orders them correctly; if
  deploying by hand, propose + wait for finalization between the
  Alice deploy and the payer's exploratory call so the vendor's
  channel is visible to the payer's post-LFB view.

## Mount integration (future work)

The current demo exercises the full data flow (transfer + fetch +
local save) but through a CLI, not a Finder drag. To support the
pure drag-and-drop UX the user prompt describes, two mount-side
extensions are needed:

1. **Contract-folder shape** in `WalletFs`:
   `/<alice-addr>/vendor/<file>` as a synthetic entry whose
   `rename` handler, when the destination is a `*.token` drop,
   combines the transfer AND the vendor call in one deploy chain.
2. **Inbox dir** under the payer's wallet: `/<my-addr>/inbox/<file>`
   showing files successfully fetched by the daemon. Would need an
   in-memory inbox map plus `read` support that returns the cached
   content bytes.

Neither is in the ADR-0001 v1 scope — the ADR explicitly notes
"non-REV tokens / arbitrary vaults" and content-delivery vendors as
v2 fork points. Shipping the Rholang contract + scripted flow now
lets us iterate on the pattern before committing mount surface.

## Running the pieces individually

```shell
# Build
cargo build --release -p demo-vendor
BIN=./target/release/demo-vendor

# Create a key for Alice (fresh, 32 bytes of hex)
openssl rand -hex 32 > /tmp/alice.hex

# Derive her REV address
ALICE_ADDR=$($BIN derive-address --key-file /tmp/alice.hex)

# Fund Alice from the validator (so she can pay phlo for her deploy)
echo -n 5f668a7ee96d944a4494cc947e4005e172d7ab3461ee5538f1f2a45a835e9657 > /tmp/validator.hex
$BIN transfer --key-file /tmp/validator.hex --to "$ALICE_ADDR" --amount 1000000

# Alice deploys the vendor
$BIN deploy-vendor --key-file /tmp/alice.hex --rho-file demo/vendor_contract.rho

# Payer transfers 100 REV + fetches manifesto.txt
$BIN buy \
    --key-file /tmp/validator.hex \
    --alice-address "$ALICE_ADDR" \
    --file manifesto.txt \
    --price 100 \
    --output /tmp/manifesto.txt

cat /tmp/manifesto.txt
```
