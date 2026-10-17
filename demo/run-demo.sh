#!/usr/bin/env bash
#
# End-to-end walkthrough of the vendor-contract demo.
#
# Scripted path (works today). Interactive drag-and-drop in Finder
# works for the payment half (Stage 4's rename handler turns a
# cross-wallet token drag into a signed transfer); the content
# fetch is a separate `demo-vendor fetch` call because the
# wallet mount doesn't yet model contract-folders + inbox dirs.
# See demo/README.md §"Mount integration (future work)".
#
# Prereqs:
#   - A f1r3node is up at $NODE_HOST:$NODE_PORT (default
#     127.0.0.1:40401) with the standalone-dev genesis wallet set
#     (so the validator key is funded).
#   - cargo + stable rust toolchain.
#
# Flow:
#   0.  mint Alice:    generate a fresh key for Alice, derive her
#                      REV address, fund her from the validator so
#                      she can pay the phlo for the deploy
#   1.  deploy:        Alice signs + submits vendor_contract.rho
#   2.  pay-and-fetch: payer (the validator) transfers 100 REV to
#                      Alice via rho:vault:system; then runs an
#                      exploratory_deploy that calls the vendor on
#                      its well-known channel and prints the file
#                      content, saved to $OUTPUT_DIR
#   3.  verify:        cat the delivered file; note the content came
#                      down the deploy's return channel so only the
#                      payer saw it in flight

set -euo pipefail

cd "$(dirname "$0")/.."

HOST="${NODE_HOST:-127.0.0.1}"
PORT="${NODE_PORT:-40401}"

# Standalone-dev validator — funded at genesis. We play the "payer"
# role from this key.
VALIDATOR_KEY_HEX="5f668a7ee96d944a4494cc947e4005e172d7ab3461ee5538f1f2a45a835e9657"
VALIDATOR_ADDR="1111AtahZeefej4tvVR6ti9TJtv8yxLebT31SCEVDCKMNikBk5r3g"

# Where we write the fetched file so step 4 ("drag to desktop") is
# a one-cp operation.
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/demo-received}"
mkdir -p "$OUTPUT_DIR"

echo "== building demo-vendor =="
cargo build -p demo-vendor --release >/dev/null
BIN="./target/release/demo-vendor"

VALIDATOR_KEY=$(mktemp)
echo -n "$VALIDATOR_KEY_HEX" > "$VALIDATOR_KEY"

# -----------------------------------------------------------------
# 0. mint Alice: fresh key + fund her from the validator
# -----------------------------------------------------------------
echo
echo "== step 0: mint Alice (fresh key, funded from validator) =="

# Deterministic key for a reproducible demo. Replace with
# $(openssl rand -hex 32) for a one-shot key.
ALICE_KEY_HEX="4a71c5a7f1ea0d6e8b2c3d4f5e6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6"
ALICE_KEY=$(mktemp)
echo -n "$ALICE_KEY_HEX" > "$ALICE_KEY"

ALICE_ADDR=$("$BIN" derive-address --key-file "$ALICE_KEY")
echo "   Alice REV address: $ALICE_ADDR"

echo "   funding Alice with 1_000_000 REV from the validator (needed for phlo)"
"$BIN" --host "$HOST" --port "$PORT" transfer \
    --key-file "$VALIDATOR_KEY" --to "$ALICE_ADDR" --amount 1000000 >/dev/null

# -----------------------------------------------------------------
# 1. deploy: Alice signs + submits the vendor contract
# -----------------------------------------------------------------
echo
echo "== step 1: Alice deploys vendor_contract.rho =="
"$BIN" --host "$HOST" --port "$PORT" deploy-vendor \
    --key-file "$ALICE_KEY" \
    --rho-file demo/vendor_contract.rho

# -----------------------------------------------------------------
# 2. pay-and-fetch: payer transfers 100 REV, then fetches
# -----------------------------------------------------------------
echo
echo "== step 2: payer transfers 100 REV + fetches manifesto.txt =="
"$BIN" --host "$HOST" --port "$PORT" buy \
    --key-file "$VALIDATOR_KEY" \
    --alice-address "$ALICE_ADDR" \
    --file manifesto.txt \
    --price 100 \
    --output "$OUTPUT_DIR/manifesto.txt"

# -----------------------------------------------------------------
# 3. verify: show the delivered file
# -----------------------------------------------------------------
echo
echo "== step 3: delivered file =="
echo "   path: $OUTPUT_DIR/manifesto.txt"
echo "   content:"
sed 's/^/      /' "$OUTPUT_DIR/manifesto.txt"
echo
echo "== step 4 (manual): drag '$OUTPUT_DIR/manifesto.txt' to your desktop =="
echo "   e.g.: cp '$OUTPUT_DIR/manifesto.txt' ~/Desktop/"
echo

# Cleanup
rm -f "$VALIDATOR_KEY" "$ALICE_KEY"
echo "demo complete."
