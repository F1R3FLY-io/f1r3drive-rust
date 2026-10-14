#!/usr/bin/env bash
#
# Mount a local f1r3node shard as a filesystem under /tmp/f1r3mnt.
# Boot the shard first with:
#   docker compose -f ../f1r3node-rust/docker/shard.yml up -d
#
# This script exists for parity with the Java f1r3drive setup; it will be
# fleshed out once the daemon loop is wired in Stages 3–6.
set -euo pipefail

MOUNT="${MOUNT:-/tmp/f1r3mnt}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-40401}"
KEY="${KEY:-$HOME/.keys/dev}"

mkdir -p "$MOUNT"
exec cargo run -p f1r3drive -- \
    --key-file "$KEY" \
    --host "$HOST" \
    --port "$PORT" \
    "$MOUNT"
