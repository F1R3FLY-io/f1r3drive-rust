#!/usr/bin/env bash
# Fails when private key material enters the tracked files.
#
# Anyone who reads the repository can sign with a tracked key. The tests of
# this repository sign deploys with the public development keys of the
# f1r3node standalone shard on purpose. .github/known-dev-keys.txt lists those
# keys, and they are not reported.
#
#   check-tracked-key-material.sh [REPO_ROOT]
#
# The check fails when:
#   - a .env file is tracked (*.env.example and *.env.sample are templates),
#   - a key or certificate store is tracked (*.pem, *.key, *.p12, *.pfx,
#     *.keystore),
#   - a 64-digit hex value that is not a known development key sits on a line,
#     or the line after a line, that names a key or a secret (private,
#     secret, _sk, sk_, key, seed). A 130-digit public key does not match.
#     The .env templates are not scanned, because they hold public
#     development keys on purpose.
#
# The script runs under bash 3.2 (the macOS system bash), because the
# pre-commit hook can run it on contributor machines.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
repo="${1:-$ROOT}"
git -C "$repo" rev-parse --git-dir >/dev/null 2>&1 || { echo "ERROR: $repo is not a git repository." >&2; exit 2; }

failed=0

# Prints matched lines indented, with every hex run of key length redacted, so
# a line with several keys leaks none of them.
redact() {
	sed -E 's/[0-9a-fA-F]{64,}/<redacted>/g; s/^/  /'
}

env_files="$(git -C "$repo" ls-files -- '.env' '*/.env' '*.env' | grep -vE '\.env\.(example|sample)$' || true)"
if [ -n "$env_files" ]; then
	echo "ERROR: .env files are tracked. Untrack them with git rm --cached and keep a .env.example template:" >&2
	sed 's/^/  /' <<<"$env_files" >&2
	failed=1
fi

stores="$(git -C "$repo" ls-files -- '*.pem' '*.key' '*.p12' '*.pfx' '*.keystore' || true)"
if [ -n "$stores" ]; then
	echo "ERROR: key or certificate stores are tracked. Untrack them with git rm --cached:" >&2
	sed 's/^/  /' <<<"$stores" >&2
	failed=1
fi

known="$repo/.github/known-dev-keys.txt"
known_keys=""
if [ -f "$known" ]; then
	known_keys="$(grep -oiE '^[0-9a-f]{64}' "$known" | tr '[:upper:]' '[:lower:]' || true)"
fi

# git grep -A1 prints each line that names a key together with the next line,
# so a constant whose value wraps onto the next line is also found.
named="$(git -C "$repo" grep -nIiE -A1 '(private|secret|_sk|sk_|key|seed)' -- . ':!Cargo.lock' ':!*.env.example' ':!*.env.sample' 2>/dev/null || true)"
leaks=""
while IFS= read -r line; do
	hexes="$(grep -oE '(^|[^0-9a-fA-F])[0-9a-fA-F]{64}([^0-9a-fA-F]|$)' <<<"$line" | grep -oE '[0-9a-fA-F]{64}' || true)"
	[ -n "$hexes" ] || continue
	unknown=0
	while IFS= read -r hex; do
		hex="$(printf %s "$hex" | tr '[:upper:]' '[:lower:]')"
		if ! grep -Fxq -- "$hex" <<<"$known_keys"; then
			unknown=1
		fi
	done <<<"$hexes"
	if [ "$unknown" -eq 1 ]; then
		leaks="$leaks$line"$'\n'
	fi
done <<<"$named"
if [ -n "$leaks" ]; then
	echo "ERROR: tracked files hold private keys that are not known development keys. Read them from the environment, or add a public development key to .github/known-dev-keys.txt:" >&2
	printf %s "$leaks" | redact >&2
	failed=1
fi

[ "$failed" -eq 0 ] || exit 1
echo "No private key material in the tracked files."
