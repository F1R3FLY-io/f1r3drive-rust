#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOL="$ROOT/.github/scripts/check-tracked-key-material.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() {
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

# The fixture keys are built at run time. As literals, they would be tracked
# private keys that the check reports in this repository.
KEY="$(printf '0123456789abcdef%.0s' 1 2 3 4)"
KEY2="$(printf 'fedcba9876543210%.0s' 1 2 3 4)"
DEV_KEY="5f668a7ee96d944a4494cc947e4005e172d7ab3461ee5538f1f2a45a835e9657"
PUBKEY="04ffc016579a68050d655d55df4e09f04605164543e257c8e6df10361e6068a5336588e9b355ea859c5ab4285a5ef0efdf62bc28b80320ce99e26bb1607b3ad93d"

# fixture NAME: creates a clean repository in $TMP/NAME and sets repo.
fixture() {
	repo="$TMP/$1"
	mkdir -p "$repo/.github" "$repo/src"
	git -C "$repo" init -q
	printf '%s  # dev\n' "$DEV_KEY" >"$repo/.github/known-dev-keys.txt"
	printf 'PRIVATE_KEY=%s\n' "$KEY" >"$repo/.env.example"
	cat >"$repo/src/lib.rs" <<RS
const BLOCK_HASH: &str = "$KEY";
const VALIDATOR_PUBKEY_HEX: &str = "$PUBKEY";
const DEV_PRIVATE_KEY_HEX: &str = "$DEV_KEY";
RS
	git -C "$repo" add -A
}

# check: sets status and out for $repo.
check() {
	set +e
	out="$(bash "$TOOL" "$repo" 2>&1)"
	status=$?
	set -e
}

fixture clean
check
[ "$status" -eq 0 ] || fail "a clean tree failed: $out"

fixture env
printf 'PRIVATE_KEY=%s\n' "$KEY" >"$repo/.env"
check
[ "$status" -eq 0 ] || fail "an untracked .env failed: $out"
git -C "$repo" add -f .env
check
[ "$status" -eq 1 ] || fail "a tracked .env passed: $out"
[[ "$out" == *".env files are tracked"* ]] || fail "the tracked .env is not named: $out"

fixture nested-env
mkdir -p "$repo/docker"
printf 'X=1\n' >"$repo/docker/local.env"
git -C "$repo" add -f docker/local.env
check
[ "$status" -eq 1 ] || fail "a tracked docker/local.env passed: $out"

fixture store
printf 'pem\n' >"$repo/node.pem"
git -C "$repo" add -f node.pem
check
[ "$status" -eq 1 ] || fail "a tracked .pem passed: $out"
[[ "$out" == *"node.pem"* ]] || fail "the tracked .pem is not named: $out"

fixture inline
printf 'const ALICE_SK_HEX: &str = "%s";\n' "$KEY" >>"$repo/src/lib.rs"
git -C "$repo" add -A
check
[ "$status" -eq 1 ] || fail "an unknown inline key passed: $out"
[[ "$out" == *"lib.rs"*"ALICE_SK_HEX"*"<redacted>"* ]] || fail "the inline key is not named: $out"
[[ "$out" != *"$KEY"* ]] || fail "the inline key is printed: $out"

fixture wrapped
printf 'const BOB_PRIVATE_KEY_HEX: &str =\n    "%s";\n' "$KEY" >>"$repo/src/lib.rs"
git -C "$repo" add -A
check
[ "$status" -eq 1 ] || fail "a key on the line after its name passed: $out"
[[ "$out" != *"$KEY"* ]] || fail "the wrapped key is printed: $out"

fixture uppercase-known
printf 'const DEV_SK: &str = "%s";\n' "$(tr '[:lower:]' '[:upper:]' <<<"$DEV_KEY")" >>"$repo/src/lib.rs"
git -C "$repo" add -A
check
[ "$status" -eq 0 ] || fail "an uppercase known development key failed: $out"

fixture two-keys
printf 'let secret = ["%s", "%s"];\n' "$DEV_KEY" "$KEY2" >>"$repo/src/lib.rs"
git -C "$repo" add -A
check
[ "$status" -eq 1 ] || fail "a line with a known and an unknown key passed: $out"
[[ "$out" != *"$KEY2"* && "$out" != *"$DEV_KEY"* ]] || fail "a key on a line with two keys is printed: $out"

fixture no-list
rm "$repo/.github/known-dev-keys.txt"
git -C "$repo" add -A
check
[ "$status" -eq 1 ] || fail "a development key without the known list passed: $out"

fixture all
printf 'K=1\n' >"$repo/.env"
printf 'pem\n' >"$repo/a.key"
printf 'const SEED: &str = "%s";\n' "$KEY" >>"$repo/src/lib.rs"
git -C "$repo" add -A -f
check
[ "$status" -eq 1 ] || fail "three violations passed: $out"
[ "$(grep -c '^ERROR:' <<<"$out")" -eq 3 ] || fail "not every violation is reported: $out"

check_repo_status=0
bash "$TOOL" "$TMP/not-a-repo" >/dev/null 2>&1 || check_repo_status=$?
[ "$check_repo_status" -eq 2 ] || fail "a path outside a repository did not exit 2: $check_repo_status"

repo="$ROOT"
check
[ "$status" -eq 0 ] || fail "the repository has tracked private keys: $out"

awk '
	/^  [a-z_]+:$/ { job = $1 }
	job == "static_checks:" && $0 == "        run: bash .github/scripts/check-tracked-key-material.sh" { found = 1 }
	END { exit !found }
' "$ROOT/.github/workflows/ci.yml" || fail "Static Checks does not run check-tracked-key-material.sh"

echo "check-tracked-key-material tests passed"
