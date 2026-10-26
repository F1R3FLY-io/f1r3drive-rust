#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOL="$ROOT/.github/scripts/check-ci-docs.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() {
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

# fixture NAME: creates a repository tree whose docs match its workflow.
fixture() {
	repo="$TMP/$1"
	mkdir -p "$repo/.github/workflows" "$repo/docs"
	cat >"$repo/.github/workflows/ci.yml" <<'YAML'
name: CI
on:
  push:
permissions:
  contents: read
jobs:
  # lint_only: a comment that names no job
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: echo
  test:
    needs: lint
    runs-on: ubuntu-latest
    steps:
      - run: echo
YAML
	cat >"$repo/docs/ci.md" <<'MD'
# CI

## Jobs of `ci.yml`

| Job id | Check name |
| --- | --- |
| `lint` | Lint |
| `test` | Test |

## Other section

| `ghost` | not a job table row |
MD
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
[ "$status" -eq 0 ] || fail "matching docs failed: $out"

fixture missing
printf '  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n' >>"$repo/.github/workflows/ci.yml"
check
[ "$status" -eq 1 ] || fail "an undocumented job passed: $out"
[[ "$out" == *"does not list"*"deploy"* ]] || fail "the undocumented job is not named: $out"

fixture extra
awk '{ print } /^\| `test` \| Test \|$/ { print "| `gone` | Gone |" }' "$repo/docs/ci.md" >"$TMP/ci.md"
mv "$TMP/ci.md" "$repo/docs/ci.md"
check
[ "$status" -eq 1 ] || fail "a documented job that ci.yml lacks passed: $out"
[[ "$out" == *"does not have"*"gone"* ]] || fail "the extra job is not named: $out"

fixture no-table
printf '# CI\n\nNo table.\n' >"$repo/docs/ci.md"
check
[ "$status" -eq 1 ] || fail "docs without a job table passed: $out"

fixture absent
rm "$repo/docs/ci.md"
check
[ "$status" -eq 2 ] || fail "a missing docs/ci.md did not exit 2: $out"

repo="$ROOT"
check
[ "$status" -eq 0 ] || fail "the repository docs/ci.md does not match ci.yml: $out"

awk '
	/^  [a-z_]+:$/ { job = $1 }
	job == "static_checks:" && /run: bash \.github\/scripts\/check-ci-docs\.sh$/ { found = 1 }
	END { exit !found }
' "$ROOT/.github/workflows/ci.yml" || fail "Static Checks does not run check-ci-docs.sh"

echo "check-ci-docs tests passed"
