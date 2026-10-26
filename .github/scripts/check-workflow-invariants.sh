#!/usr/bin/env bash
# Structural, fail-closed checks on the GitHub Actions workflows.
#
# Adapted from f1r3node-rust. These are the invariants that comments cannot
# protect: a reviewer can miss a tag-pinned action or a checkout that keeps
# the token, so the check fails CI instead.
#
# Wired into ci.yml's `static_checks` job on purpose: Static Checks is the
# job to require on the main branch ruleset, so a violation blocks the merge.
#
# Run from the repository root. Every check prints its verdict; the script exits
# non-zero if any failed, listing all failures rather than stopping at the first.
set -euo pipefail

WORKFLOWS_DIR="${1:-.github/workflows}"
fail=0

err() {
	printf '::error::%s\n' "$1"
	fail=1
}

ok() {
	printf 'ok: %s\n' "$1"
}

shopt -s nullglob
workflows=("$WORKFLOWS_DIR"/*.yml "$WORKFLOWS_DIR"/*.yaml)
if [ "${#workflows[@]}" -eq 0 ]; then
	err "no workflows found in $WORKFLOWS_DIR"
	exit 1
fi

for wf in "${workflows[@]}"; do
	# 1. Every external action is pinned to a full commit SHA. A tag can be
	#    moved to new code after review; a SHA cannot. Local actions (./) and
	#    docker:// images are out of scope.
	unpinned="$(grep -nE '^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*' "$wf" |
		grep -vE 'uses:[[:space:]]*["'"'"']?(\./|docker://)' |
		grep -vE 'uses:[[:space:]]*["'"'"']?[^@[:space:]]+@[0-9a-f]{40}([[:space:]"'"'"']|$)' || true)"
	if [ -n "$unpinned" ]; then
		err "$wf uses actions that are not pinned to a commit SHA:"
		sed 's/^/  /' <<<"$unpinned"
	else
		ok "$wf pins every action to a commit SHA"
	fi

	# 2. Every actions/checkout sets persist-credentials: false, so later steps
	#    that run repository code cannot read the token from .git/config.
	#    Comment lines are skipped so prose cannot satisfy the check.
	missing="$(awk '
		/^[[:space:]]*#/ { next }
		/uses:[[:space:]]*["'"'"']?actions\/checkout@/ {
			if (pending) print pending_line
			pending = 1; pending_line = FNR ": " $0
			match($0, /[^ -]/); indent = RSTART
			next
		}
		pending && /persist-credentials:[[:space:]]*false/ { pending = 0; next }
		pending && /^[[:space:]]*-[[:space:]]/ {
			match($0, /[^ ]/)
			if (RSTART <= indent) { print pending_line; pending = 0 }
		}
		END { if (pending) print pending_line }
	' "$wf")"
	if [ -n "$missing" ]; then
		err "$wf has checkouts without persist-credentials: false:"
		sed 's/^/  /' <<<"$missing"
	else
		ok "$wf checkouts drop persisted credentials"
	fi

	# 3. Every workflow declares a top-level permissions block, so a job gets
	#    only the token scopes that the workflow names.
	if grep -qE '^permissions:' "$wf"; then
		ok "$wf declares top-level permissions"
	else
		err "$wf has no top-level permissions block"
	fi

	# 4. A pull_request_target workflow runs with a write token, so it must
	#    never check out the pull request head.
	if grep -qE '^[[:space:]]*pull_request_target:' "$wf" &&
		grep -qE 'github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref' "$wf"; then
		err "$wf runs on pull_request_target and references the pull request head"
	fi
done

# 5. Commit Policy runs the base branch copies of its checker, exemptions, and
#    denied list, so a pull request cannot weaken the check that judges it.
CI="$WORKFLOWS_DIR/ci.yml"
for path in .github/scripts/check-commit-trailers.sh .github/scripts/commit-policy-exemptions.sh .github/denied-identities.txt; do
	if grep -qF "git show \"\${BASE_SHA}:$path\"" "$CI"; then
		ok "Commit Policy reads $path from the base commit"
	else
		err "Commit Policy in $CI does not read $path from the base commit"
	fi
done

exit "$fail"
