#!/usr/bin/env bash
# Fails when docs/ci.md and .github/workflows/ci.yml list different jobs.
#
# The job table under "## Jobs of `ci.yml`" in docs/ci.md must name every job
# id of ci.yml, and no other id. A job that the table does not describe is a
# check that nobody can look up when it turns red.
#
#   check-ci-docs.sh [REPO_ROOT]
#
# Job ids are the two-space-indented keys under the top-level `jobs:` key.
# Comment lines are skipped. The script runs under bash 3.2.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
repo="${1:-$ROOT}"
workflow="$repo/.github/workflows/ci.yml"
doc="$repo/docs/ci.md"

for f in "$workflow" "$doc"; do
	[ -f "$f" ] || { echo "ERROR: missing $f" >&2; exit 2; }
done

workflow_jobs="$(awk '
	/^[[:space:]]*#/ { next }
	/^[^[:space:]]/ { in_jobs = ($0 ~ /^jobs:[[:space:]]*$/); next }
	in_jobs && /^  [A-Za-z_][A-Za-z0-9_-]*:[[:space:]]*$/ {
		id = $1; sub(/:$/, "", id); print id
	}
' "$workflow" | sort -u)"

doc_jobs="$(awk '
	/^## / { in_table = ($0 == "## Jobs of `ci.yml`"); next }
	in_table && /^\| `[A-Za-z_][A-Za-z0-9_-]*` \|/ {
		id = $0; sub(/^\| `/, "", id); sub(/`.*/, "", id); print id
	}
' "$doc" | sort -u)"

if [ -z "$doc_jobs" ]; then
	echo "ERROR: docs/ci.md has no job table under \"## Jobs of \`ci.yml\`\"." >&2
	exit 1
fi

missing="$(comm -23 <(printf '%s\n' "$workflow_jobs") <(printf '%s\n' "$doc_jobs"))"
extra="$(comm -13 <(printf '%s\n' "$workflow_jobs") <(printf '%s\n' "$doc_jobs"))"
failed=0
if [ -n "$missing" ]; then
	echo "ERROR: docs/ci.md does not list these ci.yml jobs:" >&2
	sed 's/^/  /' <<<"$missing" >&2
	failed=1
fi
if [ -n "$extra" ]; then
	echo "ERROR: docs/ci.md lists jobs that ci.yml does not have:" >&2
	sed 's/^/  /' <<<"$extra" >&2
	failed=1
fi
[ "$failed" -eq 0 ] || exit 1
echo "docs/ci.md lists the $(wc -l <<<"$workflow_jobs" | tr -d ' ') jobs of ci.yml."
