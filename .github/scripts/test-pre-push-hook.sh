#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HOOK="$ROOT/.githooks/pre-push"
HARNESS="$(mktemp -d)"
trap 'rm -rf "$HARNESS"' EXIT
mkdir -p "$HARNESS/bin" "$HARNESS/tmp"
REAL_GIT="$(command -v git)"

cat >"$HARNESS/bin/git" <<EOF
#!/usr/bin/env bash
set -euo pipefail
case "\${1:-} \${2:-}" in
  "rev-parse --show-toplevel") exec "$REAL_GIT" "\$@" ;;
  "ls-remote origin") printf '%s\t%s\n' "\$FAKE_REMOTE_OID" "\${3:-refs/heads/test}" ;;
  "fetch origin") exit 0 ;;
  *) exec "$REAL_GIT" "\$@" ;;
esac
EOF
cat >"$HARNESS/bin/timeout" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_TIMEOUT_LOG"
shift
exec "$@"
EOF
cat >"$HARNESS/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s %s\n' "$$" "$*" >> "$FAKE_CARGO_LOG"
if [[ "${MISSING_NEXTEST:-0}" == 1 && "$*" == "nextest --version" ]]; then
    exit 101
fi
if [[ "${FAIL_NEXTEST:-0}" == 1 && "$*" == "nextest run "* ]]; then
    echo "test failure from the fake cargo"
    exit 100
fi
if [[ "${SLEEP_NEXTEST:-0}" == 1 && "$*" == "nextest run "* ]]; then
    : > "$FAKE_NEXTEST_STARTED"
    sleep 300
fi
EOF
chmod +x "$HARNESS/bin/git" "$HARNESS/bin/timeout" "$HARNESS/bin/cargo"
grep -Fq "trap 'cleanup 130' INT" "$HOOK"

HEAD_SHA="$(git -C "$ROOT" rev-parse HEAD)"
REMOTE_SHA="0000000000000000000000000000000000000001"
PUSH_INPUT="refs/heads/test $HEAD_SHA refs/heads/test $REMOTE_SHA"
COMMON_ENV=(
  env
  PATH="$HARNESS/bin:$PATH"
  TMPDIR="$HARNESS/tmp"
  FAKE_REMOTE_OID="$REMOTE_SHA"
  FAKE_TIMEOUT_LOG="$HARNESS/timeouts"
  FAKE_CARGO_LOG="$HARNESS/cargo"
  CI=
  GITLAB_CI=
  GITHUB_ACTIONS=
  SKIP_CLIPPY=1
  SKIP_CI_TESTS=1
  TEST_CRATES=f1r3drive-fs
)

reset_logs() {
  : >"$HARNESS/timeouts"
  : >"$HARNESS/cargo"
}

no_results_left() {
  if find "$HARNESS/tmp" -mindepth 1 -print -quit | grep -q .; then
    echo "$1 left temporary results" >&2
    exit 1
  fi
}

# Normal run: nextest for the selected crate, then its doctests.
reset_logs
printf '%s\n' "$PUSH_INPUT" |
  "${COMMON_ENV[@]}" bash "$HOOK" origin fake >"$HARNESS/normal.out" 2>&1
grep -q '^900 cargo nextest run --locked -p f1r3drive-fs --no-tests=pass$' "$HARNESS/timeouts"
grep -q '^900 cargo test --locked -p f1r3drive-fs --doc$' "$HARNESS/timeouts"
grep -Eq '\[test\].*nextest.*PASS.*\([0-9]+s\)' "$HARNESS/normal.out"
grep -q 'All checks passed! Proceeding with push.' "$HARNESS/normal.out"
no_results_left "normal hook exit"

# The default scope is the whole workspace.
reset_logs
printf '%s\n' "$PUSH_INPUT" |
  "${COMMON_ENV[@]}" TEST_CRATES= bash "$HOOK" origin fake >"$HARNESS/workspace.out" 2>&1
grep -q '^900 cargo nextest run --locked --workspace --no-tests=pass$' "$HARNESS/timeouts"

# QUICK=1 skips the doctests.
reset_logs
printf '%s\n' "$PUSH_INPUT" |
  "${COMMON_ENV[@]}" QUICK=1 bash "$HOOK" origin fake >"$HARNESS/quick.out" 2>&1
if grep -q -- '--doc' "$HARNESS/timeouts"; then
  echo "QUICK=1 ran the doctests" >&2
  exit 1
fi

# A missing cargo-nextest stops the hook with install instructions.
reset_logs
set +e
printf '%s\n' "$PUSH_INPUT" |
  "${COMMON_ENV[@]}" MISSING_NEXTEST=1 bash "$HOOK" origin fake >"$HARNESS/missing.out" 2>&1
MISSING_RC=$?
set -e
[[ "$MISSING_RC" -eq 1 ]]
grep -q 'cargo-nextest is required for pre-push tests' "$HARNESS/missing.out"
grep -q 'cargo install cargo-nextest --locked' "$HARNESS/missing.out"

# TEST_RUNNER=cargo never invokes nextest.
reset_logs
printf '%s\n' "$PUSH_INPUT" |
  "${COMMON_ENV[@]}" TEST_RUNNER=cargo bash "$HOOK" origin fake >"$HARNESS/cargo-runner.out" 2>&1
grep -q '^900 cargo test --locked -p f1r3drive-fs$' "$HARNESS/timeouts"
if grep -q 'nextest run' "$HARNESS/cargo"; then
  echo "cargo runner invoked nextest" >&2
  exit 1
fi

# A failing test suite aborts the push and shows the output.
reset_logs
set +e
printf '%s\n' "$PUSH_INPUT" |
  "${COMMON_ENV[@]}" FAIL_NEXTEST=1 bash "$HOOK" origin fake >"$HARNESS/fail.out" 2>&1
FAIL_RC=$?
set -e
[[ "$FAIL_RC" -eq 1 ]]
grep -q 'test failure from the fake cargo' "$HARNESS/fail.out"
grep -q 'Pre-push checks failed! Push aborted.' "$HARNESS/fail.out"
no_results_left "failed hook exit"

# A push whose refs are already on the remote runs no checks.
reset_logs
set +e
printf '%s\n' "$PUSH_INPUT" |
  "${COMMON_ENV[@]}" FAKE_REMOTE_OID="$HEAD_SHA" bash "$HOOK" origin fake >"$HARNESS/raced.out" 2>&1
RACED_RC=$?
set -e
[[ "$RACED_RC" -eq 1 ]]
grep -q 'Already up to date with remote' "$HARNESS/raced.out"
if [[ -s "$HARNESS/timeouts" ]]; then
  echo "a push already on the remote ran checks" >&2
  exit 1
fi

# Cancellation stops every worker and removes the results.
reset_logs
printf '%s\n' "$PUSH_INPUT" |
  "${COMMON_ENV[@]}" SLEEP_NEXTEST=1 FAKE_NEXTEST_STARTED="$HARNESS/started" \
    bash "$HOOK" origin fake >"$HARNESS/cancel.out" 2>&1 &
HOOK_PID=$!
for _ in $(seq 1 100); do
  [[ -f "$HARNESS/started" ]] && break
  sleep 0.05
done
[[ -f "$HARNESS/started" ]]
kill -TERM "$HOOK_PID"
set +e
wait "$HOOK_PID"
RC=$?
set -e
[[ "$RC" -eq 143 ]]
if grep -q 'No such file or directory' "$HARNESS/cancel.out"; then
  echo "hook cancellation removed results before workers stopped" >&2
  exit 1
fi
sleep 0.2
while read -r pid _; do
  if kill -0 "$pid" 2>/dev/null; then
    echo "hook cancellation left cargo process $pid" >&2
    exit 1
  fi
done <"$HARNESS/cargo"
no_results_left "hook cancellation"

printf 'pre-push hook tests passed\n'
