# CI Jobs and Check Names

This page lists the jobs of `.github/workflows/ci.yml`. Each job has one purpose, and its name states that purpose. A red check therefore tells the reader which kind of work failed. The structure follows `f1r3node-rust/docs/ci.md`. [DEVELOPER.md](../DEVELOPER.md) describes the git hooks that run the same checks locally.

`.github/scripts/check-ci-docs.sh` compares the job table below with `ci.yml`. Static Checks fails when one of them names a job that the other does not have.

## Categories

| Category | Meaning |
| --- | --- |
| Static check | Reads files and history. It runs no program under test. |
| Unit test | Runs `cargo nextest` and the doctests for the workspace. |

## Triggers

| Event | Runs |
| --- | --- |
| Pull request | Every job |
| Push to `main` | Every job except Commit Policy |
| Manual (`workflow_dispatch`) | Every job except Commit Policy |

A newer pull request head cancels the run for the earlier head. Runs for different `main` commits do not cancel each other.

## Jobs of `ci.yml`

| Job id | Check name | Category | Needs |
| --- | --- | --- | --- |
| `commit_policy` | Commit Policy | Static check | none |
| `static_checks` | Static Checks | Static check | none |
| `deny` | cargo-deny | Static check | none |
| `test` | Test (*os*) | Unit test | `static_checks` |
| `markdown_link_check` | Markdown Link Check | Static check | none |

Test waits for Static Checks, so a formatting or lint failure does not start the macOS runner.

### Commit Policy

The job verifies the commit identities of pull request commits (pull requests only). Each commit author and each `Co-authored-by` email must be ratified: it must have authored a commit in the base branch history. `.github/denied-identities.txt` lists identities that are always rejected. It blocks `@anthropic.com`.

The step fetches commit objects only. It reads the commit identity checker, the exemptions script, and the denied list from the base commit. Thus a pull request cannot weaken its own check. Before these files reach the base branch, the step uses the copies in the pull request.

`.github/scripts/commit-policy-exemptions.sh` lists the exempt commits: the commits of a human pull request author, and the contributor commits of an imported fork pull request. An exempt commit skips the author check. Its co-authors are still checked.

### Static Checks

1. Verify workflow security invariants (first, before the toolchain install)
2. Verify that docs/ci.md lists the jobs of ci.yml
3. Verify no tracked private keys
4. Run the CI script tests
5. Check formatting
6. Run clippy (`--locked`, `-D warnings`)

`check-workflow-invariants.sh` fails in these conditions:

- An action is not pinned to a commit SHA.
- A checkout keeps credentials.
- A workflow has no top-level `permissions` block.
- Commit Policy reads its files from the pull request instead of the base commit.

`check-tracked-key-material.sh` fails on a tracked `.env` file, a tracked key or certificate store, or a 64-digit hex private key that `.github/known-dev-keys.txt` does not list.

The CI script tests:

| Script | Tests |
| --- | --- |
| `test-check-commit-trailers.sh` | The commit identity checker and its CI wiring |
| `test-commit-policy-exemptions.sh` | The exemption rules and their CI wiring |
| `test-check-tracked-key-material.sh` | The key material check |
| `test-check-ci-docs.sh` | The docs/ci.md job table check |
| `test-pre-push-hook.sh` | The pre-push hook, with fake `git`, `cargo`, and `timeout` |

### cargo-deny

`EmbarkStudios/cargo-deny-action` runs `cargo deny check --all-features` with `deny.toml`. Each advisory waiver in `deny.toml` gives a reason and the backlog item that removes it.

### Test (*os*)

The job runs on `ubuntu-latest` with libfuse3 and on `macos-latest` with fuse-t. It runs `cargo nextest run --locked --workspace --no-tests=pass`, then `cargo test --locked --workspace --doc`. The live-shard suites are `#[ignore]`-gated and do not run in CI. If the job fails, it uploads the test logs for 7 days.

### Markdown Link Check

lychee checks local file links and GitHub and GitLab URLs in every `*.md` file. Other web URLs are excluded, because they answer GitHub runner IPs differently from developer machines.

## Action Pins

Every action is pinned to a commit SHA. The comment after the SHA names the release.

| Action | Release |
| --- | --- |
| `actions/checkout` | v5.1.0 |
| `actions/upload-artifact` | v4.6.2 |
| `dtolnay/rust-toolchain` | v1 |
| `Swatinem/rust-cache` | v2.9.2 |
| `taiki-e/install-action` | v2.87.7 |
| `EmbarkStudios/cargo-deny-action` | v2.1.1 |
| `lycheeverse/lychee-action` | v2.9.0 |

## Required checks

No ruleset protects `main` yet. This is the proposed `main` ruleset. It is not applied.

| Rule | `main` |
| --- | --- |
| Deletion and non-fast-forward | Blocked |
| Pull request | Required, one approval |
| Code-owner review | Required for the paths in `.github/CODEOWNERS` |
| Required checks | Commit Policy, Static Checks, cargo-deny, Test (ubuntu-latest), Test (macos-latest), Markdown Link Check |
| Branch up to date before merge | Required |

`@F1R3FLY-io/ci-maintainers` must have write access to this repository. GitHub ignores a code owner without write access.

GitHub reports a skipped job as a pass. Commit Policy is skipped on a push, but a ruleset evaluates pull requests, where the job always runs.
