# Contributing

Thanks for contributing to a [F1R3FLY.io](https://github.com/F1R3FLY-io) project. Org-wide
policy lives in [F1R3FLY-io/.github](https://github.com/F1R3FLY-io/.github); anything here
that conflicts defers to it.

## Before You Start

1. Read the repo's [README.md](README.md) and [DEVELOPER.md](DEVELOPER.md).
2. Check open GitHub Issues and Pull Requests — the work may already be claimed or in progress.
3. Read [docs/ToDos.md](docs/ToDos.md) on `main`. Look for a task that covers the work and for a claim on it.
4. For non-trivial changes, open a GitHub Issue or Discussion first so design can be agreed
   before implementation.
5. For protocol- or ecosystem-level proposals, file a [FIP](https://github.com/F1R3FLY-io/FIPS)
   rather than a PR.

## Planning and Task Tracking

Maintainers, contributors, and AI agents share one task record in the repository.

- A user story in [docs/UserStories.md](docs/UserStories.md) states the need.
- An epic in [docs/ToDos.md](docs/ToDos.md) holds the tasks for one story.
- Each task has a `TASK-NNN-N` identifier and an `acceptance` list of measurable conditions.
- Claim a task before you work on it. Set `status`, `claimed_by`, and `claimed_at` in the task.
- Deferred work goes to [docs/Backlog.md](docs/Backlog.md). Finished epics move to [docs/CompletedTasks.md](docs/CompletedTasks.md).
- A GitHub issue holds the problem and its discussion. The task file on `main` holds the status and the claims.
- Link the task to its issue and its pull request.

## Branching and Commits

- Branch from `main` and open pull requests against `main`.
- Branch prefixes: `feat/`, `fix/`, `docs/`, `perf/`, `chore/`.
- Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`,
  `perf:`, `refactor:`, `test:`, `chore:`.
- Keep one concern per pull request.
- Preserve commit history when picking up someone else's PR — don't squash unrelated commits
  without consent.
- Do not add `Co-authored-by` lines for AI tools or `Claude-Session` trailers. The
  `commit-msg` hook and the CI Commit Policy job reject them (see
  [docs/ci.md](docs/ci.md#commit-policy)).

## Local Checks

Install the git hooks once (`./scripts/setup-hooks.sh`). They run these checks on commit and
on push. To run the checks that CI enforces by hand:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo deny check
cargo nextest run --locked --workspace --no-tests=pass
cargo test --locked --workspace --doc
```

If you change a live-shard code path, also run the matching `#[ignore]`-gated suite against a
local shard ([docs/testing.md](docs/testing.md)). CI does not run those suites.

If a check is not available, identify the missing check in the pull request description.

## Reporting Issues

Open a GitHub Issue for bugs and feature requests. Search existing issues first. For bugs,
include:

- What you expected vs what happened
- Steps to reproduce, ideally a minimal proof of concept
- Version / commit and environment (OS, arch, fuse-t or libfuse3 version)
- Relevant logs or error output (no secrets or PII)

For security vulnerabilities, do **not** open a public issue — see Security and Privacy.

## Pull Requests

Every PR should describe **what** changed, **why** (link the issue / FIP / discussion), and
**how** it was verified.

A PR is ready for review when:

- [ ] CI is green (or the failure is unrelated and noted)
- [ ] New behavior has tests
- [ ] Public API / CLI / config changes are documented
- [ ] No secrets, credentials, or PII in code, commits, fixtures, or logs

Green CI on a pull request covers formatting, lint, the supply-chain audit, the commit
policy, and the unit tests on Linux and macOS. It does **not** cover the live-shard suites.
[docs/ci.md](docs/ci.md) lists every job.

Maintainers review for correctness, test coverage, scope discipline, and consistency with
documented architecture. Respond to feedback in additional commits rather than force-pushing
over reviewed history.

## Merging

A maintainer merges a pull request into `main` after review and green required checks.
[docs/ci.md](docs/ci.md#required-checks) lists the proposed required checks.

## Branches and Forks

New or occasional contributors should open pull requests from personal forks. Keep fork
branches focused and up to date with `main`.

Known recurring contributors may be invited to work from branches in the upstream
`F1R3FLY-io/f1r3drive-rust` repository. Upstream access does not bypass review.

## Documentation

- Update Markdown when commands, ports, flags, paths, or workflows change.
- Examples should be runnable from the repository root unless stated otherwise.
- Record significant design decisions as ADRs under `docs/architecture/`.
- When you add, rename, or remove a CI job, update [docs/ci.md](docs/ci.md). Static Checks
  fails when the job table and `ci.yml` disagree.

## AI-Assisted Contributions

AI-assisted contributions are welcome. Repository-wide guidance lives in [CLAUDE.md](CLAUDE.md).
When committing from an autonomous agentic session, prefix the commit subject with `[agent]`.
You are responsible for every line you submit — review generated output as you would a human
colleague's.

## Security and Privacy

- Never commit API keys, tokens, credentials, signing keys, or `.env` files. Use environment
  variables and `.env.example`. The tracked key material check in Static Checks enforces this.
- Strip PII from code, comments, tests, fixtures, and logs. Use reserved examples
  (`user@example.com`, `192.0.2.x`).
- Security vulnerabilities: do **not** open a public issue. Report privately via the repo's
  **Security** tab → "Report a vulnerability." See [SECURITY.md](SECURITY.md) for the policy.
- If you commit a secret by accident: don't push; if already pushed, contact a maintainer
  immediately.

## License

Unless stated otherwise, contributions are licensed under
[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0). By opening a pull request
you agree your contribution may be distributed under that license.
