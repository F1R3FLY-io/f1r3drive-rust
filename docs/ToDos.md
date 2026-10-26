---
doc_type: todos
version: "1.0"
last_updated: 2026-10-26
mr_status:
  ready: false
  target_branch: main
---

# Tasks and Epics

<!--
TEMPLATE USAGE INSTRUCTIONS:
0. Update the frontmatter date when modifying this file
   (Update version only for significant structural changes to template)
1. Replace all [PROJECT_NAME] and [PROJECT_SPECIFIC] markers
2. Add new epics using the YAML frontmatter format below
3. Move completed epics to docs/CompletedTasks.md
4. Use /nextTask to find the next task to work on
5. Use /implement to execute tasks with full context
6. Remove these usage instruction comments before committing
-->

This document tracks implementation work through **epics** (logical groupings of related tasks).

**Document Structure**
- Active work: This file (`docs/ToDos.md`)
- User stories: `docs/UserStories.md`
- Completed work: `docs/CompletedTasks.md`
- Backlog: `docs/Backlog.md`

**For LLM assistance in multi-repo workspace:**
See [Task Tracking Standard](https://gitlab.com/smart-assets.io/gitlab-profile/-/blob/master/docs/common/task-tracking-standard.md)

**For reference (GitLab):**
[Task Tracking Standard](https://gitlab.com/smart-assets.io/gitlab-profile/-/blob/master/docs/common/task-tracking-standard.md)

---

## MR/PR Tracking

When all tasks in this file are complete and ready for merge, update the frontmatter:

```yaml
mr_status:
  ready: true
  target_branch: main
  title: "feat: [PROJECT_SPECIFIC: MR title]"
  description: |
    ## Summary
    - [Completed items]

    ## Test plan
    - [x] All tests passing
  labels: ["feature", "enhancement"]
```

---

## Active Epics

<!-- Epics are ordered by priority. Work on the highest priority epic first. -->

---

### EPIC-001: CI and git hook parity with f1r3node-rust

```yaml
---
epic_id: EPIC-001
title: "CI and git hook parity with f1r3node-rust"
status: review
priority: p1
user_story: null
blocked_by: []
created_at: 2026-10-26
claimed_by: claude-session-e7ea5f6d
claimed_at: 2026-10-26T11:00:00Z
tasks:
  - id: TASK-001-1
    title: "Add .githooks (pre-commit, pre-push, commit-msg) and scripts/setup-hooks.sh"
    status: complete
    acceptance:
      - "pre-commit runs cargo fmt check, clippy -D warnings, and cargo deny"
      - "pre-push runs clippy, cargo nextest, and doctests, with a remote-race guard"
      - "commit-msg rejects unratified co-authors and Claude-Session trailers"
      - "All hooks skip in CI environments"
  - id: TASK-001-2
    title: "Add commit identity policy scripts and denied identities list"
    status: complete
    acceptance:
      - "check-commit-trailers.sh and commit-policy-exemptions.sh pass their script tests"
      - "Existing main history passes the policy"
  - id: TASK-001-3
    title: "Rewrite ci.yml with commit_policy, static_checks, deny, test, and markdown_link_check jobs"
    status: complete
    acceptance:
      - "All actions pinned to commit SHAs"
      - "test job runs on ubuntu (libfuse3) and macos (fuse-t) with cargo nextest"
      - "Standalone markdown-link-check.yml is removed"
  - id: TASK-001-4
    title: "Add deny.toml, CODEOWNERS, .lycheeignore, and DEVELOPER.md"
    status: complete
    acceptance:
      - "cargo deny check passes locally; each waiver has a reason"
      - "DEVELOPER.md documents hook install, SKIP_* flags, and CI jobs"
---
```

**Context:** f1r3drive-rust has a minimal CI and no git hooks. f1r3node-rust has a mature setup. This epic brings the core of that setup to this repository.

**Scope:**
- Included: git hooks, commit identity policy, static checks, cargo-deny, nextest tests on Linux and macOS, scoped link check, CODEOWNERS.
- Excluded: Mergify, release trains, soak, casper, OCI, coverage, self-hosted runner tooling.

**Notes:**
- Scripts are copied from f1r3node-rust and adapted for a single `main` branch.

---

<!-- Add more epics following the same format -->

---

## Epic Template

Use this template when adding new epics:

```yaml
---
epic_id: EPIC-XXX
title: "Short descriptive title"
status: pending
priority: p2
user_story: US-XXX
blocked_by: []
created_at: YYYY-MM-DD
claimed_by: null         # Implementer ID: human-{email}, {tool}-session[-{id}], or {team}/{role}
claimed_at: null
tasks:
  - id: TASK-XXX-1
    title: "Task description"
    status: pending
    acceptance:
      - "Measurable acceptance criterion"
---
```

---

## Task States

| Status | Meaning | Next Action |
|--------|---------|-------------|
| `pending` | Not started | Available to claim |
| `in_progress` | Being worked on | Continue or handoff |
| `blocked` | Waiting on dependency | Check `blocked_by` |
| `complete` | Done | Move to CompletedTasks.md |

The parser accepts only these four values. For a task that waits for review, keep `status: in_progress` and set `review_requested_at` and `review_type`. Move deferred work to `docs/Backlog.md`. Do not use `status: deferred`.

---

## Workflow

1. **Find next task**: Use `/nextTask` to identify the highest priority unclaimed task
2. **Claim task**: Set `claimed_by` using [Implementer Identification](https://gitlab.com/smart-assets.io/gitlab-profile/-/blob/master/docs/common/stigmergic-collaboration.md#implementer-identification) format and `status: in_progress`
3. **Implement**: Use `/implement` to execute with full context
4. **Complete**: Mark `status: complete` when acceptance criteria met
5. **Move epic**: When all tasks complete, move epic to `docs/CompletedTasks.md`

---

## References

- **User Stories:** `docs/UserStories.md`
- **Completed Work:** `docs/CompletedTasks.md`
- **Backlog:** `docs/Backlog.md`
- **MR/PR Tracking Standard:** [docs/common/todos-mr_pr-tracking-standard.md](https://gitlab.com/smart-assets.io/gitlab-profile/-/blob/master/docs/common/todos-mr_pr-tracking-standard.md)
