# Contributing to zeroauthy

Thanks for your interest in zeroauthy. This guide covers how to propose
changes and what every contribution must agree to.

## Before you start

1. **Read [`CLEAN_ROOM.md`](CLEAN_ROOM.md).** zeroauthy is a clean-room,
   Auth0-compatible implementation. Every contribution must follow that
   policy, and the pull request template asks you to confirm it.
2. **Read [`AGENTS.md`](AGENTS.md).** It holds the repository rules for AI
   agents and anyone else running tests: how to run long test suites and how
   plans are verified in CI.
3. **Agree on the work first.** Open an issue, or ask the maintainer, before
   starting anything substantial, so effort isn't spent on changes that
   can't be merged. Reviews may take a while.
4. **Report security issues privately** as described in
   [`SECURITY.md`](SECURITY.md), not in a public issue or pull request.

## How work is planned and built

zeroauthy is built with AI coding agents, following a roadmap Claude
created:

- [Management API roadmap](docs/superpowers/specs/2026-10-19-zeroauthy-management-roadmap-design.md):
  the numbered plans and the coverage table of completed and remaining work.
- [v1.0 release scope](docs/superpowers/specs/2026-11-02-zeroauthy-v1-release-scope.md):
  which plans must ship in v1.0, which ship only if ready, and which come
  after 1.0.

Specs and plans that already exist are under `docs/superpowers/specs/` and
`docs/superpowers/plans/`, with implementation records in
`docs/superpowers/`. Check them before starting, and pick up the next
unfinished item rather than starting a new one.

### 1. Set up Claude Code with the Superpowers plugin

Install [Claude Code](https://claude.com/claude-code), then install the
Superpowers plugin, which provides the brainstorming and planning skills:

```
/plugin install superpowers@claude-plugins-official
```

### 2. Write a spec and an implementation plan for each roadmap item

For each item, in roadmap order:

1. **Spec:** run the brainstorming skill (`superpowers:brainstorming`) to
   produce a design spec in `docs/superpowers/specs/`.
2. **Implementation plan:** turn the reviewed spec into a step-by-step plan
   in `docs/superpowers/plans/` using the writing-plans skill
   (`superpowers:writing-plans`).

Follow the existing naming pattern
(`YYYY-MM-DD-zeroauthy-<topic>-design.md` for specs,
`YYYY-MM-DD-zeroauthy-plan-<n>-<topic>.md` for plans).

### 3. Review each spec and plan with a stronger model

Review every spec and every implementation plan before moving to the next
step. Use a strong model such as Opus, Fable or Astra at **medium effort or
higher**. Address the review findings and commit the result before
continuing.

### 4. Implement the reviewed plan

Implement the reviewed plan with Sol or Opus, for example using
`superpowers:subagent-driven-development` or `superpowers:executing-plans`.

### 5. Review the implementation

Either option is fine:

- **Review it now** with a different or stronger model than the one that
  wrote the code. A second model brings a different perspective.
- **Finish the implementation and open the pull request.** A stronger model
  can review it later, before it is merged.

## Workflow

Contributors work from a fork. Nobody pushes directly to this repository.

1. Fork the repository and create a branch from `main`. For roadmap work,
   name it `plan-<n>-<topic>`.
2. Make your change. Keep each pull request focused on one plan or fix.
3. Test as described in [`AGENTS.md`](AGENTS.md): run each task's focused
   tests while you work, and at the end of a plan run the fast local tier
   (`go test ./...` plus the plan's own E2E suite). The full suite runs in
   GitHub Actions (`.github/workflows/plan-branch.yml`) on `plan-*`
   branches. If Actions is enabled on your fork it runs there; otherwise the
   maintainer runs it before merging. Note the commands and results in the
   pull request.
4. Sign off every commit (see below).
5. Open a pull request against `main` and complete the template, including
   the clean-room checklist. Merging needs green CI and maintainer approval.

## Licence and sign-off (DCO)

zeroauthy is licensed under the [Apache License 2.0](LICENSE). Under section 5
of that licence, any contribution you submit is licensed under the same
terms.

Every commit must also carry a `Signed-off-by` line certifying the
[Developer Certificate of Origin 1.1](https://developercertificate.org/):
that you wrote the change, or otherwise have the right to submit it under
the project's licence. Add it with `-s`:

```bash
git commit -s -m "your message"
```

which appends:

```
Signed-off-by: Your Name <you@example.com>
```

Use your real name and an email address you control. Pull requests with
unsigned commits will not be merged. To sign off commits you've already made,
run `git rebase --signoff main`.
