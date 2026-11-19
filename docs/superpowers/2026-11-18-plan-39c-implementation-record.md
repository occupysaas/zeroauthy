# Plan 39c implementation record

Started 2026-11-18 from `8eb2dd45dd337fb262d8252af466c3826ee9d001` (`main`
after PR #70).
Worktree: `/mnt/nvme2/code/zeroauthy-wt-github`.
Branch: `plan-39-github-social`.

**Current status (2026-11-18):** all nine implementation tasks are done except
the controller-owned final review and push. Plan-branch CI has not run. The
optional real-GitHub manual check was **not done**. Nothing here claims a live
GitHub or Auth0 observation.

## Commits

| Task | Commit | Subject |
|---|---|---|
| Plan | `6a8b3d73` | docs: Plan 39c GitHub rulings and implementation plan |
| 1 | `f2e574f1` | docs(github): evidence, inventory and D-0181 |
| 2 | `697b2e9c`, `839e9bf2` | feat(federation): github connection option rules; fix(federation): reject github connected_accounts.active |
| 3 | `23006e89` | feat(store): github identities and federation capability |
| 4 | `60e0dd25` | feat(federation): GitHub provider |
| 5 | `c57bc7db` | feat(login): GitHub hosted login and email-required page |
| 6 | `5a1431b3` | feat(mgmt): github connection schema, seed and deploy migration |
| 7 | `f351fe01` | feat(console): GitHub social connection |
| 8 | `af92afab` | test(e2e): GitHub acceptance and Deploy CLI lanes |
| 9 | this commit | docs(github): operator guide, compatibility and implementation record |

Task reports and diffs are under
`.superpowers/sdd/2026-11-18-zeroauthy-plan-39c-github/` (ignored, local).

## Focused test evidence per task

Environment: `TMPDIR=/dev/shm/zeroauthy-39c GOTMPDIR=/dev/shm/zeroauthy-39c`,
no `-race` unless stated.

- Task 1: RED `go test ./internal/federation -run TestFederationInventory
  -count=1` failed (five strategies, github missing); GREEN same command, and
  `go test ./internal/federation/... -count=1`, exit 0.
- Task 2: option rules and management tests. A mutation check (the
  `connected_accounts.active` rejection disabled) failed for `true`, `1` and
  `"true"` and returned 201 through the API; after restoring it,
  `go test ./internal/federation/... ./internal/connrules/... ./internal/seed/...`
  and `go test ./internal/server -run 'Conn|Mgmt'` passed.
- Task 3: store, jobs, gRPC capability and SQL identity-index tests. RED runs
  failed on the old `gh|` identity form and missing capability types; GREEN
  `go test ./internal/store ./internal/jobs ./internal/store/grpcstore
  ./internal/federation/... -run GitHub -count=1 -v` passed. Package runs
  passed (store/memory, grpcstore, jobs, federation, mgmt, seed, sqlstore on
  SQLite). **SQL run:** `./scripts/test-sql.sh -run 'GitHub' -v
  ./internal/store/sqlstore/...` with PostgreSQL 17 and MySQL 8.4 in podman,
  `-race`, exit 0; `TestSQLGitHubIdentityIndex` passed on sqlite, postgres and
  mysql.
- Task 4: 17 GitHub provider tests RED then GREEN
  (`go test ./ -run GitHub -count=1` in `internal/federation`);
  `go test ./internal/federation/... -count=1` exit 0.
- Task 5: `TestGitHubLoginFlow` RED (email-required page returned 502 with the
  change reverted) then GREEN; login, i18n, oauth and federation packages ok.
- Task 6: `TestDeployMigrationGitHub` RED ("mismatched scope: <nil>") then
  GREEN; `go test ./internal/deploymigration ./internal/seed ./api -count=1`
  and `TestMgmtGitHubConnections` ok. Generated API and console schema
  regenerated.
- Task 7: console form tests; `make console` (gen, lint, typecheck, full
  vitest, build) passed. `npx tsc --noEmit` shows only the two errors that
  predate this branch. Implementation preceded tests in this task, so no RED
  output exists.
- Task 8: `make e2e-github` needed three runs. Run 1 exit 2: a test expected
  201 where the import job returns 202 (test bug). Run 2 exit 2: 11 browser
  tests passed; the Deploy CLI script passed the config object instead of its
  name to export (script bug). Run 3 exit **0**: 11 browser tests, Deploy CLI
  YAML and directory lanes passed, no optional lanes, no skips.

## Not run locally

- `zizmor` was not run: the tool is absent here. The branch changes one token
  in the workflow matrix; CI's zizmor job checks it.
- The optional real-GitHub manual check (an OAuth app, and sign-in with a
  GitHub App) was **not done**. G1's Auth0 semantics and GitHub's behaviour for
  an error body inside HTTP 200 remain unobserved.

## Task 9 documentation

Operator guide (`docs/social-connections.md`, GitHub section), compatibility
matrix rows (including the `profile: false` / `scope` local difference named by
D-0181), `docs/compatibility.md`, CHANGELOG, roadmap and plans README. The
spec's stale "still unverified" paragraph now points at the observation note.
Inventory status of `github`, `provider_protocol.github` and `github_profile`
moved from "planned" to the active wording the Apple entries use.

## Fast local tier (Task 9, Step 2)

Snapshot: `af92afab` plus the uncommitted documentation edits of this task.

- `TMPDIR=/dev/shm/zeroauthy-39c GOTMPDIR=/dev/shm/zeroauthy-39c go test ./...`
  (no `-race`, SQLite only for SQL stores), run once, log
  `/dev/shm/zeroauthy-39c/fast-tier.log`: exit **0**, 101 packages `ok`, no
  FAIL lines, no skip lines in the log.
- The only non-documentation file touched after Task 8 is the embedded
  `internal/federation/inventory.json` (three `status` strings,
  "planned" to "active"). The tier may have compiled it before or after that
  edit, so `go test ./internal/federation/ -run 'TestFederationInventory|GitHub'
  -count=1` was rerun afterwards: exit 0. `make e2e-github` was not rerun; the
  last proof is Task 8's run 3 at `af92afab`.
- `govulncheck ./...`: not available here (`govulncheck` not on PATH, `go tool
  govulncheck` not a tool); not run. CI covers it.
- `git diff --check origin/main`: exit 0, no output.
- Postgres and MySQL ran only in Task 3's focused `test-sql.sh` run; full race
  tests, the SQL databases, the console build, every E2E suite and conformance
  are left to plan-branch CI.

## Final review

pending (controller)
