# Repository agent rules

## Long-running test suites

For full suites and other test commands expected to take more than a few minutes:

- Start the command once, write output to a log, and retain its process/session handle and exit status.
- Prefer completion notifications or a blocking process wait over model-driven polling. If polling is necessary, check no more often than every 15 minutes while the command is running.
- Assign one agent to monitor the run. Controllers and other agents must not independently poll the same process, scan its logs, or ask the monitoring agent for routine updates between checks.
- Report completion, a stage transition, or an actionable failure promptly when notified. An explicitly requested user status check is also allowed; routine minute-by-minute messages are not required.
- Do not rerun a suite merely because it has been quiet or is taking a long time. Investigate only after a recorded failure, timeout, or evidence that the process has stopped.
- Preserve commands, logs, snapshot identity, actual exit codes, failures, and skips for the final report. Waiting time must not be filled with extra review agents or audits unless the user requests them.

Apply this protocol to delegated agents as well as the controller. It changes monitoring frequency, not required test coverage or accuracy of reported results.

## Plan verification in CI

Full verification of a plan runs in GitHub Actions, not as a local sequential run (maintainer, 2026-11-07):

- During a task, run that task's focused tests.
- At the end of a plan, run a fast local tier: `go test ./...` (no `-race`) with `TMPDIR`/`GOTMPDIR` on a short tmpfs path such as `/dev/shm/<name>` (Unix socket paths must stay under 108 bytes), plus the plan's own E2E suite.
- Then push the plan branch (`plan-*`; never `main`). `.github/workflows/plan-branch.yml` runs race tests, the SQL databases, the console build, every E2E suite in parallel and conformance. Pushing plan branches needs no further approval.
- Continue with the next plan while CI runs. Fix CI failures on the plan's branch and push again.
- Merging to `main` still needs green CI and maintainer approval.

Report CI results as for local runs: the run URL, each failed job and its actual failure.

## Plan 19 database-test hold

While implementing Plan 19 (`docs/superpowers/plans/2026-10-21-zeroauthy-plan-19-tenant-settings-attack-protection.md`), do not run **any database-backed test until all implementation tasks (Tasks 1–11) are done**. This includes SQLite, PostgreSQL, MySQL, SQL-backed gRPC or plugin tests, database-backed integration and browser tests, `./scripts/test-sql.sh`, and broad test commands that would select any of them.

Write database tests and compile affected code as needed. Before Task 12, run only focused tests confirmed to use in-memory stores or mocks. In Task 12, run the deferred database tests and report their actual results. Never label a deferred test as passing.

This rule takes precedence over earlier per-task test commands in the Plan 19 implementation plan.
