# Plan 31 validation recovery report

Assigned recovery validation finished. The broad Go race run, all required E2E commands, conformance command, and the completed three-backend SQL retry exited 0. The original SQL timeout and four baseline browser failures remain recorded below. Skipped tests and conformance warnings/review outcomes are explicit; this is not a claim that every discovered test ran or every conformance module passed.

## Snapshot and execution boundaries

- Worktree: `/home/thomas/.codex/worktrees/189f/zeroauthy`.
- Broad Go race tested source `e7127d67445bba1ff14ceec81c6e5c88e35a88c8`. The runner started on the identical source tree before that final-fix commit; the starting HEAD in the original runner metadata is older. `recovery-snapshot-identity.json` records the validated source and the clean postcommit worktree.
- SQL, E2E, and conformance used runtime source `cc853d1f6f23c98f9dcfbd2a79d5f4fc2468ee35` after the separately authorized selector delta. The controller ran its affected management race checks; this agent did not restart the broad suite.
- Final HEAD: `4b51288f64785963bfa3983f86c4a5ae82c683a6`. Changes after runtime commit cc853d1 were the long-running-suite protocol and the four baseline browser fixture updates. The baseline retry and SQL retry record their exact starting HEAD and clean status in per-stage retry status files.
- This validation agent changed only recovery artifacts under this scratch directory: no production source, assertions, index, or commits. No Auth0 tenant contact was made by this runner. E2E uses local endpoints; the deploy log explicitly reports its upstream lane unavailable and no upstream call.
- Commands ran sequentially. PostgreSQL/MySQL port overrides were scoped only to the SQL shell commands. `E2E_KEEP_WORK=1` was set on every E2E command. Monitoring switched to long interruptible waits under the repository 15-minute protocol; no suite was retried because it was quiet.
- Existing old `status.json` and `final-*` logs were preserved. All new logs use `recovery-*` names.

## Commands and actual results

Every command below includes its actual GOTOOLCHAIN assignment. Durations are elapsed wall time from persistent stage timestamps.

| Stage | Exact command | Exit / result | Duration | Full log |
| --- | --- | --- | --- | --- |
| 01-go-race | `GOTOOLCHAIN=go1.26.7 ZA_REQUIRE_NODE=1 go test -json -race -timeout=50m ./...` | 0 / PASS | 30.54 min | `recovery-01-go-race.log` |
| 02-sql | `GOTOOLCHAIN=go1.26.7 ZEROAUTHY_TEST_PG_PORT=58632 ZEROAUTHY_TEST_MYSQL_PORT=58506 ./scripts/test-sql.sh -timeout=30m ./internal/store/sqlstore/...` | 1 / FAIL | 30.16 min | `recovery-02-sql.log` |
| 05-e2e-logs | `GOTOOLCHAIN=go1.26.7 E2E_KEEP_WORK=1 make e2e-logs` | 0 / PASS | 25.30 s | `recovery-05-e2e-logs.log` |
| 06-e2e | `GOTOOLCHAIN=go1.26.7 E2E_KEEP_WORK=1 make e2e` | 2 / FAIL | 2.64 min | `recovery-06-e2e.log` |
| 07-e2e-actions | `GOTOOLCHAIN=go1.26.7 E2E_KEEP_WORK=1 make e2e-actions` | 0 / PASS | 16.22 s | `recovery-07-e2e-actions.log` |
| 08-e2e-actions-ii | `GOTOOLCHAIN=go1.26.7 E2E_KEEP_WORK=1 make e2e-actions-ii` | 0 / PASS | 43.11 s | `recovery-08-e2e-actions-ii.log` |
| 09-e2e-organizations-ii | `GOTOOLCHAIN=go1.26.7 E2E_KEEP_WORK=1 make e2e-organizations-ii` | 0 / PASS | 12.05 s | `recovery-09-e2e-organizations-ii.log` |
| 10-e2e-deploy | `GOTOOLCHAIN=go1.26.7 E2E_KEEP_WORK=1 make e2e-deploy` | 0 / PASS | 17.00 min | `recovery-10-e2e-deploy.log` |
| 11-e2e-email | `GOTOOLCHAIN=go1.26.7 E2E_KEEP_WORK=1 make e2e-email` | 0 / PASS | 34.76 s | `recovery-11-e2e-email.log` |
| 12-conformance | `GOTOOLCHAIN=go1.26.7 make conformance` | 0 / PASS | 2.90 min | `recovery-12-conformance.log` |
| e2e-fixture-rerun | `GOTOOLCHAIN=go1.26.7 E2E_KEEP_WORK=1 make e2e` | 0 / PASS | 2.18 min | `recovery-e2e-fixture-rerun.log` |
| sql-timeout-rerun | `GOTOOLCHAIN=go1.26.7 ZEROAUTHY_TEST_PG_PORT=58632 ZEROAUTHY_TEST_MYSQL_PORT=58506 ./scripts/test-sql.sh -json -timeout=120m ./internal/store/sqlstore/...` | 0 / PASS | 34.17 min | `recovery-sql-timeout-rerun.log` |

## Go race events and skips

- `go test -json -race -timeout=50m ./...`: 101 packages discovered, 80 package pass events, 21 packages with no test files. 9,694 test/subtest run events: 9,690 pass, 4 skip, 0 fail. No package failure events.
- The four actual skipped test/subtest events were:

  - `github.com/zeroauthy/zeroauthy/tests/e2e/deploy-cli` / `TestE2EPrivateEmailProviderCredentialAfterImport`: email_secret_test.go:20: only runs from the isolated Plan 21 deploy lane.
  - `github.com/zeroauthy/zeroauthy/tests/e2e/deploy-cli` / `TestE2EPrivateLogStreamSecretsAfterImport`: log_stream_secret_test.go:21: only runs in isolated deploy CLI lane.
  - `github.com/zeroauthy/zeroauthy/pkg/storeplugin` / `TestConformanceThroughPluginProcess/Organizations/Limits`: organizations.go:748: store cannot override Organizations limits.
  - `github.com/zeroauthy/zeroauthy/internal/store/grpcstore` / `TestOrganizationsPluginRoundTrip/Organizations/Limits`: organizations.go:748: store cannot override Organizations limits.

- Broad-run summaries: `recovery-go-race-events.json` (all fail/skip events) and `recovery-01-go-race-summary.json` (counts, reasons, package passes). Counts include parent tests and subtests, not unique independent scenarios. The broad run did not configure external PostgreSQL/MySQL DSNs; the completed SQL matrix below supplies those backends.

## SQL timeout and completed retry

- Original 30-minute command: FAIL, exit 1. Panic: `test timed out after 30m0s`; active path `TestConformance/sqlite/ActionsII/QueueCap`, with the stack executing SQLite `EnqueueJob` query work. Package failed at 1800.108s. The script starts both throwaway SQL servers and invokes `go test -race -count=1`; its original nonverbose log cannot establish completed per-backend results. No original per-backend pass is claimed.
- Controller authorized one retry with the same assertions, race instrumentation, fresh throwaway servers, JSON events, and a 120-minute package timeout. The retry exited 0 after 34m10s wall time; package elapsed 2042.653s.
- Retry JSON: 2,975 test/subtest pass events, 0 fail events, 0 skip events. All three backend conformance parents passed:

| Backend parent | Actual pass elapsed |
| --- | --- |
| `TestConformance/sqlite` | 855.73 s |
| `TestConformance/postgres` | 113.57 s |
| `TestConformance/mysql` | 372.64 s |

- `recovery-sql-timeout-rerun-events.json`, `recovery-sql-timeout-rerun-summary.json`, and `recovery-sql-timeout-rerun-status.json` retain the backend results, all failure/skip events, and exit identity. The original timeout remains FAIL.

## E2E results and limits

- Plan 31 logs: PASS. Auth0 CLI filtered/unfiltered logs, all three HTTP stream formats, browser failure/execution/redeploy flow, restart retry persistence, SDK statistics, and privacy scan completed. Browser: 1 passed. Privacy scan: 17 artifacts, 8 representative secrets absent. Retained work: `/tmp/plan31-etIhjP`.
- Original baseline `make e2e`: FAIL, exit 2. M3/SDK/CLI lanes passed. Browser: 4 failed, 20 passed, 56 skipped. Failures were m13/m14/m15/m17 console tests expecting a level-1 page heading after resource creation; each reached the resource URL but found no such element. Full errors and emitted trace paths remain in `recovery-06-e2e.log`.
- Controller committed only fixture locator/navigation updates for the existing modal UI in 4b51288. Full baseline retry: PASS, exit 0. M3/SDK/CLI lanes and all 24 enabled browser tests passed; 56 lane-gated browser tests stayed skipped. The complete skipped browser list is in `recovery-baseline-browser-skips.json`; those skips are not passes.
- Actions: 5 browser tests passed plus SDK/CLI checks; work `/tmp/tmp.IicjiWEtU6`.
- Actions II: 4 browser tests passed; work `/tmp/tmp.xtT8ivHpsM`.
- Organizations II: 6 browser tests passed; work `/tmp/plan30-pWYAbC`.
- Deploy: PASS; work `/tmp/tmp.NmqCEyswck`. Its log explicitly excludes databases from that portability matrix, reports attackProtection tool-unavailable, and reports the upstream lane unavailable. These lanes are not passing claims. The local directory/preserved-mode import, repeat, credential, update, target-only, negative, and runtime checks passed.
- Email: 1 browser test passed and local email checks completed.

## Conformance command and module outcomes

`make conformance` exited 0. The summary contains 82 modules: 46 passed, 0 failed, 12 warning, 16 review, 8 skipped. Warnings, review modules, and skipped modules are not module passes. Results are retained under `tests/conformance/results/20261101T055756Z`.

```text
Summary (results in tests/conformance/results/20261101T055756Z):
  oidcc-basic-certification-test-plan: 35 modules: 21 passed, 0 failed, 6 warning, 4 review, 4 skipped
  oidcc-config-certification-test-plan: 1 modules: 1 passed, 0 failed, 0 warning, 0 review, 0 skipped
  oidcc-formpost-basic-certification-test-plan: 35 modules: 21 passed, 0 failed, 6 warning, 4 review, 4 skipped
  oidcc-rp-initiated-logout-certification-test-plan: 11 modules: 3 passed, 0 failed, 0 warning, 8 review, 0 skipped
```

## Carried controller/fixer checks (not repeated here)

- `GOTOOLCHAIN=go1.26.7 make console`: fixer reports exit 0 in `final-fix-report.md`; `fix-console-build.log` records 74 test files / 572 tests passed, typecheck/lint/generation and production build. Existing bundle-size and install-script advisories were reported by the fixer.
- Initial source check passed in `final-check-sources-recovery.log`. After the selector/API/provenance update, controller rerun failed exit 2 on a transient RFC6749 section-2.3.1 redirect/timeout (`selector-check-sources.log`). One controller retry exited 0 (`selector-check-sources-retry.log`). Both actual outcomes remain preserved.
- Controller owns the selector-specific affected management race checks and their final record; they were not duplicated by this validation agent.

## Persistent artifacts

Raw evidence is retained outside the repository at `/tmp/zeroauthy-plan31-evidence-2026-11-01/`. Artifact names below refer to that directory. This report is the committed summary; transient raw files are not repository dependencies.


- Original recovery sequence: `recovery-status.json`; retries: `recovery-retry-status.json`, `recovery-e2e-fixture-rerun-status.json`, `recovery-sql-timeout-rerun-status.json`.
- Snapshot transitions: `recovery-snapshot-identity.json`, `recovery-source-transitions.jsonl`.
- Full logs and parsed JSON summaries are beside this report. Old interrupted logs/status remain untouched.
- Final read-only `git status --short`: clean. `git diff --check` exited 0. No source/index/commit mutation was performed by this agent.
