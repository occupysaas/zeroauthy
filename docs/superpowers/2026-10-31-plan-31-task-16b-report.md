# Plan31 Task16b — production acceptance fixtures

Status: **DONE_WITH_CONCERNS for fixture implementation; acceptance FAIL.**
Task16 and Plan31 remain incomplete. The final fixture deliberately fails on
both remaining browser/CLI compatibility gaps below. No full acceptance PASS,
full regression, documentation completion or whole-branch approval is claimed.
Base: f4a0647. Worktree: `/home/thomas/.codex/worktrees/189f/zeroauthy`.

## Implemented fixture

`make e2e-logs` runs the shipped `cmd/zeroauthy` binary with production
`app.New` recorder/stream-worker wiring, persistent SQLite, a stable private
master key, locally generated TLS, local-only CONNECT proxy and HTTP receiver.
The existing social fixture lock serializes shared ports. It restarts the
actual server process with the same database/configuration. No session,
execution or log row is inserted by test scaffolding.

Files: `tests/e2e/m31-logs-cli.mjs`, `m31-node-auth0.mjs`,
`m31-logs.spec.mjs`, `run-m31-logs.sh`; Makefile `e2e-logs` target.

The browser uses normal, separate customer/operator sessions. The operator
is created using `zeroauthy admin create`; its setup URL goes only to a 0600
private artifact. `bootstrap.admin_email` is unset. This avoids capturing a
setup ticket in this fixture's server log; it does not resolve the separately
identified production bootstrap-link logging question.

The browser asserts an actual post-login Action denial, Live `f`, its detail
and canonical execution link, Action name and captured console with masked
secrets, then repairs/saves/deploys through the console editor. A fresh PKCE
login verifies the repaired claim and Live `s` with an execution link. The
execution-reason assertion is soft only to continue the remaining journey;
it still makes the Playwright test fail.

SDK: pinned `auth0`7.4.0 modern `logs.list`, `users.logs.list`, execution get,
`stats.getDaily`, `stats.getActiveUsersCount`; its bundled `auth0/legacy`
(auth0-legacy4.37.1) supplies the requested `logs.getAll` page/checkpoint and
`users.getLogs` methods, plus stats comparisons. The modern SDK exposes a
`search` property rather than frozen wire `q`; its supported `queryParams.q`
pass-through is used. The legacy active-user implementation returns text
`2\n` despite its number type; the fixture JSON-decodes that text before
strictly comparing the modern numeric count. No dependency was added.

CLI: actual pinned1.37.0 unfiltered list includes the browser event; HTTP
stream create/list/update/delete is exercised. Filtered list and concurrent
tail are asserted and fail, rather than skipped. Tail checks authoritative
JSON `log_id` values and duplicate IDs, with bounded process cleanup.

The local receiver validates JSONLINES/JSONARRAY/JSONOBJECT bodies and
canonical envelopes. All streams filter canonical login, token-exchange and
Management-success categories, recursively mask email, witness real503
failures with persisted target events still pending, then deliver every
expected ID after restart. Duplicates are permitted. JSONOBJECT stops at the
first failed object, so the pre-restart assertion requires an actual failed
request per stream and pending target IDs, rather than incorrectly requiring
that a later object was attempted during the outage.

Daily counts are checked against inventory-defined login events and exactly
three produced logins (browser `s`, custom database `sepft`, ordinary password
`sepft`); signups/leaked-passwords are zero and active users exactly two.

## Actual source repairs, with RED/GREEN

1. Checkpoint reads now ignore every parameter other than `from`/`take`,
   including unknown names/repetitions. Duplicated cursor/take still400;
   page mode still rejects unsupported parameters. This follows the existing
   [public checkpoint contract](https://auth0.com/docs/api/management/v2/logs/get-logs).
   Focused memory-handler and mounted-route regressions observed400 RED,
   then passed after the minimal validation-precedence repair.
2. `_id` is an authoritative optional response alias of `log_id`, overwritten
   after scrubbing and subject to normal projections. The public
   [incident-response example](https://auth0.com/docs/secure/security-guidance/incident-response-using-logs)
   shows the same value in both fields. A spoofed stored alias regression was
   RED, then GREEN. API schema, inventory and x-source were updated;
   Go/console types were regenerated, never hand-edited.
3. Documented `log_id` ranges now accept fixed-width decimal bounds, retaining
   date-only ranges for other fields. Memory matching and bound SQL use the
   same inclusive/exclusive lexical order. Public
   [search syntax](https://auth0.com/docs/deploy-monitor/logs/log-search-query-syntax)
   lists `log_id` and ranges. Parser/evaluator and SQLite/memory parity were
   RED, then GREEN; all three SQL drivers subsequently passed.
4. An affected log race selection exposed the pre-existing
   `TestLogSearchMigration29/sqlite` assertion hardcoding latest schema29,
   although Task10 added30. It now checks `LatestVersion()` and retains all
   upgrade-from28/backfill/data assertions. Observed RED version30, focused
   race GREEN, then all-three-driver migration GREEN.

No undocumented page `search_engine` support was implemented based only on
SDK/tool source. No production denial outcome was changed in this stage.

## Actual verification

All Go/make commands use `GOTOOLCHAIN=go1.26.7`; Node26.8.1, CLI1.37.0.
Scratch logs live in `.superpowers/sdd/2026-10-30-zeroauthy-plan-31-logs-streams-stats/`.

| Command / log | Actual result |
| --- | --- |
| Initial `make e2e-logs`, `task-16b-red.log` | RED: no target exists. |
| `go test ./internal/mgmt ./internal/server -run 'TestLogsAPICheckpointIgnoresAllOtherParameters\|TestLogsAPIRealCheckpointBinding' -count=1` | RED400 unsupported parameter, then GREEN mgmt0.142s/server0.223s (`task-16b-checkpoint-*`). An intermediate test cursor of all zeroes was corrected to a valid positive ID. |
| `go test ./internal/logsearch ./internal/mgmt ./internal/store/sqlstore -run 'TestLogIDRanges\|TestLogsAuthoritativeIDAlias\|TestLogSearchParity' -count=1` | RED range invalid/spoofed alias, then GREEN0.005s/0.104s/0.072s (`task-16b-cli-*`). SQLite parity only in this command. |
| `go test -race ./internal/logrules ./internal/logsearch ./internal/mgmt ./internal/server ./internal/store/sqlstore -run 'TestLog\|TestLogs' -count=1` | First four packages PASS4.192s/1.051s/17.688s/3.086s; SQL FAIL61.789s at stale migration29 version assertion. Not an all-pass run. |
| `go test -race ./internal/store/sqlstore -run '^TestLogSearchMigration29$' -count=1` | GREEN2.828s after stale assertion correction. |
| `ZEROAUTHY_TEST_PG_PORT=58432 ZEROAUTHY_TEST_MYSQL_PORT=58306 ./scripts/test-sql.sh -timeout=10m -run '^TestLogSearch' -v ./internal/store/sqlstore/...` | PASS13.152s: SQLite, PostgreSQL17, MySQL8.4 including range parity and migration/backfill (`task-16b-sql.log`). |
| Fresh `go test -race ./internal/logrules ./internal/logsearch ./internal/mgmt ./internal/server -run '^TestLog' -count=1` | PASS3.722s/1.033s/12.562s/2.606s (`task-16b-focused-final.log`). |
| Final `go test -race ./internal/logsearch -count=1` | PASS1.033s (`task-16b-logsearch-final.log`). |
| `make generate`; console `npm run gen && npm run typecheck` | PASS; generated Go and TypeScript updated. Console runtime/dist build deferred to controller's final checks. |
| `E2E_KEEP_WORK=1 make e2e-logs`, final `task-16b-acceptance-final.log` | **FAIL**: execution page omits explicit denial reason; CLI tail and filtered list reject `search_engine`. All remaining checks finish, privacy audit passes. |
| `make check-sources`, `task-16b-sources.log` | **FAIL** in existing authentication URLs: seven RFC links return301000. Make stops before management API link checking. |
| `git diff --check` | PASS before commit. |

Source-link failures were `rfc6749#section-2.3.1`, `rfc6749#section-4.1`,
`rfc6750#section-2.1`, `rfc6750#section-2.2`, `rfc7009`, `rfc7636`, and
`rfc7636#section-4.6`, all under `https://www.rfc-editor.org/rfc/`.
They were not replaced merely to make reachability pass.

Final retained artifacts: `/tmp/plan31-VLWjFG`. `acceptance.json` records the
browser's failure/success/execution IDs, persisted restart IDs, all three
formats, three daily logins and two active users. `privacy-audit.json` records
**17 sinks, 476951 bytes, eight representative secrets absent**, scanning raw,
hex, base64/base64url and URI-encoded values. Inputs include request/operator
passwords, Action secret, five-level metadata password, embedded-JSON secret,
custom-database printed password and client credentials. The custom database
script actually runs and its masked diagnostic line is asserted.

Audited sinks: acceptance/CLI-status summaries; migration/bootstrap diagnostics;
all SQLite `tenant_logs` columns including search projection; all persisted
`action_executions` columns/results; SDK monitoring responses; every browser
monitoring network response and browser console message; receiver bodies/log;
both server process logs; CLI outputs/tail/stderr; proxy log. Receiver headers
are not captured. Private exclusions are recorded in the audit: raw application
DB (users/password hashes/metadata and encrypted credentials), setup link,
config/seed/master/TLS key, CLI home/state, Action cache and binary. Playwright
trace is disabled; failure-only results may contain credential-form artifacts
and are explicitly outside the logging sink audit. No live Auth0 tenant or
vendor delivery endpoint is used.

Development attempts1–11 remain in scratch. Fixture corrections were OAuth
callback-error assertions instead of an assumed hosted body; case-insensitive
execution label; legacy undefined-dispatcher override; required custom DB
`user_id`; password grant `sepft` classification; JSONOBJECT early-abort
semantics; YYYYMMDD stats bounds; legacy text stats decoding. These were
fixture corrections, not claimed production defects. Attempts10/11 completed
all other checks but failed CLI; the final run additionally demonstrates the
previously unasserted execution-reason gap. No failed run is relabeled GREEN.

## Remaining acceptance gaps and limits

- CLI1.37.0 filtered list/tail use Go-SDK queries adding undocumented page
  `search_engine=v3`; the strict page contract returns400. Tail source uses
  log-ID range page searches, not checkpoint polling. Public source is only
  a lead for undocumented behavior under CLEAN_ROOM. An observer/evidence
  decision is still needed before supporting that selector. The alias/range
  repairs alone do not make this CLI lane pass.
- Explicit `access.deny` is a valid normal outcome, not a thrown Action error.
  Its persisted execution currently has no denial reason, so the operator
  execution page cannot display it. The log detail does display it. The final
  fixture asserts the missing execution-page reason and fails. A focused
  follow-up should persist separate, scrubbed denial metadata rather than
  manufacture an exception or change the public execution response shape.
- This lane uses SQLite and one production node. Three-driver search parity
  is checked separately; multi-node ordering, overflow/retention, old-plugin
  capability and simulated24-hour suspension/resume retain their focused
  owning-task tests. No E2E claim is made for those paths here.
- Full Go race/SQL regression, remaining E2E/conformance lanes, guide/roadmap/
  matrix updates and whole-branch review remain controller-owned Task16 work.

Self-review: all IDs are authoritative/tenant-scoped; request credentials stay
in protected inputs and are scanned out of logging sinks; only documented
alias/range behavior was added; checkpoint relaxation is restricted to the
already documented override mode. Generated files came from generators.
The E2E dependency symlink was removed before commit. Commit subject:
`test: add Plan 31 production logs acceptance fixtures`.
