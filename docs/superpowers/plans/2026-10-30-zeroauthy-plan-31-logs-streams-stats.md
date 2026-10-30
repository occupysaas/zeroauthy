# Plan 31 — Logs, Log Streams, Stats Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Record Auth0-typed tenant log events everywhere zeroauthy acts, serve
them through Auth0's logs, log-stream and stats APIs, and make Actions
troubleshooting work end to end in the console.

**Architecture:** One `internal/logs` recorder takes events from every
subsystem, scrubs them through `internal/logscrub`, and batch-writes them
asynchronously into a new Logs repository (memory, SQL, gRPC capability v1).
Reads use a bounded Lucene AST in `internal/logsearch`. Stream delivery is a
per-stream checkpoint plus lease worker. Stats are daily counters updated in
the same write batch.

**Tech Stack:** Go 1.26.7, Node >=22.13, Vue/TypeScript, SQLite/PostgreSQL/MySQL,
protobuf/gRPC, pinned auth0-cli 1.37, node-auth0 and auth0-deploy-cli 9.1.0,
Playwright. No new Go module dependency.

**Spec:** [Logs, log streams, stats design](../specs/2026-10-30-zeroauthy-logs-streams-stats-design.md).
Read it before executing any task. Section numbers below (§) refer to it.

## Global Constraints

- Use Go 1.26.7 and Node >=22.13; retain repository dependency pins; add no Go module.
- Follow `CLEAN_ROOM.md`. Documentation is evidence; SDK/CLI source is only a lead.
- Every ID and query is tenant-scoped; cross-tenant references behave as missing.
- Log recording never fails or blocks the request that caused it (§3 write path).
- Passwords and secret-named properties never reach any sink: store, stream,
  console response or server log (§3 privacy, maintainer requirement). When in
  doubt, hide.
- Retention default 30 days, minimum 1 day; checkpoint reads settle 2 s;
  per_page/take max 100; page mode limited to 1,000 results; stream batch 100,
  timeout 10 s, backoff 1 s–5 min, suspend after 24 h of failure; Action
  console capture 64 KiB per result; memory ring 10,000 events per tenant.
- Migration `0028_logs.sql` (renumber only if another migration lands first).
- Keep older gRPC plugins working; negotiate Logs v1 separately; missing
  capability returns 501 `logs_unavailable` on this plan's routes.
- Plan 19's database hold applies only to Plan 19, not this plan.
- Add `x-source` to API operations and regenerate with `make generate`; never
  hand-edit generated Go/protobuf/TypeScript. `console/dist` is a committed build artifact.
- Work in an isolated worktree. Record commits, reviews, commands and actual
  results in `docs/superpowers/2026-10-30-plan-31-implementation-record.md`.

## Review Focus

1. A password typed at login, signup or reset reaches a sink by an indirect path:
   a custom-database script or Action that prints it, a Management body that
   carries it inside a JSON string, or metadata nested five levels deep. Expect
   the redaction marker everywhere. Pinned in Tasks 2, 8, 9 and 10.
2. Two instances commit events out of sequence order while `auth0 logs tail`
   polls with `from`. Expect no skipped event and no event twice in one tail.
   Pinned in Tasks 4, 6 and 7.
3. A stream endpoint resolving (or rebinding) to 127.0.0.1, 169.254.169.254 or
   an RFC 1918 address. Expect refusal at dial time with no request sent.
   Pinned in Task 12.
4. A server restart mid-delivery, or two workers racing an expired lease.
   Expect no lost events and at most a duplicate batch. Pinned in Task 12.
5. The database is down or the queue is full during a login burst. Expect
   logins to succeed, events to be dropped with a counter, and the server
   log to warn at most once a minute. Pinned in Task 6.

## File boundaries and shared interfaces

| Responsibility | Files |
| --- | --- |
| Contracts | new `internal/logrules/{inventory.json,rules.go,rules_test.go}`; existing `api/management.yaml`, `docs/compat/decisions.md` |
| Scrubbing | new `internal/logscrub/{scrub,mask,slog}.go` and tests |
| Models and memory | new `internal/store/logs.go`, `internal/store/memory/logs.go`, `pkg/storetest/logs.go` |
| SQL | new `internal/store/sqlstore/logs.go`; migration 0028 in the three driver directories |
| Plugin | new `internal/store/grpcstore/logs.go`; existing `proto/store/v1/store.proto` |
| Recorder | new `internal/logs/{event,recorder,purge,config}.go`; existing `internal/app/app.go` wiring |
| Search and API | new `internal/logsearch/{ast,parse,eval,sql}.go`, `internal/mgmt/logs.go`, `internal/mgmt/stats.go` |
| Emitters | existing login/oauth/dbconn/session/protection/jobs/organization packages; new `internal/mgmt/logmiddleware.go` |
| Actions | existing `internal/actions/engine.go`, `internal/store/actions.go`; `internal/mgmt/system_executions.go` |
| Streams | new `internal/mgmt/log_streams.go`, `internal/logstream/{worker,sink_http,sink_vendors,pii,xxhash}.go`; existing or new dial guard in `internal/httpx` |
| Console | new `console/src/pages/logs/*`, `console/src/pages/log-streams/*`, `console/src/pages/actions/ExecutionView.vue`, `ActionsLogs.vue`; existing `Home.vue`, `sections.ts`, locales |
| Provisioning, E2E | existing seed and deploy migration; new `tests/e2e/m31-*`, `run-m31-logs.sh`, Makefile target `e2e-logs` |

Task 3 owns the storage contract. Add `Store.Logs() Logs` to every store and
transaction view, with an `UnimplementedLogs` stub returning
`ErrLogsUnavailable` until each driver lands.

```go
// internal/store/logs.go. All ctx are context.Context.
type LogEvent struct {
	TenantID, ID, Type                                      string
	Seq                                                     int64 // assigned by AppendLogs
	Date                                                    time.Time
	UserID, ClientID, ConnectionID, OrganizationID, IP      string
	Body                                                    []byte // scrubbed Auth0 log object JSON, without log_id
}
type DailyStatDelta struct{ TenantID string; Day time.Time; Logins, Signups, LeakedPasswords int }
type DailyStat struct {
	Day                              time.Time
	Logins, Signups, LeakedPasswords int
	CreatedAt, UpdatedAt             time.Time
}
type LogPage struct{ Page, PerPage int; Ascending, IncludeTotals bool }

type Logs interface {
	AppendLogs(ctx, events []LogEvent, stats []DailyStatDelta) error
	GetLog(ctx, tid, id string) (*LogEvent, error)
	SearchLogs(ctx, tid string, q *LogQuery, p LogPage) (events []LogEvent, total int, err error)
	LogsAfter(ctx, tid string, afterSeq int64, q *LogQuery, take int, settled time.Time) ([]LogEvent, error)
	LatestLogs(ctx, tid string, q *LogQuery, take int, settled time.Time) ([]LogEvent, error)
	PurgeLogs(ctx, before time.Time, limit int) (int, error)
	DeleteTenantLogs(ctx, tid string) error

	CreateLogStream(ctx, *LogStream) error
	GetLogStream(ctx, tid, id string) (*LogStream, error)
	ListLogStreams(ctx, tid string) ([]LogStream, error)
	UpdateLogStream(ctx, s *LogStream, version int) error // ErrConflict on version mismatch
	DeleteLogStream(ctx, tid, id string) error
	LeaseLogStream(ctx, owner string, now, until time.Time) (*LogStream, error) // ErrNotFound if none due
	RecordDelivery(ctx, tid, id, owner string, d LogStreamDelivery) error   // ErrPrecondition if lease lost

	DailyStats(ctx, tid string, from, to time.Time) ([]DailyStat, error)
	ActiveUsers(ctx, tid string, since time.Time) (int, error)
}
```

`LogQuery` is the storage-owned AST (spec §5) defined in `internal/store/logs.go`
to avoid an import cycle; `internal/logsearch` produces and evaluates it.
`settled` excludes events whose commit time is after it (now − 2 s), so the
store records a commit timestamp alongside `Date`. `AppendLogs` assigns
monotonically increasing `Seq` and `ID = logs.FormatID(Seq)` (56-digit
zero-padded decimal, `fmt.Sprintf("%056d", seq)`), inserts the events and
upserts the stats in one transaction. `GetLog` with an ID that is not 56 digits
returns `ErrNotFound`.

`LogStream` holds TenantID, ID, Name, Type, Status, `Sink map[string]any` (public
fields), `SealedSecrets []byte` (master-key wrapped secret fields), Filters
`[]LogStreamFilter{Type, Name string}`, IsPriority bool, `PII *LogStreamPII{LogFields
[]string; Method, Algorithm string}`, Checkpoint int64, LeaseOwner string,
LeaseUntil, NextAt, FailingSince, LastSuccessAt time.Time, Failures int,
LastErrorClass string, Version int, CreatedAt, UpdatedAt. `LogStreamDelivery`
carries the new Checkpoint, Status, NextAt, FailingSince, LastSuccessAt,
Failures and LastErrorClass.

Recorder contract (Task 6) used by every emitter:

```go
// internal/logs
type Event struct {
	TenantID, Type, Description                              string
	ClientID, ClientName, Connection, ConnectionID, Strategy string
	StrategyType, UserID, UserName, Audience, Scope          string
	OrganizationID, OrganizationName, Hostname               string
	IP, UserAgent                                            string
	Date                                                     time.Time // zero means now
	Details                                                  map[string]any
	ExecutionIDs                                             []string // becomes details.actions.executions
}
type Recorder interface{ Record(ctx context.Context, e Event) }
func FromRequest(r *http.Request) Event // fills IP, UserAgent, Hostname, tenant
var Nop Recorder
```

Scrubber contract (Task 2):

```go
// internal/logscrub
const Marker = "[REDACTED]" // replaced by the Task 1 frozen marker if different
func Scrub(doc []byte) ([]byte, error)                 // key-name scrub of a JSON document, any depth
func ScrubValue(v any) any                             // same, for map/slice values
func SensitiveKey(name string) bool
func WithValues(ctx context.Context, values ...string) context.Context
func MaskText(ctx context.Context, s string) string    // masks registered values in free text
func Handler(next slog.Handler) slog.Handler           // scrubs slog attrs by key name and masks registered values
```

For each task: write the named tests, run the focused command and observe the
stated failure, implement, rerun to PASS, review the diff, then commit only that
task's files. Run commands from the worktree root.

### Task 1: Freeze the wire contracts and decisions

**Files:** create `internal/logrules/{inventory.json,rules.go,rules_test.go}` and
the implementation record; modify `api/management.yaml`, `docs/compat/decisions.md`
(D-0057), `docs/compat/matrix.md`.

**Interfaces:** produces `logrules.Codes() []Code` (`Code{Type, Description,
Category string; Emitted bool; Plan int; StatsKind string}`), `logrules.Fields()`
(Lucene fields and their columns), `logrules.SinkSchema(type string)` (public
and secret fields), `logrules.Marker`, and the per-route contract for Tasks 7, 11 and 13.

- [ ] Write `TestLogsInventory`: every route in §§5–7 has a source URL, scopes,
  parameters with limits, envelope and errors. Every code in Auth0's event-type
  table is present with description and filter category. `Emitted=false` rows
  name a plan, and every category is one of Auth0's filter names. Every sink type has
  a schema with secret fields marked. Assert per_page/take max 100, the page-mode
  limit of 1,000, and the 56-digit ID format.
- [ ] Run `go test ./internal/logrules -run TestLogsInventory -count=1`; expect FAIL.
- [ ] Fill the inventory from the §2 sources. Map each emitted code to the exact
  zeroauthy trigger point (file and function). Write D-0057 with the ten §8 local
  rulings and every gap. Add the paths to `api/management.yaml`.
- [ ] Rerun; expect PASS. Run `make generate` and `go test ./api -count=1`; inspect generated diffs.
- [ ] Commit: `docs: freeze Plan 31 logs contracts`.

### Task 2: Secret scrubber and per-request value mask

**Files:** create `internal/logscrub/{scrub,mask,slog}.go`, `scrub_test.go`,
`fuzz_test.go`; modify `internal/app/app.go` to wrap the server's slog handler
with `logscrub.Handler`.

**Interfaces:** produces the scrubber contract above. `SensitiveKey` lowercases,
removes `_`, `-`, `.` and matches if the name *contains* any of `password`,
`passwd`, `pwd`, `secret`, `token`, `authorization`, `apikey`, `privatekey`,
`credential`, `otp`, `recoverycode`. `Scrub` also parses string values that are
JSON objects or arrays, scrubs them and re-encodes them. Registered values
shorter than 4 runes are ignored to avoid masking noise.

- [ ] Write `TestScrubKeys` (table: `password`, `Password`, `new_password`,
  `client_secret`, `x-api-key`, `httpAuthorization`, `id_token`, `otp_code`,
  `private_key`, nested arrays of objects, five-deep metadata). Each value
  becomes `Marker` whatever its type, and siblings stay unchanged.
  `TestScrubJSONInString` covers `details.request.body` as a JSON string
  containing `{"password":"hunter2!!"}`. `TestMaskText` registers `hunter2!!`
  and checks it is masked in `"login failed for hunter2!!"`.
  `TestSlogHandlerScrubs` logs `slog.String("password", …)` and a group with
  `client_secret` and checks the output. `FuzzScrub` builds random nested JSON
  with sensitive keys and asserts that no sensitive key keeps a non-marker value.
- [ ] Run `go test ./internal/logscrub -count=1`; expect FAIL (package missing).
- [ ] Implement. Keep `Scrub` allocation-light: decode with `json.Decoder.UseNumber`.
- [ ] Rerun; then `go test ./internal/logscrub -run '^$' -fuzz FuzzScrub -fuzztime=30s`; expect PASS.
  Run `go test ./internal/app -count=1` for the handler wiring.
- [ ] Commit: `feat: scrub secrets and passwords before any log sink`.

### Task 3: Logs models and memory store

**Files:** create `internal/store/logs.go`, `internal/store/memory/logs.go`,
`pkg/storetest/logs.go`; modify `internal/store/store.go` and memory
`{memory,tx,clone}.go`, every driver's stub, and `pkg/storetest/storetest.go`
registration. Add a `TestLogs` wrapper in each driver's tests using `storetest.RunSuites`.

**Interfaces:** produces everything in the storage contract above.
`ErrLogsUnavailable` joins the store errors.

- [ ] Write conformance cases `LogsAppendOrdering` (sequence and ID strictly
  increase; IDs are 56 digits), `LogsTenantIsolation` (a cross-tenant ID gives
  NotFound and search never crosses), `LogsSettledCheckpoint` (an event
  committed after `settled` is withheld, then returned once settled, never
  twice), `LogsPageLimits`, `LogsPurgeBatches` (purges only expired, respects
  `limit`), `LogsStatsUpsert` (deltas add up per UTC day), `LogStreamLease` (one owner at a time; expired
  lease taken over; `RecordDelivery` by a stale owner gives ErrPrecondition),
  `LogStreamVersionConflict`, and `LogsDeleteTenant`.
- [ ] Run `go test ./internal/store/memory -run Logs -count=1`; expect FAIL.
- [ ] Implement memory with a per-tenant ring of 10,000 events (oldest evicted)
  and deep copies at the boundary. `ActiveUsers` counts users whose
  `LastLogin >= since`.
- [ ] Rerun, and `go test ./internal/store/... -run '^$'`; expect PASS/compile.
- [ ] Commit: `feat: add logs storage contract and memory store`.

### Task 4: SQL migration and SQL store

**Files:** create `internal/store/sqlstore/logs.go`, `logs_test.go` and
`migrations/{sqlite,postgres,mysql}/0028_logs.sql`; modify tenant-deletion paths.

**Interfaces:** implements Task 3. Tables `tenant_logs` (tenant_id, seq, log_id,
date, committed_at, type, user_id, client_id, connection_id, organization_id,
ip, body), `log_streams` and `log_stats_daily`, with the §4 indexes. Use a
driver identity/autoincrement column for `seq`. Assign `committed_at` at insert;
the settle window guards against commit-order skew (Review Focus 2).

- [ ] Write `TestLogsConcurrentWritersCheckpoint`: two goroutines append through
  separate connections while a reader loops `LogsAfter` with `settled = now−2s`
  under an injected clock. The union of reads equals all events, with no duplicates.
  Write `TestLogsMigrationFrom27` (existing data survives) and
  `TestLogsSearchPageBound` (page queries use LIMIT/OFFSET in SQL; no hydration
  of the whole tenant).
- [ ] Run `go test ./internal/store/sqlstore -run 'Logs' -count=1`; expect FAIL.
- [ ] Implement parameterized queries; translate `LogQuery` via
  `logsearch.SQL` from Task 7 (stub it to "match all" here and replace it in Task 7);
  purge with `DELETE … WHERE id IN (SELECT … LIMIT n)` per driver;
  lease with conditional UPDATE on `lease_until < now OR lease_owner = owner`.
- [ ] Run `./scripts/test-sql.sh -run 'Logs' -count=1 ./internal/store/sqlstore/...`;
  expect PASS on SQLite, PostgreSQL and MySQL with no skipped driver. Use
  task-specific free ports; record each driver's result.
- [ ] Commit: `feat: persist logs, streams and stats in SQL`.

### Task 5: Logs v1 plugin capability

**Files:** create `internal/store/grpcstore/logs.go` and test; modify
`proto/store/v1/store.proto`, grpcstore client/server/transaction wiring;
regenerate via `make generate`.

**Interfaces:** `LogsSupporter{CheckLogsSupport(ctx) error; LogsSupported() bool}`;
a separate capability RPC returns version 1. All Task 3 methods are RPCs.

- [ ] Write `TestLogsCapabilities`: a v0 plugin, a pre-Logs plugin, Logs v1, and
  transient unavailability followed by recovery. Old plugins keep every existing
  feature, and Logs calls return `ErrLogsUnavailable`. Add
  round trips for empty body, zero times, sealed secrets bytes, filters and PII.
- [ ] Run `go test ./internal/store/grpcstore -run Logs -count=1`; expect FAIL.
- [ ] Add additive proto fields and RPCs; keep old field numbers; treat
  unknown-method errors as definitive and transport errors as retryable.
- [ ] `make generate`, rerun focused tests and grpcstore conformance; expect PASS.
- [ ] Commit: `feat: add Logs storage plugin capability`.

### Task 6: Asynchronous recorder, stats and retention sweep

**Files:** create `internal/logs/{event,recorder,purge,config,id}.go` and tests;
modify `internal/config` for `logs.retention`, `logs.queue_size` (default
10,000), `logs.streams.allow_insecure_http`, `logs.streams.allow_private_networks`;
wire it in `internal/app/app.go`, including shutdown flush.

**Interfaces:** produces the Recorder contract, `logs.FormatID(int64) string`,
`logs.ParseID(string) (int64, bool)`, and `logs.NewRecorder(st store.Store,
cfg Config, log *slog.Logger) *AsyncRecorder` with `Run(ctx)` and
`Flush(ctx) error`. `Record` builds the Auth0 log object (omitting empty fields,
`tenant_name` from tenant lookup cached per batch, `details.actions.executions`
from `ExecutionIDs`), calls `logscrub.ScrubValue` and `logscrub.MaskText` (for
description and strings in details) using the request ctx, then enqueues
without blocking. The batch writer uses up to 100 events or 250 ms. Stats
deltas come from `logrules.Codes()[type].StatsKind`. `purge.go` runs hourly under
the existing leader/lease helper with `PurgeLogs(now−retention, 1000)` in a loop.

- [ ] Write `TestRecorderNeverBlocks`: with a store whose AppendLogs blocks,
  1,000 `Record` calls return within 50 ms in total. Drops are counted, and the
  warning appears once per minute (injected clock). `TestRecorderScrubsBeforeStore`
  records an event with a password in nested details plus a request ctx value mask;
  the stored body has neither. `TestRecorderStats` feeds `s`, `ss`, `pwd_leak` to a day bucket.
  `TestRecorderFlushOnShutdown`. `TestPurgeRetention` (30 d default, 1 d minimum
  enforced at config load).
- [ ] Run `go test ./internal/logs -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; expect PASS. `go test ./internal/app ./internal/config -count=1`; expect PASS.
- [ ] Commit: `feat: record tenant log events asynchronously`.

### Task 7: Log search and the Logs API

**Files:** create `internal/logsearch/{ast,parse,eval,sql}.go` with tests and fuzz,
`internal/mgmt/logs.go` and `logs_test.go`; modify route registration and
`internal/store/sqlstore/logs.go` to use the real translator.

**Interfaces:** `logsearch.Parse(q string) (*store.LogQuery, error)`,
`logsearch.Match(*store.LogQuery, store.LogEvent) bool`,
`logsearch.SQL(*store.LogQuery, dialect string) (where string, args []any, err error)`.
Handlers: `ListLogs`, `GetLog`, `UserLogs`. Follow the `internal/orgsearch` structure
and bounds (q ≤ 1,000 chars, depth ≤ 16). Fields come from `logrules.Fields()`;
`description` and `user_name` match via the body column, the rest via indexed columns.

- [ ] Write `TestLogSearchParity` (memory and the three SQL drivers return the same IDs for
  `type:f`, `type:(s OR f)`, `user_id:"auth0|abc"`, `date:[2026-10-01 TO 2026-10-30]`,
  `client_name:My*`, `NOT type:sapi`). `TestLogSearchRejects`: leading wildcard, fuzzy,
  regex, unknown field and depth 17 each give 400. `TestLogsAPIPaging`: per_page 101
  and page 10 × per_page 100 give 400 with the Task 1 code; include_totals gives the
  envelope; `fields` projection. `TestLogsAPICheckpoint`: `from` + `take` ascending and
  `take` alone returns latest; settled window honored. `TestUserLogsScopes` needs
  both scopes. `TestLogsCrossTenant`: another tenant's ID gives 404. `TestLogsUnavailable`: 501.
- [ ] Run `go test ./internal/logsearch ./internal/mgmt -run 'LogSearch|LogsAPI|UserLogs|LogsCross|LogsUnavail' -count=1`; expect FAIL.
- [ ] Implement; escape LIKE wildcards in literals; do not interpolate input.
- [ ] Rerun; then `./scripts/test-sql.sh -run 'LogSearch' -count=1 ./internal/store/sqlstore/...`
  and `go test ./internal/logsearch -run '^$' -fuzz FuzzLogQuery -fuzztime=30s`; expect PASS.
- [ ] Commit: `feat: search and read tenant logs`.

### Task 8: Authentication and hosted-page events

**Files:** modify the emit points that Task 1 named in `internal/login`,
`internal/oauth`, `internal/dbconn`, `internal/session`, `internal/hostedlogin`,
`internal/devicecode`, `internal/protection`, `internal/orglogin`, `internal/federation`
and `internal/customdb`. Add `events_test.go` beside each package that has emit points.

**Interfaces:** consumes `logs.Recorder` injected through the existing handler
structs (default `logs.Nop`). On every request that receives a password, OTP or
ticket, call `logscrub.WithValues(ctx, value)` at the handler entry before any
other work, including custom-database scripts, so Review Focus 1 holds. Replace
the Plan 19 `adminNotifications` deferred warning with `limit_mu`/`limit_wc`/`pwd_leak` events.

- [ ] Write one table test per package asserting the code, description, client,
  connection, user and strategy fields for each Task 1 trigger point. Add
  `TestCustomDBPrintedPasswordMasked`: a fake script logs the password. The stored
  event and the server log (captured through `logscrub.Handler`) contain only the marker.
  Add `TestLoginSucceedsWhenRecorderFull`.
- [ ] Run `go test ./internal/login ./internal/oauth ./internal/dbconn ./internal/session ./internal/hostedlogin ./internal/devicecode ./internal/protection ./internal/orglogin ./internal/federation ./internal/customdb -run 'Event|Masked|RecorderFull' -count=1`; expect FAIL.
- [ ] Implement each emit point. A code marked `Emitted=false` in the inventory stays unemitted.
- [ ] Rerun; expect PASS. Then `go test ./internal/... -count=1 -short` to catch fallout.
- [ ] Commit: `feat: log authentication events`.

### Task 9: Management API events middleware

**Files:** create `internal/mgmt/logmiddleware.go` and test; modify route
registration; replace `h.audit(...)` calls (91 sites) with nothing, or with
`details` hints where the middleware cannot see a resource ID. Keep a one-line
server-log record in the middleware.

**Interfaces:** `func (h *Handlers) logMiddleware(next http.Handler) http.Handler`
captures the method, path, query, request body (≤ 64 KiB), status and response
body (≤ 64 KiB). It applies `logrules` per-resource allowlists, then the recorder's
scrubber. It writes `sapi` for 2xx writes, `fapi` for ≥ 400 writes, and `mgmt_api_read`
for the reads Task 1 lists. The actor comes from `CallerFrom` (client ID, or operator user ID).

- [ ] Write `TestManagementWriteLogged` (create client gives `sapi` with the
  actor; the response `client_secret` shows the marker). `TestManagementFailedWriteLogged`
  (400 gives `fapi`). `TestManagementReadNotLogged` (GET /clients has no event).
  `TestManagementSecretReadLogged` (Task 1's secret read gives `mgmt_api_read`).
  `TestManagementBodyPasswordHidden` (POST /users with password, PATCH user with
  password, a jobs import file containing hashes, email provider credentials and log
  stream sink secrets all show the marker).
- [ ] Run `go test ./internal/mgmt -run 'Management.*Logged|Management.*Hidden' -count=1`; expect FAIL.
- [ ] Implement; remove the `audit` helper once no callers remain.
- [ ] Rerun; then `go test ./internal/mgmt -count=1`; expect PASS.
- [ ] Commit: `feat: log Management API operations as sapi/fapi`.

### Task 10: Actions execution links, console capture and job outcomes

**Files:** modify `internal/actions/engine.go`, `internal/actions/jobs.go`,
`internal/store/actions.go` (`ExecutionResult.Logs []string`), memory/SQL
(column on the execution results in migration 0028)/gRPC codecs, and `internal/jobs/runner.go`;
create `internal/mgmt/system_executions.go` and test; modify `api/management.yaml` (system paths).

**Interfaces:** the engine returns execution IDs to callers that already receive
the execution result. Those callers set `logs.Event.ExecutionIDs`. Console lines
are redacted with the existing redactor, then `logscrub.MaskText`, and truncated
to 64 KiB per result with a final `… truncated` line. System routes are
`GET /api/system/tenants/{tenant}/actions/executions?after=<cursor>&trigger=&action=&take=`
(newest first, or ascending after a cursor, max 100) and
`GET /api/system/tenants/{tenant}/actions/executions/{id}` (full record with logs).
The public `GET /api/v2/actions/executions/{id}` response is unchanged.

- [ ] Write `TestLoginLogCarriesExecutionIDs` (post-login success gives `s` with
  `details.actions.executions`). `TestActionDenyLogged` (`api.access.deny("nope")`
  gives `f` with description `nope` and the ID). `TestActionThrowLogged`.
  `TestAsyncJobFailureLogged` (post-change-password fails after retries and writes
  the Task 1 failure code). `TestActionConsoleCaptured` (lines stored; an Action
  secret and the request password are masked; the 64 KiB cap is enforced).
  `TestPublicExecutionShapeUnchanged`. `TestSystemExecutionsList` (tenant-scoped; filters; cursor).
  `TestImportJobOutcomeLogged`.
- [ ] Run `go test ./internal/actions ./internal/jobs ./internal/mgmt -run 'ExecutionIDs|ActionDeny|ActionThrow|AsyncJobFailure|ActionConsole|PublicExecution|SystemExecutions|ImportJobOutcome' -count=1`; expect FAIL.
- [ ] Implement; `make generate` for proto/system API changes.
- [ ] Rerun; then `./scripts/test-sql.sh -run 'Execution' -count=1 ./internal/store/sqlstore/...`; expect PASS.
- [ ] Commit: `feat: link log events to Action executions and capture console output`.

### Task 11: Log streams Management API

**Files:** create `internal/mgmt/log_streams.go` and test; modify route registration.

**Interfaces:** handlers `ListLogStreams`, `CreateLogStream`, `GetLogStream`,
`UpdateLogStream`, `DeleteLogStream` with Task 1 scopes. Sink validation is driven by
`logrules.SinkSchema`; secret fields are sealed with the existing key wrapper and
redacted on read as Task 1 freezes. A PATCH that omits a secret keeps it. `startFrom`
(a log ID) becomes `Checkpoint = seq − 1`, and its absence means the latest seq. `eventbridge`/`eventgrid`
are created `suspended`, and PATCH to `active` is 400 (§6). Status `active` from
`suspended` resets Failures and FailingSince.

- [ ] Write `TestLogStreamCRUD` (each type: valid create, read redacts secrets,
  PATCH keeps omitted secret, immutable type gives 400, unknown sink field gives 400,
  filters validated against `logrules` categories, PII fields/method/algorithm
  validated). `TestLogStreamStartFrom`. `TestCloudStreamsSuspended`.
  `TestLogStreamCrossTenant`. `TestLogStreamSecretNotInSapi` (the Task 9 event shows the marker).
- [ ] Run `go test ./internal/mgmt -run 'LogStream|CloudStreams' -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: manage log streams`.

### Task 12: Stream delivery worker, sinks, PII and outbound guard

**Files:** create `internal/logstream/{worker,sink_http,sink_vendors,pii,xxhash}.go`
and tests; add a dial guard to `internal/httpx` (reuse it if the custom-domain or
social code already has one: search for `DialContext` guards first); wire the worker in `internal/app/app.go`.

**Interfaces:** `logstream.NewWorker(st store.Store, keys <existing key wrapper>, cfg logs.Config, client *http.Client, log *slog.Logger)` with `Run(ctx)`.
The loop is `LeaseLogStream(owner, now, now+60s)`, then
`LogsAfter(tenant, checkpoint, nil, 100, now−2s)`, filter by category, apply PII,
send, then `RecordDelivery`. Backoff doubles from 1 s and is capped at 5 min.
`FailingSince` is set on the first failure; after 24 h the stream becomes
`suspended`. Paused or suspended streams are never leased. Sinks implement
`Send(ctx, s *store.LogStream, secrets map[string]string, items []Item) error`,
where `Item{LogID string; Data json.RawMessage}`. HTTP formats: JSONARRAY is
`[item,…]`, JSONLINES is one item per line, JSONOBJECT is one request per item.
Vendor request shapes follow Task 1. `httpx.GuardedDialer(allowPrivate bool)`
checks every resolved IP at connect time (loopback, private, link-local,
unique-local, unspecified, multicast and CGNAT ranges). Error classes stored are
`timeout`, `dns`, `refused`, `blocked_address`, `http_4xx`, `http_5xx` and `tls`;
never store response bodies.

- [ ] Write `TestHTTPSinkFormats` (three formats against `httptest`; headers and authorization sent).
  `TestDeliveryFiltersAndPII` (category filter; `email` masked, and hashed with xxhash64
  against known vectors; stored event unchanged). `TestDeliveryRestartNoLoss`
  (kill the worker after send and before RecordDelivery; a new worker
  redelivers that batch; nothing is lost). `TestDeliveryLeaseRace` (two workers, one
  lease). `TestDeliverySuspendsAfter24h` and `TestResumeFromCheckpoint` (expired
  events skipped). `TestGuardedDialerBlocks` (127.0.0.1, ::1, 10.0.0.1, 169.254.169.254,
  100.64.0.1, and a resolver that answers public then private), with nothing reaching
  the listener. `TestInsecureHTTPRefusedByDefault`. `TestVendorSinkShapes` (one per vendor).
  `TestXXHash64Vectors`.
- [ ] Run `go test ./internal/logstream ./internal/httpx -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; expect PASS. `go test -race ./internal/logstream -count=3`; expect PASS.
- [ ] Commit: `feat: deliver log streams`.

### Task 13: Stats API

**Files:** create `internal/mgmt/stats.go` and test; modify route registration.

**Interfaces:** `GetActiveUsers` returns a bare JSON number from
`ActiveUsers(tid, now−30d)`. `GetDailyStats` parses `from`/`to` as `YYYYMMDD`
(UTC) with Task 1 defaults and maximum range and returns the documented array with
`date` as RFC 3339 midnight UTC. Missing days are omitted or zero-filled per Task 1. Scope `read:stats`.

- [ ] Write `TestDailyStats` (fixture deltas; range bounds; bad date gives 400 per Task 1)
  and `TestActiveUsers` (31-day-old login excluded) and `TestStatsScope`.
- [ ] Run `go test ./internal/mgmt -run 'DailyStats|ActiveUsers|StatsScope' -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: serve tenant stats`.

### Task 14: Console — Logs, executions, Actions logs, streams, Home stats

**Files:** create `console/src/pages/logs/{LogsList,LogDetail}.vue`,
`console/src/pages/log-streams/{StreamsList,StreamEdit}.vue`,
`console/src/pages/actions/{ExecutionView,ActionsLogs}.vue` and tests; modify
`console/src/layout/sections.ts` (logs live; add `log-streams` and `actions-logs`
entries under Monitoring), `router.ts`, `pages/Home.vue`, locales, and rebuild `console/dist`.

**Interfaces:** generated Management API types plus the Task 10 system routes.
Live mode polls checkpoint mode every 2 s, and Actions logs polls the system
executions route every 2 s. Requests capture the tenant key; stale responses are
ignored. Load the `dataviz` skill before writing the Home chart.

- [ ] Write tests: `logs search sends q and pages`, `live mode appends without
  duplicates`, `detail links to execution`, `execution view shows console lines
  and errors`, `actions logs filters by trigger and action`, `stream secrets are
  write-only`, `cloud stream forms explain not delivered`, `stream resume
  sends status active`, `home shows logins and signups`, `tenant switch drops
  stale log replies`, `logs unavailable plugin shows notice`.
- [ ] Run `cd console && npm test -- --run`; expect FAIL for the new tests.
- [ ] Implement; localize every string.
- [ ] Rerun; then `make console`; expect PASS and a rebuilt `console/dist`.
- [ ] Commit: `feat: monitor logs, streams and Actions in the console`.

### Task 15: Seed and Deploy CLI

**Files:** modify the seed schema/apply code and `internal/deploymigration`; extend
the existing Deploy CLI round-trip fixtures; update `docs/deploy-cli.md`.

**Interfaces:** seed `log_streams` entries are create-only; secret fields read
`${ENV}` references like existing seed secrets. The Deploy CLI 9.1.0 log-stream
handler round trips the name, type, status, filters, PII and public sink fields in YAML
and directory formats; secrets are excluded as the tool excludes them. Remove
`logStreams` from `AUTH0_EXCLUDED`.

- [ ] Write `TestSeedLogStreamsCreateOnly`, `TestSeedLogStreamSecretsFromEnv`, and
  deploy fixture cases for the http and datadog types in both formats.
- [ ] Run `go test ./internal/seed ./internal/deploymigration -run LogStream -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; then `make e2e-deploy`; expect PASS.
- [ ] Commit: `feat: provision log streams`.

### Task 16: End-to-end acceptance, docs and final regression

**Files:** create `tests/e2e/{m31-logs-cli,m31-node-auth0,m31-logs.spec}.mjs`,
`tests/e2e/run-m31-logs.sh`, `docs/logs.md`; modify `Makefile` (`e2e-logs`),
`docs/management-api.md`, `docs/actions.md`, `docs/attack-protection.md`, the
roadmap Plan 31 entry, the compatibility matrix and the implementation record.

- [ ] Browser: the §9 Actions troubleshooting journey, step by step: the post-login
  Action logs and denies; Logs Live shows `f`; the detail opens the execution with
  console lines and masked secrets; the Action is fixed and redeployed; the retry shows `s`.
  CLI: `auth0 logs list --filter`, `auth0 logs tail` sees the browser's event,
  `auth0 logs streams create http` / list / update / delete. SDK: `logs.getAll`
  in page and checkpoint modes, `users.getLogs`, `stats.getDaily`,
  `stats.getActiveUsers`. A local HTTP receiver gets the stream in all three
  formats and survives a server restart. Grep every captured artifact (DB dump,
  receiver bodies, server log, console network responses) for the test passwords
  and secrets, and fail on any hit.
- [ ] Run `make e2e-logs` once to detect missing fixtures; fix through the
  owning task's code and tests; never weaken assertions.
- [ ] Final verification, sequentially where ports overlap:
  - `ZA_REQUIRE_NODE=1 go test -race -timeout=50m ./...`
  - `./scripts/test-sql.sh -timeout=30m ./internal/store/sqlstore/...`
  - `make console` and `make check-sources`
  - `make e2e-logs`, `make e2e`, `make e2e-actions`, `make e2e-actions-ii`,
    `make e2e-organizations-ii`, `make e2e-deploy`, `make e2e-email`
  - `make conformance`
  Expected: every selected suite passes. Report unavailable, skipped or timed-out
  suites as such, never as passing.
- [ ] Write `docs/logs.md` (event codes emitted and not yet emitted, retention,
  privacy layers, streams and outbound rules, Actions troubleshooting walkthrough,
  local differences). Update the roadmap and matrix. Obtain a whole-branch review
  with the repository's review skill; fix correctness/security findings and rerun
  affected checks.
- [ ] Commit: `test: verify Plan 31 logs end to end`.

## Dependency order and completion audit

Execution order: **1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16**.
Tasks 8–10 depend on 2 and 6; 11–12 on 3–6; 13 on 6; 14 on 7 and 10–13.
Tasks 8, 9 and 13 touch disjoint packages and may run in parallel if the user
chooses parallel agents; store, proto and route-registration files are never
edited concurrently.

| Spec requirement | Owning tasks |
| --- | --- |
| Evidence, codes, schemas, local rulings | 1, 16 |
| Three-layer privacy and the password requirement | 2, 6, 8, 9, 10, 16 |
| Event shape, ID, settle window, write path | 3, 4, 6 |
| Retention and tenant deletion | 3, 4, 6 |
| Plugin capability | 5 |
| Logs API and Lucene subset | 7 |
| Authentication, hosted, protection, jobs, organizations events | 8, 10 |
| Management API events | 9 |
| Actions links and console capture | 10, 14 |
| Log streams API, delivery, PII, outbound guard | 11, 12 |
| Stats | 6, 13 |
| Console | 14 |
| Seed and Deploy CLI | 15 |
| Actions troubleshooting journey and full regression | 16 |

Planning self-review: every spec section maps above; the storage, recorder and
scrubber contracts are defined once here and used by name in later tasks; each Review
Focus risk has a named test in its owning task. No implementation, migration or
product test was run while writing these documents.
