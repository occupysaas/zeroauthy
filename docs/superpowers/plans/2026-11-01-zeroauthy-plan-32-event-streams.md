# Plan 32 — Event Streams Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce Auth0-shaped CloudEvents for user, organization and
enterprise-connection changes, deliver them through Auth0's event-streams API
to webhooks and `event-stream` Actions, and serve them live through the
Events API.

**Architecture:** A store decorator in `internal/events` appends events to a
transactional outbox in the same `WithTx` as each change. A new Events
repository (memory, SQL, gRPC capability v1) holds events, streams and
failed deliveries. A delivery worker reuses Plan 31's checkpoint, lease,
settle window and guarded dialer, with per-event retries (1/2/4 s), failure
records, redelivery and auto-disable. `GET /api/v2/events` reads the same
outbox as SSE.

**Tech Stack:** Go 1.26.7, Node >=22.13, Vue/TypeScript, SQLite/PostgreSQL/MySQL,
protobuf/gRPC, pinned auth0-cli 1.37.0, node-auth0 and auth0-deploy-cli 9.1.0,
Playwright. No new Go module dependency.

**Spec:** [Event streams design](../specs/2026-11-01-zeroauthy-event-streams-design.md).
Read it before executing any task. Section numbers below (§) refer to it.

**Completion:** implemented and locally verified 2026-11-02. All fourteen tasks and final reviews are complete under the recorded rulings; observer E1–E8 remain unavailable. See [the completion record](../2026-11-01-plan-32-implementation-record.md), [post-fix results](../2026-11-02-plan-32-postfix-validation.md), and [rulings/deferred minors](../2026-11-02-plan-32-decisions.md). Original steps below are preserved as the planned contract rather than rewritten as claims that every upstream observation occurred.

## Global Constraints

- Use Go 1.26.7 and Node >=22.13; retain repository dependency pins; add no Go module.
- Follow `CLEAN_ROOM.md`. Documentation is evidence; SDK/CLI/Terraform source is only a lead.
- Every ID and query is tenant-scoped; cross-tenant references behave as missing.
- Events are written in the same transaction as the change; a rollback emits nothing (§3).
- `data.object` comes only from the catalog allowlist; password hashes, imported
  hashes, upstream tokens and webhook secrets never appear in an event, a
  delivery record, a console response or a server log line.
- IDs: stream `est_` + 22 alphanumerics, event `evt_` + 22 alphanumerics (26 characters each).
- Delivery: 4 attempts (first + retries after 1 s, 2 s, 4 s); 4xx fails at once;
  timeout 10 s; settle window 2 s; auto-disable at 500 consecutive failed events
  or 5,000 failed deliveries; re-enable is 400 while ≥ 5,000.
- Limits: `take` default 50, max 100; `events.max_streams` 10; `events.max_connections` 4;
  `events.retention` default 7 days, minimum 1 day; memory ring 10,000 events per tenant;
  SSE heartbeat 15 s, `offset-only` 30 s, `retry: 2000`, close after 5 min.
- Migration `0031_event_streams.sql` (renumber only if another migration lands first).
- Keep older gRPC plugins working; negotiate Events v1 separately; missing
  capability returns 501 `events_unavailable` on this plan's routes.
- Plan 19's database hold applies only to Plan 19, not this plan.
- Add `x-source` to API operations and regenerate with `make generate`; never
  hand-edit generated Go/protobuf/TypeScript. `console/dist` is a committed build artifact.
- Work in an isolated worktree. Record commits, reviews, commands and actual
  results in `docs/superpowers/2026-11-01-plan-32-implementation-record.md`.
- Long suites follow `AGENTS.md`: start once, log to a file, one monitor, no
  polling more often than every 15 minutes.

## Review Focus

1. A Management API call updates a user inside a transaction that later fails
   (for example a uniqueness conflict after the user write). Expect no event in
   the outbox, the stream or the SSE feed. Pinned in Task 3.
2. Two instances commit events out of sequence while one SSE client resumes
   with `Last-Event-ID` and a worker advances a checkpoint. Expect no skipped
   event and no event twice in one SSE connection. Pinned in Tasks 4, 7 and 10.
3. A webhook endpoint resolving (or rebinding) to 127.0.0.1, 169.254.169.254 or
   an RFC 1918 address. Expect `blocked_address` failures with no request sent.
   Pinned in Task 7.
4. A user whose identities hold a provider refresh token, an imported bcrypt hash
   and `app_metadata.password`. Expect the event's `data.object` to carry the
   metadata the user stored (it is the customer's own data, as on Auth0) but
   never the token or hash fields, and the server log to show neither. Pinned in Task 2.
5. A receiver that hangs or answers 500 during a burst of 1,000 signups. Expect
   signups to succeed at normal latency, the worker to keep to the attempt
   schedule, and the stream to disable after 500 consecutive failed events.
   Pinned in Tasks 3 and 7.

## File boundaries and shared interfaces

| Responsibility | Files |
| --- | --- |
| Contracts | new `internal/eventrules/{inventory.json,catalog.json,rules.go,rules_test.go}`; existing `api/management.yaml`, `docs/compat/decisions.md`, `docs/compat/matrix.md`, `docs/compat/observations/event-streams.md` |
| Models and memory | new `internal/store/events.go`, `internal/store/memory/events.go`, `pkg/storetest/events.go` |
| SQL | new `internal/store/sqlstore/events.go`; migration 0031 in the three driver directories |
| Plugin | new `internal/store/grpcstore/events.go`; existing `proto/store/v1/store.proto` |
| Event building and capture | new `internal/events/{build,context,decorator,ids,purge,config}.go`; existing `internal/app/app.go` |
| Streams API | new `internal/mgmt/event_streams.go`, `internal/mgmt/event_deliveries.go` |
| Delivery | new `internal/eventstream/{worker,webhook,action,retry}.go`; existing `internal/httpx/guarded_dialer.go`, `internal/logstream/secrets.go` patterns |
| Actions trigger | existing `internal/actionsrules/inventory.json`, `internal/actions/engine.go`, `internal/actions/jobs.go`, Node runner trigger table |
| Events API | new `internal/mgmt/events_sse.go` |
| Console | new `console/src/pages/event-streams/{StreamsList,StreamEdit,Deliveries}.vue`; existing `sections.ts`, `router.ts`, Actions editor, locales |
| Provisioning, E2E | existing seed and `internal/deploymigration`; new `tests/e2e/{m32-events-node,m32-events-cli,m32-event-streams.spec}.mjs`, `run-m32-events.sh`, Makefile target `e2e-events` |

Task 3 owns the storage contract. Add `Store.Events() Events` to every store
and transaction view, with an `UnimplementedEvents` stub returning
`ErrEventsUnavailable` until each driver lands.

```go
// internal/store/events.go. All ctx are context.Context.
type TenantEvent struct {
	TenantID, ID, Type string
	Seq                int64     // assigned by AppendEvents
	Time               time.Time // event time; CommittedAt is store-internal
	Body               []byte    // CloudEvent JSON without a0stream/a0purpose
}
type EventStream struct {
	TenantID, ID, Name, Status, DestType string
	Subscriptions                        []string
	Config                               map[string]any // public destination configuration
	SealedSecret                         []byte         // master-key wrapped password/token/header_value
	Checkpoint                           int64
	LeaseOwner                           string
	LeaseUntil                           time.Time
	ConsecutiveFailures, TotalFailures   int
	Version                              int
	CreatedAt, UpdatedAt                 time.Time
}
type DeliveryAttempt struct {
	Status       string // "failed" or "success"
	Timestamp    time.Time
	ErrorMessage string
	DurationMS   float64
}
type EventDelivery struct {
	TenantID, StreamID, EventID, EventType, Status string // Status "failed"
	Attempts                                       []DeliveryAttempt
	Queued                                         bool // redelivery requested
	EventTime, UpdatedAt                           time.Time
}
type DeliveryFilter struct {
	Statuses, EventTypes []string
	From, To             time.Time // inclusive, exclusive; zero = open
}
type DeliveryOutcome struct {
	Checkpoint                         int64 // new checkpoint, or unchanged for redeliveries
	Failed                             *EventDelivery // upsert when non-nil
	Succeeded                          []string       // event IDs whose failure records are removed
	ConsecutiveFailures, TotalFailures int
	Disable                            bool
}

type Events interface {
	AppendEvents(ctx, events []TenantEvent) error // inside the caller's tx; assigns Seq and records CommittedAt
	GetEvent(ctx, tid, id string) (*TenantEvent, error)
	EventsAfter(ctx, tid string, afterSeq int64, types []string, take int, settled time.Time) ([]TenantEvent, error)
	EventsFromTime(ctx, tid string, from time.Time, types []string, take int, settled time.Time) ([]TenantEvent, error)
	LatestEventSeq(ctx, tid string) (int64, error)
	OldestEventSeq(ctx, tid string) (int64, error) // 0 when none
	PurgeEvents(ctx, before time.Time, limit int) (int, error) // also removes their deliveries
	DeleteTenantEvents(ctx, tid string) error

	CreateEventStream(ctx, *EventStream) error // ErrConflict on duplicate name
	GetEventStream(ctx, tid, id string) (*EventStream, error)
	ListEventStreams(ctx, tid, after string, take int) ([]EventStream, string, error) // next cursor
	CountEventStreams(ctx, tid string) (int, error)
	UpdateEventStream(ctx, s *EventStream, version int) error // ErrConflict on version mismatch
	DeleteEventStream(ctx, tid, id string) error              // deletes its deliveries
	LeaseEventStream(ctx, owner string, now, until time.Time) (*EventStream, error) // enabled with new events or queued redeliveries; ErrNotFound if none due
	RecordEventDelivery(ctx, tid, id, owner string, o DeliveryOutcome) error   // ErrPrecondition if lease lost

	ListDeliveries(ctx, tid, streamID string, f DeliveryFilter, after string, take int) ([]EventDelivery, string, error)
	GetDelivery(ctx, tid, streamID, eventID string) (*EventDelivery, error)
	QueueRedelivery(ctx, tid, streamID string, eventIDs []string, f *DeliveryFilter) (int, error) // ErrPrecondition when a named event is not failed or already queued
	QueuedDeliveries(ctx, tid, streamID string, take int) ([]EventDelivery, error)
}
```

`settled` excludes events committed after it (now − 2 s). Event builder and
capture contract (Tasks 2 and 3):

```go
// internal/events
type Context struct { // becomes data.context
	ClientID, ClientName                 string
	ClientMetadata                       map[string]string
	ConnectionID, ConnectionName, Strategy string
	IP, Hostname, CustomDomain, Method, UserAgent string
}
func WithContext(ctx context.Context, c Context) context.Context
func FromRequest(r *http.Request) Context
func NewEventID() string  // evt_ + 22 alphanumerics, crypto/rand
func NewStreamID() string // est_ + 22 alphanumerics
func Build(ctx context.Context, tenant *store.Tenant, typ string, object, previous any, at time.Time) (store.TenantEvent, error)
func Wrap(st store.Store, cfg Config) store.Store // the capturing decorator
func Stamp(body []byte, streamID string, test bool) []byte // adds a0stream / a0purpose for delivery
```

For each task: write the named tests, run the focused command and observe the
stated failure, implement, rerun to PASS, review the diff, then commit only that
task's files. Run commands from the worktree root.

### Task 1: Observation, wire contracts and decisions

**Files:** create `internal/eventrules/{inventory.json,catalog.json,rules.go,rules_test.go}`,
`docs/compat/observations/event-streams.md` (written by the observer session) and
the implementation record; modify `api/management.yaml`, `docs/compat/decisions.md`
(D-0058), `docs/compat/matrix.md`.

**Interfaces:** produces `eventrules.Types() []Type` (`Type{Name string; Emitted bool;
Plan int; Allowlist []string; Strategies []string}`), `eventrules.Route(op string) Route`,
`eventrules.Destination(type string) DestSchema` (public and secret fields),
`eventrules.Limits` (the Global Constraints numbers) and `eventrules.ValidateEvent(body []byte) error`
that checks a CloudEvent against the frozen catalog schema (a reduced copy of the
published schema in `catalog.json`, used by tests and E2E).

- [ ] The maintainer runs a separate observer session for E1–E8 (§2) on the dev
  tenant and commits `docs/compat/observations/event-streams.md`. Implementers do
  not observe. Unanswered points keep the §8 local rulings and are listed as gaps.
- [ ] Write `TestEventsInventory`: every §4 route has a source URL, scopes,
  parameters with limits, body schema and errors; all 25 catalog types are present,
  `Emitted=false` rows name plan 38; connection types list exactly the catalog
  strategies; `webhook` marks `password`/`token`/`header_value` secret; `take`
  max 100 default 50; ID patterns `^est_[A-Za-z0-9]{22}$` and `^evt_[A-Za-z0-9]{22}$`.
  `TestCatalogValidates` accepts the catalog's own `user.created` example and rejects
  one with an extra top-level field.
- [ ] Run `go test ./internal/eventrules -count=1`; expect FAIL (package missing).
- [ ] Fill the inventory and catalog from the §2 sources and observations; map each
  emitted type to its store method (Task 3). Write D-0058 with the ten §8 rulings,
  the observation answers and every gap. Add the paths to `api/management.yaml`.
  Move `event-stream` out of `deferred_triggers` only in Task 8.
- [ ] Rerun; expect PASS. Run `make generate` and `go test ./api -count=1`; inspect generated diffs.
- [ ] Commit: `docs: freeze Plan 32 event streams contracts`.

### Task 2: CloudEvent builder

**Files:** create `internal/events/{build,context,ids}.go` and `build_test.go`.

**Interfaces:** produces `Context`, `WithContext`, `FromRequest`, `NewEventID`,
`NewStreamID`, `Build`, `Stamp` from the contract above. `Build` marshals `object`
and `previous` through the Management API's existing user/organization/connection
response serializers, then keeps only `eventrules.Types()[typ].Allowlist` keys
(recursively for nested allowlists such as `identities[]`). `source` is
`"urn:auth0:" + tenant canonical domain`; `a0tenant` is the tenant ID;
`time` is RFC 3339 with milliseconds in UTC; `context.tenant.id` is always set and
`context.request.geo` is `{}` when a request is present.

- [ ] Write `TestBuildUserCreatedMatchesCatalog` (validates with `eventrules.ValidateEvent`),
  `TestBuildUserExcludesSecrets` (identity `access_token`/`refresh_token`, password hash
  and imported hash absent; `app_metadata.password` kept as user data — Review Focus 4),
  `TestBuildUpdatedHasPrevious`, `TestBuildDeletedHasDeletedAt`,
  `TestBuildOrgMemberRoleShape`, `TestBuildConnectionOnlyCatalogStrategies`
  (`oidc` builds; `auth0` and `google-oauth2` return `ErrNotEmitted`),
  `TestBuildContextFromRequest`, `TestIDFormats` (10,000 IDs match the patterns, unique),
  `TestStamp` (adds `a0stream`; test adds `a0purpose:"test"`).
- [ ] Run `go test ./internal/events -run 'Build|IDFormats|Stamp' -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: build Auth0 CloudEvents`.

### Task 3: Events storage contract, memory store and capturing decorator

**Files:** create `internal/store/events.go`, `internal/store/memory/events.go`,
`pkg/storetest/events.go`, `internal/events/{decorator,config}.go` and `decorator_test.go`;
modify `internal/store/store.go`, memory `{memory,tx,clone}.go`, every driver's stub,
`pkg/storetest/storetest.go`, `internal/config` (`events.retention`, `events.max_streams`,
`events.max_connections`, `events.allow_private_networks`, `events.allow_insecure_http`),
`internal/app/app.go` (wrap the store with `events.Wrap` before handlers are built).

**Interfaces:** produces the storage contract and `events.Wrap`. The decorator embeds
`store.Store` and overrides `Users()`, `Organizations()`, `Connections()` and `WithTx`.
Intercepted methods per §3: Users `Create`, `Update`, `Delete`, `SetPasswordHash`,
`SetPasswordHashIfEmpty` and identity link/unlink methods (not `RecordLogin`,
`UpgradeImportedHash`, `BumpVersion`); organization CRUD, member add/remove, member
role assign/remove and enabled-connection add/update/remove; connection
create/update/delete filtered by strategy. Updates read the prior row with
`GetForUpdate` in the same tx for `previous_object`. Events are buffered per
transaction, collapsed to one `user.updated` per user (final state), and appended by
`AppendEvents` just before commit. Outside a tx the decorator opens one.

- [ ] Write conformance cases `EventsAppendOrdering`, `EventsTenantIsolation`,
  `EventsSettled` (an event committed after `settled` is withheld, then returned once,
  never twice), `EventsRollback` (append in a tx that returns an error leaves nothing),
  `EventStreamCRUDAndNameConflict`, `EventStreamLease` (one owner; expired lease taken over;
  stale owner gets ErrPrecondition), `EventDeliveriesFilterPage`, `QueueRedeliveryRules`,
  `EventsPurge`, `EventsDeleteTenant`. Write decorator tests `TestDecoratorEmitsPerPath`
  (Create/Update/Delete user, org member add, oidc connection create),
  `TestDecoratorRollbackEmitsNothing` (Review Focus 1), `TestDecoratorCollapsesUpdates`,
  `TestDecoratorSkipsRecordLogin`, `TestDecoratorSkipsNonCatalogStrategies`,
  `TestDecoratorAddsLittleLatency` (1,000 user creates with no stream configured
  stay within 10% of the undecorated store — Review Focus 5).
- [ ] Run `go test ./internal/store/memory ./internal/events -run 'Events|EventStream|EventDeliver|QueueRedelivery|Decorator' -count=1`; expect FAIL.
- [ ] Implement memory with a per-tenant ring of 10,000 events and deep copies at the boundary.
- [ ] Rerun, and `go test ./internal/... -run '^$'`; expect PASS/compile.
- [ ] Commit: `feat: capture tenant events in the business transaction`.

### Task 4: SQL migration and SQL store

**Files:** create `internal/store/sqlstore/events.go`, `events_test.go`,
`migrations/{sqlite,postgres,mysql}/0031_event_streams.sql`; modify tenant-deletion paths.

**Interfaces:** implements Task 3. Tables `tenant_events` (tenant_id, seq identity,
event_id, type, time, committed_at, body), `event_streams` (columns of `EventStream`,
config JSON, sealed secret), `event_deliveries` (tenant_id, stream_id, event_id, type,
status, attempts JSON, queued, event_time, updated_at; primary key stream + event).
Indexes: (tenant, seq), (tenant, type, seq), (tenant, time), deliveries (tenant, stream,
event_time), (queued, stream).

- [ ] Write `TestEventsConcurrentWritersSettled` (two connections append while a reader
  loops `EventsAfter` with an injected clock; union equals all events, no duplicates —
  Review Focus 2), `TestEventsMigrationFrom30`, `TestEventsAppendInBusinessTx` (a user
  insert and its event commit or roll back together on each driver).
- [ ] Run `go test ./internal/store/sqlstore -run 'Events' -count=1`; expect FAIL.
- [ ] Implement parameterized queries; lease with conditional UPDATE on
  `lease_until < now OR lease_owner = owner`; purge in batches per driver.
- [ ] Run `./scripts/test-sql.sh -run 'Events' -count=1 ./internal/store/sqlstore/...`;
  expect PASS on SQLite, PostgreSQL and MySQL with no skipped driver. Use free ports;
  record each driver's result.
- [ ] Commit: `feat: persist events, streams and deliveries in SQL`.

### Task 5: Events v1 plugin capability

**Files:** create `internal/store/grpcstore/events.go` and test; modify
`proto/store/v1/store.proto`, grpcstore client/server/transaction wiring; `make generate`.

**Interfaces:** `store.EventsSupporter{CheckEventsSupport(ctx) error; EventsSupported() bool}`,
mirroring `LogsSupporter`. All Task 3 methods are RPCs; `AppendEvents` joins the remote
transaction. Without the capability the decorator does not capture.

- [ ] Write `TestEventsCapabilities` (pre-Events plugin keeps every feature and returns
  `ErrEventsUnavailable`; Events v1 round trips; transient failure then recovery) and
  `TestEventsRemoteTxRollback`.
- [ ] Run `go test ./internal/store/grpcstore -run Events -count=1`; expect FAIL.
- [ ] Add additive proto fields and RPCs; unknown-method errors are definitive, transport errors retryable.
- [ ] `make generate`, rerun focused tests and grpcstore conformance; expect PASS.
- [ ] Commit: `feat: add Events storage plugin capability`.

### Task 6: Event streams Management API

**Files:** create `internal/mgmt/event_streams.go` and test; modify route registration.

**Interfaces:** handlers `ListEventStreams`, `CreateEventStream`, `GetEventStream`,
`UpdateEventStream`, `DeleteEventStream` with Task 1 scopes and bodies. Validation from
`eventrules.Destination`; secrets sealed with the existing key wrapper (as
`internal/logstream/secrets.go`), never returned, kept when omitted, required when the
method changes. `action_id` must name a tenant Action supporting `event-stream`.
`eventbridge` is forced `disabled`, `aws_partner_event_source` set per Task 1, enabling is 400.
PATCH never changes the destination type. Enabling with `TotalFailures >= 5000` is 400;
enabling otherwise resets `ConsecutiveFailures` and sets `Checkpoint` to `LatestEventSeq`.
Create sets `Checkpoint` to `LatestEventSeq`. Stream count above `events.max_streams` or a
duplicate name is 409. Routes return 501 `events_unavailable` without the capability.

- [ ] Write `TestEventStreamCRUD` (each destination; secrets never in responses;
  PATCH keeps omitted secret; method change without secret 400; unknown field 400;
  non-https endpoint 400; unknown event type 400; `take` 101 400; `from`/`next` paging),
  `TestEventStreamActionMustBeEventStreamTrigger`, `TestEventBridgeDisabled`,
  `TestEventStreamLimitsAndNames` (409s), `TestEventStreamReenableRules`,
  `TestEventStreamCrossTenant`, `TestEventStreamSecretNotInLogs` (Plan 31's `sapi` event and
  the server log show the marker), `TestEventStreamsUnavailable` (501).
- [ ] Run `go test ./internal/mgmt -run 'EventStream|EventBridge' -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: manage event streams`.

### Task 7: Delivery worker and webhook destination

**Files:** create `internal/eventstream/{worker,webhook,retry}.go` and tests; wire the
worker and `events/purge.go` (hourly, leader/lease helper) in `internal/app/app.go`.

**Interfaces:** `eventstream.NewWorker(st store.Store, keys keys.Wrapper, cfg events.Config,
client *http.Client, runner ActionRunner, log *slog.Logger)` with `Run(ctx)` and
`Deliver(ctx, s *store.EventStream, body []byte) []store.DeliveryAttempt` (used by Task 9's
test endpoint). Loop: `LeaseEventStream(owner, now, now+60s)`; first `QueuedDeliveries`,
then `EventsAfter(checkpoint, subscriptions, 100, now−2s)`; for each event `Stamp`, then
`Deliver` with the schedule `[0, 1s, 2s, 4s]`, stopping on 2xx or 4xx; then
`RecordEventDelivery`. A failure increments both counters and upserts a failed record;
a success resets `ConsecutiveFailures` and removes any failure record for that event;
`Disable` is set at 500 consecutive or 5,000 total. `ActionRunner` is
`interface{ RunEventStream(ctx, tenantID, actionID string, message []byte) error }`
(Task 8). The HTTP client uses `httpx.GuardedDialer(cfg.AllowPrivateNetworks)` and a 10 s
timeout. Error messages: `timeout`, `connection_error`, `blocked_address`, `tls`,
`http_4xx: <code>`, `http_5xx: <code>`, `action_error: <masked message>`.

- [ ] Write `TestWebhookAuthorization` (basic, bearer, custom header; `Content-Type:
  application/json`; body is the stamped CloudEvent), `TestRetrySchedule` (500 → four
  attempts at 0/1/2/4 s under an injected clock; 404 → one attempt; timeout retried),
  `TestFailureRecordAndCounters`, `TestAutoDisable500Consecutive`,
  `TestAutoDisable5000Total`, `TestSubscriptionFilter`, `TestRestartRedelivers` (kill after
  send before record; the event is sent again, never lost), `TestLeaseRace`,
  `TestBlockedAddresses` (127.0.0.1, ::1, 10.0.0.1, 169.254.169.254, 100.64.0.1 and a
  rebinding resolver; nothing reaches the listener — Review Focus 3),
  `TestDisabledStreamSkipsNewEvents`, `TestSlowReceiverDoesNotBlockSignups`
  (Review Focus 5), `TestPurgeRetention` (7 d default, 1 d minimum enforced at config load).
- [ ] Run `go test ./internal/eventstream ./internal/events -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; then `go test -race ./internal/eventstream -count=3`; expect PASS.
- [ ] Commit: `feat: deliver event streams to webhooks`.

### Task 8: `event-stream` Action trigger and action destination

**Files:** modify `internal/actionsrules/inventory.json` (move `event-stream` from
`deferred_triggers` to supported triggers with the Task 1 version), `internal/actions/engine.go`,
`internal/actions/jobs.go`, the Node runner's trigger table and handler dispatch; create
`internal/eventstream/action.go` and tests.

**Interfaces:** implements `ActionRunner.RunEventStream`: enqueue a Plan 28 durable job
for trigger `event-stream` with `event = {message, secrets}` and wait for its result up to
the 10 s delivery timeout (a timeout is a failed attempt; the job is cancelled). Handler
`exports.onExecuteEventStream(event, api)`; `api.cache` as for other triggers; no other
`api` members unless Task 1 found them documented. A thrown error is `action_error`.
Executions are recorded so Plan 31's Actions logs show them.

- [ ] Write `TestEventStreamTriggerSupported` (Management API accepts an Action with
  supported trigger `event-stream`), `TestActionDestinationSuccess`,
  `TestActionDestinationThrowRetries` (four attempts, failed record with masked message),
  `TestActionSecretsMasked`, `TestActionExecutionLogged`.
- [ ] Run `go test ./internal/actions ./internal/actionsrules ./internal/eventstream -run 'EventStream|ActionDestination|ActionSecrets|ActionExecution' -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; then `ZA_REQUIRE_NODE=1 go test ./internal/actions -count=1`; expect PASS.
- [ ] Commit: `feat: run event-stream Actions`.

### Task 9: Test events, deliveries and redelivery API

**Files:** create `internal/mgmt/event_deliveries.go` and test; modify route registration.

**Interfaces:** handlers `TestEventStream` (build an event of `event_type` with
`a0purpose:"test"` and the given or catalog example `data`; call `Worker.Deliver`
synchronously; return 202 with `{id, event_stream_id, status, event_type, attempts, event}`;
nothing stored; disabled stream follows Task 1, default 400), `ListDeliveries` (filters
and paging per §5; dates RFC 3339 without sub-second precision, else 400),
`GetDelivery`, `Redeliver` (body filters echoed, 202; 409 when nothing failed matches or a
match is already queued) and `RedeliverOne` (202; 404 unknown; 409 not failed or queued).
Scopes as in Task 1, including `read:event_streams` **or** `read:event_deliveries` on the list.

- [ ] Write `TestSendTestEvent`, `TestDeliveriesFiltersAndPaging`,
  `TestDeliveryDatePrecision`, `TestRedeliverOneAndBatch` (succeeds after the receiver is
  fixed; records removed; works while disabled), `TestRedeliverConflicts`,
  `TestDeliveriesScopes`, `TestDeliveriesCrossTenant`.
- [ ] Run `go test ./internal/mgmt -run 'SendTestEvent|Deliver|Redeliver' -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: test, inspect and redeliver event stream deliveries`.

### Task 10: Events API (SSE)

**Files:** create `internal/mgmt/events_sse.go` and test; modify route registration to
skip Plan 31's response-capturing middleware for this route.

**Interfaces:** `GET /api/v2/events` with scope `read:events`. Offset =
base64url of the decimal seq; `Last-Event-ID` beats `from`; `from` with
`from_timestamp` is 400; unknown `event_type` 400; malformed offset 400; offset below
`OldestEventSeq − 1` (expired) 410. Starts at `LatestEventSeq` when no position is
given. Polls `EventsAfter(..., settled=now−2s)` every 1 s; writes `:connected`,
`retry: 2000`, events as `event:`/`id:`/`data:{"offset","event"}` without `a0stream`,
`: heartbeat` every 15 s, `offset-only` every 30 s, closes after 5 min, flushes each
message, and lifts the write deadline with `http.ResponseController`. A per-tenant
semaphore of `events.max_connections` answers 403 with Auth0's message when full.

- [ ] Write `TestSSEStreamsLive`, `TestSSEResumeLastEventID` (header beats `from`; no gap,
  no duplicate across a reconnect while two writers commit out of order — Review Focus 2),
  `TestSSEFromTimestamp`, `TestSSEEventTypeFilter`, `TestSSEBadParams` (400s),
  `TestSSEExpiredCursor` (410), `TestSSEConnectionLimit` (403), `TestSSEHeartbeatAndCycle`
  (injected clock), `TestSSEScope`.
- [ ] Run `go test ./internal/mgmt -run 'SSE' -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; then `go test -race ./internal/mgmt -run SSE -count=3`; expect PASS.
- [ ] Commit: `feat: stream tenant events over SSE`.

### Task 11: Request context at the HTTP layers

**Files:** modify the Management API base middleware, `internal/login`, `internal/hostedlogin`,
`internal/oauth`, `internal/dbconn`, `internal/orglogin`, `internal/federation`,
`internal/jobs/importer.go`, `internal/seed` to call `events.WithContext` (request, client and
connection known at that point); add `context_test.go` beside the Management middleware.

**Interfaces:** consumes `events.WithContext`/`FromRequest`. Jobs and seed set only the tenant.

- [ ] Write `TestSignupEventContext` (`context.client`, `context.connection`, `context.request`
  set), `TestManagementEventContext` (client is the calling M2M app), `TestImportEventContext`
  (tenant only), `TestInvitationAcceptanceEmitsMemberAdded`, `TestSocialFirstLoginEmitsUserCreated`.
- [ ] Run `go test ./internal/mgmt ./internal/login ./internal/orglogin ./internal/federation ./internal/jobs -run 'EventContext|EmitsMemberAdded|EmitsUserCreated' -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; then `go test ./internal/... -count=1 -short`; expect PASS.
- [ ] Commit: `feat: attach request context to tenant events`.

### Task 12: Console — Event streams and the trigger

**Files:** create `console/src/pages/event-streams/{StreamsList,StreamEdit,Deliveries}.vue` and
tests; modify `console/src/layout/sections.ts` (add `event-streams` under
`navGroup.monitoring`, live), `router.ts`, the Actions editor (offer `event-stream` with the
handler template), locales; rebuild `console/dist`.

**Interfaces:** generated Management API types for the §4 routes. Requests capture the tenant
key; stale responses are ignored.

- [ ] Write tests: `lists streams with status and failure count`, `webhook secrets are
  write-only`, `action picker shows only event-stream actions`, `eventbridge form explains
  not delivered`, `send test event shows attempts`, `deliveries filter and redeliver one and
  all`, `re-enable error shown above threshold`, `actions editor offers event-stream trigger`,
  `tenant switch drops stale replies`, `events unavailable plugin shows notice`.
- [ ] Run `cd console && npm test -- --run`; expect FAIL for the new tests.
- [ ] Implement; localize every string.
- [ ] Rerun; then `make console`; expect PASS and a rebuilt `console/dist`.
- [ ] Commit: `feat: manage event streams in the console`.

### Task 13: Seed and Deploy CLI

**Files:** modify the seed schema/apply code and `internal/deploymigration`; extend the
Deploy CLI round-trip fixtures and `tests/e2e/m20-deploy-cli.mjs` exclusions; update
`docs/deploy-cli.md`.

**Interfaces:** seed `event_streams` entries are create-only; secret fields read `${ENV}`
references. The Deploy CLI 9.1.0 `eventStreams` handler round trips name, subscriptions,
destination and status in YAML and directory formats; secrets excluded as the tool does.
Remove `eventStreams` from `AUTH0_EXCLUDED`.

- [ ] Write `TestSeedEventStreamsCreateOnly`, `TestSeedEventStreamSecretsFromEnv`, and deploy
  fixtures for webhook and action streams in both formats.
- [ ] Run `go test ./internal/seed ./internal/deploymigration -run EventStream -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; then `make e2e-deploy`; expect PASS.
- [ ] Commit: `feat: provision event streams`.

### Task 14: End-to-end acceptance, docs and final regression

**Files:** create `tests/e2e/{m32-events-node,m32-events-cli,m32-event-streams.spec}.mjs`,
`tests/e2e/run-m32-events.sh`, `docs/event-streams.md`; modify `Makefile` (`e2e-events`),
`docs/management-api.md`, `docs/actions.md`, `docs/logs.md`, the roadmap Plan 32 entry, the
compatibility matrix and the implementation record.

- [ ] Browser: the §9 sync journey — signup, Management API metadata update and delete reach
  a local HTTPS receiver with bearer auth; every body passes `eventrules.ValidateEvent`. The
  console creates a stream, sends a test event, shows failures from a 500 receiver and
  redelivers them after the fix. An `event-stream` Action receives events, throws, is fixed,
  and redelivery succeeds; its executions show in Actions logs.
- [ ] SDK/CLI: node-auth0 `eventStreams` create/list/get/update/delete/test/deliveries/redeliver;
  the pinned auth0-cli event commands if 1.37.0 has them (else `auth0 api`); an SSE client
  resumes with `Last-Event-ID`. Grep every captured artifact (DB dump, receiver bodies,
  server log, console responses) for the test passwords, hashes, tokens and webhook secrets;
  fail on any hit.
- [ ] Run `make e2e-events` once to detect missing fixtures; fix through the owning task's code
  and tests; never weaken assertions.
- [ ] Final verification, sequentially where ports overlap, per `AGENTS.md`:
  - `ZA_REQUIRE_NODE=1 go test -race -timeout=50m ./...`
  - `./scripts/test-sql.sh -timeout=30m ./internal/store/sqlstore/...`
  - `make console` and `make check-sources`
  - `make e2e-events`, `make e2e`, `make e2e-logs`, `make e2e-actions`, `make e2e-actions-ii`,
    `make e2e-organizations-ii`, `make e2e-deploy`
  - `make conformance`
  Expected: every selected suite passes. Report unavailable, skipped or timed-out suites as
  such, never as passing.
- [ ] Write `docs/event-streams.md` (types emitted and not yet, payload and privacy, delivery,
  retries and auto-disable, Actions destination, Events API, EventBridge limitation, local
  differences). Update the roadmap and matrix. Obtain a whole-branch review with the
  repository's review skill; fix correctness/security findings and rerun affected checks.
- [ ] Commit: `test: verify Plan 32 event streams end to end`.

## Dependency order and completion audit

Execution order: **1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14**.
Task 3 depends on 2; 4–5 on 3; 6 on 3; 7 on 3 and 6; 8 on 7; 9 on 7; 10 on 3; 11 on 3;
12 on 6, 8 and 9; 13 on 6. Tasks 10 and 11 touch disjoint files and may run in parallel
with 8–9 if the user chooses parallel agents; store, proto and route-registration files are
never edited concurrently.

| Spec requirement | Owning tasks |
| --- | --- |
| Evidence, observations, catalog, local rulings | 1, 14 |
| Event types, shape, allowlist privacy | 1, 2 |
| Transactional capture, collapse, retention | 3, 4, 5, 7 |
| Plugin capability | 5 |
| Streams API, secrets, limits, EventBridge | 6 |
| Webhook delivery, retries, failures, auto-disable, outbound guard | 7 |
| `event-stream` Action trigger and destination | 8 |
| Test, deliveries, redelivery | 9 |
| Events API (SSE) | 10 |
| Request context | 2, 11 |
| Console | 12 |
| Seed and Deploy CLI | 13 |
| Sync journey and full regression | 14 |

Planning self-review: every spec section maps above; the storage and builder contracts are
defined once here and used by name in later tasks; each Review Focus risk has a named test in
its owning task. No implementation, migration or product test was run while writing these
documents.
