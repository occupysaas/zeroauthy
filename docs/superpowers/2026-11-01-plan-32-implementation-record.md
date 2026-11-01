# Plan 32 implementation record

Plan: `docs/superpowers/plans/2026-11-01-zeroauthy-plan-32-event-streams.md`.
Base: `17d749c`. Branch: `implement-plan-32`.
Worktree: `/mnt/nvme2/code/zeroauthy-plan32`.

Implementation in progress. No completed-plan or full-regression claim.

## Evidence and decisions

- Public catalog 0.13.6 and Management OpenAPI fetched on 2026-11-01 from the spec's URLs. Frozen catalog contains structural validation constraints and examples, without documentation prose. No SDK implementation source used.
- E1–E8: no firewalled observer record was present. No Auth0 tenant observation performed by the implementer. Spec §8 defaults apply; all eight gaps remain explicit in the inventory and D-0058.
- Catalog's organization-name negative lookahead is expressed as an equivalent `pattern` plus `not` because Go's regex engine cannot parse lookahead. Pattern acceptance is unchanged.
- Catalog 0.13.6 omits `a0purpose`; the frozen validator permits the documented `"test"` extension for the test endpoint.

## Task evidence

Task 1: initial `GOTOOLCHAIN=go1.26.7 go test ./internal/eventrules -count=1` failed on missing contract functions. After implementation it passed (0.118s). Controller generation and focused API/eventrules checks passed after fixing missing prefixed schema references and Go-incompatible lookahead (exit 0, api 0.808s/eventrules 0.153s).

### Task 1 refinement and rulings

- Kept the full reduced catalog constraints and original examples; removed the
  duplicated API CloudEvent model tree in favor of a raw event object and SSE
  string boundary. The API schemas still validate stream configuration, filters
  and credentials. Existing API YAML outside these additive paths/schemas is
  byte-identical to HEAD after removing Task 1 additions.
- **Ruling:** anchor stream/event IDs to the spec's exact length and close event
  object/previous-object roots to their catalog fields. Metadata remains open.
  Recursive inventory paths enumerate identity/profileData fields individually;
  app_metadata/user_metadata remain customer-controlled arbitrary objects.
- **Ruling:** separate create/PATCH credential schemas from response schemas;
  password/token/header_value are write-only, required on create and omitted-secret
  preserving on PATCH. Runtime method-change validation belongs to Task 6.
- **Ruling:** canonical fetched OpenAPI URLs provide route provenance; delivery
  list scopes are alternatives, not a requirement for both scopes.
- Published deferred group examples fail their own group-ID pattern. Preserved
  their raw examples and strict schema, validated all 16 emitted examples, and
  recorded the upstream example mismatch without claiming deferred examples pass.
- E1–E8 remain open. No observer record created and no tenant observed.

Additional TDD evidence:
- Credential RED: `GOTOOLCHAIN=go1.26.7 go test ./api -run TestEventStreamCredentialContracts -count=1`
  failed on six absent create/PATCH credential schemas (test exit 1; shell wrapper
  printed the log and returned 0). Log: `/tmp/plan32-secret-red.log`.
- Credential GREEN: same command passed, exit 0 (0.106s); log
  `/tmp/plan32-secret-green.log`.
- Validator RED: `GOTOOLCHAIN=go1.26.7 go test ./internal/eventrules -count=1`
  failed, exit 1, on unanchored IDs and accepted password_hash. Exploring all
  examples also exposed the deferred group example mismatch. Log:
  `/tmp/plan32-validation-red.log`.
- Validator GREEN: same command passed, exit 0 (0.122s), with all 16 emitted
  examples plus negative IDs, version, missing-data, unknown-type, object secret,
  identity token and malformed-JSON cases. Log: `/tmp/plan32-validation-green.log`.
- Final generation: `GOTOOLCHAIN=go1.26.7 make generate`, exit 0;
  `/tmp/plan32-generate-final.log`.
- Final focused tests: `GOTOOLCHAIN=go1.26.7 go test ./api ./internal/eventrules -count=1`,
  exit 0 (api 0.477s, eventrules 0.148s); `/tmp/plan32-final-tests.log`.
- Earlier mgmt/app compile-only check passed, exit 0, with no tests run;
  `/tmp/plan32-compile.log`. No database or broad regression suite run for Task 1.

- Final generated-consumer compile check:
  `GOTOOLCHAIN=go1.26.7 go test ./internal/server ./internal/orgrules ./internal/mgmt ./internal/app -run '^$'`,
  exit 0; no tests selected (0.021s/0.005s/cached/cached), log
  `/tmp/plan32-compile-final.log`. Existing server adapter already embeds
  `mgmtapi.Unimplemented`, so Task 1 routes remain 501 until later handler tasks;
  no temporary runtime stub or unrelated handler edit was required.
- CLI discovery (offline): `AUTH0_CLI_ANALYTICS=false auth0 --version` reports
  1.37.0 (`a6239f907a81238e081a4abb1882c028558b2655`), exit 0;
  `auth0 --help`, exit 0, lists event-streams CRUD, trigger, deliveries,
  redeliver/redeliver-many and subscribe. Logs `/tmp/plan32-cli-version.log` and
  `/tmp/plan32-cli-help.log`. The preliminary `auth0 version` syntax failed
  (usage error); `--version` is the supported spelling. No tenant API call made.
- `git diff --check` passed, exit 0. Full suites, database tests, console/E2E and
  runtime acceptance are not run or claimed by Task 1.
- Task 1 commit: `docs: freeze Plan 32 event streams contracts` (the commit
  containing this entry). Controller review follows this implementation report.

### Task 1 important review fixes (base 10705b3)

- Closed all 30 user identity profileData schema branches across object and
  previous_object. **Ruling:** this is deliberately stricter than the published
  open schema, following the spec's recursive privacy allowlist. Cost: arbitrary
  undocumented profileData values are rejected. Customer app_metadata and
  user_metadata stay open, including arbitrary customer keys resembling secrets.
- Required subscription.event_type and reused the 25-type catalog enum. Tests
  exercise valid, absent and unknown types through actual create/PATCH schemas.
- Minor aws_partner_event_source readOnly annotation intentionally deferred by
  controller instruction; not included in this fix.
- RED: focused nested-privacy/subscription command failed, exit 1. All 60 nested
  secret combinations were accepted and four malformed create/PATCH subscription
  cases were accepted. `/tmp/plan32-review-red.log`.
- GREEN: same focused command passed, exit 0 (eventrules 0.139s/API 0.116s).
  `/tmp/plan32-review-green.log`. All five identity provider branches, both object
  roots and all three user types are covered; metadata openness is checked before
  injecting each prohibited nested field.
- `GOTOOLCHAIN=go1.26.7 make generate` passed, exit 0;
  `/tmp/plan32-review-generate.log`. Generated subscription.EventType is now a
  required catalog enum rather than an optional arbitrary string.
- Final `GOTOOLCHAIN=go1.26.7 go test ./api ./internal/eventrules -count=1`
  passed, exit 0 (API 0.777s/eventrules 0.178s), `/tmp/plan32-review-tests.log`.
- Generated-consumer compile command:
  `GOTOOLCHAIN=go1.26.7 go test ./internal/server ./internal/orgrules ./internal/mgmt ./internal/app -run '^$'`
  passed, exit 0 (server 0.042s, others cached; no tests selected),
  `/tmp/plan32-review-compile.log`.
- `git diff --check` passed, exit 0. No broad suites or database tests run.
- Fix commit: `fix: tighten event privacy and subscription contracts` (the commit
  containing this entry). No runtime implementation or minor review fix added.

## Task 2 — CloudEvent builder

- Added events Build, request Context, cryptographic event/stream IDs and Stamp.
  All emitted catalog examples validate after building; nested dotted allowlists
  remove identity/ProfileData tokens and hashes, while customer metadata remains
  open (including app_metadata.password). Source uses CanonicalHost, independently
  of request/custom domain, and times use UTC milliseconds.
- Extracted the existing user, identity, organization and connection response
  functions into internal/resourceview; existing Management API wrappers delegate
  there. Connection configuration sealing stays in the handler, and event build
  never decrypts sealed configuration. This avoids an events/mgmt import cycle
  for Task 8 without duplicating serializer logic.
- Prerequisite ruling: added only store.TenantEvent from Task 3's frozen contract;
  Task 3 extends internal/store/events.go. No Events interface was introduced.
- Request ruling: FromRequest uses httpx.ClientIP(r, false), which honors an
  authenticated boundary's recorded client IP but ignores untrusted forwarding
  headers. Resolved request host identifies a custom domain; source remains the
  tenant canonical host. Missing request/client/connection context is omitted.
- RED: `go test ./internal/events -run 'Build|IDFormats|Stamp' -count=1`
  failed with exit 1 before implementation: undefined Build, ErrNotEmitted,
  FromRequest, WithContext, NewEventID, NewStreamID and Stamp. Nine named task
  tests were written before production code. Log: /tmp/plan32-task2-red.log.
  Initial shell default was go1.27.3-X:nodwarf5; final verification uses required
  Go 1.26.7 explicitly.
- GREEN: `GOTOOLCHAIN=go1.26.7 go test ./internal/events -run 'Build|IDFormats|Stamp' -count=1`
  passed, exit 0, 0.273s. Log: /tmp/plan32-task2-green-1.26.log. Additional
  coverage exercises every emitted catalog example, invalid input, organization
  serialization, resolved custom domains and normal/invalid Stamp behavior.
- Compile: `GOTOOLCHAIN=go1.26.7 go test ./internal/mgmt ./internal/app -run '^$' -count=1`
  passed, exit 0, no tests selected. Log: /tmp/plan32-task2-compile.log.
- Self-review: checked serializer extraction equivalence and recursive projection;
  fixed import grouping and stored model time to UTC. `git diff --check` passed.
  No database, integration, broad or full suites run; these remain deferred to
  Task 14. No upstream observations and no dependencies added.
- Commit: `feat: build Auth0 CloudEvents` (this entry's containing commit).

### Task 2 Important review fix — require prior update snapshot

- Review verified: Build could produce *.updated events without previous_object.
  Build now always serializes prior input for every emitted updated event and
  rejects nil, typed-nil, empty objects and objects with no catalog fields before
  returning an event. Existing valid full previous snapshots remain unchanged.
- RED with `export GOTOOLCHAIN=go1.26.7`:
  `go test ./internal/events -run 'TestBuildUpdatedRequiresPrevious' -count=1`
  failed, exit 1, 0.126s. All four emitted updated types accepted absent, empty
  and no-catalog-field prior objects. Typed-nil variants already rejected and
  remain pinned. Log: /tmp/plan32-task2-fix-red.log.
- GREEN with the same exported toolchain:
  `go test ./internal/events -run 'Build|IDFormats|Stamp' -count=1`
  passed, exit 0, 0.274s. Log: /tmp/plan32-task2-fix-green.log.
- Consumer compilation with the same exported toolchain:
  `go test ./internal/mgmt ./internal/app -run '^$' -count=1` passed, exit 0;
  mgmt 0.021s/app 0.019s, no tests selected.
  Log: /tmp/plan32-task2-fix-compile.log.
- `git diff --check` passed, exit 0. Self-reviewed only the Important fix and
  covering regression. Misplaced test import Minor is deferred by instruction.
  No database or broad suites run. Fix base: 98eac76.
- Commit: `fix: require prior snapshots for updated events` (containing entry).

## Task 3 — Events repository, memory store and transactional capture

Base `686bc80`; branch `implement-plan-32`; required toolchain verified as
`go1.26.7 linux/amd64`. Added the frozen Events models/repository/public aliases,
fail-closed SQL/gRPC placeholders, memory outbox/streams/deliveries, configuration
and application wrapping before seed/runtime handlers. SQL persistence and Events
v1 RPC negotiation remain Tasks 4/5 and are not claimed implemented here.

Capture opens or joins the business transaction, uses Users.GetForUpdate for
prior user snapshots, preserves the original full prior snapshot across repeated
updates, reads final state before AppendEvents, and appends just before commit.
Organization/connection prior reads use their existing transaction-aware Get
methods (SQL already obtains its policy lock there). All store capability probes
and organization membership write-result reporting remain available. Missing
Events capability bypasses capture; transient capability errors prevent an
unrecorded mutation. RecordLogin, BumpVersion and imported-hash upgrades bypass
capture. Federation identity writes and password/CAS writes are intercepted.

Memory provides a per-tenant 10,000-event ring, deep-copy boundaries, monotonic
sequence/commit visibility, outer-commit timestamps, rollback snapshots and
bounded purge. Eviction/purge remove dependent deliveries. Stream CRUD/name
uniqueness/version checks, leases, atomic outcomes/counters, filtering/paging and
redelivery are tenant-scoped. Tenant deletion purges all state and discards any
same-transaction buffered events rather than resurrecting the outbox.

### Task 3 rulings and limitations

- **Latency ruling (controller):** the plan's relative 10% target was **not met**.
  Initial evidence: 1,000 standalone minimal memory user creates took 1.430932ms
  undecorated versus 496.367975ms captured (346.88x). Required transactions use the
  existing deep-snapshot memory implementation, plus JSON/outbox work; the demo
  store's microsecond baseline cannot accommodate that inside 10%. Replace that
  target with recorded baseline/capture timings and a five-second context/deadline
  regression guard for 1,000 normal creates. This is not a runtime SLO. Final
  focused evidence: 282.625µs baseline, 475.39915ms captured, ratio 1682.08x.
  No destination or worker call occurs in capture; Task 7 must separately prove a
  hanging receiver cannot block signups. Cost: memory overhead can be noticeable
  at high volume; no broad memory transaction optimization was attempted.
- **Race allowance (controller):** focused race evidence was 3.344647ms baseline,
  4.249374588s captured, ratio 1270.50x, close to the normal five-second guard.
  Test-only `race`/`!race` build-tag constants allow 30s under instrumentation and
  retain 5s normally. The test and all assertions still run; this is not a skipped
  test or production switch. Full-suite CPU contention must not turn race
  instrumentation into a claimed runtime latency SLO.
- **Cascade ruling (controller):** capture observable changes made internally by
  drivers. A connection deletion, including an auth0/social connection, captures
  owned-user deletion, surviving linked-identity changes and affected membership
  and enabled-connection removals. User/organization deletion captures active
  member-role and membership removals; organization deletion captures its enabled
  connections too. Reads occur inside the same transaction, with bounded paging;
  ordinary create/update paths do not snapshot the whole tenant. Cost: additional
  documented-type cascade events may differ from future upstream observations.
- **Dormant-role limitation (controller):** RemoveMembers deliberately keeps role
  assignments. It emits member.deleted but no false role.deleted. Later user/org
  deletion cannot enumerate retained roles of nonmembers: MemberRoles rejects
  nonmembers and RoleMembers exposes only current members. No separate role.deleted
  event is invented for those inaccessible dormant rows. Consumers retaining
  dormant roles must reconcile after member deletion; a future result API or
  observer evidence may refine this. Active observable role removals are captured.

### Task 3 verification evidence

All commands below exported `GOTOOLCHAIN=go1.26.7`. Tests use memory/mocks only.

- Initial RED:
  `go test ./internal/store/memory ./internal/events -run 'Events|EventStream|EventDeliver|QueueRedelivery|Decorator' -count=1`
  failed, actual test exit 1, on missing Store.Events/Wrap/Config. The initial
  shell wrapper printed the log and returned 0; the recorded test result is FAIL.
  `/tmp/plan32-task3-red.log`. First implementation run also failed (test exit 1;
  wrapper 0) on an invalid org fixture ID and the original 10% latency assertion;
  the fixture was corrected and the latency ruling above was obtained.
  `/tmp/plan32-task3-first.log`.
- Configuration RED: `go test ./internal/config -run TestEventsConfig -count=1`
  failed, test exit 1 (wrapper 0), on missing Config.Events;
  `/tmp/plan32-task3-config-red.log`. Final focused run includes its GREEN result.
- Additional observed RED/GREEN regressions: nested-panic buffer rollback
  (`/tmp/plan32-task3-edge-{red,green}.log`); normalized initial organization
  connection state (`/tmp/plan32-task3-normalize-{red,green}.log`); cascade capture
  (`/tmp/plan32-task3-cascade-{red,green}.log`); ring delivery eviction
  (`/tmp/plan32-task3-ring-{red,green}.log`); tenant-delete buffer cancellation
  (`/tmp/plan32-task3-tenant-{red,green}.log`); unadvertised unavailable repository
  (`/tmp/plan32-task3-noprobe-{red,green}.log`). RED commands exited 1 and final
  GREEN commands exited 0. Early fixture mistakes (connection field/IDs and
  catalog tenant/connection fields) were corrected before valid payload assertions.
- Final focused command:
  `go test ./internal/store/memory ./internal/events ./internal/config -run 'Events|EventStream|EventDeliver|QueueRedelivery|Decorator' -count=1 -v`
  passed, exit 0; memory 0.016s, events 0.727s, config 0.003s; no skips.
  `/tmp/plan32-task3-final-focused.log`. Includes all ten named conformance cases,
  six named decorator cases, deep copies/ring/commit/clock-skew/cascades,
  post-update uniqueness rollback, savepoint error/panic, failed outbox rollback,
  password/imported-hash behavior, identity writes, optional capabilities,
  normalized payloads validated against the catalog and 105-member cascade paging.
- Focused race:
  `go test -race ./internal/store/memory ./internal/events -run 'Events|EventStream|EventDeliver|QueueRedelivery|Decorator' -count=1 -v`
  passed, exit 0; memory 1.116s, events 7.328s; no race reports or skips.
  `/tmp/plan32-task3-final-race.log`.
- Final internal compile:
  `go test ./internal/... -run '^$' -count=1` passed, exit 0; **no tests selected**.
  `/tmp/plan32-task3-final-compile.log`. Earlier compile also passed at the initial
  implementation snapshot, session 42445, `/tmp/plan32-task3-compile.log`; final
  compile session 3258 was monitored once by the Task 3 builder.
- Self-review found and fixed the buffer/default/cascade/eviction/tenant-delete
  regressions above. `git diff --check` passed, exit 0. No database-backed test,
  broad/full suite, SQL/gRPC persistence test, browser test or E2E lane was run.
  Those deferred checks are not labelled passing. No dependencies, upstream
  observations, generated API or protobuf changes were introduced in this task.
- Commit: `feat: capture tenant events in the business transaction` (containing
  this entry); independent scoped review follows the builder report.
- Post-ruling race guard verification:
  `go test -race ./internal/events -run '^TestDecoratorAddsLittleLatency$' -count=1 -v`
  passed, exit 0, events 5.876s; baseline 2.108828ms, captured 4.263093384s,
  ratio 2021.55x. `/tmp/plan32-task3-race-latency-final.log`. This verifies the
  test-only 30s race allowance; the plan's 10% target remains unmet.
- Final test-only refinement verification:
  `go test ./internal/events -run '^TestDecorator(AddsLittleLatency|CollapsesUpdates)$' -count=1 -v`
  passed, exit 0, events 0.604s; normal baseline 294.678µs, captured 484.743866ms,
  ratio 1645.00x. `/tmp/plan32-task3-normal-latency-final.log`. The normal 5s guard
  remains, and collapse now asserts original name/email/user_id explicitly.
  Full focused/race/internal compilation above covered the final production
  snapshot before these test-only guard/assertion refinements; no production
  file changed afterward.

## Task 3 Important review fixes — round 1 (base fd772fa)

- Verified the active-edge finding against `RBAC.DeleteRole`: memory and SQL
  drivers remove organization-member-role assignments internally. Added an RBAC
  repository view that intercepts only DeleteRole, reads the role and pages the
  tenant's organizations and each organization's active RoleMembers inside the
  business transaction, then emits organization.member.role.deleted after the
  successful delete. Other RBAC methods and the store's optional RBAC capability
  probe continue to delegate. Missing Events still bypasses capture.
- No new event type or dormant-edge API was added. Global user-role assignments
  have no catalog event here; retained assignments of nonmembers remain outside
  RoleMembers visibility and generate no invented removal event on role deletion,
  consistent with the existing dormant-edge ruling.
- Verified the reference finding: RecordEventDelivery accepted an EventID that
  existed only in another tenant, never existed, or had been purged after reading.
  It now resolves **all** Failed.EventID and Succeeded IDs against the lease
  tenant's ring while holding the same mutation lock, before changing checkpoint,
  counters, status, timestamps/version, failure records or success removals.
- **Contract clarification:** a missing/foreign/purged/evicted event reference
  returns ErrNotFound, including Succeeded IDs. The entire outcome is rejected
  atomically. Existing ErrInvalid for malformed Failed tenant/stream/status and
  ErrPrecondition for a lost lease/backwards checkpoint remain. A successful
  delivery needs a retained tenant event, but need not have a prior failed record.
  Success deletes only the caller's tenant/stream failure key and does not change
  other tenants' or streams' records/counters.
- Added shared EventDeliveryReferences conformance cases so future SQL/gRPC
  drivers inherit foreign/missing/purged Failed and Succeeded rejection, full-state
  atomicity (including committing after catching an error inside WithTx), and
  tenant/stream success isolation. No new Store interface or wire sentinel.

All fix commands exported `GOTOOLCHAIN=go1.26.7`; memory/mocks only:

- Role RED:
  `go test ./internal/events -run 'TestDecoratorRoleDelete' -count=1 -v`
  failed, exit 1, on missing committed role-edge events and 0/105 paged edges.
  Rollback/unsupported behavior already passed. `/tmp/plan32-task3-fix-role-red.log`.
- Role GREEN:
  `go test ./internal/events -run 'TestDecoratorRoleDelete|TestDecoratorForwardsCapabilities' -count=1 -v`
  passed, exit 0, 0.270s; `/tmp/plan32-task3-fix-role-green.log`.
  Final focused coverage also includes 105 members within one org, 105 orgs,
  actual active-edge payload/catalog validation, dormant/global exclusion,
  missing-role no-op, explicit rollback and an outbox failure rolling back the role.
- Reference RED:
  `go test ./internal/store/memory -run '^TestEvents/Events/EventDeliveryReferences' -count=1 -v`
  failed, exit 1, because all six invalid-reference cases returned nil. The regex
  also selected existing memory ring tests, which passed.
  `/tmp/plan32-task3-fix-reference-red.log`.
- Reference GREEN:
  `go test ./internal/store/memory -run '^TestEvents$/^Events$/^EventDeliveryReferences' -count=1 -v`
  passed, exit 0, 0.007s; `/tmp/plan32-task3-fix-reference-green.log`.
- Final focused:
  `go test ./internal/store/memory ./internal/events -run 'Events|EventStream|EventDeliver|QueueRedelivery|Decorator' -count=1 -v`
  passed, exit 0; memory 0.022s/events 1.022s; no skips.
  `/tmp/plan32-task3-fix-focused.log`. Existing normal latency guard also passed:
  baseline 299.081µs/captured 479.430113ms, ratio 1603.01x. The relative 10% target
  remains explicitly unmet; no new performance claim.
- Minor declaration-formatting finding in store/store.go and store/events.go is
  deferred per controller instruction. Those files are not edited in this fix.
  No broad, database-backed, SQL/gRPC persistence, browser or E2E tests run.
- Final focused race:
  `go test -race ./internal/store/memory ./internal/events -run 'Events|EventStream|EventDeliver|QueueRedelivery|Decorator' -count=1 -v`
  passed, exit 0; memory 1.179s/events 10.667s; no race reports or skips.
  `/tmp/plan32-task3-fix-race.log`, session 82485, monitored only by this builder.
  Instrumented latency: baseline 2.877861ms/captured 4.381350132s, ratio 1522.43x;
  approved 30s instrumentation guard passed, not a runtime SLO.
- Internal compile after the RBAC view addition:
  `go test ./internal/... -run '^$' -count=1` passed, exit 0, **no tests selected**.
  `/tmp/plan32-task3-fix-compile.log`, session 25647, monitored by this builder.
  Existing SQL GetRole already holds lockRBAC inside a transaction, preserving
  the prior-read/delete boundary without a new repository method.
- `git diff --check` passed, exit 0. Self-review confirmed all reference checks
  occur before the first state mutation and the role wrapper delegates unchanged
  methods/capability behavior. Both Important findings addressed; independent
  scoped re-review remains. Fix commit: `fix: capture role cascades and validate delivery references`
  (containing this entry). No unrelated Minor fix or broad/database run included.

## Task 4 — SQL event persistence (2026-11-01)

Implemented the Events repository on SQLite, PostgreSQL and MySQL; migration
0031 follows the previous maximum 0030. The migration creates immutable tenant
outbox rows, stream configuration with sealed secret bytes and worker state,
and failed delivery records with attempts JSON and queue flags. It adds the
sequence/type/time, delivery-filter/queue and purge indexes. MySQL uses the
existing resumable DDL path. The existing LatestVersion expectation now says 31.
Tenant deletion removes all three new tables' tenant rows.

AppendEvents joins the caller's transaction and runs within a repository
savepoint. It acquires the established lockRBAC tenant lock in sorted tenant
order, holds it through the outermost commit, and clamps committed_at against
the preceding sequence using a locking read. This prevents a delayed lower
sequence or a backwards writer clock from being skipped by checkpoint readers.
It introduces no second lock namespace; business operations retain their
existing locking/transaction behavior. As with existing repository operations,
a caller's explicit WithTx is not automatically retried: a database deadlock
returns an error and cannot leave a committed business change without its event.

Stream CRUD enforces tenant-scoped names and versions, returns copies through
JSON decoding, and uses byte order for both cursor comparisons and ordering.
Leases use row locks plus conditional updates, permit owner renewal, ignore idle
streams and disabled new-event work, and permit queued disabled redelivery.
RecordEventDelivery validates lease ownership/expiry after locks, rejects stale
checkpoints and malformed failed identities, and resolves every failed/succeeded
event reference in the same tenant before any mutation. Missing, foreign and
purged references leave counters/checkpoint/status/deliveries unchanged, including
when the caller catches the error and commits its surrounding transaction.
Failure counters are the supplied outcome state, consistent with the shared
memory contract; the worker owns calculation of extant failures. Queue validation
is all-or-nothing. Purge selects a bounded batch, locks tenant IDs in append order,
and matches the selected sequence before removing that event's deliveries; a
stale batch cannot erase a replacement event's records.

Verification (all shell commands exported GOTOOLCHAIN=go1.26.7):

- RED: `go test ./internal/store/sqlstore -run Events -count=1 -v`, exit 1,
  0.962s; 21 SQLite leaf failures, capability unavailable / missing migration.
  `/tmp/plan32-task4-red.log`, session 84921. PostgreSQL/MySQL were not selected
  in this local RED run; they are explicitly covered by both matrices below.
- Initial SQLite GREEN: same command, exit 0, 1.135s, 21 leaf cases; then the
  extended version passed exit 0, 1.362s, 25 leaf cases. Logs:
  `/tmp/plan32-task4-sqlite-green.log` (session 70093),
  `/tmp/plan32-task4-sqlite-extended.log` (session 24825).
- First three-backend matrix:
  `ZEROAUTHY_TEST_PG_PORT=40499 ZEROAUTHY_TEST_MYSQL_PORT=52417 ./scripts/test-sql.sh -run Events -count=1 -v ./internal/store/sqlstore/...`,
  exit 0, 84.578s, race enabled by the script; 75 leaf cases / 92 passed test
  nodes, 0 failures, 0 skips. `/tmp/plan32-task4-sql-matrix.log`, actual status
  `/tmp/plan32-task4-sql-matrix.exit`, session 64082.
- Self-review metadata RED/GREEN:
  `go test ./internal/store/sqlstore -run '^TestLatestVersion$' -count=1 -v`,
  exit 1 then exit 0, 0.012s final; one test covering all dialect metadata.
  `/tmp/plan32-task4-version-{red,green}.log`, GREEN session 80774.
- Self-review stale-purge RED/GREEN:
  `go test ./internal/store/sqlstore -run '^TestEventsPurgeStaleCandidate$' -count=1 -v`,
  exit 1 because a replacement delivery was deleted; then exit 0, 0.078s.
  `/tmp/plan32-task4-purge-{red,green}.log`, sessions 91938 / 4244.
- Final three-backend matrix: same script command and ports above, exit 0,
  85.708s, race enabled; **78 leaf cases / 96 passed nodes, 0 failures, 0 skips**.
  SQLite, PostgreSQL and MySQL each passed 26 leaf cases / 29 nodes, including
  the explicit TestEventsConformance parent. Its common conformance subtree
  passed on SQLite (34.82s), PostgreSQL (3.31s), MySQL (17.59s).
  `/tmp/plan32-task4-sql-matrix-final.log`, status
  `/tmp/plan32-task4-sql-matrix-final.exit`, session 5376. Tested code snapshot:
  base 3e9a4270bbcb642e04c0ee32cd9c725913dcbb60; staged implementation tree
  7fa688dab0f3b822ced0c5179033988d71c83e81, recorded in
  `/tmp/plan32-task4-final-snapshot.txt`. Only this builder monitored each run;
  each command was started once and awaited through its retained session.
- Required named coverage: TestEventsMigrationFrom30,
  TestEventsConcurrentWritersSettled, TestEventsAppendInBusinessTx; additional
  tests cover backwards clocks, lease/counter/disabled delivery guards, tenant
  deletion and bounded purge, expiry after transaction wait, and stale purge
  candidates. Actual user and event inserts commit/roll back together; a caught
  partial append conflict also rolls back the append savepoint while allowing
  an unrelated user insert to commit.
- `git diff --check` and `git diff --cached --check` passed, exit 0.
  No broad SQL, full Go, browser, or E2E suite run; those remain Task 14.

Self-review completed. No outstanding Task 4 implementation concern identified;
per-tenant append serialization may contend with business/RBAC writes and has
not been throughput-benchmarked here. No claim of a SQL performance SLO is made.
Task commit: `feat: persist events, streams and deliveries in SQL` (containing
this entry). Independent scoped review remains with the controller.
