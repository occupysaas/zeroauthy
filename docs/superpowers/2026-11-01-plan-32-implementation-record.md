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

## Task 5 — Events v1 storage plugin capability (2026-11-01)

Base `e11fb071caf567534917a1c3e8537b8bbc2c32ec`; isolated worktree
`/mnt/nvme2/code/zeroauthy-plan32`, branch `implement-plan-32`. Added independent
Events v1 negotiation, all 20 Events repository RPCs and an additive Events
unavailable wire sentinel. Generated protobuf/Go files came only from
`make generate`; no dependency or existing field/RPC renumbering was introduced.
The existing public pkg/store aliases already cover the complete Events contract.

Every repository request carries the remote transaction handle. AppendEvents
returns assigned sequences, and stream create/update return assigned versions,
so the client preserves those caller-visible repository mutations. Transactions
share the capability cache; explicit operations re-probe to observe upgrades and
downgrades. Only Unimplemented, version zero and the domain unavailable sentinel
are definitive. Transient transport failures retain their errors and allow a
subsequent successful probe, rather than permanently negative-caching support.
The server consults backend declarations and recognizes both value and pointer
UnimplementedEvents stubs without acquiring a backing repository lock.

Codecs preserve int64 sequences/checkpoints, float64 attempt durations, exact
Config JSON numbers via UseNumber, nanosecond UTC timestamps including year0000,
Go zero and Unix epoch, arbitrary sealed/body bytes, and nil/empty nested lists,
maps and bytes. Protocol boundaries clone mutable slices/bytes and marshal/decode
nested maps. Invalid time/config/attempt messages are rejected before repository
writes. The backend's tenant-scoped outcome validation remains authoritative;
the full shared reference regression runs through both gRPC backends.

Integration review confirmed that capture.available already calls the explicit
CheckEventsSupport before its cheap predicate: only ErrEventsUnavailable skips
capture. No wrapper adjustment was needed. Real gRPC tests prove a transient
negotiation failure prevents an uncaptured user mutation, recovery records the
user event, old plugins still permit the user mutation without capture, and an
AppendEvents transport/unknown-method failure rolls the business write back.
Callback failure and nested savepoint tests independently verify business/outbox
rollback and successful commit on both memory and SQLite.

Verification (all commands exported GOTOOLCHAIN=go1.26.7; actual logs/statuses):

- Initial RED: `go test ./internal/store/grpcstore -run Events -count=1 -v`,
  exit 1, 8.859s, `/tmp/plan32-task5-red.log`, status `.exit`, session99698.
  V1/shared Events conformance/remote rollback failed on the unavailable stub;
  the full pre-Events prior-feature compatibility suite passed (7.51s).
- Assigned-field RED:
  `go test ./internal/store/grpcstore -run '^TestEventsAssignedFields$' -count=1 -v`,
  exit 1, 0.081s, memory/SQLite unavailable stubs;
  `/tmp/plan32-task5-assigned-red.log`, status `.exit`, session95449.
- `make generate` passed, exit 0, `/tmp/plan32-task5-generate.log`, session16973;
  final regeneration also passed, exit 0,
  `/tmp/plan32-task5-generate-final.log`, status `.exit`, session32628.
- First GREEN: the initial RED command passed, exit 0, 9.574s;
  `/tmp/plan32-task5-first-green.log`, status `.exit`, session61762. Includes
  every shared Events case on memory/SQLite, callback rollback and assigned
  sequence/version assertions, plus every prior-feature suite on an old plugin.
- Extended GREEN:
  `go test ./internal/store/grpcstore -run '^TestEvents' -count=1 -v`, exit 0,
  7.842s, `/tmp/plan32-task5-extended-fixed.log`, status `.exit`, session8920.
  Adds backend declarations, capability version changes, lossless transport and
  capture negotiation. The preceding attempt failed to compile because the test
  fixture used User.ID rather than UserID (exit1,
  `/tmp/plan32-task5-extended.log`); corrected before behavioral validation.
- Final normal focused command: same extended command, exit 0, 7.836s;
  `/tmp/plan32-task5-final-focused-fixed.log`, status `.exit`, session51982.
  Adds direct codec copy/malformed-message checks, malformed-batch no-partial-write,
  append-failure capture rollback and nested remote rollback. The preceding
  cleanup attempt failed to compile on `:=` with an already declared error
  (exit1, `/tmp/plan32-task5-final-focused.log`); corrected to assignment.
- Initial combined race/conformance:
  `go test -race ./internal/store/grpcstore -run '^(TestEvents.*|TestConformance(SQLite)?)$' -count=1 -v`,
  exit 1, 600.734s: Go's default ten-minute suite timeout fired in
  TestConformanceSQLite/RefreshTokens/RotateUnknownAndConflict during a fresh
  SQLite fixture's migration14/Commit. `/tmp/plan32-task5-conformance-race.log`,
  status `.exit`, session88753. TestConformance (memory) completed PASS56.84s.
  No assertion failure, skip or race report preceded the timeout. SQLite had
  executed Events and reached RefreshTokens; the incomplete SQLite parent and
  not-yet-started top-level Events tests are **not** claimed passing by this run.
- **Timeout ruling (controller):** preserve the original timeout as FAIL. Prior
  Plan31 evidence records approximately14min for SQL-race SQLite even without
  RPC overhead; retry SQLite alone with an explicit90m timeout using the same
  assertions, race instrumentation and implementation snapshot. Do not rerun
  completed memory conformance. Cost: a slower real verification lane and wider
  hang timeout; no assertion, backend or race instrumentation is removed.
- Focused Events race:
  `go test -race ./internal/store/grpcstore -run '^TestEvents' -count=1 -timeout=90m -v`,
  exit 0, 106.826s; `/tmp/plan32-task5-focused-race.log`, status `.exit`,
  session11456. All new tests plus the prior-feature old-plugin suite and explicit
  memory/SQLite shared Events conformance completed; no failures/skips/race reports.
  Source is unchanged from the recorded final implementation tree.
- SQLite-only full gRPC conformance race retry:
  `go test -race ./internal/store/grpcstore -run '^TestConformanceSQLite$' -count=1 -timeout=90m -v`,
  exit 0, 943.084s (parent941.28s; Events37.55s),604 passed nodes/555 passed
  leaves,0 failures/skips/race reports. `/tmp/plan32-task5-sqlite-conformance-race.log`,
  status `.exit`, session18136. Memory full conformance's earlier56.84s pass
  likewise has604 nodes/555 leaves. Focused Events race has675 nodes/612 leaves,
  including18 shared Events leaves per backend (20 nodes each).
- Tested source identity: Go1.26.7 linux/amd64; base as above, staged
  implementation tree `b991e0dee20da82fb42d355cf66ca0491eec9e7c`,
  `/tmp/plan32-task5-final-snapshot.txt`. No implementation/test source changed
  between the timed-out run, focused race and SQLite retry; only this record and
  the builder report changed. Each run started once with its own retained log,
  actual exit status and session; only this builder monitored. Blocking process
  waits and filesystem completion notifications avoided routine log polling.
  No run remains active. `git diff --check` and cached check passed, exit0.

Self-review checked additive protocol evolution, all method/tenant/transaction
arguments, assigned field propagation, capability recovery/old-plugin behavior,
codec precision/copies and preservation of common atomic reference checks.
No broad Go/full SQL matrix/browser/E2E suite was run; those remain Task 14 and
are not claimed passing. No new upstream observation or external source used.
Task commit: `feat: add Events storage plugin capability` (containing entry).

## Task 6 — Event streams Management API

Base `1e4f990`, branch `implement-plan-32`, isolated worktree
`/mnt/nvme2/code/zeroauthy-plan32`. Go toolchain `go1.26.7` throughout.

Implemented scoped list/create/get/PATCH/delete using the generated route
signatures. Lists default to 50 and cap at 100, with last-seen stream-ID cursors.
Unknown/repeated parameters and invalid cursors are rejected. Request validation
rejects unknown nested fields, null/malformed values and duplicate JSON keys;
names/subscriptions/destination fields follow the frozen contract. Destination
type is immutable; EventBridge is forced disabled and its configuration cannot
be patched. Tenant Actions must have the `event-stream` trigger. Trigger
activation, workers, test deliveries, delivery endpoints and SSE remain later
Tasks 7–10; generated Unimplemented declarations are intact.

Webhook password/token/header_value are sealed with tenant/stream/type-bound
`event-stream/v1` envelopes in `internal/eventstream/secrets.go`, ready for Task 7.
Public projections omit all credential fields. Omitted same-method credentials
survive PATCH; changing methods requires and retains only the new credential.
Both `sapi` and plain server operation logs use Plan 31's deny-all body
projection and retain redaction markers. Existing credential registration is
reused; no logging body allowlist was widened.

Creation performs a transactional quota/name check and starts at the latest
committed sequence. SQL transactional CountEventStreams locks the tenant before
the count, including an empty stream table. PATCH locks the tenant before
reading stream/checkpoint state, retries optimistic conflicts up to three times
and rolls back invalid/conflicting candidates. Re-enabling below 5,000 extant
failures clears consecutive failures, starts at the latest sequence, clears old
lease ownership, and preserves the extant failure count; 5,000 rejects enabling.

Integration rulings approved by the controller, recorded in D-0058/matrix:

- E8 remains unobserved. The read-only local partner-source placeholder is
  `aws.partner/zeroauthy/<stream-id>`; it does not register an AWS source.
- Endpoint URL embedded credentials/fragments and custom transport/framing headers
  are rejected to prevent secret reflection and request-integrity failures.
  Ordinary endpoint query strings, including empty queries, are preserved
  (Task 6 review fix I1). Authorization credentials remain separately sealed.
  Cost: stricter userinfo/fragment/header acceptance pending evidence.
- `total_failures` is a read-only nonnegative local console extension, reporting
  extant failed deliveries maintained by the worker, never lifetime attempt count.
  Added to all three source YAML response variants and regenerated with
  `make generate`; clients cannot PATCH it. Cost: a local response field, explicitly
  not observed Auth0 parity. Console types will regenerate with Task 12.
- Positive Action validation uses a tenant-scoped test-only GetAction adapter
  because the real Actions inventory intentionally rejects the deferred trigger
  until Task 8. Wrong-trigger validation uses the real memory Actions store;
  production availability was not changed.
- The SQL exception is narrow: two concurrency regressions on all three drivers,
  not a broad SQL suite. Per-tenant count/startpoint locking adds brief contention.

Verification evidence:

- Initial test-harness attempt exit1: CreateAction correctly rejected the still
  deferred trigger. Corrected the fixture with the approved test-only adapter.
  The authoritative RED rerun then failed because Management handlers were missing:
  `go test ./internal/mgmt -run 'EventStream|EventBridge' -count=1`, exit1,
  `/tmp/plan32-task6-red.log`, session54613 (initial fixture session72514).
- Server RED: same focused selector on `./internal/server`, exit1,
  `/tmp/plan32-task6-server-red.log`, session18418: routes returned Unimplemented
  501 and seed rejected missing Management scopes.
- Additional RED regressions: duplicate JSON fields accepted201 (exit1,
  `/tmp/plan32-task6-strict-red.log`, session62460); missing failure-count response
  (exit1, `/tmp/plan32-task6-summary-red.log`, session21472).
- SQL quota RED: `./scripts/test-sql.sh ./internal/store/sqlstore -run
  '^TestEventStreamCountSerializesCreateQuota$' -v -timeout=10m`, exit1,
  `/tmp/plan32-task6-sql-red.log` and `.exit`, session39632. SQLite passed;
  PostgreSQL/MySQL allowed the second quota transaction through. GREEN after
  locking: exit0, all3 drivers, `/tmp/plan32-task6-sql-green.log` and `.exit`,
  session36431, Go4.707s.
- SQL enable/append RED: actual Management UpdateEventStream invoked while an
  append commit is delayed. Temporarily removed only the pre-read tenant lock;
  `./scripts/test-sql.sh ./internal/store/sqlstore -run
  '^TestEventStreamEnableCheckpointSerializesAppend$' -v -timeout=10m`, exit1,
  `/tmp/plan32-task6-enable-red.log` and `.exit`, session49063. SQLite passed;
  PostgreSQL/MySQL retained checkpoint0 and would replay disabled-period history.
  Restored lock; combined focused SQL run exit0, all6 leaves/0skips/0races,
  `/tmp/plan32-task6-sql-final.log` and `.exit`, session72963, Go9.034s.
- Focused race GREEN: `go test -race ./internal/mgmt ./internal/server -run
  'EventStream|EventBridge' -count=1 -v`, exit0, 25passed nodes/24passed leaves,
  0failures/0skips/0race reports. `/tmp/plan32-task6-final-focused-v2.log` and
  `.exit`, session7760; mgmt6.376s/server3.676s. Includes all named Task 6 cases,
  real route/M2M scopes and scope discovery, live operator revocation, config
  wiring, all webhook methods and replacement/binding, paging defaults/max,
  transient capability recovery, atomic failed PATCH and optimistic retries.
- `make generate`, exit0, `/tmp/plan32-task6-generate.log` and `.exit`, session65122.
- `go test ./api ./internal/eventrules -count=1`, exit0,
  `/tmp/plan32-task6-contract.log` and `.exit`, session7311,0.890s/0.353s.
- Affected compile only: `go test ./internal/app ./internal/eventstream
  ./internal/tenantsetup ./internal/store/sqlstore ./internal/store/grpcstore
  ./internal/seed ./internal/deploymigration -run '^$'`, exit0,
  `/tmp/plan32-task6-compile.log` and `.exit`, session64292. These compile results
  are not database tests or claims that deferred runtime suites passed.

Self-review checked strict allowlists, error masking, tenant/transaction scope,
create/enable ordering, rollback, optimistic state refresh, secret method changes,
M2M/operator gates, deployment config propagation, generated interface signatures,
and preservation of future-task endpoints. No new dependency or upstream
observation. Full Go/SQL/conformance/browser/E2E coverage remains Task 14.

Final self-review corrections and snapshot verification:

- Validation errors now use the frozen `invalid_request` code, including malformed
  bodies and generated collection-query binding errors. The prior reuse of
  `badBody`/the generic router emitted `invalid_body`/`invalid_query_string`;
  explicit RED assertions failed (exit1,
  `/tmp/plan32-task6-error-codes-red.log` and `.exit`, session94551). Fixed with a
  stream-specific generic error and collection-route query normalization.
- Full-tenant quota checks must not mask invalid bodies. RED
  TestEventStreamLimitsAndNames observed409 for an unknown body field (exit1,
  `/tmp/plan32-task6-quota-validation-red.log` and `.exit`, session31630).
  Validation now occurs under the acquired count lock before the quota rejection.
- Final focused race run after those changes: same command above, exit0,
  27passed nodes/26passed leaves,0failures/0skips/0race reports;
  `/tmp/plan32-task6-final-focused-v4.log` and `.exit`, session75885,
  mgmt8.979s/server4.351s. This supersedes intermediate GREEN counts; it adds
  handler and real-route error-code assertions and full-quota input validation.
- Final SQL snapshot: same combined focused race selector above, exit0,
  all6 leaves (two per SQLite/PostgreSQL/MySQL),0failures/0skips/0race reports,
  `/tmp/plan32-task6-sql-final-v3.log` and `.exit`, session53901, Go8.992s.
  Free host ports56861/50837; script containers were removed on completion.
  Earlier final-v2 snapshot also passed9.059s (session62113), before final
  validation-code changes. Repeated verification was tied to source changes,
  never silence or elapsed runtime.
- Final affected compile-only command above: exit0,
  `/tmp/plan32-task6-compile-final.log` and `.exit`, session63108. Cached
  no-test compile results remain compile-only claims.
- Final implementation source tree (before this report-only record amendment):
  `34d75fab904bdb62db013a914a7e994f95ee0968`,
  `/tmp/plan32-task6-implementation-tree.txt`. No implementation/test source
  changed after the final focused/SQL/compile runs. `git diff --check` and
  cached check passed, exit0. All run handles have completed; no run remains active.

Task commit: `feat: manage event streams` (containing entry). Detailed builder
report: `.superpowers/sdd/2026-11-01-zeroauthy-plan-32-event-streams/task-6-report.md`.

### Task 6 review fix I1 — Preserve webhook endpoint query strings

Base `810c23d381d4583f2149efce255b565e470466cb`. The review correctly found that
blanket `RawQuery`/`ForceQuery` rejection narrowed the frozen HTTPS webhook
contract. Removed only those checks. Ordinary queries and empty queries are
preserved exactly through create and PATCH in public destination configuration.
Embedded userinfo, fragments, control characters, invalid ports and framing/header
protections remain enforced. Authorization password/token/header_value remain
separately sealed and omitted from public representations; no query-key secrecy
classification or query credential schema was introduced. Corrected D-0058 and
the matrix to distinguish endpoint queries from Management API list parameters.

- RED: added real-handler create/PATCH coverage for `?tenant=acme`,
  `?format=cloudevents&tenant=acme`, and empty `?`. Before the fix all three
  creation cases failed400; `go test ./internal/mgmt -run
  '^TestEventStreamWebhookRoutingQuery$' -count=1 -v`, exit1,
  `/tmp/plan32-task6-fix1-red.log` and `.exit`, session13529.
- GREEN: `go test -race ./internal/mgmt ./internal/server ./internal/eventstream
  -run 'EventStream|EventBridge' -count=1 -v`, exit0,
  `/tmp/plan32-task6-fix1-green.log` and `.exit`, session8500. 31passed nodes,
  29passed leaves,0failures/0skips/0race reports; mgmt7.046s/server3.955s.
  `internal/eventstream` has no direct test files; the Management tests exercise
  its configuration/secret helpers through actual handlers. The new test checks
  exact URL preservation after both create and PATCH, same-method omitted-token
  preservation, stored envelope contents and absence of credentials from public
  authorization configuration and responses. Existing invalid URL/header cases
  and log privacy cases also passed.
- Implementation tree before this documentation-only amendment:
  `428dfc23daba90a7f24e3c116bcf26cd3a6ab905`,
  `/tmp/plan32-task6-fix1-implementation-tree.txt`. All commands used
  `GOTOOLCHAIN=go1.26.7`. No SQL source changed, so the SQL matrix was not rerun.
  No broad suite or subagents. No process remains active. Minor M1 application-log
  noise remains deferred as directed. `git diff --check` and cached check pass.

### Task 7 — Webhook delivery worker and event retention

Base `48066e381a0124fd143faac00d55c7875a275d09`. Added
`eventstream.NewWorker`, `Run` and reusable `Deliver`, the future durable
`ActionRunner` interface, guarded webhook transport, exponential retry intervals,
and an hourly fenced event purger. App construction and shutdown now own both
background workers. Task 8 still owns the durable Action adapter and trigger
activation; this change does not activate that trigger.

Each webhook POST sends a stamped copy of the persisted CloudEvent, JSON content
type, configured basic/bearer/custom authorization, and the complete endpoint
query. Each attempt has a 10-second context and client timeout. Every normal HTTP
transport uses the existing guarded dialer, with proxy/custom TLS-dial bypasses
removed. Redirects are refused for every authorization method. Diagnostics contain
only the specified safe classes and status codes; response bodies are closed
without reading, and Action messages pass through the Plan 31 redactor.

Queued redeliveries precede new events, including on disabled streams. Failures
advance the checkpoint atomically with their record and counters. Successful
redelivery removes its failure record and reduces the count; a failed redelivery
does not add a second failure record. Success resets the consecutive streak.
Streams disable at 500 consecutive failed events or 5,000 extant failed records.

Ruling: bound each lease iteration to one event and reacquire before the next —
four attempts consume at most 47 seconds, so draining 100 under an unchanged
60-second lease is unsafe. Preprocessing, delivery and recording share an earlier
deadline; sending requires 52 seconds of remaining lease budget. Ownership and
configuration version are checked before sending and again under the transaction's
existing tenant lock, with the repository's final ownership fence. Cost if wrong:
more repository reads and lower throughput than a batched renewal design.

Ruling: `total_failures` counts current failed records, including after retention
and memory-ring eviction — otherwise stale counts incorrectly prevent re-enable.
The worker counts records under the tenant transaction lock before each outcome;
memory purge/eviction and SQL purge update cached counts and increment the stream
version atomically with deletion. Purge preserves consecutive failures and disabled
status. The controller authorized this narrow memory/SQL correction and the
three-driver focused regression. Cost if wrong: extra count/pagination work per
record and purge batch.

Ruling: refuse redirects and classify 3xx as `connection_error` under the frozen
safe error classes — following even same-host redirects can forward custom
credentials and adds another SSRF surface. Cost if wrong: receivers must configure
the final endpoint instead of a redirecting URL.

Verification used `GOTOOLCHAIN=go1.26.7`. Final implementation tree before this
documentation-only record addition:
`18c0d75d93831ddbcb7da2593fb91f6deec1f11c`, saved in
`/tmp/plan32-task7-implementation-tree.txt`.

| Check | Actual result | Evidence |
| --- | --- | --- |
| Initial `go test ./internal/eventstream ./internal/events -count=1` | RED exit1: missing Worker/NewWorker/NewPurger | `/tmp/plan32-task7-red.log`, `.exit` |
| Memory purge-counter regression | RED exit1: in-transaction count2 instead of1; then GREEN exit0 | `/tmp/plan32-task7-purge-red.log`, `.exit`, session46296; `/tmp/plan32-task7-purge-green.log`, `.exit` |
| Memory ring-eviction regression | RED exit1: removed failure still counted1; then GREEN exit0 | `/tmp/plan32-task7-eviction-red.log`, `.exit`, session81282; final memory run below |
| `go test ./internal/eventstream ./internal/events -count=1 -v` | exit0;116 passed leaves,0fail/skip; eventstream2.039s/events1.483s | `/tmp/plan32-task7-focused-final.log`, `.exit`, session36398 |
| `go test -race ./internal/eventstream -count=3 -v` | exit0;105 leaf executions across3 runs,0fail/skip/race reports;52.197s | `/tmp/plan32-task7-race-final.log`, `.exit`, session62442 |
| Focused memory Events/ring tests under race | exit0;21 passed leaves,0fail/skip/races;1.186s | `/tmp/plan32-task7-memory-final.log`, `.exit`, session81826 |
| Existing guarded-dialer/rebinding and Events-config tests under race | exit0;10 passed leaves,0fail/skip/races | `/tmp/plan32-task7-network-config-final.log`, `.exit`, session18740 |
| Focused SQL purge-counter regression via `scripts/test-sql.sh` | exit0;3 passed leaves,one each SQLite/PostgreSQL/MySQL;0fail/skip/races;5.701s | `/tmp/plan32-task7-sql-final.log`, `.exit`, session58989 |
| Affected app/eventstream/events/mgmt/server/grpcstore/sqlstore compile | exit0;7 packages,`-run '^$'`,no runtime-test claim | `/tmp/plan32-task7-compile-final.log`, `.exit`, session77487 |
| Whitespace checks | `git diff --check` and cached check exit0 | command transcript |

The SQL command selected only
`^TestEventsConformance$/^(sqlite|postgres|mysql)$/^Events$/^EventsPurgeFailureCounters$`,
with `-race -count=1 -v` supplied by the script, free ports recorded in
`/tmp/plan32-task7-sql-final-ports`, and temporary containers removed on exit. The
shared case covers bounded deletion, identical event IDs in separate tenants,
transaction rollback, count/version changes, preserved consecutive streaks, and
an idempotent second sweep. No broad SQL suite or full application suite ran.

All named Task 7 tests ran, plus cancellation, configuration changes during sends,
concurrent lease holders, expired/preprocessing lease boundaries, purge during
delivery, queued-first ordering, redirect credentials, Action error masking,
unsupported plugin shutdown and real DNS rebinding tests. Local TLS fixtures emit
expected certificate-rejection diagnostics; these contain no credentials.

1,000 captured memory signups took653.050ms normally and621.450ms while a receiver
remained blocked. Race runs measured5.564s/5.709s,4.404s/4.690s and4.362s/4.575s
(normal/blocked). This demonstrates originating writes remain independent of the
receiver. The earlier Task 3 relative10% capture-overhead target remains **not met**;
this check does not replace or claim that target.

Self-review checked lease/checkpoint fencing, subscription settle ordering,
retention/redelivery counter races, endpoint query preservation, redirect and DNS
SSRF protections, and diagnostics. No unresolved Task 7 finding. No new dependency
or generated source changed. All runs have completed. Full execution report:
`.superpowers/sdd/2026-11-01-zeroauthy-plan-32-event-streams/task-7-report.md`.

### Task 7 review fix I1 — Fair lease scheduling

Base `493f5b86686bd481dc455f832172c4eb5ba8d73f`. The worker's stable owner could
repeatedly reacquire the lexicographically first due stream, starving every later
stream when the first retained a backlog or an unsettled tail. Fixed the shared
memory/SQL lease selection policy; the worker's bounded event handling and final
ownership/version fences remain in place. gRPC delegates this operation to those
repositories; no RPC, schema or migration changed.

Ruling: persist fairness through the existing `LeaseUntil` scheduling key. Select
eligible due streams by ascending lease expiry, then tenant/ID. A renewed expiry
is `max(requestedUntil, previousLeaseUntil + 1ns)`, ensuring equal/frozen-clock
requests rotate after the first round. This policy was approved by the controller.
The owner/expiry eligibility predicate and SQL conditional update/locking are
unchanged. Cost if wrong: renewal under a frozen/backward clock or a shorter
requested lease can retain and slightly extend the previous deadline, instead of
shortening it. A monotonic bump past year9999 returns `ErrInvalid` before mutation.
The returned expiry is the actual persisted value. All three SQL backends retain
the nanosecond increments through their existing fixed-width text timestamps.

- RED: new `TestWorkerStreamFairness` failed with turns `[s s s s s s]` under
  continuous traffic and no second-stream delivery under an unsettled first tail.
  Shared `EventStreamFairLease` failed on its second acquisition (`a`, expected
  `b`). Exact combined command: `go test ./internal/eventstream
  ./internal/store/memory -run
  '^TestWorkerStreamFairness$|^TestEvents$/^Events$/^EventStreamFairLease$'
  -count=1 -v`, exit1, `/tmp/plan32-task7-fix1-red.log`, `.exit`, session26269.
  RED tree `8ec29539e92401c84b47994924a0e37a43fc0ad5` is saved in
  `/tmp/plan32-task7-fix1-red-tree.txt`.
- GREEN: same focused command exit0, three passed leaves,
  `/tmp/plan32-task7-fix1-green.log`, `.exit`, session46042.
- Final `go test ./internal/eventstream ./internal/events -count=1 -v`: exit0,
  118 passed leaves,0fail/skip; eventstream5.433s/events3.798s.
  `/tmp/plan32-task7-fix1-focused.log`, `.exit`, session16022.
- Final `go test -race ./internal/eventstream -count=3 -v`: exit0,
  111 leaf executions,0fail/skip/race reports;52.188s.
  `/tmp/plan32-task7-fix1-race.log`, `.exit`, session92265.
- Memory Events conformance plus ring-eviction counter regression under race:
  exit0,21 passed leaves,0fail/skip/races;1.104s.
  `/tmp/plan32-task7-fix1-memory.log`, `.exit`, session9370. Existing purge-counter
  assertions remain and passed.
- Focused shared fair-lease case on SQLite/PostgreSQL/MySQL through
  `scripts/test-sql.sh`: exit0,3 passed leaves,0fail/skip/races;6.203s.
  `/tmp/plan32-task7-fix1-sql.log`, `.exit`, session75916. Selection was only
  `^TestEventsConformance$/^(sqlite|postgres|mysql)$/^Events$/^EventStreamFairLease$`
  with `-v`; the script supplies `-race -count=1`. Temporary container ports are
  saved in `/tmp/plan32-task7-fix1-sql-ports`; containers were removed on exit.
- Affected app/grpcstore/sqlstore compile: exit0 with `-run '^$'`, no runtime/DB
  test claim. `/tmp/plan32-task7-fix1-compile.log`, `.exit`, session64444.
- Every Go command exported `GOTOOLCHAIN=go1.26.7`; each log records explicit UTC
  START/END timestamps and a separate actual exit file. One monitor, no reruns of
  quiet processes, no broad SQL/full suites, and no subagents. All runs finished.

The shared regression pins repeated fixed-clock rotation across tenants, exact
persisted nanosecond increments, exclusion of competing owners from live leases,
takeover after expiry and rejection of the stale owner's record, fair eligibility
for disabled queued work, removal of eligibility once that queue clears, and safe
maximum-time overflow. Worker regressions pin repeated two-stream progress and a
settled second stream receiving while the first retains an unsettled tail.

Final implementation tree before this documentation-only record addition:
`8c2398c413aab403ed50ca69d8aa344ed823df9e`, saved in
`/tmp/plan32-task7-fix1-implementation-tree.txt`. Self-review of the changed
selection and update paths found no unresolved I1 issue. Minor M1 expected TLS
fixture diagnostics remain deferred as directed. The prior relative10% capture
overhead target remains explicitly **not met**. Full fix report with exact
commands, timestamps and limits:
`.superpowers/sdd/2026-11-01-zeroauthy-plan-32-event-streams/task-7-fix1-report.md`.

## Task 8 — Event-stream Actions (2026-11-01)

Base `72175ff`; activates the `event-stream` inventory entry, the exact
`onExecuteEventStream` Node handler, and a durable Action destination wired into
the app's existing stream/job worker lifecycles. The queue snapshots the selected
tenant Action's deployed version, Action/Module secrets and immutable Module
versions, together with the original CloudEvent and an absolute deadline. Only
the queue worker invokes Node. Each delivery retry creates a distinct job and
execution; existing Plan 31 recording/masking makes executions discoverable.
`event.message` and `event.secrets` are the only event fields and cache
get/set/delete are the only enabled APIs. Customer payload fields are passed
through without a credential-name blacklist.

Public [event](https://auth0.com/docs/actions/reference/event-stream/event-stream-event-object)
and [API](https://auth0.com/docs/actions/reference/event-stream/event-stream-api-object)
references were checked on this task. They confirm the event shape and cache;
`api.message.fail` is not enabled. Task 1 omitted a trigger-version declaration:
`v1` is a local compatibility default, **not** a documented/observed upstream
version. That gap and its correction cost are recorded in D-0058.

Controller-authorized prerequisite: tenant-scoped `GetJob` and `CancelJob` for
memory, SQL and storage plugins, with additive generated RPCs and no Actions
capability-version change. Older plugins missing either operation reject this
new destination before enqueue while prior Actions jobs remain usable. Cancel
atomically marks pending jobs failed and clears/fences their leases. Workers
check the persisted state before dispatch and every25ms while running, so another
process can stop Node; the sealed deadline prevents late execution even after the
delivery process disappears. Delivery waits reserve up to100ms inside their10s
budget for cancellation I/O, proportionally less for short caller deadlines.
Storage failure can prevent the cancellation write; the sealed deadline remains
an independent execution fence. Cost: extra queue polling, up to100ms less runtime
budget, and external plugin updates for this destination.

RED evidence: initial required command rejected the trigger and lacked the
adapter (exit1); memory/plugin common tests lacked read/cancel and the real
Management Action creation returned400 (exit1). Self-review regressions reproduced
a cancelled warm Node claim executing before the periodic check, cancellation
cleanup extending a100ms deadline to1.100589s, and deadline/runtime timeouts being
classified as action errors. Each was repaired and the corresponding focused
checks passed. An intermediate compile failure from an unused test import was
fixed; its failing log is preserved. No RED/deferred run is labelled passing.

Validation (all Go commands exported `GOTOOLCHAIN=go1.26.7`, real Node26.8.1,
`ZA_REQUIRE_NODE=1` on Actions executions):

- Final required Actions/actionsrules/eventstream selection:25 passed leaves,
  exit0,0skips, `/tmp/plan32-task8-final.log`, `.exit`; session55714.
- Required full Actions suite, started once:225 passed leaves, exit0,0skips,
 34.648s; `/tmp/plan32-task8-actions-full.log`, `.exit`, session12956;
  UTC19:59:28–20:00:04. Later repairs changed only the destination adapter/worker
  and its tests; this Actions engine snapshot is unchanged.
- Focused Actions/eventstream/memory/plugin race run:17 passed leaves, exit0,
 0skips/race reports; `/tmp/plan32-task8-race.log`, `.exit`, session79350.
- Final adapter/timeout/secret/failure-record race selection:12 passed leaves,
  exit0,0skips/race reports; `/tmp/plan32-task8-adapter-final2.log`, `.exit`,
  session16659.
- Real Management create Action/create stream/build/deploy/durable execution/read
  execution path plus plugin read/cancel and old-plugin compatibility:5 passed
  leaves, exit0,0skips; `/tmp/plan32-task8-api-plugin.log`, `.exit`, session8326.
- Only the new shared `TestActionJobReadCancel` on SQLite/PostgreSQL/MySQL through
  `scripts/test-sql.sh -run '^TestActionJobReadCancel$' ./internal/store/sqlstore`:
  exit0 under race,5.144s,0reported skips; `/tmp/plan32-task8-sql.log`, `.exit`,
  session27379. The script exported both server DSNs and removed its containers.
  No broad SQL/plugin conformance suite was run.
- App/server/CLI compile only with `-run '^$'`:exit0;
  `/tmp/plan32-task8-compile.log`, `.exit`, session94870. No runtime-test claim.
- `go generate ./proto/store/v1` and `git diff --check`:exit0. Protobuf outputs
  were generated with the repository toolchain; no generated file was hand edited.

Implementation tree before this record-only addition:
`e6ab0be5271eb452714208aad136e35df7b1a207`
(`/tmp/plan32-task8-final.tree`). Self-review checked durable-only execution,
selected trigger/version pinning, tenant separation, stale-lease fencing,
queued/running timeout cancellation, retry uniqueness, masking and lifecycle
wiring. No unresolved Task8 issue. The earlier Plan32 relative10% capture-overhead
target remains explicitly **not met**; no broad suites were repeated to fill
waiting time. All runs finished; one sole monitor. Exact commands, failures,
limits and snapshots are retained in
`.superpowers/sdd/2026-11-01-zeroauthy-plan-32-event-streams/task-8-report.md`.

### Task 8 review fix I1 — Terminate cancelled Node executions

Base `956a1b67321e2a74f8299a5fe07371669e978345`. Review correctly found that the
original cancellation test established only a prompt Go return. The runner's
ordinary `CallWith` intentionally left JavaScript running under its watchdog,
whose budget could still be20s rather than the sealed10s delivery deadline.
The original Task8 report's claim that this test proved Node stopped was too
strong. The review overlay and the permanent regressions below demonstrated late
HTTP side effects. This entry corrects that earlier evidence/claim.

Controller-approved repair: additive `CallOptions.Isolated`, enabled only for
`event-stream`. A private one-call Node process is killed and reaped on every
return, including success (detached timers), error, cancellation and timeout.
Shared `CallWith` cancellation and shared tenant processes retain their previous
behavior. The event-stream flow/watchdog is capped by the remaining sealed
context deadline, including capacity wait/startup. Admission allows one isolated
call per tenant and64 per Pool; ref-counted tenant slots are removed after owners
and waiters finish. Isolated children join the Pool's existing live tracking and
Close drain. `api.cache` remains host-managed across jobs; JS globals reset.

Cost/limits: per-attempt Node startup and same-tenant event-stream serialization.
OS process kill/reaping is scheduled work, so waiting for guaranteed exit can add
a small interval after the execution deadline. This is not a real-time wall-clock
guarantee. No JS survives the call's return, but an already-sent network request
cannot be recalled. D-0058 records this local runtime policy. M1 setup-timeout
classification and M2 fixture log noise remain deferred as directed.

- RED: permanent `TestEventStreamExecutionStopsNodeSideEffects` reproduced late
  HTTP requests in all four modes: persisted cancellation, sealed deadline,
  failed storage cancellation, successful return with detached timer. Command
  `ZA_REQUIRE_NODE=1 go test ./internal/actions -run
  '^TestEventStreamExecutionStopsNodeSideEffects$' -count=1 -v`, exit1,
  `/tmp/plan32-task8-fix1-red.log`, `.exit`, session50743. Reviewer overlay RED
  remains `/tmp/plan32-task8-review-late-side-effect.log`, `.exit`.
- Runner RED: `ZA_REQUIRE_NODE=1 go test ./internal/noderunner -run
  '^TestIsolatedCall' -count=1 -v`, exit1 because Isolated option did not exist;
  `/tmp/plan32-task8-fix1-runner-red.log`, `.exit`; completed in initial call.
- Initial GREEN: same permanent side-effect tests plus `TestIsolatedCall`
  selection across Actions/runner, exit0,7 passed leaves,0skips;
  `/tmp/plan32-task8-fix1-green1.log`, `.exit`, session24206.
- Focused race: `ZA_REQUIRE_NODE=1 go test -race ./internal/noderunner
  ./internal/actions ./internal/eventstream -run
  'IsolatedCall|EventStream|ActionDestination|ActionSecrets|ActionExecutionLogged'
  -count=1 -v`, exit0,24 passed leaves,0skips/race reports;
  `/tmp/plan32-task8-fix1-race.log`, `.exit`, session94060. Covers actual late HTTP
  side effects, following job recovery, cache persistence/fresh JS globals,
  concurrent shared call preservation, unchanged default cancellation, tenant
  and global capacity, queued cancellation, Close drain, destination masking and
  failed deliveries. Global saturation is tested through production permits to
  avoid spawning64 Node processes just to test admission.
- Required full suites, started once after final production edits:
  `ZA_REQUIRE_NODE=1 go test ./internal/actions ./internal/noderunner -count=1 -v`,
  exit0,240 passed leaves,0skips/failures; Actions37.249s, runner22.040s.
  `/tmp/plan32-task8-fix1-full.log`, `.exit`, session41386;
  UTC20:17:54–20:18:34. One sole monitor, blocking wait, no repeated quiet run.
  Existing expected invalid-envelope warning and sandbox fixture diagnostics
  remain visible; no new secret-bearing diagnostic was introduced.
- Every Go command exported `GOTOOLCHAIN=go1.26.7`; Node26.8.1 was required,
  with no fallback. Storage/protocol source did not change; no database or broad
  conformance suite was rerun. `git diff --cached --check` passed.

Final implementation tree before documentation-only additions:
`2f51723b66673d8513a923d45e325b47dc4e62db`
(`/tmp/plan32-task8-fix1-implementation.tree`). Full-run source/status preserved
at `/tmp/plan32-task8-fix1-full.snapshot.patch`, `.snapshot.status`.
Self-review checked return/termination boundaries, shared-call isolation,
capacity ownership/release, context/watchdog clamping, live-process shutdown and
cache behavior. I1 has no unresolved finding; M1/M2 remain deferred. All runs
finished. Full task report:
`.superpowers/sdd/2026-11-01-zeroauthy-plan-32-event-streams/task-8-fix1-report.md`.

### Task 9 — Immediate tests, failure inspection and redelivery

Base `90f5693`; task commit recorded by the controller after review.
Implemented Management handlers and generated-route adapters for synchronous test
send, failure list/get and single/batch redelivery. The application injects the
same worker used for background processing, including its durable Actions runner;
no alternate transport/client or undurable runner is created by a handler.
Default transports retain guarded dialing. Focused tests inject a trusted
RoundTripper through the worker's existing constructor.

Validation covers strict duplicate/unknown bodies and queries, catalog types,
failed-only statuses, 50/100 default/maximum paging, anchored IDs, inclusive/exclusive
dates, non-fractional RFC3339 with published maximum20, 404 tenant/event/stream
boundaries, and 409 no-match/already-queued/not-failed conflicts. Queue selection
uses the repository's atomic all-or-nothing operation. Disabled streams accept
redelivery and reject test sends. Public attempts expose duration, status, safe
error class and UTC timestamp; no queue/lease/sealed-secret internals are exposed.

All25 default catalog types pass strict event validation, including deferred
group types with a test-fixture-only valid group-ID substitution. Frozen catalog
constraints and invalid caller-provided group IDs remain unchanged. Test sends
never append outbox/failure records or change stream counters. Given data is
validated before generating trusted tenant context. See D-0058 clarification;
E4 remains unobserved. Corrected Task1's failed-only schema reference on immediate
test outcomes/attempts, preserving failed-only storage/filter enums, then ran
`GOTOOLCHAIN=go1.26.7 make generate`; exit0. Generated files were not hand edited.

Initial RED `go test ./internal/mgmt -run 'SendTestEvent|Deliver|Redeliver' -count=1`
failed exit1 because handlers/dependency were missing. Route RED separately
confirmed unimplemented routes bypassed scope checks. Later focused REDs pinned
unknown nested tenant fields, API success-response schema, missing generated
tenant context and overlong/invalid date offsets. One intermediate minimal-data
fixture omitted catalog-required user fields and was corrected before recording
the intended context RED; the failed intermediate run is retained, not claimed
passing. Full commands, sessions, logs, actual exits and final verification are
in `.superpowers/sdd/2026-11-01-zeroauthy-plan-32-event-streams/task-9-report.md`.

Focused non-race combined API/eventrules/Management/server run passed87leaves,
0failures/skips (`/tmp/plan32-task9-focused2.log`, exit0). Affected app/Management/
server/generated API compile passed (no tests run). Final race command/results
are recorded below after completion. No database tests, broad suites, Node
runtime suites or console build were run for this handler-only task; final
Plan32 acceptance remains Task14.

Task9 final verification: `GOTOOLCHAIN=go1.26.7 go test -race ./api
./internal/eventrules ./internal/mgmt ./internal/server -run
'SendTestEvent|Deliver|Redeliver|EventStream|EventsInventory|SpecsAreValid'
-count=1 -v`, exit0,88passed leaves,0skips/failures/races. API7.288s,
eventrules2.773s, Management27.781s, server6.905s; UTC20:29:26–20:30:12.
Log `/tmp/plan32-task9-final.log`, `.exit`, session77779; sole task monitor,
all commands finished. Includes real server successful test delivery, live
operator revocation, receiver404→204 worker recovery while disabled, full retry
attempt schedule, strict event privacy and actual202 response schema validation.
Expected Management operation fixture INFO/ERROR diagnostics remain visible;
privacy tests check request logs, sapi/fapi records, responses and payloads.
`git diff --check` passed. No outstanding self-review finding; controller review
is still required before Task9 is marked complete in the ledger.

Task9 implementation tree before final documentation-only additions:
`2888495f7b5ae4da9fa4c1776aafdf8173981252` (`/tmp/plan32-task9-implementation.tree`).

### Task 9 fix round 1 — Catalog-valid supplied update test data

Base `002dc0a`; Important I1 addressed. Synthetic test events now construct their
fresh envelope independently from the catalog fixture and supplied data, then
strictly validate and stamp it. They no longer invoke `events.Build`, whose
capture-time mandatory-prior requirement incorrectly rejected catalog-valid
user.updated, organization.updated and connection.updated object-only data.
Absent caller prior stays absent; a valid supplied previous_object is preserved.
The production capture builder and frozen catalog/validator are unchanged.

TDD regression `TestSendTestEventUpdatedData` covers all3 types with literal
schema-valid minimal objects, optional valid prior preservation, actual sent
catalog-valid body/trusted tenant stamps, nested unknown-field400 without a send,
and no outbox/failure/counter mutation. RED focused new test exit1 reproduced
all3 unexpected400s;6valid-prior/strict-rejection cases passed. GREEN same command
exit0,9passed leaves. Logs `/tmp/plan32-task9-fix1-{red,green}.log`, sessions41156
and14417, actual exit files retained.

Final `GOTOOLCHAIN=go1.26.7 go test -race ./api ./internal/eventrules
./internal/events ./internal/mgmt ./internal/server -run
'SendTestEvent|Deliver|Redeliver|EventStream|EventsInventory|SpecsAreValid|^TestBuild'
-count=1 -v` passed143leaves,0failures/skips/races, exit0. API6.957s,
eventrules2.536s, events2.846s, Management27.539s, server6.977s;
UTC20:35:25–20:36:07. Session35662 finished, sole task monitor. All25 default
types and existing capture Build prior-state regressions passed. No DB/broad/
Node-runtime/console suite, dependency or generated file change. Minor M1
expected fixture log noise remains deferred. No additional self-review finding;
controller review pending. Full report
`.superpowers/sdd/2026-11-01-zeroauthy-plan-32-event-streams/task-9-fix1-report.md`;
final log/exit/snapshot prefix `/tmp/plan32-task9-fix1-final`.

Task9fix1 implementation tree before final documentation-only additions:
`f67de8555729c2e9def7c75925e5d693cc169206` (`/tmp/plan32-task9-fix1-implementation.tree`).

### Task 10 — Events API SSE

Base `0dfaf16`; generated SubscribeEvents adapter now enforces `read:events`.
GET `/api/v2/events` bypasses Management response capture and clears the real
HTTP write deadline. A tenant-local semaphore defaults to4; public403 wording
comes from the frozen public OAS `/events` GET403. Existing Auth/live operator
checks run at connect; no extra midstream authorization policy was introduced.

One-second polls read unfiltered settled sequence pages (2s window) in short
transactions with the existing tenant mutation lock, then release before any
network write. Type and inclusive timestamp filters apply during traversal;
progress offsets describe only rows already processed. Timestamp floor remains
active across all pages/future commits, including earlier event-time arrivals.
Connected/retry2000, CloudEvent frames without a0stream/a0purpose, heartbeat15s,
offset-only30s, cycle5min, disconnect/error/timer cleanup are covered. Progress
checks between replay rows prevent heartbeat starvation. Fixed public errors
alone reach responses/diagnostics, including failed capability probes; RED
privacy regressions demonstrated why the generic raw backend error logger
cannot be reused for this route.

Rulings: canonical unpadded base64url decimal nonnegative int64 offsets, max1024;
valid future offsets wait. Last-Event-ID wins over from or timestamp, while the
forbidden from+from_timestamp query pair always400. Timestamp is strict20-character
UTC RFC3339 seconds (including valid Go-zero-time year0001 via an explicit flag).
Expire only when oldest>0 and cursor<oldest-1. Existing repositories have no
watermark when every retained event was purged: explicit cursor validation is
then deferred until a new retained oldest proves expiry (controller accepted;
cost: delayed410). Fresh default/timestamp starts with initially empty retention
bootstrap to first observed oldest-1 because globally allocated sequences may
start above1 for that tenant; events created and fully purged before first
observation cannot be diagnosed without a persisted watermark. No repository
interface or SQL production change was added.

TDD initial missing-handler compile RED exit1; later focused REDs reproduced
raw store/probe diagnostic leakage, zero-time timestamp collision, replay
heartbeat starvation, and fresh-empty tenant false expiry. Intermediate fixture
failures and all failed outputs are preserved in task report. The stronger real
writer assertion caught a test fixture mistakenly requesting `/`; corrected
request `/api/v2/events` verifies capture bypass, immediate flush, delivery after
a50ms server write timeout, and actual response-body disconnect slot release.
Two concurrent append writers are held/serialized beyond settle time and the
Last-Event-ID reconnect returns the second commit once without replaying first.

Final `GOTOOLCHAIN=go1.26.7 go test ./internal/mgmt -run SSE -count=1 -v`
PASS44leaves (exit0,1.371s); race count3 PASS132leaf executions (exit0,8.310s,
0failures/skips/races). Focused server scopes/live-grant/middleware race checks
PASS4leaves (exit0,3.690s); affected app/Management/server/generated compile
PASS with no tests selected. Final race UTC20:49:19–20:49:41, server through
20:49:35, compile through20:49:26. Logs/actual exits/timestamps prefix
`/tmp/plan32-task10-ready-{race,server,compile}`, focused log
`/tmp/plan32-task10-ready-focused.log`; sessions40815/52896/8060/16867 completed,
sole task monitor. Implementation tree before documentation-only additions:
`78d43765fc913ed55f36ddc01fb8bf42f2f89390`.

No DB-backed/broad/Node/E2E/console suite was run; final acceptance remains Task14.
No new dependency or manual generated edit. `git diff --check` passed. Full
commands, failures, skips/rulings and self-review report:
`.superpowers/sdd/2026-11-01-zeroauthy-plan-32-event-streams/task-10-report.md`.
Controller review is pending; no active test run remains.

### Task 10 fix round 1 — Bound blocked transport writes

Base `287a5a7`; Important I1 addressed. Clearing the server write deadline left
synchronous Write/Flush unbounded, so a stalled reader could prevent cycle or
cancellation cleanup and retain its tenant slot. The handler still lifts the
original server deadline, then installs the remaining five-minute cycle deadline
before any SSE I/O. Each send uses the minimum of the original real cycle bound
and translated remaining logical lifetime; no shorter normal-reader timeout was
introduced, and frozen/backward injected clocks cannot extend the real bound.

One watcher owns polling and cycle/cancellation signals while serving is blocked.
It immediately expires the transport deadline and cancels the stream context;
subsequent snapshots use that context. A mutex serializes deadline preparation
with permanent interruption, so a concurrent send cannot undo cancellation.
Deferred cleanup joins the watcher and stops both timers before returning or
releasing the semaphore, preventing a deadline hook from racing response reuse.
In-process nonblocking recorders may lack deadline support; standard net/http
transports provide the required ResponseController capability.

TDD RED `go test ./internal/mgmt -run
'SSE(BlockedTransport|DeadlineHookJoinedBeforeReturn|StalledTCPReaderCycle)'
-count=1 -v` with Go1.26.7 exit1 reproduced all6 regression leaves: blocked
Write/Flush survive both cycle and cancellation, deadline hook absent, real TCP
stalled reader survives cycle. GREEN same command exit0,6 leaves/0skips.
Real net.Pipe regressions verify403 while blocked and capacity reuse after
interruption. Hook-join test holds SetWriteDeadline after the actual write is
interrupted and proves ServeHTTP cannot return until the watcher exits. Actual
HTTP/TCP small-window4MiB replay stalls after headers, then injected cycle expiry
returns the handler/releases resources while the client socket remains open.
Independent native-time regression proves real cycle expiry with backward/frozen
logical clock. Existing50ms server WriteTimeout/later event test remains passing.

Final `GOTOOLCHAIN=go1.26.7 go test ./internal/mgmt -run SSE -count=1 -v`
PASS51leaves (exit0,1.856s); race count3 PASS153leaf executions (exit0,7.503s,
0failures/skips/races). Focused server scopes/live-grant/middleware race checks
PASS4leaves (exit0,2.859s); affected app/Management/server/generated compile PASS
with no tests selected. UTC20:59:37–20:59:55 race, server through20:59:50,
focused/compile through20:59:44. Logs/actual exits/timestamps prefix
`/tmp/plan32-task10-fix1-{focused-final,race,server,compile}`; sessions79419,
97951,84077,43960 completed, sole task monitor, no active process. Implementation
tree before documentation-only additions:
`9cc280bdce8aa562641c3a7dc19d30fcbb5036ae`.

No DB-backed/broad/Node/E2E/console suite or production SQL/API/generated/dependency
change. Prior cursor rulings remain unchanged. `git diff --check` passed.
Full commands, RED/GREEN, resource/clock tests and actual verification results:
`.superpowers/sdd/2026-11-01-zeroauthy-plan-32-event-streams/task-10-fix1-report.md`.
No remaining self-review finding; controller review pending.
