# Plan 31 implementation record

Plan: [Logs, streams and stats](plans/2026-10-30-zeroauthy-plan-31-logs-streams-stats.md).
Spec: [design](specs/2026-10-30-zeroauthy-logs-streams-stats-design.md).
Branch: `plan-31-logs-streams-stats`.
Worktree: `/home/thomas/.codex/worktrees/189f/zeroauthy`.

## Task 1 — contract freeze

Task 1 publishes contract metadata and generated API definitions only. It does
not implement or activate log recording, storage, routes, stream delivery or the
console. The task commit has subject `docs: freeze Plan 31 logs contracts`;
its hash is recorded in the task report/controller ledger after commit.

Public docs reviewed 2026-10-30, without a live Auth0 tenant or vendor account.
The original event-code URL now redirects to /docs/tenant-logs. Its public
catalog exposes 171 factual code/page/category rows; the older filter document
adds eight historical codes. The explicit spec requirement adds local legacy
fapi, yielding 180 rows, 60 Plan 31 emission targets and 120 deferred rows.
Descriptions are original summaries. Every emitted row identifies exact existing
file/function and a conditional outcome; deferred rows identify a roadmap owner
for future reassessment, not a promise to deliver Auth0 cloud or retired features.

The inventory includes all ten explicit Management routes in spec §§5–7,
20 category identifiers, 16 search fields and seven bare-term fields, the log
object shape, eight complete strict sink field schemas, public/secret markings,
resource-specific body allowlists, status rules, vendor request mappings and
limits. D-0057 records all ten §8 local rulings and evidence gaps; the matrix
states that this is contract publication. No new dependency was added and no
generated file was edited by hand.

### Durable rulings carried to later tasks

- Public checkpoint prose is authoritative: from ignores q and all arguments
  except from/take. Task 7's filtered-checkpoint test must verify this precedence,
  not filtered results. take-only recent mode is local.
- Public startFrom is an ISO 8601 datetime, not a log ID. Controller confirmed
  the storage extension `StartFrom time.Time` (memory/SQL/protobuf). The initial
  checkpoint precedes the lowest retained Seq with Date>=StartFrom, or latest
  committed Seq if none matches; worker skips Date<StartFrom while advancing.
  This handles event-time/sequence skew and keeps startFrom absent on reads.
- Two-second settlement alone is insufficient for concurrent writer correctness.
  Task 4 must serialize sequence allocation and commit visibility. Shared ID
  primitives belong to store (avoiding import cycles), with logs forwarding.
- Daily stats default to seven inclusive UTC days and max 366 days, controller
  confirmed as local bounds. Missing dates produce zero counters; provided
  bounds validate as UTC calendar dates. s/ssa/sepft count once per matching
  login flow; code/refresh exchanges do not add another login.
- Global read:logs and user-route read:logs+read:logs_users follow the spec;
  public scope lists do not establish conjunction/alternatives here. Public
  prose q wins over embedded search naming. Exact local error codes, totals
  cap, lower bounds, redaction marker and PATCH-marker preservation are gaps
  explicitly resolved locally, not called observed parity.
- Legacy Hook codes fpurh/fcph remain deferred; Actions failures use
  actions_execution_failed and never masquerade as legacy Hooks.
- Canonical sdu and ublkdu replace provisional du/ubr. scpn means phone change;
  userrules.CheckPatch currently forbids phone changes, so scpn/fcpn await
  Plan 34. No sn or password-notification code is invented. Social failures
  use f; enterprise connector fc remains deferred. fapi is deliberately local
  legacy middleware compatibility because current tables do not list it.
- Sink endpoint credentials can lack sensitive key names: mark all Sumo source
  addresses and HTTP custom-header arrays secret. Public/secret field types,
  required fields and enums are frozen, including Splunk port as string and
  custom headers as {header,value} array. Never disable TLS verification from
  stored splunkSecure. Exact vendor adapter mappings are local; no Auth0 private
  adapter behavior is claimed.
- Emitted means later implementation target, not existing recording. w/fco
  classification remains deferred within Plan 31; deprecation/general Auth API
  limiter signals remain Plan 45. All runtime acceptance and per-code trigger
  tests remain later tasks.

### Commands and actual results

All Go/make commands use `GOTOOLCHAIN=go1.26.7`; host default Go 1.27 was not used.
Node was confirmed by controller as 26.8.1. Plan 19's database hold applies only
while implementing Plan 19; this task is Plan 31.

- Controller baseline `GOTOOLCHAIN=go1.26.7 go test -short ./...`: exit 0;
  all selected packages passed, existing test skips remain skips. Full output:
  `.superpowers/sdd/2026-10-30-zeroauthy-plan-31-logs-streams-stats/baseline.log`.
- RED `GOTOOLCHAIN=go1.26.7 go test ./internal/logrules -run TestLogsInventory -count=1`:
  exit 1, test failed because inventory.json did not exist. This was before
  writing the inventory or rules implementation.
- Additional API RED: focused TestLogsOpenAPIContract failed all ten missing
  operations before adding YAML. Accessor test first failed to compile on
  missing exported functions, then caught a test's invalid index assumption
  (the lexically first catalog row has no triggers); corrected the test to
  choose an emitted row. Initial inventory fill also failed on the guessed
  Execute symbol (actual Action engine function run) and test JSON scope tag;
  corrected these without weakening contract assertions.
- GREEN `GOTOOLCHAIN=go1.26.7 go test ./internal/logrules ./api -count=1`: exit 0
  after the complete inventory, typed accessors and OpenAPI contract were added.
- `GOTOOLCHAIN=go1.26.7 make generate`: exit 0; only generated Management API
  Go changed. Existing schemas are preserved; inserted alphabetical enums and
  compressed embedded spec account for generated diff churn. No hand edits.
- Final verification commands and their results are appended below after they
  complete. Deferred runtime checks are never labeled passing.

### Task 1 final verification and self-review

- `GOTOOLCHAIN=go1.26.7 go test ./... -run '^$'`: exit 0; all packages compile,
  no runtime tests selected.
- `GOTOOLCHAIN=go1.26.7 go test -short ./...`: exit 0 on the contract snapshot
  before the final schema-only corrections. Full output is task-1-short.log in
  the task scratch directory. Existing skips remain skips; this is not Plan 31
  runtime acceptance and is not a PostgreSQL/MySQL service-validation claim.
- Fresh final focused `GOTOOLCHAIN=go1.26.7 go test ./internal/logrules ./api ./internal/gen/mgmtapi -count=1`:
  exit 0 after final contract corrections and generation.
- `GOTOOLCHAIN=go1.26.7 make generate`: exit 0 after final schemas. The generated
  diff adds models, serializers, enum declarations, ten route wrappers and the
  embedded spec; no existing generated type, function or typed constant was
  removed. All pre-existing YAML paths/components compare semantically equal.
  Added YAML uses no anchors, preserving the baseline's reused anchor labels.
- `./scripts/check-sources.sh api/management.yaml`: exit 0, including all new
  operation URLs; all checked source URLs returned acceptable responses.
- `git diff --check`: exit 0.

Self-review caught and corrected two wire-schema defects before commit, each
with a focused failing test first: `$event_schema` must be an object, and the
read schema must accept a marker string for the entirely secret HTTP custom
header array (input remains an array). Read sink schemas are separate, strict
objects with all secret fields restricted to the marker. Cloud-only response
status is restricted to suspended. HTTP endpoint schemas admit http/https so
runtime deployment opt-in can govern insecure local testing; default/public
behavior remains HTTPS. Provenance identifies the upstream HTTPS-only pattern.

A supplementary PyYAML audit initially rejected reused anchor labels already
present in the baseline; a loader honoring the most recent preceding anchor
confirmed every old node was unchanged. No unrelated baseline rewrite was made.

No subagents/reviewers were spawned. Review remains with the controller. Task 1
has no runtime logs store, recorder, parser, management routes, delivery worker,
console, browser or per-code emission test implementation. Dedicated SQL driver,
Logs plugin, race, vendor network and E2E acceptance remains deferred to the
corresponding tasks; none is labeled passing here.

## Task 1 review correction — field projection

Review of `778af39` identified an Important contradiction: page-mode
fields/include_fields could remove log_id/date/type, but the published list
schema required those fields. Added `LogEventListItem`, with the same typed
properties and no required fields, and used it in bare-array and totals-envelope
items. GET-by-ID retains `LogEvent` and its required log_id/date/type.
Regenerated Management API models; the list model uses optional fields with
omitempty, while the full generated LogEvent struct is byte-for-byte unchanged.
No route, provenance URL, privacy ruling or emitter inventory changed. The two
Minor review findings are left to the controller ledger as requested.

Verification, with Go 1.26.7:

- RED `GOTOOLCHAIN=go1.26.7 go test ./internal/logrules -run TestLogProjectionResponseSchemas -count=1`:
  FAIL, both include_user_id and exclude_log_id_and_type rejected by the old
  bare-array and totals schemas because required log_id was missing. Captured
  output: task scratch `task-1-projection-red.log`.
- GREEN same focused command: `ok github.com/zeroauthy/zeroauthy/internal/logrules`.
- `GOTOOLCHAIN=go1.26.7 make generate`: exit 0. No generated hand edits.
- Fresh `GOTOOLCHAIN=go1.26.7 go test ./internal/logrules ./api ./internal/gen/mgmtapi -count=1`:
  exit 0; logrules and api passed, generated package compiled with no tests.
  API checks include provenance completeness and spec validity. No source URL
  changed, so external URL checking was not repeated.
- `git diff --check`: exit 0.

Self-review: both projection modes validate in both list envelopes; full-event
lookup still rejects each incomplete projection and accepts a complete event.
The new schema retains field types, ID/date constraints and strict unknown-field
behavior. Only the Important finding was changed; runtime acceptance remains
with later tasks. Fix commit subject: `fix: allow projected log list responses`.

## Task 2 — scrubber and request value masks

Implemented `internal/logscrub` and wrapped the logger at the start of
`app.New`, before startup logging and before passing it to server components.
The scrubber uses the frozen `logrules.Marker`, normalizes sensitive key names
and matches the complete specified substring list. It clones map/slice values,
walks arbitrary nesting (including JSON objects/arrays encoded inside strings),
uses `json.Decoder.UseNumber`, and accepts exactly one JSON document.

Request value masks inherit immutably, ignore values shorter than four runes,
and merge overlapping matches in the original text. The slog wrapper resolves
LogValuers, scrubs record/bound/group attributes and messages, and applies the
current Handle context even to values bound before the request. JSON-string
values are decoded before masking so escaped passwords cannot evade matching.
Typed maps/slices/structs and RawMessage pass through JSON normalization before
scrubbing. Unsupported values and cyclic subtrees become the marker.

### Task 2 rulings and boundaries

- Ruling: retain bound attributes and group operations inside the wrapper until
  Handle — a background-context scrub during WithAttrs misses request values —
  costs repeated per-record sanitizing instead of eager formatting.
- Ruling: redact the union of overlapping exact-value occurrences and match
  only the original text — avoids suffix exposure and remasking replacement
  text — costs a small match-span collection when values occur.
- Ruling: normalize typed JSON-shaped values, redact unsupported values and
  cyclic subtrees, and preserve shared noncyclic children — handing opaque
  Any values directly to a JSON sink bypasses key policy — may hide unsupported
  diagnostic types and changes typed objects to their JSON-compatible shape.
- Ruling: mask decoded JSON string values while preserving numeric values and
  the frozen marker — replacing the encoded JSON text can corrupt numbers or
  repeatedly wrap markers — numeric values are not treated as free text.
- Strict single-document validation applies to Scrub and to recognizing embedded
  object/array strings. Non-JSON strings remain free text for exact-value masking.
- Install Handler before binding values: the slog interface cannot inspect
  attributes already hidden inside a supplied downstream handler. The production
  serve constructor supplies a fresh unbound text/JSON handler.
- Plan 19's hold does not apply to Plan 31. The app package's existing SQLite
  and plugin tests were run as requested. No new Go dependency was introduced.
- Focused package checks replace another broad suite run under the controller's
  explicit verification scope; the baseline short suite is already green and
  full Plan 31 regression belongs to Task 16. Runtime registration at emitters,
  recorder/store/streams/API integration and E2E acceptance remain later tasks.

### Task 2 commands and actual results

Every Go command used `GOTOOLCHAIN=go1.26.7`.

- Required RED `go test ./internal/logscrub -count=1`: exit 1, no non-test Go
  files in the new package, before production implementation was written.
- Additional RED: TestSlogEmbeddedJSONMasksDecodedValues failed for message,
  direct string, bound string and Any-nested string values with JSON escapes;
  TestNewScrubsServerLogger failed because the unwrapped app logger leaked
  message, bound note and password values. Both passed after their changes.
- Cycle RED: TestScrubValueCyclesFailClosed first failed with a stack overflow
  from recursive native-map traversal; path identity tracking fixed the cause.
  Expanded RED caught invalid json.Number escaping the fail-closed policy;
  scalar JSON validation now also redacts nonfinite floats.
- Additional RED: TestSlogEncodedJSONPreservesNumbersAndMarkers caught encoded
  numeric JSON corruption and repeated marker masking; decoded value masking
  fixed it. TestSlogTypedAndUnsupportedValues caught JSON in error text bypassing
  key scrubbing; error strings now follow the ordinary string scrub path.
- GREEN `go test ./internal/logscrub -count=1`: exit 0 after implementation and
  again after the final scalar handling changes.
- Final `go test ./internal/logscrub ./internal/app -count=1`: exit 0; scrubber
  passed in 0.006 s and app in 9.045 s.
- Final `go test -race ./internal/logscrub -count=1`: exit 0, 1.040 s.
- Final `go test ./internal/logscrub -run '^$' -fuzz FuzzScrub -fuzztime=30s -parallel=4`:
  exit 0, 31.050 s, 517,491 executions, 26 newly interesting inputs. An earlier
  pre-scalar-hardening run also passed (183,098 executions); the final run above
  verifies the finished implementation. Fuzz generation bounds its own shape
  to avoid exponential repeated JSON-string encoding; the scrubber has no local
  depth cutoff and a separate 128-level nested-object/array test passes.
- `git diff --check`: exit 0.

Self-review checked secret-key types and normalization, immutable parent/child
masks and derived loggers, overlaps, JSON escaping, precision, group paths,
LogValuers, error strings, typed JSON and unsupported/cyclic graphs. No agents
or reviewers were spawned by the implementer. Commit subject:
`feat: scrub secrets and passwords before any log sink`.

## Task 2 review correction — dynamic key text

Review of `c24dd35` found an Important privacy escape: a registered password
could appear as a dynamic JSON key, slog attribute name or WithGroup name.
The current Handle context now masks these names, including names in bound
attributes/groups and JSON objects encoded inside strings. SensitiveKey still
checks the original name before masking. Fixed built-in sink field names are
unaffected. The separate Minor marker-in-prose finding is unchanged as directed.

Added reusable public entry points, also documented in the shared plan contract:

```go
func ScrubContext(ctx context.Context, doc []byte) ([]byte, error)
func ScrubValueContext(ctx context.Context, v any) any
```

These apply the original key-name policy and current request's immutable value
mask to keys and values. The JSON entry point retains strict single-document
UseNumber decoding; both handle encoded object/array strings. Later recorders,
console capture, API and stream code should use them where a context is available.
The existing context-free interfaces remain key-name scrubbers.

Ruling: when different original keys mask to one name, replace their values with
one marker member — selecting a winner loses provenance and depends on map order
— hides colliding diagnostic values while preserving public siblings. Slog detects
collisions across bound/record attrs and treats empty-key inline groups as sharing
their parent's namespace; pre-existing duplicate attrs with the same original
name retain their ordinary slog behavior.

Actual verification, all with `GOTOOLCHAIN=go1.26.7`:

- RED `go test ./internal/logscrub -run 'TestSlogMasks' -count=1`: exit 1,
  direct/bound attribute keys, direct/bound group names, Any map keys and encoded
  JSON keys leaked registered text. Corrected the escaped-key fixture to avoid
  accidentally naming the password itself with the sensitive substring secret.
- Public API RED: context tests failed to compile because ScrubContext and
  ScrubValueContext were missing. Implemented the shared helpers and key masking;
  focused package GREEN passed.
- Collision RED: TestSlogDynamicKeyCollisionsFailClosed caught separate inline
  group/attribute collision values surviving. Expanded inline groups before the
  collision pass; GREEN. Self-review RED TestSlogInlineNormalizationResolvesValueOnce
  caught double evaluation introduced by that expansion; retained the resolved
  value so the original diagnostic value remains unchanged; GREEN.
- The first context-fuzz seed run failed because its generator repeatedly encoded
  scalar strings, outside the embedded object/array contract, then asserted that
  the inner secret-key policy applied. Fixed the generator to wrap encoded objects
  in a body object on each level. No production behavior was changed for this
  fixture correction. The interim package/race commands also reported that seed
  failure; final runs below are after correcting the fixture.
- Final `go test ./internal/logscrub ./internal/app -count=1`: exit 0;
  logscrub 0.005 s, app 8.427 s.
- Final `go test -race ./internal/logscrub -count=1`: exit 0, 1.033 s.
- Final `go test ./internal/logscrub -run '^$' -fuzz '^FuzzScrubContext$' -fuzztime=30s -parallel=4`:
  exit 0, 30.094 s, 492,313 executions, two newly interesting inputs. This final
  run follows the last production change. An earlier context-fuzz run passed
  448,512 executions before the single-evaluation correction.
- `git diff --check`: exit 0.

Self-review covered original sensitivity before key masking, escaped JSON names,
immutable caller maps and request contexts, deterministic collisions including
literal marker-name collisions, direct/bound/nested/inline group namespaces, and
public data preservation. No new dependencies, app restructuring or extra agents.
Fix commit subject: `fix: mask registered secrets in dynamic log keys`.

## Task 3 — Logs models and memory store

Implemented the Logs v1 storage interface, event/stat/stream models, unavailable
error and stub, optional context-aware capability probe, and public `pkg/store`
aliases/ID forwards. `Store.Logs()` is available on memory, SQL and gRPC store
views, including transaction views. SQL and gRPC return `ErrLogsUnavailable`
until Tasks 4 and 5 implement them. Their real `TestLogs` conformance wrappers
are registered; they have not been run or represented as passing here.

Memory stores a true 10,000-event ring per tenant, with global monotonic int64
sequences and canonical 56-digit IDs. Event bodies and stream sink/secrets/
filters/PII are copied at inputs, outputs and transaction snapshots. Rollback
restores rings (including an eviction), sequence allocation, stats, streams and
lease/delivery state. Page reads sort Date then Seq; checkpoint/latest reads
sort Seq and gate on commit timestamps. Outer transaction success fixes the
commit timestamp after the callback; nested transactions join that commit and
retain existing savepoint rollback behavior. Tenant deletion removes events,
streams and stats; user deletion retains that user's events. Retention purges
only expired event rows, in bounded batches, leaving daily stats intact.

Daily deltas atomically add per UTC calendar day alongside append; range reads
are inclusive and sparse. ActiveUsers counts tenant users with LastLogin>=since.
Streams support copy-safe CRUD, optimistic admin versions, atomic exclusive
leases, expiry/owner fencing, nondecreasing delivery checkpoints, and admin
updates that invalidate in-flight leases while preserving fresh delivery state.
Resuming resets scheduling/failure state without losing checkpoint or success.

### Task 3 rulings and interfaces carried forward

- Ruling: shared ID primitives are `store.FormatLogID` and `store.ParseLogID`,
  also forwarded by `pkg/store`; Task 6 forwards these from logs — store cannot
  import logs without a cycle — costs preserving these names at later call sites.
  Parse accepts only positive int64 sequences in the canonical 56-digit form;
  malformed/overflowing/cross-tenant IDs read as NotFound.
- Ruling: `store.LogQuery` has Op/Field/Value/Upper strings, Left/Right children
  and lower/upper-exclusive flags. Nil/empty root matches all; and/or are binary,
  not has only Left, and leaves use eq/sw/range — aligns storage, parser and SQL
  without a cycle — costs keeping parser/SQL consistent with this documented AST.
- Ruling: introduce `internal/logsearch/eval.go` and its tests early in Task 3,
  including Validate and Match, rather than a temporary second memory evaluator
  — one implementation owns evaluation — Task 7 still owns parser/SQL and must
  retain/extend the early evaluator/tests. Validation uses logrules fields and
  organization-search bounds (1000 runes, depth 16, five predicates).
- Ruling: admin UpdateLogStream merges only admin fields, retaining latest
  delivery state and create-only StartFrom, increments Version and clears the
  lease — a stale admin snapshot must not rewind a completed delivery — costs
  implementing the same merge rule in SQL and gRPC.
- Ruling (controller approved): paused/suspended→active sets NextAt=now,
  Failures=0, FailingSince zero and LastErrorClass empty; retain checkpoint,
  StartFrom and LastSuccessAt — resume must escape suspension/backoff — store
  now owns documented resume semantics across drivers.
- Ruling: LeaseOwner is a unique token per acquisition, not a stable worker name
  — the existing RecordDelivery signature cannot distinguish successive leases
  that deliberately reuse a token — Task 12 must generate fresh acquisition
  tokens. Expired, replaced, deleted or admin-invalidated leases are fenced.
- Verification is focused on memory/runtime plus all-store compilation as the
  task/controller requests. Full regression remains Task 16; no database test
  was executed for Task 3. No new module, dependency, generated file or agent.

### Task 3 commands and actual results

Every Go command used `GOTOOLCHAIN=go1.26.7`. Captured outputs are under
`.superpowers/sdd/2026-10-30-zeroauthy-plan-31-logs-streams-stats/task-3-*.log`.

- RED `go test ./internal/store/memory -run Logs -count=1`: exit 1, missing
  Store.Logs and storage types, before implementation. After contract/stub
  scaffolding, the same command again exited 1: all eleven then-written real
  conformance cases failed with `store: logs repository unavailable`.
- First implementation run failed only LogsDeleteTenant because its user
  fixture prepends `auth0|` while deletion used bare `u`; corrected the fixture
  reference to u.UserID and aligned the event's UserID with that real user.
  No production behavior was weakened to accommodate the fixture.
- Additional RED `go test ./internal/store/memory -run 'Logs/Logs/LogStreamResume' -count=1`:
  exit 1, resume could not lease because the old future NextAt survived.
  Implemented the controller-approved atomic reset; focused/full Logs GREEN.
- Self-review RED `go test ./internal/logsearch -run TestValidateQueryBounds -count=1`:
  exit 1, six predicates were accepted. Matched the existing orgsearch five-leaf
  bound; GREEN `go test ./internal/logsearch -count=1`, exit 0, 0.004 s.
- Final required `go test ./internal/store/memory -run Logs -count=1`: exit 0,
  0.023 s. All nine required named cases exist, plus transaction rollback,
  boolean queries, StartFrom policy, concurrent leases, resume and admin merge;
  memory-specific tests also verify ring/input-copy/eviction rollback and outer
  commit timestamps with nested rollback.
- `go test ./internal/store/memory ./internal/logsearch -count=1`: exit 0;
  memory 8.542 s, logsearch 0.007 s. This covers the complete memory package;
  the final fixture-only UserID correction was followed by the required focused
  Logs run above. Earlier full memory run also passed (5.404 s).
- `go test -race ./internal/store/memory ./internal/logsearch -run 'Logs|MatchLogQueries|ValidateQueryBounds' -count=1`:
  exit 0; memory 1.146 s, logsearch 1.038 s. Earlier focused Logs race also
  passed (1.133 s). No data race was reported.
- Required `go test ./internal/store/... -run '^$'`: exit 0, compile-only.
  Final expanded compile check `go test ./internal/store/... ./internal/logsearch ./pkg/store ./pkg/storetest -run '^$'`:
  exit 0; SQL/gRPC explicitly report no tests to run. This is not database or
  transport runtime acceptance.
- `git diff --check`: exit 0.

Self-review checked every named case against the brief, ring rotation and
snapshot ownership, outer commit visibility, UTC normalization, date/sequence
ordering, cross-tenant reads/deletion, query rejection and boolean/date/prefix
behavior, lease expiry/takeover/concurrency, stale-delivery fencing, admin merges
and resumed delivery. Controller supplies review; no subagents were spawned.
Commit subject: `feat: add logs storage contract and memory store`.

Deferred/unrun: SQL Logs runtime conformance (SQLite/PostgreSQL/MySQL), gRPC Logs
runtime conformance (memory and SQL backends), SQL scripts, recorder/API/worker,
stream network delivery, browser/E2E acceptance and broad project regression.
SQL/gRPC stubs remain an intentional Task 3 boundary, not passing implementations.

## Task 3 review correction — typed stream sink ownership

Review of `8b1dae6` found an Important deep-copy gap: cloneJSON only recurses
through map[string]any and []any, leaving typed nested maps/slices aliased.
Confirmed that create input, get/list/lease output, update input and transaction
snapshot rollback could all mutate stored sink configuration through typed
[]string, map[string]string and []map[string]string values.

Added a stream-local write-boundary normalization helper. Create and update
marshal the supplied Sink as JSON and decode into fresh ordinary map/slice
containers using UseNumber before acquiring the mutation lock. Snapshots and
read copies can then use the existing JSON clone safely. The unrelated baseline
cloneJSON/cloneJSONValue behavior is unchanged. Invalid/cyclic JSON, unsupported
channels/functions, nonfinite numbers, invalid RawMessage and invalid json.Number
return ErrInvalid before any stream/version/lease change. Typed and native map
cycles and a self-referential slice are covered without panic.

Ruling: stream Sink accepts JSON-serializable values and drivers may normalize
Go types to their JSON meaning — arbitrary serializable typed containers must
not retain caller ownership, and all real sink fields are JSON values — costs
one JSON round trip on create/update and normalized Go representations on reads.
UseNumber preserves exact numeric JSON, including 9007199254740993. The storage
contract now states normalization and ErrInvalid behavior explicitly. Existing
admin merge, resume, lease fencing and transaction semantics are unchanged.

Actual verification (all GOTOOLCHAIN=go1.26.7):

- RED `go test ./internal/store/memory -run 'TestLogsStream(TypedSinkCopies|RejectsInvalidSink)$' -count=1`:
  exit 1. All six ownership boundaries changed the stored sink to "changed";
  all six initial invalid-value cases were accepted with nil error. Full output
  task-3-sink-red.log in the plan scratch workspace.
- GREEN same focused command after normalization: exit 0, memory 0.010 s;
  task-3-sink-green.log. Extended invalid tests then added native-map and
  native-slice cycles; final covering run below includes them.
- `go test ./internal/store/memory ./internal/logsearch -run 'Logs|MatchLogQueries|ValidateQueryBounds' -count=1`:
  exit 0; memory 0.105 s, logsearch 0.011 s; task-3-sink-focused.log.
- `go test -race ./internal/store/memory ./internal/logsearch -run 'Logs|MatchLogQueries|ValidateQueryBounds' -count=1`:
  exit 0; memory 1.152 s, logsearch 1.025 s; task-3-sink-race.log.
- `go test ./internal/store/... ./internal/logsearch ./pkg/store ./pkg/storetest -run '^$'`:
  exit 0; all selected packages compile, SQL/gRPC explicitly have no tests to
  run; task-3-sink-compile.log. No database runtime test was executed.
- `git diff --check`: exit 0.

Self-review verified normalization happens before any mutation, every sink write
uses it, reads/snapshots only see owned ordinary containers, large numeric JSON
retains its exact value, and invalid updates preserve the prior sink, Version
and active LeaseOwner. SQL/gRPC runtime acceptance remains Tasks 4/5; broad
project regression remains Task 16. No subagents or unrelated clone changes.
Fix commit subject: `fix: own typed log stream sink values`.

## Task 4 — SQL log events, streams and statistics

Implemented all SQL Logs methods and migration0028 in SQLite/PostgreSQL/MySQL.
Events/stats write atomically. Sorted tenant row locks precede driver identity
allocation and remain held through outer WithTx commit. A bounded locking read
of the latest tenant committed_at clamps backwards clocks; memory uses the same
nondecreasing timestamp rule, including transaction commit. Added bounded page,
checkpoint/latest and purge queries, stream admin CAS/runtime merge/resume/lease
fencing, daily UTC counters, active-user counts, and tenant cleanup. Stream Sink
JSON reads use UseNumber and all writes/reads own their values. Wide federation
user IDs retain existing capacity (MySQL VARBINARY1280; PG/SQLite TEXT).

Ruling: settlement alone cannot prevent lower-sequence late commits — serialize
per tenant before identity allocation, sorting multi-tenant locks — costs tenant
write contention. The delayed-commit test actually blocks a lower sequence's
outer transaction while separate connections append and poll under an injected
clock. A Go overlay removing the serialization reproduced the PostgreSQL defect.

Ruling: backwards clocks must not let higher sequences settle first — clamp to
max(now,last retained tenant committed_at) using a LIMIT1 locking read — costs
one bounded indexed read per tenant batch; an instance far ahead can postpone
settlement until clocks catch up. Memory clamps direct writes in O(1) per event
and outer transaction commits per retained ring, with explicit pending flags.

Ruling: use full-range fixed-width UTC text timestamps — UnixNano wraps outside
approximately1678–2262 and a numeric zero sentinel aliases epoch — costs wider
indexes. Bind new log/stream/stat times as t.UTC().Format(store.LogTimeLayout),
`2006-01-02T15:04:05.000000000Z`. Go zero is ordinary year0001, epoch is distinct,
and year0000 sorts before it. Shared ValidateLogTimes rejects normalized UTC
years outside0000–9999 in memory and SQL. Existing users.last_login remains
microseconds, so ActiveUsers binds the existing representation. Task7 must use
the shared text layout for event date query parameters.

Ruling: SQL identity rollbacks may consume sequence numbers — the contract is
strictly increasing opaque IDs, not contiguous integers — updated the shared
rollback assertion while retaining absence/state rollback checks. Clients must
tolerate gaps. Ruling: delivery expiry must be measured after stream row locking
— obtaining a connection/savepoint/row lock can exceed remaining lease life —
costs one locking read/transaction. Owner remains a unique caller acquisition
token; stale and expired acquisitions fail ErrPrecondition.

Task4 intentionally adds a temporary logsearch.SQL that validates AST then
matches all. This is the plan's Task7 handoff, not established query parity.
No negative-filtering/API parity claim is made. Broad project/E2E regression
remains Task16; gRPC runtime conformance remains Task5.

Actual verification, all Go commands with GOTOOLCHAIN=go1.26.7:

- RED `go test ./internal/store/sqlstore -run 'Logs' -count=1`: exit1,
  unavailable repository; named migration27/page-bound tests and conformance
  failed. task-4-red.log in scratch workspace.
- RED checkpoint mutation `go test -overlay=<task-4-no-lock-overlay.json>
  ./internal/store/sqlstore -run '^TestLogsConcurrentWritersCheckpoint$'
  -count=1` with a real PostgreSQL DSN: exit1, second connection committed
  before intentionally delayed first commit. task-4-checkpoint-lock-red.log.
- RED expiry-after-wait test: exit1, expired lease accepted before lock/clock fix;
  task-4-delivery-wait-red.log. RED backwards-clock tests: SQL and both memory
  direct/transaction cases exposed higher sequences early;
  task-4-clock-skew-red.log. RED out-of-range-year conformance: memory and SQL
  accepted year -1; task-4-year-range-red.log and task-4-year-range-sql-red.log.
- RED full-range timestamp expansion exposed empty-zero sentinel ordering;
  task-4-zero-time-red.log. Initial microsecond truncation had also failed
  StartFrom/LastSuccessAt equality; task-4-green-initial.log.
- RED real accepted1280-byte user roundtrip via all-driver script (ports56643,
  38895): PostgreSQL22001 and MySQL1406 on tenant_logs.user_id; SQLite passed;
  task-4-wide-id-red.log. Fixed schema capacities before final test.
- Intermediate all-driver failures are retained and explained in full report:
  invalid MySQL CREATE INDEX engine options; PostgreSQL query-spy placeholder
  assertion (including rebinding suffix starting numbering at1); timestamp test
  stats range excluding the extra early-year rows it expected. These were fixed
  and not reported passing. Despite its filename,
  task-4-driver-regressions-green.log is a failing intermediate run.
- Final authoritative command:
  `GOTOOLCHAIN=go1.26.7 ZEROAUTHY_TEST_PG_PORT=56644
  ZEROAUTHY_TEST_MYSQL_PORT=38896 ./scripts/test-sql.sh -v -run 'Logs'
  -count=1 ./internal/store/sqlstore/...`: exit0, SQL75.327s, race enabled by
  script. SQLite PASS, PostgreSQL PASS, MySQL PASS, no skips or race warnings.
  Each driver ran conformance plus migration27, page bounds, delayed-commit
  checkpoint, expiry/precision, timestamp boundaries, expiry after wait,
  backwards clock and wide-ID tests. task-4-sql-authoritative.log.
- `go test -race ./internal/store/memory ./internal/logsearch -run
  'Logs|MatchLogQueries|ValidateQueryBounds' -count=1`: exit0, memory1.224s,
  logsearch1.038s; task-4-memory-search-final.log.
- `go test ./internal/store/... ./internal/logsearch ./pkg/store ./pkg/storetest
  -run '^$'`: exit0; task-4-compile-final.log. Compilation evidence only.
- Focused local SQL/memory race `-run 'Logs|TestLatestVersion'`: exit0;
  task-4-clock-skew-green.log. Final memory optimization separately race checked
  above. `git diff --check`: exit0.

Self-review checked parameterization/tenant scoping, page arithmetic and bound
arguments, sorted locks through outer commit, MySQL locking current reads,
atomic counters/rollback, runtime-preserving stream updates, resume reset,
lease fencing after waits, sink precision/ownership, migrated-versus-fresh table
shape, identifier capacity, pending snapshot state, and user/tenant deletion.
No external evidence or live Auth0 tenant used; no subagents/reviewers spawned.
Controller supplies review. Full report and per-command logs:
`.superpowers/sdd/2026-10-30-zeroauthy-plan-31-logs-streams-stats/task-4-report.md`.
Task4 implementation commit subject: `feat: persist logs, streams and stats in SQL`.

## Task 5 — Logs v1 plugin capability

Implemented all sixteen `store.Logs` operations as additive typed RPCs, with an
independent version1 `LogsCapabilities` negotiation and error kind14. Existing
protobuf field numbers and capabilities remain unchanged; generated bindings
came only from `GOTOOLCHAIN=go1.26.7 make generate`. Transaction clients share
only their Logs capability state and send their held transaction token on every
repository operation; the server consistently dispatches through `Server.with`.
Memory, SQL and gRPC now expose the required `LogsSupporter` shape:
`CheckLogsSupport(context.Context) error; LogsSupported() bool`. The existing
public `pkg/store.LogsSupporter` alias follows that contract automatically.

Only definitive unsupported answers (version0, unknown method or the unavailable
sentinel) are cached by `LogsSupported`. Active operations negotiate once per
call, so transport failures remain retryable and plugin downgrade/upgrade can be
observed without rebuilding the client. The capability RPC does not acquire a
repository lock, avoiding deadlock during a held memory transaction. A backend
that explicitly returns UnimplementedLogs advertises version0.

Ruling: Logs protocol timestamps use `store.LogTimeLayout` UTC text with nine
fractional digits rather than protobuf Timestamp — the established store range
includes year0000, which protobuf Timestamp cannot represent — this costs text
parsing and slightly larger payloads, and is documented in the protocol for
non-Go plugin authors. Year0000, ordinary Go zero, epoch, year9999 and nanos all
survive independently; invalid ranges return ErrInvalid. Optional bytes preserve
nil versus empty event bodies and sealed secrets. Wrapper messages preserve
nil/empty filters and PII fields. Sink JSON decodes with UseNumber, retaining
nested integers and decimals beyond float64 precision.

Actual verification (Go toolchain1.26.7 throughout):

- Initial RED `go test ./internal/store/grpcstore -run Logs -count=1`: exit1,
  missing capability probe and unavailable Logs stub, including real memory and
  SQLite Logs conformance. `task-5-red.log`.
- Initial GREEN same focused command: exit0,0.777s. Expanded named
  `TestLogsCapabilities` matrix (v0/preLogs/v1/transient) and every unavailable
  operation then passed,0.796s. `task-5-green.log`.
- Named capability mutation RED: `go test -overlay=<scratch>/task-5-transient-
  cache-overlay.json ./internal/store/grpcstore -run
  '^TestLogsCapabilities/transient$' -count=1`: exit1, `LogsSupported=false want
  true` when all transient errors were deliberately cached. Actual source was
  unchanged by the overlay. `task-5-capabilities-mutant-red.log`.
- `go test ./internal/store/grpcstore -count=1 -v`: exit0,108.970s. Full
  `TestConformance` (memory,5.77s) and `TestConformanceSQLite` (25.25s) passed,
  including Logs and all preexisting repositories. Existing reflection test
  consumed its normal60s idle-transaction timeout and passed. One actual skip:
  `TestOrganizationsPluginRoundTrip/Organizations/Limits`, whose wrapper cannot
  override Organizations limits. It is not reported as passing; the main
  conformance wrappers do supply that limit setter. `task-5-grpcstore.log`.
- `go test -race ./internal/store/grpcstore -run Logs -count=1 -v`: exit0,
  28.576s, memory+SQLite Logs conformance, capability matrix, full stream state,
  nil/empty bodies/secrets/Sinks/filters/PII, AST and numeric precision passed;
  no skips or race warnings. `task-5-race.log`.
- Final focused `go test ./internal/store/grpcstore -run Logs -count=1 -v`:
  exit0,0.828s; no skips. `task-5-focused-final.log`.
- `go test ./... -run '^$'`: exit0, compilation only, no runtime-test claim.
  `task-5-compile.log`.
- `make generate`: exit0, repeated with generated-file checksum equality:
  both proto Go files OK. `task-5-generate{,-final}.log`.
- `git diff --check`: exit0.

Self-review checked all actual Logs methods/fields, proto number preservation,
independent negotiation/cache transitions, non-Logs compatibility, transaction
routing and rollback, byte and JSON ownership, full timestamp range, AST bounds,
filters/PII, unavailable sentinels and generated-only bindings. No external
source, live tenant, subagent or reviewer was used. Controller supplies review.
No PostgreSQL/MySQL gRPC lane is defined by this package; those drivers were not
run again in Task5. Whole-project runtime/E2E regression remains Task16.
No later task is claimed complete. Full evidence/report is in
`.superpowers/sdd/2026-10-30-zeroauthy-plan-31-logs-streams-stats/task-5-report.md`.
Task5 implementation commit subject: `feat: add Logs storage plugin capability`.

## Task 6 — asynchronous recorder, statistics and retention

Added `internal/logs` Event/Recorder/Nop/FromRequest contracts, forwarding ID
helpers, bounded asynchronous recorder and fenced retention purger. Events are
copied and scrubbed with request masks before admission, including nested JSON,
dynamic keys, descriptions, indexed string columns and Action execution IDs.
No request context is retained. Tenant names are looked up only by the writer,
once per tenant per batch. Batches contain at most 100 events and partial batches
write every 250 ms. Stats mappings come from `logrules.Codes` and the UTC-day
counter deltas accompany events in the same atomic `AppendLogs` call.

Record performs no store/tenant lookup and no synchronous logger operation.
Queue overflow, invalid admission and failed writes increment the exposed dropped
counter. A separate bounded notification worker emits at most one warning per
minute, using the injected clock, even while AppendLogs is blocked. Failed batches
are not retried. Missing Logs capability falls back to the scrubbed server logger;
transient capability errors drop only the affected batch and later batches probe
again. The first batch error remains available to shutdown callers.

`Flush` is terminal: it closes admission, waits for queued and in-flight batches,
and reports storage errors. A deadline cancels ongoing backend work; late Record
calls drop without waiting. Concurrent Run/Record/Flush are covered by race tests.
Run cancellation performs a bounded shutdown flush. App Serve starts the recorder
and hourly purger, drains HTTP/other workers before final flush, and App Close
also flushes before closing storage. Emitter dependency wiring remains later tasks.

Configuration adds `logs.retention` (30 days default, minimum 24h),
`logs.queue_size` (10,000 default, positive), and both explicit stream transport
flags (false by default). Environment/YAML loading and unknown keys are tested.

Ruling: reuse the existing TLSAssets fenced lease repository under the distinct
`logs/retention` namespace (certificate resources use `domain/` and `hosted/`).
There is no exported generic leader helper. Sweep renews the lease between bounded
1,000-row deletion transactions and checks the fence inside each transaction.
This preserves ownership through deletion across current memory, SQL and gRPC
stores. Cost if wrong: a plugin implementing Logs without the older TLS lease
capability cannot purge; it logs an hourly warning and other features continue.

Ruling: Flush permanently closes admission, rather than being a temporary drain
barrier. This makes concurrent admission/in-flight completion precise for shutdown.
Cost if wrong: a future caller wanting a reusable drain barrier needs a separate API.

Actual verification (all commands use `GOTOOLCHAIN=go1.26.7`):

- RED `go test ./internal/logs ./internal/config -count=1`: exit 1, missing
  Recorder/Event/Config symbols and missing config.Logs (before implementation).
- RED `go test ./internal/logs ./internal/app -run 'TestPurge|TestRecorderMissing|TestAppCloses' -count=1`:
  exit 1, missing NewPurger/lease key/app recorder field (before wiring).
- RED `go test ./internal/logs -run TestPurgeUnavailableWarningRate -count=1`:
  exit 1, observed zero unavailable warnings; added hourly suppression.
- RED strengthened `go test ./internal/logs -run '^TestRecorderNeverBlocks$' -count=1`:
  exit 1, warning could not run while AppendLogs blocked; separated notification
  handling from the writer. The earlier test setup overflowed before blocking,
  so it was corrected to fill exactly one initial batch before testing overflow.
- RED `go test ./internal/logs -run '^TestRecorderScrubsExecutionEnrichment$' -count=1`:
  exit 1, enrichment reintroduced a masked `actions` key; moved enrichment before
  the complete document scrub, preserving caller immutability.
- Final GREEN `go test ./internal/logs ./internal/app ./internal/config -count=1`:
  exit 0; logs 0.334s, app 4.846s, config 0.007s.
- Final race `go test -race ./internal/logs ./internal/app ./internal/config -count=1`:
  exit 0; logs 1.436s, app 10.388s, config 1.029s.
- `git diff --check`: exit 0. Self-review checked all new files and integration
  changes; no generated files/dependency pins changed.

The named behavior tests cover bounded/full queues, 1,000 Record calls within
50ms while the store is blocked, warning rate/DB-busy responsiveness, immutable
scrubbing, UTC statistics, batch size/delay, per-batch tenant cache, blocked tenant
lookup, queued/in-flight/deadline/error shutdown, concurrent admission/flush,
capability fallback/recovery, ID/request helpers, retention cutoff and lease
contention/release. App tests cover both Close and Serve shutdown flushes.

Unrun: broad repository/SQL-driver conformance/browser/stream/emitter regression
suites; final regression remains Task 16. The required focused app suite did run
its existing SQLite/plugin checks. No deferred or unrun check is called passing.

### Task 6 review fixes — asynchronous masking and semantic statistics

Review of commit `4799d67` identified two Important defects. Both were reproduced
before changes: a registered value `acme` leaked through asynchronously loaded
`tenant_name` in stored and fallback server bodies, and registered `leak` masked
`pwd_leak` before classification, incorrectly leaving LeakedPasswords at zero.

Added `logscrub.DetachedScrubber(ctx)`, which copies only immutable registered
mask strings into a scrub function. It captures no request context, cancellation
or unrelated context values. Its calls reuse ScrubValueContext, including
secret-key, dynamic-key and encoded-JSON handling. Each queued event carries its
own snapshot so cached tenant lookups can safely serve events with different
masks. The writer masks the tenant-name value before the final sink scrub;
`tenant_name` remains a fixed schema key. Tests explicitly assert no request
context reads occur after Record, and that one batch lookup preserves distinct
masked/unmasked values for separate events in both storage and fallback logging.

Statistics classification is now captured from the original event type before
privacy masking. Only the frozen semantic StatsKind is queued; the original
unmasked event code is not retained for statistics. Public body/indexed type
remain masked, while the original semantic daily counter still increments in
the same AppendLogs call.

Actual verification, all under `GOTOOLCHAIN=go1.26.7`:

- RED `go test ./internal/logs -run 'TestRecorderScrubsAsyncTenantName|TestRecorderStats' -count=1`:
  exit 1; both tenant-name sink tests showed `acme`, and the UTC fixture had
  LeakedPasswords:0 instead of 1. Output: `task-6-review-red.log`.
- RED `go test ./internal/logscrub -run '^TestDetachedScrubber$' -count=1`:
  exit 1, missing DetachedScrubber before implementing the helper. Output:
  `task-6-review-red-detached.log`.
- GREEN `go test ./internal/logscrub ./internal/logs ./internal/app ./internal/config -count=1`:
  exit 0; logscrub 0.015s, logs 0.350s, app 5.094s, config 0.009s.
- Race `go test -race ./internal/logscrub ./internal/logs ./internal/app ./internal/config -count=1`:
  exit 0; logscrub 1.032s, logs 1.455s, app 13.465s, config 1.037s.
- `git diff --check`: exit 0. Reviewed only the two fixes, helper and regression
  tests; no feature scope, dependency or generated-file changes.

Ruling: retain detached immutable mask metadata alongside already scrubbed queued
JSON so asynchronous enrichment can use the original masks without retaining
request contexts. Cost: each queued event holds a cloned mask list until its
batch is written; this remains bounded by the existing queue/batch sizes.
Earlier statements that events are scrubbed before enqueue still hold for event
JSON; detached masking metadata intentionally contains the values needed to
scrub enrichment. No such metadata reaches storage or fallback output.

Broad/final regression suites remain unrun and assigned to Task 16. The exact
review was copied to the plan scratch `task-6-review.md`; detailed fix output is
in `task-6-review-{red,red-detached,green,race}.log`.

### Task 7 — log search and Logs API

Implemented the inventory-backed bounded Lucene parser and replaced Task 4's
match-all SQL placeholder with parameterized SQLite/PostgreSQL/MySQL predicates.
The existing SQL repository already calls this translator for bounded page and
checkpoint queries, so no repository read-path rewrite or tenant hydration was
needed. The store-owned AST and earlier Match/Validate remain the shared contract;
no duplicate AST package was introduced. Search covers boolean precedence, NOT,
field groups, quoted/bare literals, escaped literals, trailing prefixes, and UTC
date ranges. Date-only inclusive upper bounds cover their full UTC day; SQL binds
all dates using store.LogTimeLayout with nine fractional digits. JSON extraction
accepts string properties only, missing/null/non-string properties have memory
semantics, NOT is two-valued, LIKE metacharacters are literal, and prefix matching
is case-sensitive across all three drivers. MySQL's BLOB body is explicitly
converted to utf8mb4 before JSON extraction.

Added tenant-scoped ListLogs/GetLog/UserLogs, bounded pagination, projection,
capped totals, settled checkpoint reads, safe errors and capability 501. Final
responses use ScrubValueContext and preserve JSON numeric precision. Canonical
server-assigned log_id is attached after body scrubbing, keeping cursors intact
when registered masks overlap digits. User logs require a currently present
user; missing/deleted/cross-tenant users return this route's not_found rather
than the general Users API's inexistent_user code. Authentication registration
uses existing scopedAll (read:logs; both read:logs and read:logs_users for user
logs). Both scopes are registered in tenantsetup's Management API scope catalog.

Rulings and costs:

- The generated GetLogs wrapper binds typed page parameters before delegation,
  which incorrectly rejects ignored invalid values in checkpoint mode. The real
  server replaces that one GET route after generated registration using the same
  router middleware and scopedAll check, with raw query binding in ListLogs.
  A real seeded server regression proves invalid ignored parameters return200;
  unknown parameters and repeated from/take still return400. Known ignored
  parameters may repeat. Cost: direct consumers of the generated handler outside
  server.New retain generated binding behavior; our application uses server.New.
- Inventory's 56-decimal cursor shape is narrowed to store.ParseLogID's canonical
  positive int64 sequence representation. Zero/overflow 56-digit cursors return
  invalid_query_string400. Controller explicitly accepted this local gap; a
  wider cursor domain would need API saturation or a wider storage sequence.
- Nil/empty Body is accepted by the repository contract. SQL JSON expressions
  treat it as an empty object, matching memory's missing-field behavior. Invalid
  nonempty/non-object Body was previously accepted incidentally, despite the
  documented Auth0-object JSON contract. Controller ruled to reject it atomically
  with store.ErrInvalid using shared ValidateLogEvents in memory and SQL, rather
  than mutate bytes silently or require PostgreSQL16 IS JSON. Cost: callers that
  supplied malformed/scalar/array payloads must now provide object JSON. Earlier
  already-persisted malformed nonempty bodies are outside that contract and not
  repaired; no released Plan31 data migration is needed. Empty-body parity and
  shared batch/stats atomicity tests cover this correction; gRPC delegates to the
  same backend validation.
- No generated source or dependency pins changed. Existing generated route and
  optional list projection schemas already cover these handlers. Full repository
  regression stays in Task16, as instructed; this is Task7 only.

Actual verification (all Go commands use GOTOOLCHAIN=go1.26.7):

- RED `go test ./internal/logsearch ./internal/mgmt -run 'LogSearch|LogsAPI|UserLogs|LogsCross|LogsUnavail' -count=1`:
  exit1, missing Parse and Logs handlers before implementation. A test-only
  RequireAll typo was corrected to composition of the existing Require helper.
- RED `go test ./internal/store/sqlstore -run LogSearch -count=1` against the
  original match-all translator: exit1, requested searches incorrectly returned
  every tenant row, demonstrating real memory/SQL parity assertions.
- RED real-server route tests first exposed absent Management API scopes, then
  generated page binding rejected ignored page=bad. Both failures were fixed.
- RED parser/API regressions rejected unknown-field bypass (`unknown:(type:f)`)
  only after field-group validation was added. Additional RED tests observed
  inexistent_user rather than not_found for deleted users, and a registered
  cursor value replacing log_id. Both are fixed and covered.
- Three-driver verification initially failed MySQL with error3144 (binary BLOB
  JSON input). After the conversion change an overly broad text replacement
  temporarily put MySQL syntax in SQLite; the subsequent run exposed this and
  it was restricted to the MySQL branch.
- RED body validation: `go test ./internal/store/memory -run '^TestLogs$/Logs/LogsBodyValidation$' -count=1`
  failed because malformed JSON returned nil; SQLite LogSearch failed with
  malformed JSON for an accepted nil-body event. Shared validation and guarded
  empty-body extraction fixed both. Final memory `go test ./internal/store/memory -run '^(TestLogs|TestLogsRingRollbackAndCopies|TestLogsCommitTimestampAndNestedRollback|TestLogsBackwardsClockCheckpoint)$' -count=1`:
  PASS0.026s, covering Logs conformance plus selected ring/commit/clock checks.
- Final GREEN `go test ./internal/logsearch ./internal/mgmt -run 'LogSearch|LogsAPI|UserLogs|LogsCross|LogsUnavail' -count=1`:
  PASS (exact package times retained in task-7-green.log).
- Final GREEN `go test ./internal/server ./internal/tenantsetup -run 'LogsAPI|ManagementAPI' -count=1`:
  PASS (route/scope catalog regression, task-7-route-green.log).
- `go test ./internal/logsearch -count=1`: PASS0.005s, including prior evaluator
  and AST validation tests as well as the new parser tests.
- Final `ZEROAUTHY_TEST_PG_PORT=56437 ZEROAUTHY_TEST_MYSQL_PORT=54317 ./scripts/test-sql.sh -v -run 'LogSearch' -count=1 ./internal/store/sqlstore/...`:
  PASS8.039s with -race, all three drivers. Checks the six
  required queries plus literal wildcards, case, NULL/missing/non-string JSON,
  NOT, bare terms, precedence, nanosecond boundaries, tenant isolation, matching
  totals and both checkpoint repository methods. TestLogSearchBodyValidation
  also passed PostgreSQL/MySQL/SQLite, proving invalid batch and statistics
  atomicity. No driver skipped.
- Final `go test ./internal/logsearch -run '^$' -fuzz FuzzLogQuery -fuzztime=30s -parallel=4`:
  PASS30.091s, 2,959,995 executions. This is an actual FuzzLogQuery target;
  an earlier full30s run also passed before the field-group validation change.
- Self-review covered parser bounds/precedence, SQL placeholder/value ordering,
  dialect JSON types and LIKE escaping, tenant scopes, capability/error mapping,
  route replacement, final response scrubbing and numeric precision.
  `git diff --check`: PASS. Feature commit subject: `feat: search and read tenant logs`.

Unrun: broad suites, full SQL store conformance, gRPC/plugin regression, browser,
SDK and CLI end-to-end checks; those are reserved for Task16. None is claimed
passing. Task7 report and complete local command output are in the plan scratch
workspace (`task-7-report.md`, `task-7-*.log`).

### Task 7 review fix — accepted JSON search parity

Review of `1aef951` found that valid object JSON accepted by AppendLogs could
poison body-field SQL searches: PostgreSQL jsonb rejects escaped NUL, unpaired
surrogates and numbers outside its numeric range, even in unrelated details;
MySQL rejects lone surrogate escapes; SQLite disagreed with Go's replacement
character semantics. `json.Valid` is deliberately broader than these database
JSON domains. Rejecting these bodies would narrow the valid JSON contract, and
changing jsonb to json would still fail searched-field Unicode extraction.

Controller approved a materialized, ASCII-only search projection. New shared
`logsearch.BodyFields` uses Go JSON decoding with UseNumber and the frozen
inventory to extract supported string fields; Match uses the same helper.
SQL Append stores these values as UTF-8 hex strings in a separate searchable_body
JSON document. SQL extracts only that safe projection and hex-encodes parameters
for body fields; hex preserves byte equality and prefix behavior, including NUL
and Go's replacement character for lone-surrogate escapes. Missing/non-string
values are omitted; empty strings are retained. Physical indexed columns keep
their original predicates. Original Body bytes, timestamps, cursors and public/
gRPC interfaces are unchanged, and read queries remain bounded in SQL.

Added migration0029 rather than altering already-applied0028. Each dialect adds
one searchable_body column (TEXT, MySQL LONGTEXT). The Go migration hook backfills
100 rows per batch ordered by seq, respecting gaps and preserving original
bytes. PostgreSQL/SQLite include DDL, backfill and version marker in one
transaction. MySQL uses the existing resumable DDL mechanism, generalized from
custom-domain migrations: its column DDL may already exist, then backfill and
version marker commit atomically. Upgrade tests cross the batch boundary with
103 rows and simulate a MySQL process stop after implicit-commit DDL.

Ruling/cost: projection storage adds roughly twice the UTF-8 size of the selected
string values plus JSON syntax, and Append/migration decode those selected values
in Go. This avoids database Unicode/numeric restrictions without rejecting valid
object JSON, mutating original bodies, raising the PostgreSQL14 minimum, or
hydrating a tenant on reads. Migration numbering now ends at29; all migration
sets and LatestVersion tests agree. No generated files or dependency pins changed.

Actual verification, all under GOTOOLCHAIN=go1.26.7:

- RED `ZEROAUTHY_TEST_PG_PORT=56437 ZEROAUTHY_TEST_MYSQL_PORT=54317 ./scripts/test-sql.sh -v -run 'LogSearchAcceptedJSON' -count=1 ./internal/store/sqlstore/...`:
  FAIL3.636s. PostgreSQL raised22P05, MySQL3141, and SQLite returned the wrong
  lone-surrogate result. Fixtures include escaped NUL/lone surrogate in unrelated
  details and searched strings, huge exponent and a150000-digit number, and a
  non-string searched number. Bodies were accepted and byte preservation checked.
  Output: task-7-review-red.log.
- RED `go test ./internal/store/sqlstore -run LogSearchMigration29 -count=1`:
  FAIL0.084s, version remained28 before adding the migration/backfill.
  Output: task-7-review-migration-red.log.
- GREEN `ZEROAUTHY_TEST_PG_PORT=56437 ZEROAUTHY_TEST_MYSQL_PORT=54317 ./scripts/test-sql.sh -v -run 'LogSearch|TestLogsMigrationFrom27|LatestVersion|MigrationSetsMatch' -count=1 ./internal/store/sqlstore/...`:
  PASS22.320s with race detection, all three drivers and no skipped driver.
  Existing parity PASS3.60s; accepted JSON parity PASS3.84s; body validation
  PASS3.39s; 28→29 migration/backfill/resume PASS3.62s; 27→29 upgrade PASS6.81s;
  migration set/version checks PASS. Output: task-7-review-sql-green.log.
- GREEN `go test ./internal/logsearch ./internal/mgmt ./internal/store/memory ./internal/server -run 'LogSearch|MatchLog|LogsAPI|UserLogs|LogsCross|LogsUnavail|^TestLogs$' -count=1`:
  PASS logsearch0.009s/mgmt0.927s/memory0.015s/server0.263s. Includes memory Logs
  conformance and the previously implemented API/parser/scope regressions.
  Output: task-7-review-green.log.
- Self-review checked all projection fields against inventory, parameter encoding
  for mixed bare/indexed/body queries, exact bytes/prefixes, safe database input,
  bounded backfill queries, row cursor closure before updates, migration version
  consistency and MySQL resumability. `git diff --check`: PASS.

Parser fuzz was not repeated: parser code is unchanged, the earlier actual30s
run remains recorded, and controller explicitly limited the review verification
to focused regressions and all-driver parity. Broad/final regression, full SQL
conformance and gRPC/browser/SDK/CLI suites remain Task16 work and are unrun here.
Review fix commit subject: `fix: preserve accepted JSON log search parity`.

## Task 8 — authentication and hosted-page events

Implementation: `48fac15` (`feat: log authentication events`), based on `de1f267`.
The task report and complete code-to-test matrix are in
`.superpowers/sdd/2026-10-30-zeroauthy-plan-31-logs-streams-stats/task-8-report.md`.
All 47 inventory trigger/code pairs in Task 8 (36 distinct codes) are mapped.
Session, hostedlogin, devicecode, federation and customdb have no direct emitted
inventory targets; federation/customdb privacy paths are tested without inventing
codes. Actual app/server recorder injection, login/signup/reset/verification,
OAuth grants/device/PAR/revocation, protection and organization outcomes are wired.
Recording remains separate from business writes and queue overflow preserves login.

Privacy integration registers passwords, effective passwords, OTPs and tickets
before scripts/Actions. Real custom-database script tests verify stored events,
slog output, encoded JSON/dynamic keys, late output and password prefixes cut by
the runner. Short credentials cannot rename protocol fields or corrupt generated
Action links. Dynamic Details are scrubbed before explicit server ExecutionIDs are
attached; canonical-looking input credentials remain masked. Strategy types reuse
the existing federation classification, and unavailable attribution stays omitted.

Rulings and costs:

- Retain generic WithValues' four-rune minimum and add WithCredentials for every
  nonempty submitted credential. Preserve fixed event schema names, generated
  timestamps/catalog types and provenance-proven generated execution links;
  mask input-derived names/values. Cost: explicit schema/source trust boundaries
  must remain intact when future fields or emitters are added.
- Stage membership additions until the outer authentication/user transaction
  commits. Existing SQL GetConnection already takes the tenant policy lock before
  the membership precheck; memory transactions serialize too. Cost: callers of
  EnsureMembership must use the staging boundary to emit success after commit.
- Reject logging-only denial Blocks reads. Return optional DeniedKinds from the
  existing atomic admission, with additive protobuf field 8. Unknown old-plugin
  attribution omits uncertain blocking events without changing authentication.
- Reject the proposed invitation IsMember read solely for logging. Optional
  OrganizationMembershipWriter.AddMembersResult reports actual INSERT rows from
  the existing write, through native stores and an additive gRPC report_inserted
  request flag; public aliases/forwarder are exported. SQL INSERT SELECT WHERE NOT
  EXISTS works with MySQL ClientFoundRows=true. Old repositories/plugins retain
  writes but omit uncertain member-added events until upgraded.
- Return confirmed breach hit separately from admission error, retaining existing
  wrappers. Notify-only hits produce the inventoried leak event; clean passwords
  and unavailable checkers do not fabricate hits. The deferred admin warning is
  replaced by actual outcome events, not a new notification code.
- Carry only already-resolved attribution and available synchronous Action IDs
  in request contexts. The trace is bounded to 128 IDs. Federation's OnResolved
  observer receives immutable event fields, no transaction/profile/config objects
  or new reads. Full Actions jobs/console capture remain Task 10.
- Customdb retains detached masks for its existing process lifetime to protect
  late output, mirroring configuration-rotation masking. Cost: conservative
  over-redaction and mask state growth with distinct submitted credentials until
  the runner process retires; no request cancellation/context values are retained.

Verification (all Go/make commands used `GOTOOLCHAIN=go1.26.7`):

- Required ten-package `go test ... -run 'Event|Masked|RecorderFull' -count=1`
  initially failed on missing recorder interfaces. Dedicated behavior REDs also
  demonstrated missing reset/verification events, malformed short-mask schemas,
  lost callback attribution, upstream credential-prefix disclosure, unwanted
  attribution reads, missing atomic membership reports, generated-ID corruption
  and untrusted Details provenance. Each has a focused GREEN log in task scratch.
  One early test-literal typo and one overlapping outcomes log were corrected;
  clean dedicated RED logs are the report's authoritative evidence.
- Final exact focused command (login/oauth/dbconn/session/hostedlogin/devicecode/
  protection/orglogin/federation/customdb): PASS, exit 0,
  `task-8-accepted-focused.log`. Session/hostedlogin/devicecode correctly report
  no selected tests because there are no direct targets there.
- `make generate`: PASS; `task-8-generate-final.log`. Store protobuf was generated,
  never hand-edited. Focused native/SQLite/memory-gRPC/SQLite-gRPC membership,
  admission, privacy, schema and execution provenance tests: PASS.
- `ZEROAUTHY_TEST_PG_PORT=55631 ZEROAUTHY_TEST_MYSQL_PORT=53531
  GOTOOLCHAIN=go1.26.7 ./scripts/test-sql.sh ./internal/store/sqlstore
  -run '^TestMembershipWriteResult$' -v`: PASS under race detector on actual
  PostgreSQL, MySQL and SQLite; `task-8-membership-sql-three-drivers.log`.
  MySQL's driver sets ClientFoundRows=true, so the exact no-op report is covered.
  Ports and database environments were scoped to this command.
- Initial required internal short suite failed only TestRecorderStats and
  TestAdminNotificationStillDeferred: obsolete expectations for masking static
  catalog codes and retaining the deferred warning. Tests were updated to the
  approved contracts; a full short run then passed 70 packages.
- Final self-review caught enterprise strategies labeled social, an invented
  discovery strategy and fv's omitted known identity strategy. Dedicated tests
  failed first, then passed using existing classification and identity data.
- Final `go test ./internal/... -count=1 -short`: PASS, exit 0, 70 tested packages,
  after those corrections; `task-8-accepted-internal-short.log`.
- `go test ./pkg/store -count=1`: PASS; final `git diff --check`: PASS.
- Existing skip reproduced explicitly: grpcstore
  TestOrganizationsPluginRoundTrip/Organizations/Limits skips because the raw
  plugin client cannot override Organizations limits; `task-8-known-skip.log`.
  No Task 8 behavior test was deliberately deferred; real Node v26.8.1 scripts ran.

No full browser/E2E, stream delivery or final Actions troubleshooting regression
is claimed here; those remain later plan tasks/Task 16. Broader PostgreSQL/MySQL
suites were not run in Task 8 beyond the new membership write contract. The full
internal short suite exercised native/SQLite-backed paths. Controller review is
pending; implementation self-review found no remaining task-level blocker.

### Task 8 focused correction — bounded customdb mask retention

This correction supersedes Task 8's earlier accepted lifetime-growing customdb
mask-state limitation. The controller chose bounded process muting, without a
noderunner/request-ID or JavaScript protocol redesign. Configured values and
request masks now share one actual distinct allowance: at most 256 nonempty
values and 64 KiB plaintext payload per process (not exact allocator overhead).
Values are detached; no request context or per-connection history is retained.
A no-copy logscrub iterator lets admission stop at the first excess value instead
of cloning a large request list or copying lifetime history.

One absolute timer starts at the first admitted sensitive value. At 60 seconds,
or whenever admitting a new value would exceed either cap, the process permanently
stops admitting all stderr/captured console diagnostics, physically clears its
mask/redactor state, and cancels its timer. Retirement also clears and cancels.
There is no evict-and-log/raw fallback. Old configured values after rotation and
passwords cached in script globals remain protected across later requests.
Business results and error kind/code/message continue unchanged. Small policy
limits and injectable clock/timer hooks are internal only; public config is unchanged.

Cost/ruling: a sensitive busy process provides only its initial diagnostic window,
possibly shortened by capacity, and process-wide masks can over-hide other
connections' output. The controller also ruled that arbitrary slog handlers run
outside the mask mutex, with Background and already-safe strings: no new diagnostics
are admitted after muting, but an already-scrubbed in-flight line may finish.
A blocked handler must not delay physical clearing or business admission.

Verification used `GOTOOLCHAIN=go1.26.7` throughout:

- Behavioral RED against the original code: `go test ./internal/customdb
  -run TestRunnerBoundedMasksMuteAtCapacity -count=1` failed on call 256 continuing
  captured output with a cached first password; task-8-bounded-red.log.
- Final-review RED: the real-Node blocked-handler test failed with
  `slow stderr handler blocked physical mask clearing`; it passed after releasing
  the mutex before handler emission. See task-8-bounded-blocked-logger-red.log.
- Final `go test ./internal/customdb ./internal/logscrub -count=1`: PASS, exit 0;
  task-8-bounded-final-green.log. Final `go test -race ./internal/customdb
  ./internal/logscrub -count=1`: PASS, exit 0; task-8-bounded-final-race.log.
- Required ten-package Task 8 command (`go test ./internal/login ./internal/oauth
  ./internal/dbconn ./internal/session ./internal/hostedlogin ./internal/devicecode
  ./internal/protection ./internal/orglogin ./internal/federation ./internal/customdb
  -run 'Event|Masked|RecorderFull' -count=1`): PASS, exit 0;
  task-8-bounded-final-focused.log. Session/hostedlogin/devicecode have no selected
  tests. Real Node tests ran; no customdb/logscrub test was skipped.
- `go test ./internal/... -count=1 -short`: PASS, exit 0, 70 tested packages;
  task-8-bounded-final-internal-short.log. The required focused command and this
  short suite preceded the final narrow log-lock adjustment; final full customdb/
  logscrub and race checks include it. Controller accepted those focused final
  checks without repeating the full short suite. Ordinary nonverbose short output
  does not enumerate individual skips; environment/short-gated external driver
  tests are not claimed.
- Tests include a 270-call live-process loop with count/byte checks, combined
  config/password capacity, oversized metadata and payload, cached credentials
  and rotated configuration in capture/stderr, unknown/unstructured output,
  exact short masks, deterministic physical expiry without lookup, real quiet
  process timer expiry, cancellation/watch safety, retirement/timer races, and
  business success/error behavior after muting. Existing late30ms, 200ms rotation,
  JSON keys and truncation regressions remain green.
- `git diff --check`: PASS. No dedicated noderunner/Actions rerun was needed since
  their code and Prepare API are unchanged; their short tests ran in the suite.
  No full PostgreSQL/MySQL script, browser/E2E, generated build, or Task 16 final
  suite was run for this correction. No new behavior test is deferred.

Full focused report: `.superpowers/sdd/2026-10-30-zeroauthy-plan-31-logs-streams-stats/task-8-bounded-report.md`.

### Task 8 review privacy correction — overlapping console masks

Review found that configuration replacement preceded credential matching in
customdb process output and Client.Try capture: configuration `middle` could turn
password `prefix-middle-suffix` into `prefix-■■■■■■■■-suffix`, defeating the full
credential match and exposing fragments. This pass addresses only that console
privacy finding; other review groups are separate.

Console masking now collects full and potentially truncated-prefix matches for
both groups from original text, then replaces their merged spans. A configuration
match that covers the entire span retains the configuration marker; an extending
credential masks the full union with logscrub.Marker. Identical configured/masked
values retain the configuration marker. Decoded JSON dynamic keys/values use the
same policy, with existing original secret-key and key-collision protection.
Process stderr/capture and independent Client.Try OnLogs share this helper.
Business result/profile and error behavior, and all 256-value / 64-KiB /
60-second retention/muting/timer rules, remain unchanged. There is no raw fallback.

All commands used `GOTOOLCHAIN=go1.26.7`:

- RED: `go test ./internal/customdb -run 'CredentialConfigurationOverlap'
  -count=1` failed with leaked credential prefixes/suffixes in process capture,
  real Node output, Client.Try capture, truncation and escaped dynamic JSON;
  task-8-composition-red.log.
- The initial full focused normal/race runs also found the existing
  TestTryMasksConfigurationValues marker-compatibility expectation failing.
  Preserving a covering configuration span's marker fixed it; no existing test
  assertion was weakened or changed.
- `go test ./internal/customdb ./internal/logscrub -count=1`: PASS, exit 0;
  task-8-composition-green.log. Final `go test -race ./internal/customdb
  ./internal/logscrub -count=1`: PASS, exit 0; task-8-composition-race.log.
- Tests cover contained/partial overlaps, one-rune values, truncation, escaped
  JSON keys/values, unknown/unstructured stderr, real Node captured/late30ms
  console, and preserved business output. Existing bounded-state, quiet expiry,
  retirement, cancellation, blocked-handler and configuration-rotation tests pass.
- `git diff --check`: PASS. No focused test was skipped. No broad/internal-short,
  SQL, E2E, Actions or noderunner repeat was run in this scoped privacy pass.

Full evidence and ruling are appended to the scratch `task-8-bounded-report.md`.


### Task 8 review correction — already-resolved attribution

Corrected the four attribution omissions identified in task-8-review.md using
only existing business objects. PAR retains the authenticated client ID/name in
request context before later validation (including Basic authentication with no
body client_id). Refresh retains token user/org/connection IDs only after origin
and client ownership validation, before revoked/reuse/expiry/audience/scope
rejection; both ferrt and fertft have the known IDs without a user/name lookup.
Invitation acceptance captures connection/strategy/user/client/org names as
existing resolutions succeed; failure retains them, while success remains after
commit. Prompt-after-login bindOrg enriches the staging context with its already
resolved client/connection metadata before EnsureMembership. No extra store read,
public response change, policy change, transaction boundary change or generated
file is introduced. Unknown names/strategy remain absent.

All commands used `GOTOOLCHAIN=go1.26.7`:

- RED: `go test ./internal/oauth ./internal/orglogin ./internal/login -run
  'TestPARBasicFailureEventAttribution|TestRefreshFailureEventAttribution|TestInvitationFailureEventAttribution|TestOrganizationPickerMembershipEventAttribution'
  -count=1` exited 1 with expected missing-attribution assertions in all four
  paths; no compile/setup failure. Same command GREEN, exit 0, three packages.
  Logs: task-8-attribution-red.log and task-8-attribution-green.log.
- Final-source `go test -race ./internal/oauth ./internal/orglogin
  ./internal/login -count=1 -v`: PASS, exit 0, no skipped tests or race reports;
  task-8-attribution-race.log.
- Exact required Task 8 focused command (`go test ./internal/login
  ./internal/oauth ./internal/dbconn ./internal/session ./internal/hostedlogin
  ./internal/devicecode ./internal/protection ./internal/orglogin
  ./internal/federation ./internal/customdb -run 'Event|Masked|RecorderFull'
  -count=1`): PASS, exit 0. Session/hostedlogin/devicecode explicitly report no
  matching tests. Log: task-8-attribution-focused.log.
- Final `go test ./internal/... -count=1 -short -v`: PASS, exit 0, 70 tested
  packages, nine with no test files, zero failures. Exactly one actual skip:
  `TestOrganizationsPluginRoundTrip/Organizations/Limits`, reason `store cannot
  override Organizations limits`. No new behavior test was skipped. Log:
  task-8-attribution-internal-short.log. Final source includes the prior console
  privacy composition correction and remained stable before race/focused/short.
- `git diff --check`: PASS. Focused source/test diff self-reviewed. Real memory
  regressions assert exact known fields, unchanged response status/error,
  ownership/origin identity boundaries, unknown metadata omission and no member
  on invitation failure. Existing rollback/success tests passed under race.
- No three-driver PostgreSQL/MySQL script, browser/E2E, generated build or later
  Task 16 suite was run for this correction; SQLite/native/gRPC paths ran in the
  internal short suite. No new behavior test is deferred. Scope/ruling cost:
  scalar field capture and context enrichment only; no enrichment lookup.

Full focused report and commit:
`.superpowers/sdd/2026-10-30-zeroauthy-plan-31-logs-streams-stats/task-8-attribution-report.md`.

## Task 9 — Management events and owning-handler outcomes

Implemented the single `Handlers.LogMiddleware` after token authentication and
live operator-grant checks, before operation scopes. Successful public
`/api/v2` POST/PUT/PATCH/DELETE requests emit one `sapi`; failures >=400 emit one
`fapi`. Successful credential-bearing reads emit `mgmt_api_read` according to
actual serialized fields, excluding metadata, redacted-only values and Action
secret names. A 429 also emits exactly one `api_limit`. System/console operations
retain the shared server record without becoming public Management tenant events.
Unauthenticated or revoked-grant requests do not enter this downstream emitter;
this follows the frozen middleware placement and prevents fabricated actors.

Replaced all 91 baseline `h.audit` calls with context detail hints and removed
the helper. The middleware emits the single scrubbed server line, preserving
already-resolved resource details. Request/response copies use the frozen
per-resource dotted allowlists, unknown-subtree markers and context scrubbing,
including embedded JSON and credential-bearing URLs. Captures retain at most
64 KiB (request reads one overflow sentinel and replays it). Invalid/partial
bodies become one marker, never a plaintext prefix. The existing strict decoder
retains its 1 MiB limit and errors and registers validated credentials before
business work, including bodies beyond the logging budget. Response serialization
is unchanged; a request-local JSON observer detects secret reads beyond the
capture limit without copying another body. Writer wrappers preserve optional
HTTP interfaces, accepted bytes, informational statuses, streaming, read errors,
close behavior and ResponseController flush errors.

Controller-assigned scope extension implements the inventory's owning Management
outcomes: sce/fce, scp/fcp, scu/fcu, sdu/fdu, svr/fvr, reset_pwd_leak,
organization_member_added, ublkdu and custom_domain_verification_failed. Profile
successes compare actual locked-row changes; deletion/membership/unblock no-ops
emit no domain success. Native and gRPC/SQL optional clear-result attribution
uses already-loaded protection state, with an additive optional protobuf field;
older plugins preserve clearing and suppress uncertain event attribution.
Custom-domain proof results distinguish definitive missing proof from resolver
outages without another read. Attribution uses existing user, connection,
organization and caller results. No lookup was added solely for logging.

Controller ruling: confirmed breached-password corpus hits emit reset_pwd_leak
also under monitor-only policy, with `details.blocked=false`. The narrow mgmt
inventory trigger now states this, matching the catalog description and Task 8
confirmed-hit behavior. Costs: conservative body hiding loses diagnostic detail
when a capture is invalid/too large; old plugins cannot report uncertain clear
or membership outcomes; malformed/unresolved profile requests rely on fapi until
an actual subject/change is known. No task 10/12 worker behavior is claimed.

Actual evidence, all Go commands with `GOTOOLCHAIN=go1.26.7`:

- Required RED `go test ./internal/mgmt -run
  'Management.*Logged|Management.*Hidden' -count=1`: failed with missing sapi,
  fapi and secret-read events; body privacy cases failed for missing events.
  The no-event ordinary-read control passed. Additional domain RED tests showed
  missing profile/deletion/verification/membership/unblock/proof events;
  optional-interface, sink-copy, URL-copy, metadata-only read and FlushError
  regressions were each observed failing before their fixes.
- Required focused GREEN, same command: PASS (3.494s), no skipped cases reported.
- First full Management run failed 11 old audit tests: TestProtectionSettingsSecretsAndMerge,
  TestCustomSigningKeysAPI, TestUsersImportCreate, TestTenantSettingsTransactionAndAudit,
  TestPasswordChangeTicket, TestEmailVerificationTicket, TestLinkUserIdentity,
  TestUnlinkUserIdentity, TestDeleteSessionsAndTokens, TestCreateUserShape,
  TestDeleteUser. Shared fixtures now invoke the middleware with CallerFrom
  already populated; actor/tenant/resource/privacy assertions remain and check
  the central record. Focused repaired fixtures passed (6.666s).
- Final `go test ./internal/mgmt -count=1`: PASS (28.692s), no skips reported;
  task-9-mgmt-full.log. Final run includes the FlushError fix.
- `go test -race ./internal/mgmt ./internal/server ./internal/store/grpcstore
  -run 'Management|TestProtection(ClearResult|ClearOlderPlugin|DeniedKinds|SettingsSecretsAndMerge)|TestTenantSettingsTransactionAndAudit'
  -count=1`: PASS (15.727s/16.397s/6.426s), no race reports.
- After the final FlushError fix, `go test -race ./internal/mgmt -run
  'ManagementCapture|ManagementStrictParser' -count=1`: PASS (2.127s).
- Native/gRPC/SQLite-gRPC clear-result and old-plugin tests: PASS (0.198s).
  Real mounted server auth/scope and custom-domain checks: PASS (1.335s).
  `go test ./internal/logs ./internal/logscrub ./internal/customdomain -count=1`:
  PASS (0.546s/0.033s/0.962s), preserving Task 8 short-credential protocol tests.
  Final inventory-only check: PASS (0.391s).
- `make generate`: PASS; protobuf generated with repository tooling.
  `git diff --check`: PASS. Self-review checked all 91 audit replacements,
  actor/grant ordering, no-op outcomes, immutable response observation, decoder
  compatibility, secret masking and exact optional-writer forwarding.
- Not run: PostgreSQL/MySQL scripts, full repository suite, browser/E2E,
  Task 10 asynchronous jobs, Task 12 stream delivery, or Task 16 regression.
  These are not represented as passing or as completed later tasks.

Commit subject: `feat: log Management API operations as sapi/fapi`.
Detailed report and exact command logs:
`.superpowers/sdd/2026-10-30-zeroauthy-plan-31-logs-streams-stats/task-9-report.md`.

### Task 9 review correction — independent strict-parser baseline

The Important review finding against `c6c7417` was confirmed: both arms of
`TestManagementStrictParserPreserved` called the shared client fixture, which
now installs the middleware, so their comparison could not detect a consistent
body-replay regression. This section supersedes that test's earlier claimed
independent parity evidence. Production behavior did not need a change.

The corrected test invokes `CreateClient` directly for the bare baseline, and
explicitly invokes `LogMiddleware(CreateClient)` for the comparison. Each request
has its own original body with identical tenant, authenticated caller, method,
path and query context. Both arms independently require HTTP/body status 400,
`invalid_body`, and literal expected messages for trailing JSON, array, null,
malformed JSON, and more than 1 MiB. Only invalid cases are compared, avoiding
server-generated ID/secret differences.

Actual evidence with `GOTOOLCHAIN=go1.26.7`:

- Scoped mutation changed only the replay reader temporarily from the full
  captured prefix to its first 13 bytes. `go test ./internal/mgmt -run
  '^TestManagementStrictParserPreserved$' -count=1` failed, exit 1 (0.103s):
  trailing JSON became 201 instead of 400, and the oversized request lost its
  size-error message. The bare baseline retained its expected errors. The
  mutation was restored in a `finally` block before any GREEN checks; no
  production diff remains. Log: task-9-parser-review-red.log.
- `go test ./internal/mgmt -run 'ManagementStrictParser|ManagementCapture'
  -count=1`: PASS (0.872s). Log: task-9-parser-review-focused.log.
- Final `go test ./internal/mgmt -count=1`: PASS (30.032s), exit 0.
  The full package ran once after the test correction and restored mutation.
  Log: task-9-parser-review-full.log.
- `git diff --check`: PASS. Self-review verified distinct bare/wrapped calls,
  independent expected error assertions, fresh matching requests and restored
  production source. No additional source behavior, generated files or broader
  scope was changed; no new tests were deferred.

Review-correction commit subject: `test: compare Management parser with bare handler`.

### Task 10 — Action execution console, links and worker outcomes

Implemented immutable console lines and Action IDs in execution results across
memory, SQL JSON storage and additive protobuf/gRPC codecs. The engine captures
successful and failed Action output, masks Action/Module/delivery secrets and
request credentials against original text (including 1–3 rune credentials,
overlapping values, dynamic object keys, encoded JSON and truncated prefixes),
then caps each persisted result at 64 KiB including a final `… truncated` line.
Quoted JSON scalar strings now pass through the shared context scrubber so
`console.log(JSON.stringify(password))` cannot retain an escaped credential.
Delayed runner diagnostics retain at most 256 credentials / 64 KiB for 60 s;
exhausting either bound or the lifetime clears history and permanently drops
later diagnostics until that runner retires.

System operator routes list and retrieve full executions with logs. Tenant
lookup and live operator grants remain in the existing system middleware;
listing accepts trigger, immutable Action ID, execution-ID cursor and take
(clamped at 100). Ordering is `(created_at, id)` descending initially and
ascending after a tenant-scoped cursor. SQL uses `LIMIT` and indexed Action-ID
membership rather than hydrating every tenant execution. Public execution JSON
retains its exact previous shape and excludes console, Action IDs and job data.

Authz post-login outcomes now use the request recorder and existing execution
trace: `s` on a completed bound flow, `f` with its safe denial reason, and generic
`f` on a throw; persisted `details.actions.executions` links resolve to the stored
record. Async Action workers emit `actions_execution_failed` only after a
terminal failed finish succeeds; retries and failed finish writes do not emit.
Import processors emit `sui`/`fui` only after successful terminal `Jobs.Finish`.
App wiring supplies the shared recorder to both worker types.

Rulings and scope:

- Migration **0030_execution_console.sql**, not a modification of 0028/0029:
  results already reside in a JSON column, so no redundant logs column is needed.
  0030 adds keyset indexes and an Action-ID membership relation, with resumable
  MySQL DDL. Explicit upgrade tests preserve a populated version-29 execution.
- `action=` means immutable Action ID. Older executions have only names and
  cannot be attributed safely after rename/deletion; they remain available in
  unfiltered/trigger reads and GET, and do not match an Action-ID filter.
- Preserve existing once-only post-change-password/post-user-registration
  attempts. Custom-email-provider retries still produce six attempts before
  terminal failure. This task does not invent retries for once-only triggers.
- Task 10 exposed an authz emitter gap. New events cover actual bound post-login
  flows; no-engine/no-binding generic login coverage remains a Task 16 source
  audit item, without altering existing signup event boundaries.
- Controller explicitly assigned the remaining import abandonment edge to
  Task 16: `Jobs.DeleteExpired` in memory/SQL can mark processing imports failed
  for timeout/exhausted leases but returns only a deletion count. It cannot
  authoritatively report per-import `fui` through the runner's Finish boundary.
  This is an outstanding acceptance gap, not a claim that all terminal job
  failures are covered. A future optional outcome-reporting writer must return
  the actual committed transitions; old plugins must omit uncertain events.
- Generated Go/protobuf outputs use `make generate`; console API types use
  `npm run gen`. That generated type refresh also incorporates earlier Plan 31
  API additions. No console UI/dist behavior changed in Task 10.

Evidence uses `GOTOOLCHAIN=go1.26.7` throughout:

- Initial console RED: missing Logs field, then actual empty captured console.
  Store RED: missing bounded-list contract. Initial combined named RED:
  async jobs and import jobs produced no terminal events. Login RED: post-login
  success, deny and throw produced no events. Escaped scalar regression RED:
  the actual Action leaked `"line\\nbreak\\\"value"` before the shared fix.
  Memory isolation RED exposed an uncommitted execution before rollback;
  transaction-aware read locking fixed it. Logs are in the task scratch folder.
- Required focused command `go test ./internal/actions ./internal/jobs
  ./internal/mgmt -run 'ExecutionIDs|ActionDeny|ActionThrow|AsyncJobFailure|ActionConsole|PublicExecution|SystemExecutions|ImportJobOutcome'
  -count=1`: PASS (0.634s / 0.022s / 0.752s).
- Final focused `-race` Actions, management, login, jobs, logscrub and customdb
  checks: PASS (4.210s / 4.651s / 4.507s / 1.160s / 1.070s / 1.468s).
  Includes short/overlapping/truncated/escaped credential cases, permanent
  diagnostic mute bounds, six-attempt failure, no event on finish rollback,
  live tenant grants, 100-result cap and exact public JSON shape.
- Final named login tests also flush the real recorder and assert persisted
  `details.actions.executions`, not merely the emitter input: PASS under race
  (2.058s). Its first strengthened read used a historical settle cutoff against
  the memory store's real commit clock and returned no records; the test now
  uses a bounded ordinary search to inspect the persisted documents.
- Final store focused `-race 'Execution|LatestVersion'`: PASS memory/gRPC/SQLite
  (1.105s / 1.085s / 5.685s), including transaction isolation after rollback.
- Required `./scripts/test-sql.sh -run Execution -count=1
  ./internal/store/sqlstore/...`: PASS under its race detector (12.303s).
  Final authoritative verbose run with `-run 'Execution|LatestVersion'`: PASS
  (7.667s), explicitly showing SQLite, PostgreSQL and MySQL console/upgrade
  subtests and no skips. Command-scoped ports PG=56430, MySQL=54330.
- Shared helper final full `go test -race ./internal/logscrub ./internal/customdb
  -count=1`: PASS (1.035s / 7.312s).
- `make generate`, API source checks, generated console API types and TypeScript
  typecheck: PASS. Full console/browser/E2E and full repository regression were
  not run; Task 14/16 owns those. The full affected-package race run is recorded
  separately below with its actual terminal result.

Self-review checked bounded SQL reads, cursor tenant boundaries, immutable slices,
rollback visibility, projection cascade deletion, upgrade from 29, field numbers,
auth middleware, nonduplicated request execution tracing, safe denial/error text,
redaction-before-truncation and terminal-write-before-event ordering. Public-shape
and system-route checks were added after the initial implementation slice; the
combined RED showed missing async outcomes, while those compatibility/API tests
were already green. No independent before-implementation RED is claimed for
those two checks or the later diagnostics-bound controls.

Commit subject: `feat: link log events to Action executions and capture console output`.
Detailed report and exact outputs:
`.superpowers/sdd/2026-10-30-zeroauthy-plan-31-logs-streams-stats/task-10-report.md`.

Task 10 final review corrections and broader-check results:

- Full affected-package race command (`actions jobs mgmt authz login customdb
  store/memory store/grpcstore server app`, `-count=1`) returned FAIL. Seven
  packages passed (actions 200.741s, jobs 31.257s, mgmt 104.812s, authz 25.809s,
  login 98.565s, customdb 9.727s, memory 85.353s); app passed (25.208s).
  gRPC hit the default 10-minute timeout during `TestConformanceSQLite/Users/
  AppMetadataIsCopiedAndNilRoundTrips`. Its stack was actively creating a
  pre-existing migration-002 index through modernc SQLite, rather than waiting
  on an execution-list lock. A full gRPC race rerun with `-timeout=30m` is the
  authoritative follow-up, with its terminal result recorded below.
- Server's initial full run failed `TestActionsManagementResponseSchemas`
  because empty test-console lines had become null. The test endpoint now
  preserves its initialized empty array. `TestDomainSecretExposure` also
  failed because its historical assertion prohibited the literal field name
  `cname_api_key` in the central redacted audit. A diagnostic rerun confirmed
  actual key=false, hash=false, field-name=true. The assertion still prohibits
  actual key/hash in every sink and that field in every later public response;
  it permits the redacted audit field name. Both server regressions passed
  under race (3.297s), and again with the final operator/capability checks.
- New mounted operator tests exposed the required path-target grant check:
  `operatorTarget` previously recognized only presentation and `/attempt`
  routes. A tenant-only Acme operator got 403 on the new console routes.
  The classifier now covers exactly execution list/detail. Positive Acme-only,
  signed-other-target, persisted-revoked-target, tenant-host and anonymous
  checks run through the mounted server. Existing attempt/email target tests
  remain covered. A negative-only direct fixture was insufficient evidence;
  the mounted positive check is the authoritative grant test.
- Missing Logs v1 capability returned 200, and an unavailable new list RPC
  returned legacy Actions 503 in the initial regression. Per controller ruling,
  the two new system routes check optional `LogsSupporter` after authentication
  and map missing Logs/Actions capability to 501 `logs_unavailable`. Existing
  public Actions errors remain unchanged. Final mgmt/server capability, grant,
  public-shape and prior-regression race checks passed (2.756s / 5.122s).
- Keyset IDs now use the existing byte-order dialect suffix in both ORDER BY
  and the cursor predicate, with matching PostgreSQL indexes. Final verbose
  all-three-driver execution/upgrade/version race run passed (8.409s), including
  mixed-case IDs at identical times. Final memory/gRPC execution checks passed
  (1.091s / 1.076s).
- A short credential initially changed a credentials-exchange denial's fixed
  error code into an invalid command. The real regression failed with ErrFlow;
  only display messages are now scrubbed before truncation, preserving fixed
  error-code arguments. Final Action/login race checks passed (3.785s / 2.098s).
- The escaped-scalar test additionally reproduced valid JSON credentials
  (`"quoted-secret"` and an object-shaped password). Original covering text
  matches now win before structural scrubbing, and decoded scalar strings are
  masked once without recursively stripping their own quotes. Final focused
  helper/customdb/Actions race checks passed (1.047s / 3.370s / 4.111s).
- API/protobuf generation and console API generation/typecheck were rerun
  after documenting both new routes' 501 responses. No generated file was
  hand-edited. `git diff --check` passed.

Task 10 final terminal evidence:

- Full gRPC race follow-up `go test -race -timeout=30m
  ./internal/store/grpcstore -count=1`: **PASS**, exit 0, 1229.746s.
  `task-10-grpc-full-final.log`. The default-timeout failure above remains
  disclosed. This package run began before final byte-order/handler hardening;
  current-source focused SQL/store/system/privacy checks cover those changes.
- Final required named command after all source corrections: **PASS**,
  actions2.209s/jobs0.018s/mgmt1.022s (`task-10-required-complete.log`).
- Final staged diff check: PASS. Task 10 implementation is complete with the
  explicitly assigned Task 16 source-audit/import-abandonment gaps above.


## Task 10 I1 follow-up — enforce console privacy before formatting

Review I1 found that the prior Task10 self-review missed the Node boundary:
objects were serialized, severity-prefixed and cut before Go could scrub their
keys; escaped credentials in prefixed/incomplete JSON evaded raw-value masks.
This follow-up is limited to that privacy defect, from base `0c2558c`.

Both existing Action/customdb runners now scrub independent console argument
trees before serialization, joining, severity and cutoff. The policy matches
Go's original-key normalized-contains rule (including dotted-I simple lowercase).
Nested objects, arrays and encoded JSON are covered. Cycles/accessors/functions,
depth beyond64, trees beyond8192 nodes/properties, oversized arrays and
structured strings beyond64KiB fail closed. Original script values and business
results are unchanged. JSON-shaped strings retain their original bytes when
safe; if decoded key scrubbing changes them, the entire console string becomes
Marker. This explicit over-hiding prevents a password that itself is JSON from
being rewritten before Go's original-credential mask can match its other members.

The Go sink adds raw/JSON-escaped/Node-compatible credential and configuration
variants (at most three ephemeral spellings per value), including cutoff prefixes,
to the existing original-span union. Configuration-covered spans retain the
configuration marker, extending credentials retain Marker, and raw JSON-valued
credentials keep whole-original-match precedence. Literal backslash-u sequences
are not decoded accidentally. Existing bounded delayed-diagnostic state,
256-value/64KiB/60-second limits and permanent mute behavior are unchanged. No
credentials are added to the Node request protocol; no module/dependency,
API/generated/store/migration/UI changes or business-result mutations.

Actual TDD evidence (all Go commands use GOTOOLCHAIN=go1.26.7 and require Node):

- Initial actual-Node Action/customdb plus escaped-span regression command
  **FAIL** in all three packages (`task-10-i1-red.log`): reviewer warn object,
  oversized object and escaped newline/quote cutoff fixtures leak through
  persisted/system list/detail output or captured/delayed stderr output.
- Raw JSON password spelling/escaped-HTML refinement command **FAIL**
  (`task-10-i1-raw-red.log`), then fixed. Raw JSON password containing a secret
  key and dotted-I sensitive-key refinement command **FAIL**
  (`task-10-i1-json-key-red.log`), then fixed. Some defensive matrix fixtures
  were added after implementation or already safe; no individual RED is claimed
  for every later row.
- Final regression command `go test ./internal/actions ./internal/customdb
  ./internal/logscrub -run 'ConsolePrivacyBeforeFormatting|ActionConsoleEscaped|EscapedOriginalSpans|ConsoleRawJSONCredentials' -count=1`: **PASS** actions2.239s/customdb1.635s/logscrub0.003s
  (`task-10-i1-green-final.log`). Includes immutable source objects, normalized
  key families, encoded nested JSON, cycle/depth/width/sparse/accessor/toJSON,
  credential/config cutoffs and overlap, system responses and actual Action
  delayed stderr. Customdb responses retain exact business data.

Final-source checks, all terminal exit0:

- `go test -race ./internal/actions ./internal/logscrub ./internal/customdb
  -count=1`: **PASS** actions119.962s/logscrub1.028s/customdb8.812s
  (`task-10-i1-full-race-final.log`). Includes existing64KiB cap, short/raw
  credentials, config overlap, late output, diagnostic capacity/expiry/mute,
  and customdb console baseline tests.
- `go test ./internal/actions ./internal/jobs ./internal/mgmt ./internal/login
  -run 'ExecutionIDs|ActionDeny|ActionThrow|AsyncJobFailure|ActionConsole|PublicExecution|SystemExecutions|ImportJobOutcome'
  -count=1`: **PASS** actions4.178s/jobs0.014s/mgmt0.703s/login0.641s
  (`task-10-i1-required-final.log`). The required Task10 packages plus actual
  persisted login execution links are covered.
- `GOTOOLCHAIN=go1.26.7 make check-sources`: **PASS**, exit0
  (`task-10-i1-check-sources.log`). `git diff --check`: **PASS**.
- Focused follow-up commit subject: `fix: scrub console arguments before runner formatting`.


The intermediate full affected race PASS119.699s/1.026s/7.981s and required
focused PASS4.058s/0.028s/0.767s/0.592s predate the final JSON-string/dotted-I
corrections; they are intermediate evidence only. Final-source evidence is the
run above. Full gRPC20-minute/SQL/store/repository-wide/generation/console/E2E
checks were not rerun for this diagnostic-only fix; previous results remain
historical evidence. Task16 no-engine/no-binding authz emission and import sweep
abandonment outcomes remain open and assigned to the controller. No later task
is claimed complete. Detailed decisions/commands/report:
`.superpowers/sdd/2026-10-30-zeroauthy-plan-31-logs-streams-stats/task-10-privacy-report.md`.
