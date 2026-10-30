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
