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
