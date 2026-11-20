# Plan 48 implementation record

Status: **in progress**. This is not a completed plan or a claim that runtime
features pass. Work started 2026-11-18 from `origin/main` at `8eb2dd45`
(Plan 36 merged). Branch: `plan-48-refresh-tokens-ii`; worktree:
`/mnt/nvme2/code/zeroauthy-plan48`. No branch push or CI run yet.

Design: [Refresh tokens II](specs/2026-11-16-zeroauthy-refresh-tokens-ii-design.md).
Plan: [implementation tasks](plans/2026-11-16-zeroauthy-plan-48-refresh-tokens-ii.md).

## Scope and rulings

The protocol track puts P2 / Plan 48 before P3 / Plan 41a. The maintainer
asked to start the next OIDC-related plan after Plan 36.

The 2026-11-18 public-source check found that online refresh tokens require
DPoP for public clients, reject combined online/offline scopes, and are not
Management API refresh-token resources. The maintainer authorized DPoP
support in this conversation. The amended design adds downstream DPoP as
Task 6a before ORT Task 7, and includes its persistence in Tasks 2 and 3.
DPoP runtime is implemented and reviewed as Task 6a; plan-level E2E and full verification remain pending.

The public MRRT configuration guide now specifies 10 policies per client;
the design's previous local limit of 100 was updated. Bulk revoke retains
its separate maximum of 100 IDs. The existing Go 1.26.11 module pin is
preserved; the plan's stale 1.26.10 text was corrected without a pin change.

Conversion uses presented-token identity for atomic claims. The SQL and
quota work must serialize family-head and absent-counter decisions, and
quota results must expose atomic warning-threshold crossings. These are
implementation requirements, not results already verified.

Review corrected the proposed DPoP design to separate authorization-server
and UserInfo nonce domains and to support both PAR binding mechanisms.
No nonce or proof runtime implementation was present in that review.

## Progress

| Task | State | Evidence |
|---|---|---|
| 1 Contracts, decisions, inventory | Complete; reviewed | `af75a3de`, `3b8074af`, fix `1be49d7a`; design amendments `c3affc3b`, `3c038cfa` |
| 2 Memory store and contracts | Complete; reviewed | `e7f81cbd`, fix `d59f1c22`; memory conformance passed, no skips |
| 3 SQL, gRPC and migration | Complete; reviewed | `4df0e8cc`, fix `7bab65d2`; SQLite/gRPC and memory/plugin tests passed; PostgreSQL/MySQL pending CI |
| 4 Conversion and strict overlap | Complete; reviewed | `8f8d6015`, fix `31b64bac`; full OAuth and focused store/plugin tests passed |
| 5 Grant cascade | Complete; reviewed | `5f3bf19f`, fix `3b5afed3`; focused Management/OAuth/store tests passed |
| 6 MRRT | Complete; reviewed | `261ab36d`, fix `969f3c1f`; focused and full OAuth tests passed |
| 6a DPoP | Complete; reviewed | `a09bed3d`, fix `c04a1e25`; required packages and 343 OAuth tests passed |
| 7 ORT | Complete; reviewed | `e7ae33b3`, fix `473a1850`; OAuth/supporting suites and build passed |
| 8 Management runtime | Complete; reviewed | `f8001e9d`, fix `227b8b11`; full Management/OAuth and supporting tests passed |
| 9 Quotas | Complete; reviewed | `9f9fae1a`; OAuth/shared configuration/supporting tests and build passed |
| 10 Console | Starting | UI verification pending |
| 11 Seed and Deploy CLI | Pending | Not run |
| 12 E2E, docs and final verification | Pending | Not run |

## Task 1 verification

All commands below completed with actual exit code 0 on the snapshots
recorded in the task report. They used the current Go 1.26.11 toolchain.

- Baseline `go test ./api/ ./internal/tenantrules/ ./internal/actionsrules/`
  at `8eb2dd45`.
- `make generate`, `go build ./...`.
- `go test ./api/ ./internal/tenantrules/ ./internal/actionsrules/` after
  the API, inventory and ORT contract changes.
- `go test ./internal/server/ -run '^TestRefreshTokensIIRouteScopes$'`.
- Organization quota schema regression was observed failing first, then
  passing with the active create/get/patch operation schemas wired to the
  shared quota definition. `go test ./api/` passed after that fix.

The first task review reported three important findings: missing quota
fields in active organization schemas, shared DPoP nonce domains in the
design, and missing PAR proof-header binding in the design. All three were
addressed in `1be49d7a`; scoped re-review approved the fix.

One minor finding remains deferred for final review: the temporary route
scope test lacks a fully authorized 501 case. Runtime handlers will replace
the temporary adapters later in this plan.

Detailed logs, task reports and review packages remain in this worktree's
ignored `.superpowers/sdd/2026-11-16-zeroauthy-plan-48-refresh-tokens-ii/`
workspace while implementation runs. Full local verification, plan E2E,
whole-branch review and full CI are pending. CI monitoring will be handed
to the maintainer with the exact run URL after the completed branch push.

## Task 2 verification checkpoint

At `e7f81cbd`, `GOTOOLCHAIN=go1.26.11 go test -count=1 -v
./internal/store/memory/` exited 0 in 7.581s, with no skips. The
organization independent-copy regression also passed. The shared suites
include conversion, strict overlap, metadata, quotas and DPoP replay.

The SQL, gRPC, plugin and seed test binaries compiled with `go test -c`;
those tests were not executed. Durable implementation and database checks
remain Task 3. Task 2 review was interrupted by a usage limit before it
returned findings; the maintainer said continue and the review resumed.

The conversion interface now includes the overlap duration so the store
can atomically authorize conversion using the immediately previous token.
A stale token revokes only its family and creates no successor. The memory
implementation tracks insertion order independently of tied clock values.
Quota results carry atomically claimed warning thresholds for later logging.

Task 2 review found two important issues: conversion could reuse an unrelated
family ID, and replay purge traversal was unbounded. `d59f1c22` fixes both;
regressions failed first, then passed. Full memory conformance exited 0 in
6.564s with no skips. Scoped re-review approved both fixes. One Minor
comment remains for final review: document all ownership/binding preconditions
already enforced by memory Rotate. Durable drivers must follow those checks.

The next migration is provisionally 0042 after merged Plan 36's 0041,
replacing the design's stale 0038. Recheck main before the eventual push.

## Task 3 verification checkpoint

Signed commit `4df0e8cc` contains verified tree
`744c25c9bf0f5bd95c84c129e4ba4f204307eab3`. Tests used Go 1.26.11 and a
short tmpfs TMPDIR/GOTMPDIR, with external SQL DSNs unset.

The initial affected-store run exited 1 (session 87975, tree
`960e0e01dbff5b406d689a32ae6a9afba19b46ee`): memory passed in 9.984s and
real plugin-process tests passed in 52.859s, but two historical SQLite
fixture builders and seven gRPC full-field fixtures needed updates:

- `TestMigration0019PreservesLegacyHostedData/sqlite`
- `TestNativeSocialMigrationLeavesClients/sqlite`
- `TestTenantRoundTrip`, `TestClientRoundTrip`, `TestResourceServerRoundTrip`
- `TestSessionRoundTrip`, `TestAuthTransactionRoundTrip`, `TestAuthCodeRoundTrip`
- `TestRefreshTokenRoundTrip`

All nine focused fixture tests then passed. The corrected complete SQL and
gRPC retry (session 69559) exited 0: SQL 125.743s, gRPC 205.904s. No Plan 48
case skipped. Two existing organization-limit cases skipped across the
runs: `TestOrganizationsPluginRoundTrip/Organizations/Limits` and
`TestConformanceThroughPluginProcess/Organizations/Limits`; the test-only
limit setter is not forwarded through those protocol lanes. These skips
are not passing tests. PostgreSQL and MySQL have not run locally.

Generation and focused migration, capability, transport-failure and sweeper
checks passed. Detailed initial and intermediate failures, commands,
snapshots, logs and final exits are in `task-3-report.md` in the active plan
workspace. Full repository and plan E2E verification remain pending.

SQL uses a per-tenant refresh insertion sequence and serialization lock;
this favors atomic family transitions over independent-family write
parallelism. Later performance changes must preserve those atomic outcomes.
`store.CheckRefreshTokensIISupport(ctx, st)` distinguishes support, definitive
older-plugin refusal, and transport failure. Versioned RPC writes protect
new fields from silent downgrade.

Task 3 review found two Important gRPC downgrade gaps. `7bab65d2` adds
versioned binding-sensitive reads and code consumption, a lost-capability
latch, and receiving checks against the base and transaction backing stores.
Regressions failed before the fix and passed after it. The final focused
gRPC/plugin verification exited 0 (gRPC 25.650s, plugin/SDK 35.390s) with
one existing `ConformanceThroughPluginProcess/Organizations/Limits` skip.
Scoped re-review approved both fixes.

Task 3 Minor findings retained for final review: protected-write exact
sentinel identity; sub-microsecond replay deadlines; tenant-wide refresh
lock contention; cancellation while waiting for another initial probe.
The caller contract permits legacy fallback only on an initial capability
probe returning `ErrRefreshTokensIIUnavailable`. A previously capable
connection returns distinct `ErrRefreshTokensIISupportLost` and fails closed;
protected-operation errors never license a legacy retry.

## Task 4 verification

`8f8d6015` implements refresh conversion, strict overlap and offline API
rechecks. It adds store `CheckRotation` to detect reuse before audience,
scope or Actions can mask it; final mutations recheck under the store lock.
Full OAuth passed in 168.500s and affected memory/SQLite/gRPC/plugin tests
passed with no skips. The test report accounts for the ancillary snapshot
index-lock diagnostic with identical tree checks before/after the runs.

Review found two Important races: no-successor exchanges skipped final
source validation, and checks used the request-entry clock. `31b64bac`
fixes both; seven regression cases failed first, then passed. Full OAuth
passed in 148.195s with no skips, and scoped re-review approved the fixes.

Three Minor findings remain for final review: explicit support-lost
precedence for joined probe errors; HTTP test file placement; capture the
snapshot identity once before parallel commands. No full-plan verification
or CI push has occurred.

## Task 5 verification

`5f3bf19f` adds atomic grant deletion, matching refresh-token revocation and
user-version invalidation. Flag-enabled OAuth revocation rechecks consent
eligibility under the user lock; stale presentations cannot revoke new
consent or sibling families. UserInfo audiences map to the exact issuing
origin. Initially legacy plugins retain their prior behavior; loss and
transport errors fail closed.

Focused Management, OAuth, memory, SQLite and gRPC tests passed with no
skips. A mistyped conformance subtest filter was corrected and the intended
`ListByUserPageAndRevocation` test then ran and passed; the task report
records both selections.

Review found one Important deadline race while awaiting the user lock.
`3b5afed3` fixes it; the deterministic regression failed first and then
passed, along with focused Management and OAuth checks (2.553s and 4.439s,
zero skips). Scoped re-review approved. A Minor test cleanup remains for
final review: assert conformance counts after checking the transaction error.

## Task 6 verification

`261ab36d` implements MRRT target resolution, shared Management/seed policy
validation, Action event fields, target signing and authorization, and
family-ceiling preservation. MRRT seed mapping moved forward from Task 11
to exercise both write paths. All 81 focused and 330 full OAuth tests passed
with zero skips.

Review found two Important cases: first-policy activation during a plain
refresh, and target deletion before signing returning the wrong error.
`969f3c1f` fixes both; deterministic regressions failed first and then passed.
All 15 selected tests and 332 full OAuth tests passed (146.411s), zero skips.
Scoped re-review approved. A Minor additional `at_hash` value assertion is
retained for final review. DPoP runtime is next; no full-plan checks or push.

## Task 6a verification

`a09bed3d` implements downstream DPoP proof validation, independent nonce
domains, replay prevention, token/PAR/UserInfo binding, shared configuration,
CORS, scrubbing and Management/operator boundaries. New tenants default to
strict refresh binding; absent legacy settings retain per-API behavior.
Bound refresh-token revocation requires proof after existing owner/origin
checks. Existing wrong-client 400 and unknown/cross-origin 200 semantics
remain unchanged.

The initial required-package run failed two OAuth MFA groups because a
synthetic audience was treated as a stored API; the virtual-resource lookup
was corrected. Other required packages passed and unchanged packages were
not repeated. Additional RED/GREEN cases covered explicit bound-token
revocation and omitted default-audience proof policy. Final build and 341
OAuth tests passed with no skips; the task report retains all initial failure
names/output, corrections, commands and snapshot identities.

Review found two Important pre-consumption gaps: device-code proof policy
used the wrong audience source, and a wrong client could consume or replay a
bound authorization code. `c04a1e25` fixes both. Regressions failed first,
then focused checks and all 343 OAuth tests passed (140.229s, zero skips).
Scoped re-review approved. One Minor nonce-origin test improvement remains
for final review. No full-plan verification or push has occurred.

## Task 7 verification

`e7ae33b3` implements online refresh-token issuance/reuse/session lifecycle,
DPoP, Actions revocation, Management invisibility and explicit session revoke.
Ordinary session deletion preserves offline tokens. Stored ORT expiry is the
session absolute expiry; session state remains authoritative for idle life.
Initial verification passed 356 OAuth and 329 supporting tests, zero skips.

Review found two Important issues: stale Touch-as-lock could rewind a newer
session interaction, and a revoked ORT could end a fresh live session.
`473a1850` adds real Sessions.GetForUpdate across memory/SQL/versioned gRPC
and validates current revocation/expiry authority. Regressions failed first,
then all 361 OAuth and 75 supporting top-level tests passed with zero skips;
build passed. Scoped re-review approved both fixes. One Minor cross-client
lifecycle assertion remains for final review.

Task 8 still owns the retained offline-only bulk selector and remaining list,
metadata and device/exchange recording endpoints. Explicit session revoke was
pulled forward to Task 7. All snapshot, command and selector/test-harness
corrections are retained in the task report; no full-plan or CI claim yet.

## Task 8 verification

`f8001e9d` completes token lists/bulk revoke/metadata, session metadata,
exact offline-only retained-token selection, token-owned device/exchange
history, real scope adapters and metadata redaction. Full Management/OAuth
passed 833 tests with zero skips. Supporting store/SDK/router/API checks
and build passed. Initially unmatched metadata filters were corrected and
the exact cases ran on memory, SQLite, gRPC and the real SDK process.

Review reproduced a public audience mismatch for alias-issued UserInfo
tokens. `227b8b11` renders from the issuing origin, with canonical fallback
for legacy records. RED/GREEN tests cover list-to-revoke using the reported
audience and legacy views through an alias. All 470 Management tests passed
(111.631s, zero skips); scoped re-review approved. One Minor issuance-device
probe error classification remains for final review. Plan-wide checks and
CI remain pending.

## Task 9 verification

`9f9fae1a` enforces client/organization quotas atomically after signing and
fresh authorization. Refused/failed requests consume no quota. UTC windows,
headers, exact concurrent winners and post-commit warning claims are tested.
Shared rules support Management and seed, partial PATCH preservation, null
clearing and valid legacy stored-only tenant defaults. Invalid legacy limits
fail closed. Existing wrapper-extension compatibility remains preserved.

Full OAuth passed 380 tests; supporting checks passed 209 and the final tenant
capability-guard delta passed 32, all zero skips; build passed. The report
retains RED/GREEN, fixture/import-cycle corrections and the reverted proposal
to reject already permitted wrapper extensions. Review approved with no
Important findings. One Minor repeated tenant-wrapper PATCH compatibility
edge remains for final review. Full-plan checks and CI are still pending.
