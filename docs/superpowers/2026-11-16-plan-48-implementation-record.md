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
DPoP runtime is **not implemented yet**.

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
| 4 Conversion and strict overlap | Starting | No runtime verification result yet |
| 5 Grant cascade | Pending | Not run |
| 6 MRRT | Pending | Not run |
| 6a DPoP | Pending | Not run |
| 7 ORT | Pending | Not run |
| 8 Management runtime | Pending | Not run |
| 9 Quotas | Pending | Not run |
| 10 Console | Pending | Not run |
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
