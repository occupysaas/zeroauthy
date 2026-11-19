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
| 3 SQL, gRPC and migration | Starting | Database verification not run yet |
| 4 Conversion and strict overlap | Pending | Not run |
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
