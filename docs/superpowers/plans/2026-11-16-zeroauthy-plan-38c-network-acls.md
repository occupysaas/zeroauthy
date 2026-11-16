# Plan 38c — Tenant network ACLs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `/api/v2/network-acls` and first-match enforcement of tenant ACLs
on every tenant request, with `acls_summary` logs.

**Architecture:**
- **`internal/netacl`** (new, pure): validation, compilation (CIDR tries,
  hash sets), evaluation, scope classification of a request path.
- **`internal/netacl/middleware.go`**: per-tenant compiled cache keyed by
  the tenant's ACL revision; mounted first in the tenant router chain
  (after tenant resolution, before rate limiting and CORS).
- **Storage:** `store.NetworkACLs` (memory, SQL, gRPC `network_acls.v1`).
- **`internal/mgmt/network_acls.go`**: the six operations.

**Tech Stack:** Go 1.26.10 (`net/netip`; no new module), Vue/TypeScript
console, node-auth0 7.4.0, auth0-deploy-cli 9.1.0.

**Spec:** [Plan 38c design](../specs/2026-11-16-zeroauthy-network-acls-design.md). § refers to it.

## Global Constraints

- **Toolchain/dependencies.** Go `1.26.10`; keep every pin.
- **Clean room.** Own words.
- **Parity.** LR38c-1…9 and N1–N7 in **D-0250**; N points in
  `docs/superpowers/plan-1-followups.md`.
- **Limits.** 10 ACLs per tenant; 20 entries per signal type; description
  ≤ 255; `redirect_uri` ≤ 2000, absolute HTTPS.
- **Performance.** Evaluation allocation-free on the hot path; benchmark
  10 ACLs × 20 entries < 5 µs.
- **Propagation.** ≤ 10 s across replicas; immediate on the writing
  replica.
- **Migration.** One forward-only migration in three dialects written as
  `0043_network_acls.sql`; renamed to main's latest + 1 at merge.
- **Verification** per `AGENTS.md`: focused tests; final fast tier
  `TMPDIR=/dev/shm/za38c GOTMPDIR=/dev/shm/za38c go test -p 4 ./...` plus
  `make e2e` and `make e2e-deploy`; push `plan-38c-network-acls`; report CI.
- **Worktree.** `/mnt/nvme2/code/zeroauthy-plan38c`, branch
  `plan-38c-network-acls`; record in
  `docs/superpowers/2026-11-16-plan-38c-implementation-record.md`.
- **Commits** signed off.

## Review Focus

1. **Spoofed `X-Forwarded-For`** from an untrusted peer does not satisfy an
   `allow` or avoid a `block`. Task 4 `TestACLClientIPTrustBoundary`.
2. **System tenant exemption:** a `tenant`-scope `match_all` block on tenant
   A never affects the console or system API. Task 4 `TestACLSystemExempt`.
3. **Priority and monitoring:** a monitoring rule at priority 1 followed by a
   block at 2 → the request is blocked and both are counted. Task 2
   `TestEvaluateMonitoringContinues`.
4. **Stale cache:** after a write on replica A, replica B enforces the new
   set within 10 s, and never a mix of old and new rules. Task 5
   `TestACLPropagation`.

---

## File boundaries and shared interfaces

```go
// internal/netacl
type ACL struct{ ID, Description string; Active bool; Priority int; Rule Rule }
type Rule struct{ Action Action; Scope string; Match, NotMatch *Signals; MatchAll bool }
type Action struct{ Block, Allow, Log, Redirect bool; RedirectURI string }
type Signals struct{ IPv4, IPv6, ConnIPv4, ConnIPv6 []string; Hostnames, UserAgents, JA3, JA4 []string; Geo, Subdivisions []string; ASNs []int; Auth0Managed []string }
func Validate(a *ACL) error
type Compiled struct{ /* sorted rules with tries/sets */ }
func Compile(acls []*ACL) *Compiled
type Request struct{ ClientIP, PeerIP netip.Addr; Host, UserAgent, JA3, JA4 string; Scope Scope }
type Decision struct{ Action string /* "block"|"allow"|"redirect"|"none" */; RedirectURI, RuleID string; Counted []string }
func (c *Compiled) Evaluate(r Request) Decision
func ScopeOf(path string) Scope // management | authentication | dcr | other
```

---

### Task 1: Contracts and decisions

**Files:** `api/management.yaml` (six operations, schema, `x-source`);
`make generate`; `501` stubs; `docs/compat/decisions.md` (D-0250 with §8
open); `docs/superpowers/plan-1-followups.md` (N1–N7); logs inventory
(`acls_summary`).

- [ ] **Step 1:** Edits; `go build ./...`; `go test ./api/`.
- [ ] **Step 2:** Commit `docs: freeze Plan 38c contracts and D-0250`.

### Task 2: Validation and evaluation

**Files:** `internal/netacl/acl.go`, `eval.go`, `scope.go`, tests,
`bench_test.go`.

- [ ] **Step 1: Failing tests**
  - `TestValidate`: required fields; `match_all` with `match` → error; two actions → error; `redirect` without `redirect_uri` or with `http://` → error; 21 CIDRs → error; bad CIDR → error; HTTP message signature → error (LR38c-3); geo/ASN accepted with a warning flag.
  - `TestEvaluate` table: priority order and ID ties; AND across types, OR within; IPv4+IPv6 counted as one type; `not_match`; `match_all`; unevaluable signals never match; default none.
  - `TestEvaluateMonitoringContinues` (Review Focus 3).
  - `TestScopeOf`: each path in spec §4.
  - Benchmark under the target.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(netacl): rule validation and first-match evaluation`.

### Task 3: Storage and Management API

**Files:** `internal/store/network_acls.go`, memory/sql/grpc, storetest,
migration, proto, `internal/mgmt/network_acls.go`, tests.

- [ ] **Step 1: Failing tests**: storetest CRUD + revision bump in the same transaction + 11th ACL refused; handler CRUD, PUT vs PATCH semantics, scopes, `404`, warning header on unevaluable signals, capability off → `501`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(mgmt): network ACL resource`.

### Task 4: Middleware

**Files:** `internal/netacl/middleware.go`, tests; `internal/server/server.go`
(mount on tenant routers: auth, hosted, `/api/v2`, `/me`, `/oidc/register`
when present); responses per spec §3.

- [ ] **Step 1: Failing tests**: block on each scope (JSON for APIs, page for `/u/*`); allow short-circuits a later block; redirect `302`; hostnames restricting the canonical host while a custom domain passes; `TestACLClientIPTrustBoundary` (Review Focus 1); `TestACLSystemExempt` (Review Focus 2); JA3/JA4 only from trusted headers.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(netacl): enforce tenant ACLs on every tenant request`.

### Task 5: Propagation and summaries

**Files:** `internal/netacl/cache.go`, `summary.go`, tests; the sweeper or a
ticker in `internal/app` for 10-minute summaries.

- [ ] **Step 1: Failing tests**: `TestACLPropagation` (Review Focus 4) with two servers on one SQLite store and an injected clock; `TestACLSummary` (one log per rule per window with counts, none for idle rules, IP sample ≤ 5).
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(netacl): revision cache and acls_summary logs`.

### Task 6: Console, seed, Deploy CLI, E2E, docs, final verification

- [ ] **Step 1:** Console Security → Network ACLs with the local "test request" panel; Vitest; `console/dist`.
- [ ] **Step 2:** Seed `network_acls`; tests.
- [ ] **Step 3:** Deploy CLI four-cell round trip with `networkACLs` (keys handler excluded).
- [ ] **Step 4:** E2E curl suite in `make e2e` (block, allow, redirect, monitoring, hostname).
- [ ] **Step 5:** Docs: new `docs/network-acls.md`; `docs/attack-protection.md` pointer; compatibility files; `CHANGELOG.md`; roadmap; implementation record.
- [ ] **Step 6:** Fast tier + `make e2e` + `make e2e-deploy`; push `plan-38c-network-acls`; record CI; review, fix wave, green CI, maintainer approval.
