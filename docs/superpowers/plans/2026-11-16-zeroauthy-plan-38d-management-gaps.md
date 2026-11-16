# Plan 38d — Management API gaps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The GA Management API routes no other paths item owns (effective
roles/permissions, revoke-access, client connections, device credentials,
risk-assessment settings, the legacy rules/hooks answers) and an audit
that removes silently ignored list parameters.

**Architecture:** handlers in `internal/mgmt` on existing stores; one small
`store.DeviceCredentials` repository; risk settings in tenant settings;
the audit as a generated table test over `api/management.yaml` and the
Auth0 OpenAPI.

**Tech Stack:** Go 1.26.10 (no new module), Vue/TypeScript console,
node-auth0 7.4.0, auth0-cli 1.37.0.

**Spec:** [Plan 38d design](../specs/2026-11-16-zeroauthy-management-gaps-design.md). § refers to it.

## Global Constraints

- **Toolchain/dependencies.** Go `1.26.10`; keep every pin.
- **Clean room.** Own words.
- **Parity.** LR38d-1…5 and G1–G9 in **D-0240**; G points in
  `docs/superpowers/plan-1-followups.md`; update the roadmap coverage
  table (§0) with the inventory of spec §1.
- **Scopes** exactly as the OpenAPI (two-scope routes included).
- **Pagination:** checkpoint `from`/`take` (`take` ≤ 100, default 50) where
  the OpenAPI says so; offset paging elsewhere.
- **Migration.** One forward-only migration in three dialects written as
  `0042_management_gaps.sql`; renamed to main's latest + 1 at merge.
- **Verification** per `AGENTS.md`: focused tests; final fast tier
  `TMPDIR=/dev/shm/za38d GOTMPDIR=/dev/shm/za38d go test -p 4 ./...` plus
  `make e2e`; push `plan-38d-management-gaps`; report CI.
- **Worktree.** `/mnt/nvme2/code/zeroauthy-plan38d`, branch
  `plan-38d-management-gaps`; record in
  `docs/superpowers/2026-11-16-plan-38d-implementation-record.md`.
- **Commits** signed off.

## Review Focus

1. **`revoke-access` with another user's `session_id`** → no change.
   Task 3 `TestRevokeAccessForeignSession`.
2. **Device-credential delete** of a refresh-token entry keeps the grant
   and revokes only that token. Task 5 `TestDeviceCredentialDeleteKeepsGrant`.
3. **User-scoped token on `/device-credentials`** for another `user_id` →
   `403` with the documented message. Task 5 `TestDeviceCredentialsSubject`.
4. **Audit completeness:** a list route gaining a parameter in a later
   OpenAPI version fails the audit test until handled. Task 1
   `TestListParameterAudit`.

---

### Task 1: Inventory, audit test, decisions

**Files:**
- Create: `api/gap_inventory.md` is **not** created; the inventory lives in
  the roadmap §0 table and D-0240.
- Create: `internal/mgmt/param_audit_test.go` with a fixture extracted
  from the pinned Auth0 OpenAPI (`testdata/auth0-list-params.json`: route →
  documented query parameters, generated once by a small script kept in
  `scripts/`), asserting each zeroauthy list route either honours or
  rejects each parameter.
- Modify: `api/management.yaml` (new routes with `x-source`), `make generate`,
  `501` stubs; `docs/compat/decisions.md` (D-0240),
  `docs/superpowers/plan-1-followups.md` (G1–G9), roadmap §0 coverage table.

- [ ] **Step 1:** Script + fixture; audit test listing today's ignored parameters as expected failures (`t.Skip` entries named in the test, each removed by a later task).
- [ ] **Step 2:** OpenAPI, stubs, D-0240, follow-ups, roadmap table.
- [ ] **Step 3:** Commit `docs: freeze Plan 38d contracts, D-0240 and the list-parameter audit`.

### Task 2: Effective roles and permissions

**Files:** `internal/mgmt/user_effective.go`, tests; `internal/rbacrules`
(shared computation with the token-time RBAC so both agree).

- [ ] **Step 1: Failing tests**: roles with `sources`; permissions union de-duplicated; `resource_server_identifier` filter; `sources/effective-roles` for a permission; checkpoint paging; scopes; unknown user `404`; token-time permissions equal the endpoint's (property test over random role graphs).
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(mgmt): user effective roles and permissions`.

### Task 3: `revoke-access`

**Files:** `internal/mgmt/user_sessions.go`, tests.

- [ ] **Step 1: Failing tests**: all sessions + tokens; one session; `preserve_refresh_tokens`; `TestRevokeAccessForeignSession` (Review Focus 1); both scopes required; back-channel logout job enqueued when Plan 41a is on main.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(mgmt): revoke a user's sessions and refresh tokens`.

### Task 4: Client connections

**Files:** `internal/mgmt/clients.go` (or `client_connections.go`), store
query (connections by enabled client, paged), tests.

- [ ] **Step 1: Failing tests**: ordering, `strategy` filter, `fields`, checkpoint `next`, `404` unknown client, scope combinations (`read:connections` + `read:clients` | `read:client_summary`).
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(mgmt): list a client's enabled connections`.

### Task 5: Device credentials

**Files:** `internal/store/device_credentials.go` + memory/sql/grpc +
storetest; migration; `internal/mgmt/device_credentials.go`, tests.

- [ ] **Step 1: Failing tests**: list merges refresh tokens and public keys with `type` filter; `TestDeviceCredentialsSubject` (Review Focus 3); POST `409` on duplicate device; `TestDeviceCredentialDeleteKeepsGrant` (Review Focus 2); public key never usable at `/oauth/token` (a grep-level test that no grant reads the table).
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(mgmt): device credentials`.

### Task 6: Risk assessment settings

**Files:** `internal/settingsrules` / tenant settings handlers,
`internal/mgmt/risk_assessments.go`, `internal/mfa` known-device expiry,
tests.

- [ ] **Step 1: Failing tests**: GET defaults; PATCH `enabled`; `remember_for` 0/366 → `400`; known devices expire after `remember_for` days (injected clock); `clear` with `new-device` empties the user's known devices on that connection; unknown assessor → `400`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(mgmt): risk assessment settings`.

### Task 7: Rules, hooks, rules-configs answers

**Files:** `internal/mgmt/retired.go`, tests.

- [ ] **Step 1: Failing tests**: each missing route answers per spec §4; Deploy CLI export still sees empty lists (existing m20 tests).
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(mgmt): complete the retired rules and hooks routes`.

### Task 8: List parameters

**Files:** `internal/mgmt/clients.go`, `roles.go`, `logs.go` and any route
the audit flagged; store list filters where needed (`Clients.List` gains
`AppType`, `IsFirstParty`, `IsGlobal`, `Query`; checkpoint variants).

- [ ] **Step 1:** Remove each audit skip one at a time with a failing test first: `/clients` `q`/`is_global`/`app_type`/`is_first_party`/`from`/`take`; `/roles` `name_filter`/`from`/`take`; `/logs` `sort` fields.
- [ ] **Step 2–4:** FAIL → implement → PASS; `TestListParameterAudit` (Review Focus 4) passes with no skips left for this plan's routes.
- [ ] **Step 5:** Commit `fix(mgmt): honour documented list parameters`.

### Task 9: Console, E2E, docs, final verification

- [ ] **Step 1:** Console: effective permissions panel, revoke-access, client connections tab via the new route, risk settings; Vitest; `console/dist`.
- [ ] **Step 2:** E2E: node-auth0 calls for the routes it exposes, auth0-cli `api` for the rest, added to the existing `make e2e` lane.
- [ ] **Step 3:** Docs: `docs/management-api.md` coverage table and new routes, `docs/compatibility.md`, `docs/compat/matrix.md`, `CHANGELOG.md`, roadmap; implementation record.
- [ ] **Step 4:** Fast tier + `make e2e`; push `plan-38d-management-gaps`; record CI.
- [ ] **Step 5:** Whole-branch review, fix wave, green CI, maintainer approval.
