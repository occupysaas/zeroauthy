# Plan 43 — Token Vault and connected accounts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connected Accounts through the My Account API, the Token Vault
store with provider refresh, the federated-connection access-token
exchange (refresh-token and access-token subjects), the Management
listing, and revocation.

**Architecture:**
- **`internal/tokenvault`** (new): connected-account service (connect,
  complete, list, delete), exchange service (select account, refresh with
  the provider, CAS store), revocation.
- **`internal/federation`** gains an attempt purpose `connect` reusing
  Plan 24's start/callback with a different completion.
- **`internal/myaccount`** (from Plan 42a, or a skeleton here) mounts the
  five routes.
- **`internal/oauth/grant_federated_access.go`**: the grant.

**Tech Stack:** Go 1.26.10 (no new module), Vue/TypeScript console,
Playwright 1.64.0, `@auth0/auth0-spa-js` 2.28.3, the Plan 24 fixture
provider.

**Spec:** [Plan 43 design](../specs/2026-11-16-zeroauthy-token-vault-design.md). § refers to it.

**Gate:** Task 4 waits for ruling §9.1.

## Global Constraints

- **Toolchain/dependencies.** Go `1.26.10`; keep every pin.
- **Parity.** LR43-1…4 and T1–T11 in **D-0110**; follow-ups; amend the
  Plan 24 decision on stored-only `connected_accounts`.
- **Never logged:** provider tokens, connect codes, `auth_session`.
- **Concurrency:** provider refresh happens once per expiry under
  concurrent exchanges (CAS on `version`).
- **Migration.** One forward-only migration in three dialects written as
  `0049_token_vault.sql`; renamed to main's latest + 1 at merge.
- **Verification** per `AGENTS.md`: focused tests; final fast tier
  `TMPDIR=/dev/shm/za43 GOTMPDIR=/dev/shm/za43 go test -p 4 ./...` plus
  `make e2e-token-vault e2e-social`; push `plan-43-token-vault`; report CI.
- **Worktree.** `/mnt/nvme2/code/zeroauthy-plan43`, branch
  `plan-43-token-vault`; record in
  `docs/superpowers/2026-11-16-plan-43-implementation-record.md`.
- **Commits** signed off.

## Review Focus

1. **Connect code theft:** a `connect_code` replayed, used with another
   `auth_session`, another user's token or a different `redirect_uri` →
   refused, nothing stored. Task 3 `TestCompleteBindings`.
2. **Upstream account of another user** → `409`. Task 3 `TestConnectOwnedElsewhere`.
3. **Exchange scope:** requested `scope` beyond the granted set → refused
   or trimmed per T-point ruling; never widened. Task 4 `TestExchangeScopeSubset`.
4. **Refresh once:** 10 concurrent exchanges with an expired provider token
   → one provider refresh call. Task 4 `TestExchangeRefreshOnce`.
5. **Rotating subject token** refused without being consumed. Task 4
   `TestExchangeRefusesRotating`.

---

### Task 1: Contracts and decisions
**Files:** `api/myaccount.yaml` (five routes; create the file if Plan 42a
has not), `api/management.yaml` (`GET /users/{id}/connected-accounts`,
connection `connected_accounts` schema), `api/authentication.yaml` (grant),
`make generate`, stubs; D-0110; follow-ups.
- [ ] Edits → build → commit `docs: freeze Plan 43 contracts and D-0110`. Ask for §9 rulings.

### Task 2: Storage
**Files:** `internal/store/connected_accounts.go` + drivers + storetest,
migration, capability `token_vault.v1`; connection-delete and user-delete
cascades.
- [ ] storetest (unique upstream subject, CAS version, cascades, `allow_missing_user_id` one-per-user rule) → implement → commit `feat(store): connected accounts`.

### Task 3: Connect and complete
**Files:** `internal/tokenvault/connect.go`, `internal/federation` purpose
`connect`, `internal/login/social.go` callback branch, `internal/myaccount`
routes, tests.
- [ ] Tests: happy path with the fixture provider; `TestCompleteBindings` (Review Focus 1); `TestConnectOwnedElsewhere` (Review Focus 2); expiry; reconnect unions scopes; connection without `connected_accounts.active` → `400`; list routes; delete revokes upstream (fixture records the RFC 7009 call) → implement → commit `feat(tokenvault): connected accounts flow`.

### Task 4: Exchange grant (gated §9.1)
**Files:** `internal/oauth/grant_federated_access.go`, `internal/tokenvault/exchange.go`, tests.
- [ ] Tests: refresh-token subject; access-token subject; `TestExchangeRefusesRotating` (Review Focus 5); missing account `401`; `login_hint` selection; `TestExchangeScopeSubset` (Review Focus 3); `TestExchangeRefreshOnce` (Review Focus 4); provider `invalid_grant` marks unavailable; client rule per the ruling → implement → commit `feat(oauth): federated connection access token exchange`.

### Task 5: Management listing and lifecycle
**Files:** `internal/mgmt/users_connected_accounts.go`, tests; deletion
paths; Plan 45c sweep hook.
- [ ] Tests: listing shape and paging; user deletion and connection deletion remove accounts and revoke upstream; `active: false` refuses exchanges and keeps accounts → implement → commit `feat(mgmt): users' connected accounts`.

### Task 6: Console, seed, E2E, docs, final verification
- [ ] **Step 1:** Console connection switch, user tab, application grant; Vitest; `console/dist`.
- [ ] **Step 2:** Seed fields.
- [ ] **Step 3:** `make e2e-token-vault` lane; CI matrix.
- [ ] **Step 4:** Docs: new `docs/token-vault.md`; `docs/social-connections.md`, `docs/my-account-api.md`, compatibility files, `CHANGELOG.md`, roadmap; implementation record.
- [ ] **Step 5:** Fast tier + E2E; push `plan-43-token-vault`; record CI; review; maintainer approval.
