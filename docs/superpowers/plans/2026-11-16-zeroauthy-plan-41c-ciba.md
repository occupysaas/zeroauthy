# Plan 41c — CIBA (email channel) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `/bc-authorize`, the CIBA poll grant, email approval through the
`async_approval` template and a hosted approval page, client settings,
limits and discovery.

**Architecture:**
- **`internal/ciba`** (new): request validation, state machine
  (pending → approved/denied/expired → redeemed), limits.
- **`internal/oauth/grant_ciba.go`**: the poll grant.
- **`internal/login/ciba.go`**: `/u/ciba` approval page on the hosted
  stack (sign-in, MFA, Actions).
- **Storage:** `store.CIBA` repository.

**Tech Stack:** Go 1.26.10 (no new module), Vue/TypeScript console,
Playwright 1.64.0, the Plan 21 E2E mail sink.

**Spec:** [Plan 41c design](../specs/2026-11-16-zeroauthy-ciba-design.md). § refers to it.

## Global Constraints

- **Toolchain/dependencies.** Go `1.26.10`; keep every pin.
- **Parity.** LR41c-1…6 and C41-1…8 in **D-0100**; follow-ups; amend
  D-0025 (CIBA is first-party only) and roadmap §5 (Guardian push note).
- **Limits.** 500 requests/min and 5000 pending per tenant; `requested_expiry`
  1–259200 s; `binding_message` ≤ 64; `interval` 5 s (+5 on `slow_down`).
- **Never logged:** `auth_req_id`, approval tickets, tokens.
- **Migration.** One forward-only migration in three dialects written as
  `0048_ciba.sql`; renamed to main's latest + 1 at merge.
- **Verification** per `AGENTS.md`: focused tests; final fast tier
  `TMPDIR=/dev/shm/za41c GOTMPDIR=/dev/shm/za41c go test -p 4 ./...` plus
  `make e2e-ciba`; push `plan-41c-ciba`; report CI.
- **Worktree.** `/mnt/nvme2/code/zeroauthy-plan41c`, branch `plan-41c-ciba`;
  record in `docs/superpowers/2026-11-16-plan-41c-implementation-record.md`.
- **Commits** signed off.

## Review Focus

1. **No account oracle:** unknown user, unverified email and valid user get
   byte-identical `/bc-authorize` responses and timings within noise.
   Task 3 `TestBCAuthorizeNoOracle`.
2. **Wrong approver:** a session of user B opening user A's link must sign
   in as A; approving as B is impossible. Task 4 `TestApprovalRequiresHintedUser`.
3. **Single redemption:** concurrent polls after approval → one token
   response, others `invalid_grant`. Task 5 `TestCIBARedeemOnce`.
4. **Other client polling** someone else's `auth_req_id` → `invalid_grant`
   (no state change). Task 5 `TestCIBAOtherClient`.

---

### Task 1: Contracts and decisions
**Files:** `api/authentication.yaml` (`/bc-authorize`, CIBA grant),
`api/management.yaml` (client `async_approval_notification_channels`,
grant type), `make generate`, stubs; D-0100; follow-ups.
- [ ] Edits → build → commit `docs: freeze Plan 41c contracts and D-0100`.

### Task 2: Storage and client rules
**Files:** `internal/store/ciba.go` + drivers + storetest, migration,
capability `ciba.v1`; `internal/clientrules` (grant restrictions,
channels).
- [ ] storetest (create, transition CAS, redeem once, pending count, sweep) and client rule tests (third-party, `none`, non-conformant refused; push-only refused) → implement → commit `feat(store): CIBA requests`.

### Task 3: `/bc-authorize`
**Files:** `internal/ciba/request.go`, `internal/oauth/bc_authorize.go`,
route, discovery fields, limits, email send through Plan 21 with the
`async_approval` template, tests.
- [ ] Tests: parameter table; `TestBCAuthorizeNoOracle` (Review Focus 1); limits `429`; JAR request object; email content and link host → implement → commit `feat(oauth): backchannel authentication requests`.

### Task 4: Approval page
**Files:** `internal/login/ciba.go`, templates, i18n keys, tests.
- [ ] Tests: `TestApprovalRequiresHintedUser` (Review Focus 2); MFA per policy; Actions run and can deny; approve/deny transitions; expired or used ticket page → implement → commit `feat(login): CIBA approval page`.

### Task 5: Poll grant
**Files:** `internal/oauth/grant_ciba.go`, tests.
- [ ] Tests: state machine with injected clock (`authorization_pending`, `slow_down`, `expired_token`, `access_denied`); `TestCIBARedeemOnce` (Review Focus 3); `TestCIBAOtherClient` (Review Focus 4); tokens and refresh per Plan 48 rules → implement → commit `feat(oauth): CIBA token grant`.

### Task 6: Console, seed, E2E, docs, final verification
- [ ] **Step 1:** Console application settings; Vitest; `console/dist`.
- [ ] **Step 2:** Seed client fields.
- [ ] **Step 3:** `make e2e-ciba` lane; CI matrix.
- [ ] **Step 4:** Docs: new `docs/ciba.md`; `docs/email.md` (template), compatibility files, `CHANGELOG.md`, roadmap; implementation record.
- [ ] **Step 5:** Fast tier + E2E; push `plan-41c-ciba`; record CI; review; maintainer approval.
