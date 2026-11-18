# Plan 45b — Flow and API correctness fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the eleven pre-1.0 review findings listed in the spec and the
Plan 33 minors M3, M6 and M7, each with a regression test.

**Architecture:** no new packages; each task edits one flow or handler.
Task 1 (side effects after MFA) is the only cross-cutting one.

**Tech Stack:** Go 1.26.10 (no new module), Vue/TypeScript console.

**Spec:** [Plan 45b design](../specs/2026-11-16-zeroauthy-flow-api-fixes-design.md). § and item numbers refer to it.

## Global Constraints

- **Toolchain/dependencies.** Go `1.26.10`; keep every pin.
- **Parity.** LR45b-1…4 and B1–B4 in **D-0270**; amend D-0043, D-0047,
  D-0055, D-0060; B points in `docs/superpowers/plan-1-followups.md`;
  mark each review finding "fixed by Plan 45b" in its review file.
- **Do not move post-login Actions** relative to MFA (LR45b-4).
- **Migration.** Item 10 needs an online data migration of the email
  provider blob (Go code in the store's startup backfill, like
  `internal/keys/backfill.go`), not a schema change unless the public
  config column is missing; if a schema change is needed, one migration
  written as `0045_flow_api_fixes.sql`, renamed at merge.
- **Verification** per `AGENTS.md`: focused tests; final fast tier
  `TMPDIR=/dev/shm/za45b GOTMPDIR=/dev/shm/za45b go test -p 4 ./...` plus
  `make e2e-mfa e2e-organizations-ii e2e-passwordless e2e-email`; push
  `plan-45b-flow-api-fixes`; report CI.
- **Worktree.** `/mnt/nvme2/code/zeroauthy-plan45b`, branch
  `plan-45b-flow-api-fixes`; record in
  `docs/superpowers/2026-11-16-plan-45b-implementation-record.md`.
- **Commits** signed off, one per task.

## Review Focus

1. **Abandoned MFA leaves nothing behind** (invitation, membership,
   session, counters, consent). Task 2 `TestNoSideEffectsBeforeMFA`.
2. **Bucket locks:** concurrent attempts on two identifiers of one tenant
   proceed in parallel; the same identifier still serializes; no deadlock
   under randomized order. Task 12 `TestProtectionBucketLocks`.
3. **Provider blob migration** is idempotent and a crash mid-way leaves
   both forms readable. Task 11 `TestEmailProviderMigrationIdempotent`.

---

### Task 1: Decisions and review markers

- [ ] **Step 1:** D-0270 with LR45b-1…4 and B1–B4; the amendments; follow-ups.
- [ ] **Step 2:** Commit `docs: D-0270 for the Plan 45b fixes`.

### Task 2: Side effects after MFA (item 1, spec §3)

**Files:** `internal/authz/handlers.go` (`Resume`, `finish`, `approve`),
`internal/login/login.go` (password commit, `complete`), `internal/login/consent.go`,
`internal/orglogin` (membership), tests.

- [ ] **Step 1: Failing tests**: `TestNoSideEffectsBeforeMFA` (Review Focus 1) for password, passwordless, social and passkey first factors with an invitation and auto-membership; `TestConsentAfterMFA`; `TestSideEffectsOneTransaction` (a store failure in step 4 leaves none of them); existing Plan 29/30/33 tests still pass.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `fix(login): commit invitations, membership, sessions and counters after MFA`.

### Task 3: Signup code lifetime and budget (item 2)

**Files:** `internal/login/phone_codes.go`, tests.
- [ ] Tests `TestSignupCodeLifetime900`, `TestCodeBudgetPerConnectionAndKind` → implement → commit `fix(login): signup code lifetime and per-connection send budget`.

### Task 4: Brute-force log events (item 3)

**Files:** `internal/protection/service.go`, tests.
- [ ] Test `TestBruteForceLogsLimitWCOnce` (first denial logs `limit_wc`; later denials in the same block log nothing; no `limit_sul`) → implement → commit `fix(protection): log one limit_wc per brute-force block`.

### Task 5: Passwordless try route (item 4)

**Files:** `api/management.yaml` (system route), `internal/mgmt` system
handler calling `internal/passwordless` start, `console/src/pages/connections/PasswordlessSettings.vue`,
tests (Go and Vitest).
- [ ] Tests `TestPasswordlessTryRoute` (operator-only, tenant-scoped grant, sends through the provider fixture, never echoes the code) and the Vitest call-site test → implement → `console/dist` → commit `fix(console): passwordless test send through a system route`.

### Task 6: Admin CSP (item 5)

**Files:** `internal/server/admin.go`, `admin_test.go`.
- [ ] Test `TestAdminCSPNoTenantDomains`; console Management calls to custom-domain tenants still work through the system host → implement → commit `fix(admin): CSP without tenant domain enumeration`.

### Task 7: `PATCH /users` nulls and `verify_phone_number` (item 6)

**Files:** `internal/mgmt/users.go`, `internal/userrules`, tests.
- [ ] Tests `TestPatchUserNulls` (each field; required identifier `400`), `TestVerifyPhoneNumber` (sends the Plan 34 code; `false` no-op) → implement → commit `fix(mgmt): clear user attributes with null; verify_phone_number`.

### Task 8: Verification `organization_id` (item 7)

**Files:** `internal/mgmt/jobs.go`, `tickets.go`, email context, tests.
- [ ] Tests `TestVerificationOrganizationID` (member → accepted and branded; non-member → `400`) → implement → commit `fix(mgmt): organization_id on verification jobs and tickets`.

### Task 9: Organization read scopes (item 8)

**Files:** `internal/server/mgmtapi.go`, tests, D-0055 amendment.
- [ ] Test `TestOrganizationReadScopes` → implement → commit `fix(mgmt): organization reads require the documented scopes`.

### Task 10: `connection` filter (item 9)

**Files:** `internal/mgmt/users.go`, `docs/user-search.md`, tests.
- [ ] Test `TestUsersConnectionV1Only` → implement → commit `fix(mgmt): ignore the v1-only connection filter under v2 and v3`.

### Task 11: Email provider public credentials (item 10)

**Files:** `internal/emailrules/provider.go`, `internal/mgmt/email_provider.go`,
the startup backfill, tests.
- [ ] Tests `TestEmailProviderPublicCredentials`, `TestEmailProviderFields`, `TestEmailProviderMigrationIdempotent` (Review Focus 3) → implement → commit `fix(mgmt): return non-secret email provider credentials`.

### Task 12: Protection bucket locks (item 11)

**Files:** `internal/store/sqlstore/protection.go`, storetest, a contention
test runnable against PostgreSQL/MySQL in CI.
- [ ] Test `TestProtectionBucketLocks` (Review Focus 2) → implement → commit `perf(store): lock protection buckets instead of the tenant row`.

### Task 13: Plan 33 minors M3, M6, M7

**Files:** `internal/mfa` (purge job for abandoned pending authenticators in
the sweeper), `internal/mgmt/users.go` (batched `multifactor`),
`internal/oauth/minter.go` + auth code record (`amr` at issue), tests.
- [ ] Tests `TestPurgeAbandonedPending`, `TestUsersMultifactorBatched` (one query for a page), `TestAMRAtCodeIssue` → implement → commit `fix(mfa): Plan 33 review minors M3, M6 and M7`.

### Task 14: Docs and final verification

- [ ] **Step 1:** `CHANGELOG.md` (behaviour changes: consent after MFA, scopes, CSP), `docs/upgrading.md` (scope tightening may break tokens with only `read:users` for organization reads), roadmap; implementation record.
- [ ] **Step 2:** Fast tier + the four E2E targets; push `plan-45b-flow-api-fixes`; record CI.
- [ ] **Step 3:** Whole-branch review, fix wave, green CI, maintainer approval.
