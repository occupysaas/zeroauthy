# Plan 40 — Actions III Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Post-login `api.session`, `api.refreshToken`,
`api.authentication.setPrimaryUser` and `recordMethod`; the newer event
members (risk assessment, custom domain, security context, session,
refresh token, user MFA and password-reset fields); `/userinfo` custom
claims; custom signup fields in `pre-user-registration`; the Actions
follow-up ledgers.

**Architecture:**
- **`internal/actions`** gains result fields (`SessionEffects`,
  `RefreshTokenEffects`, `PrimaryUserID`, `RecordedMethods`) collected from
  the runner, and the new event builders.
- **`internal/noderunner`** prelude exposes the new `api` methods (one shared
  prelude for every trigger, as today), still fail-closed for anything not
  listed.
- **`internal/authz`/`internal/login`** apply session effects and linking at
  flow completion in the existing finish transaction.
- **`internal/oauth/grant_refresh_token.go`** applies refresh-token effects.
- **`internal/oidc/userinfo.go`** reads the stored claims.

**Tech Stack:** Go 1.26.10, Node runner (existing), Vue/TypeScript console
type hints, SQLite/PostgreSQL/MySQL, Playwright 1.64.0,
`@auth0/auth0-spa-js` 2.28.3 (pinned).

**Spec:** [Plan 40 design](../specs/2026-11-16-zeroauthy-actions-iii-design.md). § refers to it.

**Depends on:** Plans 27/28 (merged). Metadata members and `api.refreshToken`
need Plan 48 (LR40-4): Task 4 checks whether Plan 48 is on `main` and, if
not, implements only the non-metadata `api.session` members and leaves the
rest fail-closed with a follow-up entry.

## Global Constraints

- **Toolchain/dependencies.** Go `1.26.10`; keep every pin and the Node
  runner version.
- **Clean room.** Own words; type hints written by us.
- **Parity.** LR40-1…7 and X1–X10 in **D-0190**; X points in
  `docs/superpowers/plan-1-followups.md`; update
  `internal/actionsrules/inventory.json` statuses (`supported` /
  `unsupported` / `empty`) for every member touched.
- **Limits.** Metadata per Plan 48; `recordMethod` URL ≤ 2048 bytes;
  `/userinfo` claims blob ≤ the Plan 27 custom-claim limit.
- **Never logged.** Tokens and metadata values (log key names only).
- **Tenant isolation.** Every new member reads only the Action's tenant.
- **Migration.** One forward-only migration in three dialects written as
  `0040_actions_iii.sql`; renamed to main's latest + 1 at merge.
- **Verification** per `AGENTS.md`: focused tests; final fast tier
  `TMPDIR=/dev/shm/za40 GOTMPDIR=/dev/shm/za40 go test -p 4 ./...` plus
  `make e2e-actions`; push `plan-40-actions-iii`; report CI.
- **Worktree.** `/mnt/nvme2/code/zeroauthy-plan40`, branch
  `plan-40-actions-iii`; record in
  `docs/superpowers/2026-11-16-plan-40-implementation-record.md`.
- **Commits** signed off.

## Review Focus

1. **Expiry setters extending a session** past its current absolute expiry
   or the tenant maximum must be capped. Task 3 `TestSessionSettersOnlyShorten`.
2. **`setPrimaryUser` race:** two concurrent logins linking the same
   secondary into different primaries → exactly one link; the other login
   fails `access_denied`. Task 5 `TestSetPrimaryUserOneWinner`.
3. **`session.revoke` with later Actions:** the session is gone after the
   flow even if a later Action redirects; no tokens are issued. Task 3
   `TestSessionRevokeStopsIssuance`.
4. **`/userinfo` claims after a refresh** reflect the latest flow, and a
   token from another client of the same session does not see them. Task 7
   `TestUserinfoClaimsPerClient`.
5. **Trusted fingerprint headers:** a client-supplied `X-JA3` without the
   operator setting yields `null`. Task 6 `TestSecurityContextTrustedOnly`.

---

## File boundaries and shared interfaces

```go
// internal/actions
type SessionEffects struct {
    Revoke *struct{ Reason string; PreserveRefreshTokens bool }
    ExpiresAt, IdleExpiresAt *time.Time
    CookieMode string // "" | "persistent" | "non-persistent"
    Metadata   *MetadataOps
}
type RefreshTokenEffects struct {
    Revoke *string; ExpiresAt, IdleExpiresAt *time.Time; Metadata *MetadataOps
}
type MetadataOps struct{ Set map[string]string; Delete []string; Evict bool } // applied in order: Evict, Set/Delete in call order (builder keeps the call log)
// PostLoginResult gains: Session *SessionEffects; RefreshToken *RefreshTokenEffects; PrimaryUserID string; RecordedMethods []string

type RiskAssessment struct{ Confidence string; Assessments map[string]Assessment }
type Assessment struct{ Code, Confidence string; Details map[string]any }
func AssessRisk(in RiskInput) RiskAssessment // pure

// internal/config
TrustedJA3Header, TrustedJA4Header string // ZEROAUTHY_TRUSTED_JA3_HEADER / _JA4_HEADER
```

---

### Task 1: Contracts, recheck, decisions

**Files:** `internal/actionsrules/inventory.json`; the bundled Actions type
definitions (find with `grep -rl "setCustomClaim" internal/noderunner
console/src`); `docs/compat/decisions.md` (D-0190; amend D-0053 for the
members that become supported); `docs/superpowers/plan-1-followups.md`
(X1–X10); a short recheck note in the D-0190 entry recording the
documentation status on the build date of the four deferred triggers and
`setUserId`.

- [ ] **Step 1:** Recheck the four triggers and `setUserId` in Auth0's docs; if any is now documented, stop and add a task for it to this plan (spec §1 item 10) before continuing.
- [ ] **Step 2:** Inventory and type hints; `go test ./internal/actionsrules/`.
- [ ] **Step 3:** D-0190; follow-ups.
- [ ] **Step 4:** Commit `docs: freeze Plan 40 contracts and D-0190`.

### Task 2: Runner prelude and result plumbing

**Files:** `internal/noderunner` prelude (the shared JS that builds `api`),
`internal/actions/engine.go` (result decoding), `internal/actions/*_test.go`.

- [ ] **Step 1: Failing tests** (runner-level, real Node):
  - `TestPreludeSessionMethods`: each `api.session.*` call is recorded in call order; invalid arguments throw `TypeError` inside the Action (cookie mode other than the two values, negative times, non-string metadata values, 26th key).
  - `TestPreludeRefreshTokenAbsent`: `api.refreshToken` is `undefined` when `event.refresh_token` is absent.
  - `TestPreludeRecordMethodOnlyInContinue`: throws in `onExecutePostLogin`.
  - `TestPreludeSetPrimaryUser`: records the last call; non-string throws.
  - `TestResultDecodeBounds`: oversized results are refused (existing result cap).
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(actions): session, refresh token and linking api members in the runner`.

### Task 3: Apply session effects

**Files:** `internal/authz/flow.go` (finish transaction), `internal/session`,
`internal/login` (cookie mode), `internal/logout` (Plan 41a initiator, if
merged; else a direct session delete with a TODO-free follow-up entry),
tests.

- [ ] **Step 1: Failing tests**
  - `TestSessionRevokeStopsIssuance` (Review Focus 3): denied with `access_denied`; session deleted; refresh tokens revoked unless `preserveRefreshTokens`.
  - `TestSessionSettersOnlyShorten` (Review Focus 1).
  - `TestSessionCookieMode`: `non-persistent` → cookie without `Expires`.
  - `TestSessionMetadataApplied` (when Plan 48 is on main): set/delete/evict order.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(actions): apply api.session effects at login`.

### Task 4: Apply refresh-token effects

**Files:** `internal/oauth/grant_refresh_token.go`, tests. Gate on Plan 48
(see Depends on).

- [ ] **Step 1: Failing tests**
  - `TestRefreshTokenRevokeFromAction`: family revoked, `invalid_grant`; an online token ends its session.
  - `TestRefreshTokenSettersOnlyShorten`.
  - `TestRefreshTokenMetadataFromAction`.
- [ ] **Step 2–4:** FAIL → implement → PASS (or record LR40-4 fallback).
- [ ] **Step 5:** Commit `feat(actions): apply api.refreshToken effects on refresh`.

### Task 5: `setPrimaryUser` and `recordMethod`

**Files:** `internal/authz/flow.go`, `internal/mgmt/user_identities.go`
(extract the link operation into a shared service if it is not already
one), `internal/session` (methods), `internal/oauth/minter.go` (`amr`),
tests.

- [ ] **Step 1: Failing tests**
  - `TestSetPrimaryUserLinks`: social secondary into database primary; tokens carry the primary `sub`; secondary gone; identities moved; link log.
  - `TestSetPrimaryUserRefusals`: absent, self, blocked primary, multi-identity secondary, identity already on primary → `access_denied`, nothing changed.
  - `TestSetPrimaryUserOneWinner` (Review Focus 2).
  - `TestRecordMethod`: after redirect and continue, session methods include the URL; `amr` contains `mfa`; next login's `event.authentication.methods` lists it.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(actions): account linking and external methods in post-login`.

### Task 6: Event members

**Files:** `internal/actions/event.go`, `risk.go`, `risk_test.go`,
`internal/config` (trusted headers), `internal/store` login session reads
for the full `session` member, Plan 33 known-device lookup, Plan 19
suspicious-IP state read.

- [ ] **Step 1: Failing tests**
  - `TestRiskAssessment` table: known/unknown device × blocked/clean IP → expected codes and overall confidence; `ImpossibleTravel` and `AgentDetection` `neutral`.
  - `TestEventCustomDomain`: present on a custom-domain request, absent on canonical.
  - `TestSecurityContextTrustedOnly` (Review Focus 5).
  - `TestEventUserFields`: `last_password_reset` for database users only; `multifactor` names.
  - `TestEventSessionMembers` and `TestEventRefreshTokenMembers` snapshots on login and refresh.
  - `TestEventTransactionIDs`: `linking_id` stable across the flow's Actions; `correlation_id` from the request.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(actions): risk assessment, custom domain, security context and session members`.

### Task 7: `/userinfo` custom claims

**Files:** `internal/oidc/userinfo.go`, `internal/authz/flow.go` (store the
claims), `internal/oauth/grant_refresh_token.go` (update), migration
`0040_actions_iii.sql` (session claims blob, cookie mode override), store
drivers and storetest.

- [ ] **Step 1: Failing tests**
  - `TestUserinfoCustomClaims`: namespaced claim set in post-login appears in `/userinfo` (X9: non-namespaced handling per the build-time doc).
  - `TestUserinfoClaimsPerClient` (Review Focus 4).
  - `TestUserinfoClaimsAfterRefresh`.
  - `TestUserinfoNoSession`: client-credentials token → no claims.
  - storetest round trip in memory, SQLite, gRPC.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(oidc): return Action custom claims from /userinfo`.

### Task 8: Custom signup fields and script context

**Files:** `internal/login/passkey_signup.go` / signup handlers (pass `ulp-`
fields into the pre-registration event), `internal/actions/event.go`,
hosted signup error rendering; `internal/customdb` (context argument, only
if documented, LR40-7).

- [ ] **Step 1: Failing tests**
  - `TestSignupFieldsInEvent`: `ulp-company` appears in `event.request.body`; not stored on the user; not logged.
  - `TestValidationErrorOnField`: `api.validation.error` message rendered on the signup page with fields kept.
  - `TestScriptContext` (if documented): `enableScriptContext: true` passes the frozen context; false passes none.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(actions): custom signup fields in pre-user-registration`.

### Task 9: Ledgers

- [ ] **Step 1:** Work through the Plan 27/28 deferred-minor ledgers in `docs/superpowers/plan-1-followups.md` (console log aggregate cap, sandbox probe assertions, and any Actions entry needing no ruling); each with a test; mark each entry closed with the commit.
- [ ] **Step 2:** Commit `fix(actions): Plan 27 and 28 deferred minors`.

### Task 10: Console, E2E, docs, final verification

- [ ] **Step 1:** Console: editor type hints, execution log rendering for the new effects; Vitest; `console/dist`.
- [ ] **Step 2:** E2E additions to `make e2e-actions` per spec §10.
- [ ] **Step 3:** Docs: `docs/actions.md` (new members, limits, LR40 rulings), `docs/compatibility.md`, `docs/compat/matrix.md`, `CHANGELOG.md`, roadmap; `docs/superpowers/2026-11-16-plan-40-implementation-record.md`.
- [ ] **Step 4:** Fast tier + `make e2e-actions`; rename the migration; push `plan-40-actions-iii`; record CI URL and failures.
- [ ] **Step 5:** Whole-branch review, fix wave, green CI, maintainer approval.
