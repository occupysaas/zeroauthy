# Plan 48 — Refresh tokens II Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Auth0-compatible rotation conversion, strict leeway, grant
revocation cascade, offline-access re-check, multi-resource refresh tokens,
online (session-bound) refresh tokens, the remaining refresh-token and
session Management API, and client-credentials token quotas.

**Architecture:**
- **`internal/oauth/grant_refresh_token.go`** gains a small decision step
  (`refreshPlan`) that picks one of: rotate, leeway-rotate, convert-to-rotating,
  convert-to-non-rotating, reuse-online, touch. The existing checks stay in
  front of it.
- **`internal/oauth/mrrt.go`** resolves the target audience and scopes from
  `refresh_token.policies`.
- **`internal/oauth/quota.go`** wraps the client-credentials grant with the
  store-backed `TokenQuotas` repository and writes the headers.
- **Storage.** `store.RefreshTokens` gains conversion, strict-leeway,
  session and bulk methods; new `store.TokenQuotas`; gRPC capability
  `refresh_tokens_ii.v1`.
- **`internal/mgmt`** completes `/refresh-tokens`, `/sessions/{id}` PATCH and
  revoke, grant cascade.

**Tech Stack:** Go 1.26.11 (no new module), Vue/TypeScript console,
SQLite/PostgreSQL/MySQL, protobuf/gRPC, Playwright 1.64.0, pinned
`@auth0/auth0-auth-js` 1.16.1, node-auth0 7.4.0, auth0-cli 1.37.0,
auth0-deploy-cli 9.1.0 (`@auth0/auth0-spa-js` only if already pinned in
`tests/e2e/package.json`; otherwise raw requests — no new pin without
approval).

**Spec:** [Plan 48 design](../specs/2026-11-16-zeroauthy-refresh-tokens-ii-design.md). § refers to it.

**2026-11-18 amendment:** Maintainer authorized downstream DPoP for online
refresh tokens. Spec §5.1 is binding. Task 6a precedes Task 7; Tasks 2/3
include its persistence contracts. This remains one active plan.

## Global Constraints

- **Toolchain/dependencies.** Go `1.26.11`; keep every pin; no new module.
- **Clean room.** Own words everywhere (`CLEAN_ROOM.md`).
- **Parity.** LR48-1…12 and R1–R8 go in **D-0070**; R points also in
  `docs/superpowers/plan-1-followups.md`. Amend D-0012 (strict leeway) and
  D-0043 (U8 still holds for offline tokens; ORTs end with the session).
- **Limits.** MRRT ≤ 10 policies, audience ≤ 600, scope ≤ 280; metadata ≤ 25
  string properties ≤ 255 characters (keys ≤ 255, R6 note); bulk revoke ≤ 100
  ids; quota values 1–2147483647.
- **Quota windows.** UTC hour and UTC day, injected clock only.
- **Never logged.** No refresh token or token hash in any log, stream,
  event or Action log.
- **Generated code.** `x-source` on API changes; `make generate`; never
  hand-edit generated files; commit `console/dist`.
- **Migration.** One forward-only migration in three dialects, written as
  `0038_refresh_tokens_ii.sql`; renamed to main's latest + 1 at merge.
- **Plugins.** `refresh_tokens_ii.v1` negotiated and latched; behaviour
  without it per LR48-12.
- **Tests.** Injected clocks; concurrency tests assert exact winner counts.
- **DPoP.** Spec §5.1 limits, nonce policy and authenticated binding are mandatory; never log proof/nonce/token material. DPoP capability gates fail closed.
- **Verification** per `AGENTS.md`: focused tests per task; final fast tier
  `TMPDIR=/dev/shm/za48 GOTMPDIR=/dev/shm/za48 go test -p 4 ./...` plus
  `make e2e-refresh-tokens`; push `plan-48-refresh-tokens-ii`; report CI.
- **Worktree.** `/mnt/nvme2/code/zeroauthy-plan48`, branch
  `plan-48-refresh-tokens-ii`; record in
  `docs/superpowers/2026-11-16-plan-48-implementation-record.md`.
- **Commits** signed off (`git commit -s`).

## Review Focus

1. **Second-to-last token inside the leeway** revokes the whole family,
   including the newest token. Task 4 `TestStrictLeewaySecondToLast`.
2. **Conversion races:** two concurrent first exchanges of the same
   non-rotating token after rotation is enabled → exactly one new rotating
   token; the other gets `invalid_grant`. Task 4 `TestConvertOneWinner`.
3. **MRRT ceiling:** after an MRRT exchange for API B, a plain refresh for
   API A must not carry B's scopes, and the stored family scopes are
   unchanged. Task 6 `TestMRRTFamilyUnchanged`.
4. **ORT after logout** fails with `invalid_grant`, and `/oauth/revoke` on an
   ORT logs the session out of every application. Task 7
   `TestORTSessionLifecycle`.
5. **Quota concurrency:** 50 parallel requests at `per_hour: 10` → exactly 10
   tokens. Task 9 `TestQuotaConcurrent`.

---

## File boundaries and shared interfaces

```go
// internal/store/types.go — RefreshToken gains
DPoPJKT         string
ParentID        string
Access          string            // "offline" (default) | "online"
Metadata        map[string]string
Device          *RefreshTokenDevice
LastExchangedAt *time.Time
type RefreshTokenDevice struct{ InitialIP, InitialASN, InitialUserAgent, LastIP, LastASN, LastUserAgent string }
// AuthTransaction and AuthCode gain DPoPJKT string.
// Client gains RequireProofOfPossession bool.
// ResourceServer gains ProofOfPossession *ProofOfPossession.
// type ProofOfPossession struct { Mechanism string; Required bool; RequiredFor string }
// LoginSession gains Metadata map[string]string
// RefreshTokenPolicy gains Policies []MRRTPolicy (nil = null)
type MRRTPolicy struct{ Audience string; Scope []string }
// ResourceServer gains AllowOnlineAccess, AllowOnlineAccessWithEphemeralSessions bool
// Client, Organization gain TokenQuota *TokenQuota; TenantSettings gains DefaultTokenQuota *DefaultTokenQuota
type TokenQuota struct{ Enforce bool; PerHour, PerDay int } // client_credentials block
type DefaultTokenQuota struct{ Clients, Organizations *TokenQuota }

// store.RefreshTokens gains
ConvertNonRotating(ctx context.Context, tid, presentedID string, next *RefreshToken) error // deletes all non-rotating (tid, client, audience, user); ErrNotFound if presented already gone
ConvertRotating(ctx context.Context, tid, presentedID string, next *RefreshToken, at time.Time) error // revokes rotating tokens of (tid, client, audience, user)
RevokeByUserClient(ctx context.Context, tid, userID, clientID, audience string, at time.Time) (int, error)
RevokeBySession(ctx context.Context, tid, sessionID string, at time.Time) (int, error)
ListByUserPage(ctx context.Context, tid, userID, clientID, from string, take int) ([]*RefreshToken, string, error)
UpdateMetadata(ctx context.Context, tid, id string, md map[string]string) (*RefreshToken, error)
RecordExchange(ctx context.Context, tid, id string, ip, ua string, at time.Time) error
// Rotate semantics change: inside leeway succeeds only if oldID is the parent of the family's newest live token; otherwise family revoked, ErrAlreadyUsed.

// internal/store/token_quotas.go
type QuotaSubject struct{ Kind string /* "client"|"organization" */; ID string; Quota TokenQuota }
type QuotaBucket struct{ Name string /* "per_hour"|"per_day" */; Limit, Remaining int; Reset time.Time }
type QuotaState struct{ Subject QuotaSubject; Buckets []QuotaBucket; Exceeded bool }
type TokenQuotas interface {
    Consume(ctx context.Context, tid string, subjects []QuotaSubject, now time.Time) ([]QuotaState, error) // increments only if no enforced bucket would exceed
    Peek(ctx context.Context, tid string, subjects []QuotaSubject, now time.Time) ([]QuotaState, error)
    PurgeBefore(ctx context.Context, before time.Time, limit int) (int, error)
}
// Store gains TokenQuotas() TokenQuotas and DPoP() DPoP
// type DPoP interface {
//   UseProof(ctx context.Context, tid, origin, jkt, jti string, now, expiresAt time.Time) error
//   PurgeBefore(ctx context.Context, before time.Time, limit int) (int, error)
// }

// internal/oauth
func (h *Handlers) mrrtTarget(ctx context.Context, tid string, c *store.Client, rt *store.RefreshToken, audience string, requested []string) (rs *store.ResourceServer, scopes []string, err *Error)
func quotaHeader(states []store.QuotaState, kind string) string // "b=per_hour;q=10;r=7;t=3540,b=per_day;..."
```

---

### Task 1: Contracts, decisions, inventory

**Files:**
- Modify: `api/management.yaml`: `GET /refresh-tokens`,
  `POST /refresh-tokens/revoke`, `PATCH /refresh-tokens/{id}`,
  `PATCH /sessions/{id}`, `POST /sessions/{id}/revoke`; schema additions
  (`refresh_token.policies`, `token_quota`, `default_token_quota`,
  resource-server online flags, metadata, device); `x-source` per spec §2.
- Modify: `api/authentication.yaml`: online_access scope (conflict rejected, DPoP required for public ORT), resource-server online flags in Management spec, and `/oauth/token` refresh grant
  `audience` description (MRRT); 429 quota response and headers on the
  client-credentials grant; `online_access` scope note.
- Modify: `internal/tenantrules/inventory.go`: `flags.revoke_refresh_token_grant`
  stored → enforced; `default_token_quota` active.
- Modify: `internal/actionsrules/inventory.json`: `event.refresh_token.access`,
  `event.refresh_token.metadata`, `event.session.metadata`,
  `event.client.refresh_token.policies`; `api.refreshToken.revoke` ORT note.
- Modify: scope inventory (`internal/tenantsetup/management.go`,
  `internal/server/mgmtapi.go`): `update:refresh_tokens`, `update:sessions`
  if absent.
- Modify: `docs/compat/decisions.md` (D-0070; amend D-0012, D-0043),
  `docs/superpowers/plan-1-followups.md` (R1–R8).
- Test: `api/spec_test.go`, inventory tests.

- [ ] **Step 1:** OpenAPI edits; `make generate`; `501` stubs for new operations; `go build ./...`.
- [ ] **Step 2:** Inventory edits; `go test ./api/ ./internal/tenantrules/ ./internal/actionsrules/` → fix only pinned expectations.
- [ ] **Step 3:** D-0070 and amendments; follow-ups.
- [ ] **Step 4:** Commit `docs: freeze Plan 48 contracts and D-0070`.

### Task 2: Store contract and memory driver

**Files:**
- Modify: `internal/store/types.go`, `internal/store/store.go`,
  `internal/store/memory/refresh_tokens.go` (or the file holding them),
  `internal/store/memory/sessions.go`.
- Create: `internal/store/dpop.go`, `internal/store/memory/dpop.go` (shared replay contract from spec §5.1), `internal/store/token_quotas.go`, `internal/store/memory/token_quotas.go`,
  `pkg/storetest/refresh_tokens_ii.go`, `pkg/storetest/token_quotas.go`.

- [ ] **Step 1: Write the storetest cases**
  - `StrictLeeway`: chain t0→t1→t2; inside leeway Rotate(t1) succeeds (t1 is parent of newest t2); Rotate(t0) inside leeway → `ErrAlreadyUsed` and whole family revoked.
  - `ConvertNonRotating`: three non-rotating tokens of (client, aud, user) + one of another audience → after convert, the three are gone, the other remains, `next` stored.
  - `ConvertRotating`: two rotating families of (client, aud, user) → both revoked; `next` (non-rotating) stored.
  - `ConvertOneWinner`: 8 concurrent ConvertNonRotating of the same presented token → 1 success, 7 `ErrNotFound`.
  - `RevokeByUserClient` with and without audience; `RevokeBySession`.
  - `ListByUserPage`: ID ascending; `client_id` filter; checkpoint `next`.
  - `UpdateMetadata` replace/clear; `RecordExchange` sets last device and time, keeps initial.
  - `SessionMetadata` round trip.
  - DPoP fields/config round trips and deep-copy isolation; auth transaction/code binding round trip.
  - `DPoPReplay`: same tenant/origin/key/jti accepted once, second ErrConflict; independent tenants/origins/keys do not conflict; expired entry can be claimed again; purge limit honored; transaction rollback restores proof state; 8 simultaneous uses exactly one winner.
  - Add shared DPoP storetest suite and register it; temporary unavailable adapters in SQL/gRPC may preserve compilation until Task 3, but are never passing implementation evidence.
  - `QuotaConsume`: hour/day buckets; enforced bucket at limit → `Exceeded`, nothing incremented in any subject; non-enforced over limit → incremented, `Exceeded=false`, remaining 0; window rollover with injected clock.
  - `QuotaConcurrent`: 50 goroutines at limit 10 → exactly 10 successes.
- [ ] **Step 2:** Run `go test ./internal/store/memory/` → FAIL; implement memory; → PASS.
- [ ] **Step 3:** Commit `feat(store): refresh tokens II and token quota contracts in memory`.

### Task 3: SQL and gRPC drivers, migration

**Files:**
- Create: `internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0038_refresh_tokens_ii.sql`
  (columns and table per spec §8.1; backfill `access='offline'`; index
  `(tenant_id, user_id, client_id, audience)` and `(tenant_id, session_id)`,
  `(tenant_id, family_id, created_at)`).
- Modify: `internal/store/sqlstore/refresh_tokens.go` (or equivalent),
  `sessions.go`, `clients.go`, `resource_servers.go`, `organizations.go`,
  tenant settings codec; create `token_quotas.go`.
- Modify: `proto/store/v1/store.proto` (fields, RPCs, capability
  `refresh_tokens_ii.v1`), `internal/store/grpcstore/*`; `make generate`.
- Modify: `internal/app/sweeper.go` (quota counter and DPoP replay purge).
- Include spec §5.1 DPoP replay table, auth transaction/code and refresh-token DPoPJKT fields, client PoP flag and API PoP configuration in the same migration and all SQL/gRPC codecs. Use `refresh_tokens_ii.v1` capability for replay support. Test DPoP storetest in SQLite and gRPC, and old-plugin fail-closed behavior.
- Test: sqlstore/grpcstore storetest runs; `migrate_test.go` oldest-schema upgrade.

- [ ] **Step 1:** Migration + drivers. Strict-leeway Rotate and Convert* use row locks (`FOR UPDATE` / `BEGIN IMMEDIATE`) on the presented token row; quota Consume uses `INSERT ... ON CONFLICT DO UPDATE` (PostgreSQL/SQLite) / `ON DUPLICATE KEY UPDATE` (MySQL) inside one transaction with a pre-check read under lock.
- [ ] **Step 2:** gRPC with latch; without capability: Rotate keeps old semantics (warn once at startup), other new methods return `ErrRefreshTokensIIUnavailable`.
- [ ] **Step 3:** SQLite locally; PostgreSQL/MySQL in CI.
- [ ] **Step 4:** Commit `feat(store): refresh tokens II and token quotas in SQL and gRPC`.

### Task 4: Refresh grant — conversion, strict leeway, offline re-check

**Files:**
- Modify: `internal/oauth/grant_refresh_token.go`, `refresh.go`.
- Create: `internal/oauth/refresh_plan.go`, `refresh_plan_test.go`.
- Test: `internal/oauth/grant_refresh_token_test.go`.

- [ ] **Step 1: Write the failing tests**
  - `TestConvertToRotating`: client switched to rotating; exchange of a non-rotating token → response has a new refresh token; the presented and the user's other non-rotating tokens for that client+audience no longer work; a token of another audience still works.
  - `TestConvertToNonRotating`: client switched off; exchange of a rotating token → non-rotating token returned; old family revoked.
  - `TestConvertOneWinner` (Review Focus 2).
  - `TestStrictLeewayPrevious`, `TestStrictLeewaySecondToLast` (Review Focus 1), `TestLeewayExpired`.
  - `TestOfflineRecheck`: API flips `allow_offline_access` off → `invalid_grant`; no rotation happened.
  - `TestConvertAfterChecks`: a blocked user's non-rotating token is not converted (no deletion).
- [ ] **Step 2–4:** FAIL → implement the `refreshPlan` decision → PASS (keep every existing refresh test green).
- [ ] **Step 5:** Commit `feat(oauth): refresh token conversion, strict leeway and offline re-check`.

### Task 5: Grant cascade and revoke-deletes-grant

**Files:**
- Modify: `internal/mgmt/grants.go`, `internal/oauth/revoke.go`,
  `internal/store` user-grant delete call sites.
- Test: `internal/mgmt/grants_test.go`, `internal/oauth/revoke_test.go`.

- [ ] **Step 1: Write the failing tests**
  - `TestDeleteGrantRevokesTokens`: grant (user, client) deleted → that client's refresh tokens of the user fail; another client's still work; user version bumped.
  - `TestDeleteGrantsByUser`: all grants and their tokens.
  - `TestRevokeDeletesGrantFlag`: flag on → `/oauth/revoke` deletes the grant and the user's other tokens for client+audience fail; flag off → only the token.
  - `TestUnlinkKeepsGrant`: `DELETE /refresh-tokens/{id}` keeps the grant.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat: grant deletion revokes its refresh tokens`.

### Task 6: Multi-resource refresh tokens

**Files:**
- Create: `internal/oauth/mrrt.go`, `mrrt_test.go`.
- Modify: `internal/oauth/grant_refresh_token.go`, `internal/clientrules`
  (policy validation), `internal/actions/event.go`
  (`event.client.refresh_token.policies`).
- Test: `internal/clientrules/*_test.go`.

- [ ] **Step 1: Write the failing tests**
  - `TestMRRTPolicyRules`: 11 policies, duplicate audience, Management API audience, third-party client → `400`; unknown audience stored.
  - `TestMRRTNoAudience`: requested scopes ∪ policy scopes for the token's own audience.
  - `TestMRRTOtherAudience`: policy audience → access token `aud` = B, scopes ⊆ policy ∩ requested ∩ API definitions ∩ RBAC; unauthorized requested scopes dropped silently.
  - `TestMRRTRefusals`: non-policy audience → `invalid_request`; API without skip-consent → `invalid_request`; API deleted → `invalid_request`.
  - `TestMRRTFamilyUnchanged` (Review Focus 3).
  - `TestMRRTRotation`: rotating client → new refresh token for the family's own audience.
  - `TestMRRTActionEvent`: post-login sees `event.resource_server.identifier` = B and the policies.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(oauth): multi-resource refresh tokens`.

### Task 6a: Downstream DPoP

**Files:**
- Create: `internal/dpop/proof.go`, `nonce.go`, `context.go`, and focused tests.
- Modify: `internal/oauth/token.go`, `minter.go`, `grant_authorization_code.go`, `grant_refresh_token.go`, `refresh.go`, all shared refresh issuance helpers, `internal/authz` authorize/PAR/JAR parsing and transaction/code creation, `internal/oidc/handlers.go`, `userinfo.go`, `internal/httpx` CORS, `internal/logscrub`.
- Modify: `internal/clientrules`, `internal/apirules`, `internal/mgmt` client/API codecs, seed rules, `internal/tenantrules` strict binding default, `api/*.yaml`, generated code via `make generate`.

**Interfaces:** Consume Task 2/3 `Store.DPoP` and DPoPJKT fields. Produce
`dpop.Service{Store store.Store, Wrapper keys.Wrapper, Now func() time.Time}`
with `Verify(ctx context.Context, r *http.Request, res tenant.Resolved,
requireNonce bool, accessToken, expectedJKT string) (*dpop.Proof, *dpop.Error)`;
`Proof{JKT string}`; `Error{Code string, Nonce string, Internal bool}`.
Shared context helpers carry authenticated proof to minter and issuance;
no raw proof enters request-info/Action/log context. Bind access claims via
an explicit `AccessTokenParams.DPoPJKT`; setting token_type follows actual
access-token binding, independently of refresh binding.

- [ ] **Step 1:** RED tests for spec §5.1 validation: ES256/RS256 success; wrong typ, none/HS256, private/remote JWK, weak/oversized RSA, wrong curve, malformed/duplicate JSON members, critical headers, oversized/repeated/comma headers, missing/wrong-type/expired/future claims, endpoint method/origin mismatch, query/default-port URI equivalence. Run `go test ./internal/dpop/` and observe expected failures.
- [ ] **Step 2:** Implement bounded verifier using existing jose and standard library. `go test ./internal/dpop/` → PASS.
- [ ] **Step 3:** RED nonce/replay tests with injected clock, two service instances sharing store/wrapper, exactly one replay winner, wrong tenant/origin/key and expired nonce, infrastructure failure closes access. Implement challenge handling and durable replay via Task 2/3 repo; focused suite → PASS.
- [ ] **Step 4:** RED configuration/policy tests: published client/API matrix including public-only required; strict binding per tenant; `dpop_jkt` on authorize/PAR/JAR and mismatch at redemption; valid proof binds refresh independently of API policy; no silent upgrade; all rotation/conversion/MRRT preserve key; missing/wrong proof changes no family/code/session/quota state; bound tokens cannot become Bearer or lose cnf via Actions. Implement at authenticated token boundary before grant side effects. Run `go test ./internal/oauth/ ./internal/authz/ ./internal/clientrules/ ./internal/apirules/` → PASS.
- [ ] **Step 5:** RED UserInfo tests: DPoP scheme with ath/key/nonce/method/URI/replay validation succeeds; Bearer/form downgrade, stolen token with another key, token substitution, other tenant/host and replay fail; unbound Bearer still works. Management/operator paths reject bound tokens without a verifier and do not mint them. Implement, then `go test ./internal/oidc/ ./internal/mgmt/ ./internal/server/ -run 'DPoP|Dpop|Userinfo|UserInfo|ProofOfPossession'` → PASS.
- [ ] **Step 6:** RED discovery, CORS allow/expose headers and log scrub tests; implement, regenerate; `go test ./internal/dpop/ ./internal/oauth/ ./internal/authz/ ./internal/oidc/ ./internal/httpx/ ./internal/logscrub/ ./api/` → PASS. Commit signed `feat(oauth): downstream DPoP proofs and token binding`.

### Task 7: Online refresh tokens

**Files:**
- Create: `internal/oauth/online.go`, `online_test.go`.
- Modify: `internal/oauth/grant_authorization_code.go` (issuance),
  `grant_refresh_token.go` (reuse path), `revoke.go` (ORT ends session),
  `internal/session` (idle reset; session end hooks call
  `RevokeBySession` for online tokens), `internal/actions` (`event.refresh_token.access`,
  `api.refreshToken.revoke` on ORT ends session), `internal/rbacrules` or
  `apirules` (resource-server flags).

- [ ] **Step 1: Write the failing tests**
  - `TestORTIssue`: `online_access` + API flag → refresh token with `access=online`, session ID; flag off → no refresh token, `online_access` dropped; ephemeral session without the ephemeral flag → none (R3).
  - `TestORTWithOffline`: both scopes → invalid_request at authorization entry, no transaction or token (LR48-7).
  - `TestORTRequiresDPoP`: public issuance and exchange require valid nonce/proof and same key; confidential ORT authenticates normally and preserves supplied binding; invalid proof cannot consume code or extend session.
  - `TestORTHiddenFromManagement`: no list/get/patch/delete refresh-token route reveals or individually mutates ORTs; session revoke ends them.
  - `TestORTReuse`: exchange returns no new refresh token; same token works again; session idle reset, absolute unchanged.
  - `TestORTSessionLifecycle` (Review Focus 4): logout, `DELETE /sessions/{id}`, session expiry and `POST /sessions/{id}/revoke` each invalidate it.
  - `TestORTRevokeEndsSession`: `/oauth/revoke` on an ORT → session gone, SSO to another client prompts login.
  - `TestORTOtherGrants`: device/password grants never issue ORTs.
  - `TestOfflineTokensSurviveSessionDelete` (U8 unchanged).
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(oauth): online refresh tokens bound to the login session`.

### Task 8: Management API completion

**Files:**
- Modify: `internal/mgmt/user_sessions.go` (JSON fields: `device` from the
  token, metadata, `last_exchanged_at`), create
  `internal/mgmt/refresh_tokens.go`, `sessions.go`, tests.
- Modify: `internal/oauth` exchange paths call `RecordExchange`.

- [ ] **Step 1: Write the failing tests**
  - `TestListRefreshTokens`: `user_id` required; unknown user `404`; ascending ID; `client_id` filter; `from`/`take` checkpoint; scope `read:refresh_tokens`.
  - `TestBulkRevoke`: each valid combination `202`; `ids` + `user_id` `400`; `client_id` alone `400`; `audience` without `client_id` `400`; 101 ids `400`.
  - `TestPatchRefreshTokenMetadata`: set, replace, clear with `null` and `{}`; 26 properties `400`; non-string value `400`; 256-char value `400`.
  - `TestPatchSessionMetadata` same rules.
  - `TestRevokeSession`: session deleted, its online and offline tokens revoked; both scopes required.
  - `TestRefreshTokenDevice`: issue from IP A/UA A, exchange from IP B/UA B → `initial_*` A, `last_*` B; `last_exchanged_at` updates on every exchange.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(mgmt): refresh token list, bulk revoke, metadata and session revoke`.

### Task 9: Token quotas

**Files:**
- Create: `internal/oauth/quota.go`, `quota_test.go`.
- Modify: `internal/oauth/grant_client_credentials.go`, `internal/clientrules`,
  `internal/orgrules`, `internal/settingsrules` (quota validation),
  `internal/mgmt` client/organization/tenant handlers, `internal/logs`
  (`token_quota_consumption_warning` type in the inventory if absent;
  `feccft` exists from Plan 31 — confirm).

- [ ] **Step 1: Write the failing tests**
  - `TestQuotaPrecedence`: client quota beats tenant default; organization quota beats tenant organization default; none → no headers.
  - `TestQuotaHeaders`: exact header text `b=per_hour;q=10;r=9;t=<secs>,b=per_day;q=50;r=49;t=<secs>` with an injected clock; organization header only on organization requests.
  - `TestQuotaExceeded`: 11th request at `per_hour:10` → `429` body as spec, `X-RateLimit-Remaining: 0`, `Retry-After`, `feccft` logged; `enforce:false` → 200 and warning logs.
  - `TestQuotaRefusedNoConsume` (LR48-11): a request failing client auth or scope checks does not count.
  - `TestQuotaWarnings`: logs once at 60/80/100 % per window.
  - `TestQuotaWindowRollover`: UTC hour boundary resets `per_hour`, not `per_day`.
  - `TestQuotaConcurrent` (Review Focus 5).
  - `TestQuotaValidation`: `{}` → `400` (minProperties 1); `per_hour: 0` → `400`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(oauth): client-credentials token quotas`.

### Task 10: Console

**Files:** under `console/src/pages/applications/` (refresh token panel,
MRRT editor, quota), `apis/` (online access switches), `settings/`
(revoke-deletes-grant flag, default quota), `organizations/` (quota),
`users/` (sessions revoke, metadata, device); Vitest tests; `console/dist`.

- [ ] **Step 1:** DPoP client/API configuration controls and public-client help text follow spec §5.1. Tests first: MRRT editor hidden for third-party apps; audience picker excludes the Management API; quota fields send `null` on clear; session revoke confirmation names that refresh tokens are revoked.
- [ ] **Step 2:** Implement; `npm --prefix console test && npm --prefix console run build`.
- [ ] **Step 3:** Commit `feat(console): refresh tokens II, online access and token quotas`.

### Task 11: Seed and Deploy CLI

- [ ] **Step 1:** Seed parsing for policies, quotas, online flags and DPoP client/API configuration through the shared rules packages; tests.
- [ ] **Step 2:** Deploy CLI four-cell round trip with policies, quotas and online flags where the 9.1.0 handlers carry them; record unsupported fields.
- [ ] **Step 3:** Commit `feat(seed): refresh token policies, quotas and online access`.

### Task 12: E2E lane, docs, final verification

**Files:**
- Create: `tests/e2e/run-m48-refresh-tokens.sh`, `m48-refresh-tokens.spec.mjs`,
  `m48-node-auth0.mjs`; modify `Makefile` (`e2e-refresh-tokens`),
  `.github/workflows/ci.yml` (suite matrix).
- Docs: new `docs/refresh-tokens.md` (rotation, leeway, conversion, MRRT,
  ORT, revocation paths, quotas); update `docs/token-exchange.md` pointer,
  `docs/compatibility.md`, `docs/compat/matrix.md`, `CHANGELOG.md`,
  `docs/upgrading.md` (strict leeway is a behaviour change: clients that
  retried with an older token inside the overlap now trip reuse detection),
  roadmap status.
- Create: `docs/superpowers/2026-11-16-plan-48-implementation-record.md`.

- [ ] **Step 1:** E2E per spec §8.4, with real generated proof keys and nonce retry: public ORT issuance/refresh/UserInfo and logout; wrong-key, proof replay, missing proof, Bearer downgrade, combined scopes and Management invisibility. Include external API cnf verification fixture; no new npm package. Cover DPoP client/API seed and Deploy round trip where tools support fields.
- [ ] **Step 2:** Docs.
- [ ] **Step 3:** Fast tier + `make e2e-refresh-tokens`; record exit codes.
- [ ] **Step 4:** Complete whole-branch review and local checks; rename the migration to main's latest + 1; push `plan-48-refresh-tokens-ii`; record CI URL, failed jobs and failures.
- [ ] **Step 5:** Obtain exact CI run URL once, hand monitoring to maintainer and wait for continue. Green CI and maintainer approval are required to merge.
