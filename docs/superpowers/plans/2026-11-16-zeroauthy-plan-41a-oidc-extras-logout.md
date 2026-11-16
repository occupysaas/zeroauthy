# Plan 41a — OIDC extras, back-channel logout and global token revocation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `address`/`phone` scopes and the remaining `profile` claims, the
`claims` parameter, `acr_values` step-up with `acr`, client `oidc_support`,
`HS256`/`PS256` ID tokens, the `resource` compatibility profile, the first
non-compliant switches, OIDC Back-Channel Logout with initiators, global
token revocation for `oidc`/`okta` connections, and new conformance plans
for certification.

**Architecture:**
- **`internal/claims`** owns the scope → claim table, the `claims`
  parameter parser and the selection function used by the minter and
  `/userinfo`.
- **`internal/authz`** parses `claims`, `acr_values`, `resource`; the hosted
  login flow reads a `StepUp` flag on the transaction.
- **`internal/oauth/minter.go`** signs ID tokens per client algorithm.
- **`internal/logout`** (new): initiator fan-out → durable job
  (`internal/jobs`) → sender with the outbound network policy.
- **`internal/oauth/global_revocation.go`** verifies the upstream JWT with
  the Plan 36 pinned JWKS and ends sessions through `internal/logout`.
- **`internal/compat`** (new, tiny): reads `ZEROAUTHY_COMPAT__NONCOMPLIANT_*`
  and logs the startup warning.

**Tech Stack:** Go 1.26.10 (no new module), Vue/TypeScript console,
SQLite/PostgreSQL/MySQL, protobuf/gRPC, Playwright 1.64.0,
`express-openid-connect` 3.4.0 (pinned), node-auth0 7.4.0, auth0-cli
1.37.0, auth0-deploy-cli 9.1.0, OpenID conformance suite `release-v5.3.3`.

**Spec:** [Plan 41a design](../specs/2026-11-16-zeroauthy-oidc-extras-logout-design.md). § refers to it.

**Depends on:** Plan 35 (merged). Global token revocation (Task 10) needs
Plan 36's `okta` strategy and pinned JWKS; if Plan 36 has not merged when
Task 10 starts, implement it for `oidc` only and leave `okta` to Plan 36's
branch (a one-line strategy check). Session metadata in logout tokens is
`{}` until Plan 48 lands (L9).

## Global Constraints

- **Toolchain/dependencies.** Go `1.26.10`; keep every pin; no new module.
- **Clean room.** Own words everywhere.
- **Parity.** LR41a-1…16 and L1–L14 in **D-0080**; L points also in
  `docs/superpowers/plan-1-followups.md`. Amend D-0036 (cleared entries)
  and D-0063 (discovery algorithms).
- **Compat switches.** Exactly three, all default off:
  `ZEROAUTHY_COMPAT__NONCOMPLIANT_IGNORE_CLAIMS_PARAMETER`,
  `ZEROAUTHY_COMPAT__NONCOMPLIANT_OPTIONAL_REDIRECT_URI`,
  `ZEROAUTHY_COMPAT__NONCOMPLIANT_LOGOUT_TOKEN_TYP_JWT`. Startup logs one
  warning naming each switch that is on. `make conformance` runs with all off.
- **Limits.** `claims` ≤ 4 KiB; one back-channel URL ≤ 2048 bytes; logout
  token `exp` = `iat` + 120 s; delivery timeout 5 s; retry window 10 min;
  global-revocation JWT lifetime ≤ 5 min.
- **Never logged.** Logout tokens, global-revocation JWTs, client secrets
  (HS256 keys).
- **Generated code.** `x-source`; `make generate`; commit `console/dist`.
- **Migration.** One forward-only migration in three dialects written as
  `0039_oidc_logout.sql`; renamed to main's latest + 1 at merge.
- **Plugins.** Capability `oidc_logout.v1` gates writes of `oidc_logout`,
  `oidc_support` and non-RS256 `jwt_configuration.alg`.
- **Verification** per `AGENTS.md`: focused tests per task; final fast tier
  `TMPDIR=/dev/shm/za41a GOTMPDIR=/dev/shm/za41a go test -p 4 ./...`,
  `make e2e-logout` and `make conformance`; push `plan-41a-oidc-extras-logout`;
  report CI.
- **Worktree.** `/mnt/nvme2/code/zeroauthy-plan41a`, branch
  `plan-41a-oidc-extras-logout`; record in
  `docs/superpowers/2026-11-16-plan-41a-implementation-record.md`.
- **Commits** signed off.

## Review Focus

1. **`claims` widening consent.** `claims={"id_token":{"email":null}}` with
   only `openid` scope must not add `email` unless consent covers it (§3.3
   rule). Task 3 `TestClaimsNoConsentWidening`.
2. **Step-up inside SSO.** An existing session authenticated with password
   only + `acr_values` multi-factor → MFA prompt, then `acr` and `amr`
   `mfa`; a second request in the same session with MFA done → no prompt.
   Task 4 `TestStepUpInSSO`.
3. **HS256 with a public client** refused at write; an existing HS256
   client whose secret rotates signs with the new secret only. Task 5
   `TestHS256SecretRotation`.
4. **Logout fan-out duplicates:** one session, three clients, one of them
   twice in the session client list → each client gets exactly one token
   per session end. Task 8 `TestFanOutOncePerClient`.
5. **Global revocation forged JWT:** signed by another connection's issuer
   or replayed → `401`, nothing revoked. Task 10
   `TestGlobalRevocationRefusals`.

---

## File boundaries and shared interfaces

```go
// internal/claims
type Request struct{ IDToken, UserInfo map[string]*Requested } // nil map = none
type Requested struct{ Essential bool; Value any; Values []any }
func ParseRequest(raw string) (*Request, error)                       // ≤ 4 KiB, Core §5.5
func Select(user *store.User, identityProfile map[string]any, scopes []string, req *Request, target string /* "id_token"|"userinfo" */) map[string]any
const ACRMultiFactor = "http://schemas.openid.net/pape/policies/2007/06/multi-factor"

// internal/compat
type Switches struct{ IgnoreClaimsParameter, OptionalRedirectURI, LogoutTokenTypJWT bool }
func FromEnv(getenv func(string) string) Switches
func (s Switches) Warn(log *slog.Logger)

// store.Client gains
OIDCLogout  *OIDCLogout
OIDCSupport *OIDCSupport
IDTokenAlg  string // "" = RS256
type OIDCLogout struct{ BackchannelURLs []string; InitiatorsMode string; Initiators []string; IncludeSessionMetadata *bool }
type OIDCSupport struct{ IsAllowed bool; AllowAllScopes *bool; AllowedScopes []string }
// TenantSettings gains RPLogoutEndSessionDiscovery *bool

// internal/logout
type Initiator string // "rp-logout", "idp-logout", "password-changed", "session-expired", "session-revoked", "account-deleted", "email-identifier-changed"
func (s *Service) SessionsEnded(ctx context.Context, tid string, sessions []*store.LoginSession, why Initiator) error // enqueues jobs in the caller's tx
func (s *Service) Deliver(ctx context.Context, job *store.Job) error                                              // job handler
```

---

### Task 1: Contracts, decisions, conformance inventory

**Files:**
- Modify: `api/management.yaml` (client `oidc_logout`, `oidc_support`,
  `jwt_configuration.alg` enum; tenant `oidc_logout`), `api/authentication.yaml`
  (`claims`, `acr_values`, `resource` at `/authorize`, `/oauth/par`,
  `/oauth/token`; `POST /oauth/global-token-revocation/connection/{connectionName}`).
- Modify: `internal/tenantrules/inventory.go` (`resource_parameter_profile`,
  `acr_values_supported`, `oidc_logout` active), `internal/logrules/inventory.json`
  (`sslo`, `fslo` emitted; global revocation types from the logs schema).
- Modify: `docs/compat/decisions.md` (D-0080; amend D-0036, D-0063),
  `docs/superpowers/plan-1-followups.md` (L1–L14; Session Transfer Tokens
  as a new roadmap follow-up, LR41a-2).
- Create: `docs/superpowers/2026-11-16-plan-41a-conformance-check.md`
  recording the Implicit/Hybrid OP pass/fail check (§8) against a local run.
- Test: `api/spec_test.go`, inventory tests.

- [ ] **Step 1:** OpenAPI edits; `make generate`; `501` stub for the global revocation route; `go build ./...`.
- [ ] **Step 2:** Inventory edits; fix only pinned expectations.
- [ ] **Step 3:** Run `tests/conformance/run.sh` locally with ad-hoc Implicit and Hybrid plan entries (not committed to `plan_spec` yet); record results in the check file.
- [ ] **Step 4:** D-0080 and amendments; follow-ups.
- [ ] **Step 5:** Commit `docs: freeze Plan 41a contracts and D-0080`.

### Task 2: Compat switches

**Files:**
- Create: `internal/compat/compat.go`, `compat_test.go`.
- Modify: `internal/config` (wire `Switches`), `internal/app` (startup warning),
  `docs/conformance.md` (switch table).

- [ ] **Step 1:** Tests: unset → all false; `1`/`true` → true; anything else → false and a config error at startup (no silent misspelling, LR41a-10 rationale); `Warn` logs one line per enabled switch.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(config): non-compliant compat switches with a startup warning`.

### Task 3: Claims — scopes, profile, address, phone, `claims` parameter, `oidc_support`

**Files:**
- Modify/Create: `internal/claims/scopes.go`, `request.go`, `select.go`,
  tests; `internal/oauth/minter.go`, `internal/oidc/userinfo.go` (or the
  userinfo handler), `internal/authz` request parsing (`claims`),
  `internal/oauth/par.go`, JAR merge (Plan 35), `internal/clientrules`
  (`oidc_support` validation), `internal/oidc/handlers.go` (discovery
  `scopes_supported`, `claims_supported`, `claims_parameter_supported`).

- [ ] **Step 1: Write the failing tests**
  - `TestScopeClaims`: `profile` yields only present attributes; `phone` → `phone_number`, `phone_number_verified`; `address` → structured object when the root attribute exists, else nothing.
  - `TestClaimsParse`: valid Core §5.5 examples; > 4 KiB → `invalid_request`; non-object → `invalid_request`; unknown members ignored.
  - `TestClaimsSelect`: requested `email` with `email` scope → present; `TestClaimsNoConsentWidening` (Review Focus 1); `userinfo` vs `id_token` targets.
  - `TestClaimsIgnoredBySwitch`: switch on → parameter ignored, discovery omits `claims_parameter_supported`.
  - `TestOIDCSupport`: `is_allowed:false` drops `openid` (no ID token); `allowed_scopes:[email]` drops `profile`; both `allow_all_scopes` and `allowed_scopes` → `400`; `is_allowed` missing on POST → `400`.
  - `TestDiscoveryClaims`: lists updated as spec §2/§3.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(claims): address/phone scopes, profile claims, claims parameter and oidc_support`.

### Task 4: `acr_values` step-up and `acr`

**Files:**
- Modify: `internal/authz` (parse `acr_values`, `claims.acr`), store
  `AuthTransaction` (`StepUp bool` in the hosted state JSON), `internal/login`
  MFA decision (`internal/mfa` policy call site), `internal/oauth/minter.go`
  (`acr`, `amr`), `internal/oidc/handlers.go` (`acr_values_supported`).

- [ ] **Step 1: Write the failing tests**
  - `TestACRStepUpForcesMFA`: tenant policy `never` + `acr_values` multi-factor → MFA prompt (enrol if not enrolled, Plan 33 behaviour).
  - `TestStepUpInSSO` (Review Focus 2).
  - `TestACRClaim`: requested and satisfied → `acr` value, `amr` contains `mfa`; not requested → no `acr`.
  - `TestACRUnknownValue`: only unknown values → no step-up, no `acr`.
  - `TestACRViaClaimsEssential`: same as `acr_values`.
  - `TestACRRefreshToken`: refresh keeps the family's `acr` only if the session still has MFA (L4 note).
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(oidc): acr_values step-up and acr claim`.

### Task 5: ID token signing per client

**Files:**
- Modify: `internal/mgmt/clients.go` (`readJWTConfiguration` accepts
  `HS256`/`PS256` with the rules of spec §5), `internal/clientrules`,
  `internal/oauth/minter.go`, `internal/keys` (HS256 signer from the
  sealed client secret), `internal/oidc/handlers.go`
  (`id_token_signing_alg_values_supported`).

- [ ] **Step 1: Write the failing tests**
  - `TestJWTAlgRules`: `HS256` on a public client / `none` auth / `private_key_jwt`-only → `400`; `PS256` OK.
  - `TestIDTokenHS256`: verifies with the client secret; header has no `kid`.
  - `TestIDTokenPS256`: verifies with the tenant JWKS key.
  - `TestHS256SecretRotation` (Review Focus 3).
  - `TestDiscoveryIDTokenAlgs`: `["HS256","RS256","PS256"]`.
  - Logout tokens stay RS256 (asserted in Task 8).
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(oauth): HS256 and PS256 ID tokens per client`.

### Task 6: `resource` profile and optional `redirect_uri`

**Files:**
- Modify: `internal/authz` (`resource` → `audience` under `compatibility`;
  optional redirect with the switch), `internal/oauth/token.go`,
  `internal/oauth/par.go`, `internal/settingsrules`.

- [ ] **Step 1: Write the failing tests**
  - `TestResourceProfileAudience`: default → `resource` ignored.
  - `TestResourceProfileCompatibility`: `resource` alone → used as `audience`; both equal → OK; both different → `invalid_request`; two `resource` values → `invalid_target`.
  - `TestRedirectURIRequired`: omitted → error page (today's behaviour, now pinned).
  - `TestRedirectURIOptionalSwitch`: switch on + one non-wildcard callback → used; two callbacks or a wildcard → error page.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(authz): resource compatibility profile and optional redirect_uri switch`.

### Task 7: Client and tenant logout settings, storage

**Files:**
- Create: `internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0039_oidc_logout.sql`.
- Modify: `internal/store/types.go`, memory/sql/grpc codecs, `proto/store/v1/store.proto`
  (capability `oidc_logout.v1`), `internal/clientrules` (`oidc_logout`
  validation per spec §7.1), `internal/mgmt/clients.go`, tenant settings
  handler (`oidc_logout.rp_logout_end_session_endpoint_discovery`),
  `internal/oidc/handlers.go` (discovery logout fields).
- Test: storetest client round trip; clientrules tests; discovery tests.

- [ ] **Step 1: Write the failing tests**
  - `TestOIDCLogoutRules`: two URLs → `400`; `http://` → `400`; `custom` without required initiators → `400`; unknown initiator → `400`; OpenAPI-only initiators accepted (LR41a-11); absent → defaults on read.
  - `TestRPLogoutDiscoveryFlag`: `false` → no `end_session_endpoint` in discovery; endpoint still answers.
  - `TestDiscoveryBackchannel`: both flags `true`.
  - storetest round trip in memory, SQLite, gRPC; capability off → writes `400`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat: client oidc_logout and oidc_support settings`.

### Task 8: Back-channel logout fan-out and delivery

**Files:**
- Create: `internal/logout/service.go`, `token.go`, `deliver.go`, tests.
- Modify: every session-ending path to call `SessionsEnded` in the same
  transaction: `internal/oidc/logout.go`, `rp_logout.go` (`rp-logout`),
  `internal/mgmt/user_sessions.go` (`session-revoked`), user delete
  (`account-deleted`), password change/reset paths (`password-changed`),
  email change (`email-identifier-changed`), the session sweeper
  (`session-expired`).
- Modify: `internal/jobs` (register the `backchannel-logout` job kind),
  `internal/logs` (`sslo`, `fslo` with client ID and URL host only).

- [ ] **Step 1: Write the failing tests**
  - `TestLogoutTokenShape`: claims per spec §7.3; `typ: logout+jwt`; switch → `JWT`; RS256; no `nonce`; verifies with tenant JWKS.
  - `TestInitiatorSubscription`: default subscribes `rp-logout`/`idp-logout` only; `all`; `custom` lists.
  - `TestFanOutOncePerClient` (Review Focus 4).
  - `TestDeliveryOutcomes` (httptest receiver): `200` → `sslo`; `400` → `fslo`, no retry; `503` twice then `200` → one `sslo`, fresh token each attempt (LR41a-13); timeout > 5 s → retry; after 10 min → `fslo`.
  - `TestDeliveryNoRedirects`: `302` → `fslo`.
  - `TestDeliveryOutboundPolicy`: private address → refused before connecting, `fslo`.
  - `TestDeliverySurvivesRestart`: job persisted; a new service instance delivers it.
  - `TestEachInitiatorWired`: one test per trigger path asserting the job kind and initiator.
  - `TestLogoutUnblocked`: the user's logout response does not wait for delivery.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(logout): OIDC back-channel logout with initiators and durable delivery`.

### Task 9: Session metadata in logout tokens

**Files:** `internal/logout/token.go`.

- [ ] **Step 1:** Test: `include: true` adds `session_metadata` (`{}` until Plan 48's `LoginSession.Metadata` exists; when the field exists, its value) (L9).
- [ ] **Step 2:** Implement behind a small accessor so Plan 48's field is picked up without touching this package again.
- [ ] **Step 3:** Commit `feat(logout): optional session metadata in logout tokens`.

### Task 10: Global token revocation

**Files:**
- Create: `internal/oauth/global_revocation.go`, `global_revocation_test.go`.
- Modify: `internal/server/server.go` (route), `internal/oidc/handlers.go`
  (discovery fields), the `jti` replay table (Plan 35) with a `kind` column
  or a new table in Task 7's migration (builder's choice, spec §12).

- [ ] **Step 1: Write the failing tests**
  - `TestGlobalRevocationSuccess`: fixture issuer key signs a valid JWT for a linked user → `204`; sessions ended with `idp-logout` (back-channel tokens enqueued); refresh tokens revoked.
  - `TestGlobalRevocationRefusals` (Review Focus 5): wrong issuer, other connection's key, `alg: none`, expired, `exp` > 5 min, replayed `jti`, wrong `aud` → `401`.
  - `TestGlobalRevocationUnknownSubject`: `204`, nothing changed (LR41a-14).
  - `TestGlobalRevocationConnection`: unknown name or `google-oauth2` → `404`; malformed body → `400`.
  - `TestGlobalRevocationNoUserLookupByEmail`: `email` format resolves only through the identity index of that connection.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(oauth): global token revocation for enterprise OIDC connections`.

### Task 11: Console

**Files:** `console/src/pages/applications/` (Logout panel, OIDC support,
ID token algorithm), `console/src/pages/settings/` (RP logout discovery,
resource profile), `console/src/pages/logs/` (`sslo`/`fslo` rendering);
Vitest tests; `console/dist`.

- [ ] **Step 1:** Tests: required initiators fixed on; HS256 option disabled without a secret; one URL only.
- [ ] **Step 2:** Implement; `npm --prefix console test && npm --prefix console run build`.
- [ ] **Step 3:** Commit `feat(console): logout, OIDC support and ID token algorithm settings`.

### Task 12: Seed and Deploy CLI

- [ ] **Step 1:** Seed: `oidc_logout`, `oidc_support`, `jwt_configuration.alg`; tests.
- [ ] **Step 2:** Deploy CLI four-cell round trip with `oidc_logout`.
- [ ] **Step 3:** Commit `feat(seed): client logout and OIDC support settings`.

### Task 13: Conformance plans and certification kit

**Files:**
- Modify: `tests/conformance/run.sh` (`plan_spec` entries: `basic-post`,
  `formpost-post`, `backchannel`, plus Implicit/Hybrid if Task 1 recorded a
  pass), `tests/conformance/configs/*.json` (new configs; clients
  `za-cert-post` and a back-channel client), `expected-*.json` (remove the
  cleared D-0036 entries; add nothing without triage), the certification
  seed script (`make-seed.sh`: `oidc_logout` URL of the suite's receiver).
- Modify: `docs/conformance.md` (profiles table, switch table, certification
  steps for the new profiles).

- [ ] **Step 1:** Run `make conformance` locally; every module FINISHED; record results.
- [ ] **Step 2:** Triage any new warning/skip per the conformance guide; maintainer rulings only for Auth0-parity conflicts; record in D-0080.
- [ ] **Step 3:** Commit `test(conformance): back-channel logout and client_secret_post plans`.

### Task 14: E2E lane, docs, final verification

**Files:**
- Create: `tests/e2e/run-m41a-logout.sh`, `m41a-logout.spec.mjs`,
  `m41a-node-auth0.mjs`; `Makefile` (`e2e-logout`), `.github/workflows/ci.yml`
  (suite matrix).
- Docs: new `docs/logout.md` (RP-initiated, back-channel, initiators,
  global revocation, switches); update `docs/mfa.md` (step-up),
  `docs/client-authentication.md` (ID token algorithms),
  `docs/compatibility.md`, `docs/compat/matrix.md`, `CHANGELOG.md`, roadmap.
- Create: `docs/superpowers/2026-11-16-plan-41a-implementation-record.md`.

- [ ] **Step 1:** E2E: `express-openid-connect` app logged in, then `/oidc/logout` from another client → the Express app's session ends through back-channel; Playwright step-up; node-auth0 `oidc_logout` CRUD; fixture IdP global revocation; secret scan.
- [ ] **Step 2:** Docs.
- [ ] **Step 3:** Fast tier, `make e2e-logout`, `make conformance`; record exit codes.
- [ ] **Step 4:** Rename the migration; push `plan-41a-oidc-extras-logout`; record CI URL and failures.
- [ ] **Step 5:** Whole-branch review, fix wave, green CI, maintainer approval; then the maintainer runs the certification steps (§8).
