# Plan 39a — Sign in with Apple Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**State:** Tasks 1–7 implemented and reviewed. Task 8 E2E/docs acceptance passed; full Go tier, final review and CI remain separate gates. No push until all local checks and reviews finish (maintainer instruction).

**Goal:** An Auth0-compatible `apple` social connection with the web
(form-post) flow and the native iOS authorization-code exchange, plus the
`native_social_login` and `mobile.ios` client fields.

**Architecture:**
- **`internal/federation/rules/apple.go`**: option validation.
- **`internal/federation/apple.go`**: fixed endpoints, client-secret JWT
  signer with a short cache, the Apple provider (`Provider` interface:
  `AuthorizationURL`, `Exchange`), profile mapping including the one-time
  name.
- **`internal/login/social.go`**: `POST /login/callback` (shared with
  Plan 36; add it here if Plan 36 has not merged).
- **`internal/oauth/grant_native_social.go`**: the reserved
  `subject_token_type` branch of the token-exchange grant.

**Tech Stack:** Go 1.26.11 (no new module; go-jose v4 signs ES256),
Vue/TypeScript console, Playwright 1.64.0, node-auth0 7.4.0, auth0-cli
1.37.0, auth0-deploy-cli 9.1.0.

**Spec:** [Plan 39a design](../specs/2026-11-16-zeroauthy-apple-design.md). § refers to it.

## Global Constraints

- **Toolchain/dependencies.** Go `1.26.11`; keep every pin.
- **Clean room.** Own words; Apple's protocol from Apple's public docs.
- **Parity.** LR39a-1…10 and A1–A7 in **D-0170**; A points also in
  `docs/superpowers/plan-1-followups.md`; amend D-0039 (the client fields
  stop being "accepted and ignored").
- **Limits.** `user` / `user_profile` JSON ≤ 1 KiB; first/last name ≤ 150
  characters each; client-secret JWT lifetime 5 min, cache 4 min.
- **Never logged.** `app_secret`, client-secret JWTs, Apple codes, ID tokens,
  upstream tokens.
- **Generated code.** `x-source`; `make generate`; commit `console/dist`.
- **Migration.** 0037 adds native-social client persistence in SQLite, PostgreSQL and MySQL; recheck main before merge.
- **Verification** per `AGENTS.md`: focused tests; final fast tier
  `TMPDIR=/dev/shm/za39a GOTMPDIR=/dev/shm/za39a go test -p 4 ./...` plus
  `make e2e-apple`; push `plan-39a-apple`; report CI.
- **Worktree.** `/mnt/nvme2/code/zeroauthy-plan39a`, branch `plan-39a-apple`;
  record in `docs/superpowers/2026-11-16-plan-39a-implementation-record.md`.
- **Commits** signed off.

## Review Focus

1. **Native code for another bundle** → `invalid_grant`, no user created.
   Task 6 `TestNativeAppleWrongBundle`.
2. **Posted `user` name on a later login** is ignored; a forged `user` on
   an attempt that did not request `name` is ignored. Task 5
   `TestAppleUserFieldOnce`.
3. **`email_verified: "false"`** and absent → false; no linking by email.
   Task 4 `TestAppleProfileEmailVerified`.
4. **Key rotation:** a PATCH of `kid`/`app_secret` invalidates pending
   attempts and the client-secret cache. Task 3 `TestAppleSecretCacheRevision`.

---

## File boundaries and shared interfaces

```go
// internal/federation/rules
const Apple = "apple"
// Settings gains AppleTeamID, AppleKID string (sealed key read separately via ClientSecret-like AppSecret())

// internal/federation
func AppleEndpoints() Endpoints
type AppleOverride struct { Endpoints Endpoints; Issuer, DiscoveryURL string }
func (ps *Providers) WithAppleFixture(e AppleOverride) *Providers
func appleClientSecret(teamID, kid, sub string, key *ecdsa.PrivateKey, now time.Time) (string, error)
type AppleUser struct{ FirstName, LastName string } // from `user` or `user_profile`
func ParseAppleUser(raw string) (*AppleUser, error)

// internal/oauth
const SubjectTokenTypeAppleAuthzCode = "http://auth0.com/oauth/token-type/apple-authz-code"

// store.Client gains
NativeSocialLogin map[string]bool // "apple", "facebook", "google"
MobileIOS         *MobileIOS
type MobileIOS struct{ TeamID, AppBundleIdentifier string }
```

---

### Task 1: Contracts, decisions, inventory

**Files:** `api/management.yaml` (strategy `apple`, `ConnectionOptionsApple`,
client `native_social_login`, `mobile.ios`), `api/authentication.yaml`
(native exchange parameters, `user_profile`), `internal/federation/inventory.json`
(`apple` block), `docs/compat/decisions.md` (D-0170, amend D-0039),
`docs/superpowers/plan-1-followups.md` (A1–A7).

- [x] **Step 1:** Edits; `make generate`; `go build ./...`.
- [x] **Step 2:** `go test ./api/ ./internal/federation/` → fix pinned expectations only.
- [x] **Step 3:** Commit `docs: freeze Plan 39a contracts and D-0170`.

### Task 2: Option rules

**Files:** `internal/federation/rules/apple.go`, `apple_test.go`;
`rules.IsFederated`/`IsSocial` gain `apple`; `internal/connrules` dispatch.

- [x] **Step 1: Failing tests** `TestAppleRules`: missing any credential → error; `team_id` `abc` → error; non-EC or P-384 key → error; PATCH without `app_secret` preserves; empty `app_secret` → error; `client_id` change → error; `freeform_scopes: ["openid"]` → error; `name:false,email:false` → scope empty, OK.
- [x] **Step 2–4:** FAIL → implement → PASS.
- [x] **Step 5:** Commit `feat(federation): apple connection option rules`.

### Task 3: Client secret signer

**Files:** `internal/federation/apple.go`, `apple_secret_test.go`.

- [x] **Step 1: Failing tests**
  - `TestAppleClientSecretShape`: header `alg ES256`, `kid`; claims `iss`, `iat`, `exp-iat`=300, `aud` `https://appleid.apple.com`, `sub`; verifies with the public key.
  - `TestAppleSecretCache`: two calls within 4 min → same token; at 4 min + 1 s → new token.
  - `TestAppleSecretCacheRevision` (Review Focus 4).
- [x] **Step 2–4:** FAIL → implement → PASS.
- [x] **Step 5:** Commit `feat(federation): Apple client secret JWT`.

### Task 4: Provider and profile

**Files:** `internal/federation/apple.go`, `profile.go`, `discovery.go`
(dispatch `apple`), tests; `tests/e2e/social/provider/provider.go` gains an
Apple mode (form post, `user` field, string `email_verified`, ES256 client
secret verification against a registered public key).

- [x] **Step 1: Failing tests**
  - `TestAppleAuthorizeURL`: `response_mode=form_post` with scopes, `query` without; `nonce`; PKCE only if metadata lists S256.
  - `TestAppleExchange`: token request carries `client_id`=Services ID and the JWT secret; ID token validated (`aud`, `iss`, `nonce`).
  - `TestAppleProfileEmailVerified` (Review Focus 3) with `true`, `"true"`, `"false"`, absent.
  - `TestAppleProfilePrivateEmail`: `is_private_email` in profile data; relay email stored as is.
- [x] **Step 2–4:** FAIL → implement → PASS.
- [x] **Step 5:** Commit `feat(federation): Sign in with Apple provider`.

### Task 5: Form-post callback and the one-time name

**Files:** `internal/login/social.go` (`SocialCallbackPost` if absent;
Apple attempts set `SameSite=None; Secure`), `internal/server/server.go`,
`internal/federation/service_flow.go` (carry the parsed `user` into
completion), tests.

- [x] **Step 1: Failing tests**
  - `TestAppleFormPostCallback`: POST with `code`, `state` → signed in.
  - `TestAppleUserFieldOnce` (Review Focus 2): first login sets `given_name`/`family_name`/`name`; second login with a different `user` → unchanged; attempt without `name` scope → `user` ignored.
  - `TestAppleUserFieldLimits`: > 1 KiB or malformed JSON → ignored, login succeeds.
  - `TestCallbackGetStillWorks`.
- [x] **Step 2–4:** FAIL → implement → PASS.
- [x] **Step 5:** Commit `feat(login): form-post social callback for Apple`.

### Task 6: Native exchange

**Files:** `internal/oauth/grant_native_social.go`, `grant_native_social_test.go`;
`internal/oauth/grant_token_exchange.go` (branch on the reserved type
before profile lookup); `internal/clientrules` (`native_social_login`,
`mobile.ios` validation); `internal/mgmt/clients.go` (store and return the
fields instead of ignoring them).

- [x] **Step 1: Failing tests**
  - `TestNativeAppleDisabled`: flag off or no bundle ID → `invalid_request`.
  - `TestNativeAppleSuccess`: code exchanged with `client_id` = bundle ID; tokens issued; post-login ran with `apple` strategy; `user_profile` name applied on first login.
  - `TestNativeAppleWrongBundle` (Review Focus 1).
  - `TestNativeAppleNoNonce`: no nonce required.
  - `TestNativeAppleAppleError`: fixture returns `invalid_grant` → `invalid_grant`, failure log without the code.
  - `TestNativeAppleNotCustomProfile`: a custom token exchange profile cannot claim the Apple type (already refused by Plan 35 rules; pinned).
  - `TestClientNativeFieldsRoundTrip`: PATCH/GET returns `native_social_login` and `mobile.ios`.
- [x] **Step 2–4:** FAIL → implement → PASS.
- [x] **Step 5:** Commit `feat(oauth): native Sign in with Apple token exchange`.

### Task 7: Console, seed, Deploy CLI

- [x] **Step 1:** Console Social → Apple (create/detail, key paste with PEM check, switches) and Application → Device settings (Native Social Login Apple, iOS fields); Vitest tests; build `console/dist`.
- [x] **Step 2:** Seed: strategy, client fields; tests.
- [x] **Step 3:** Deploy CLI four-cell round trip with an `apple` connection and the client fields.
- [x] **Step 4:** Commit `feat(console): Apple connection and native social login settings`.

### Task 8: E2E lane, docs, final verification

**Files:** `tests/e2e/run-m39a-apple.sh`, `m39a-apple.spec.mjs`,
`m39a-native.mjs`; `Makefile` (`e2e-apple`); `.github/workflows/ci.yml`;
`docs/social-connections.md` (Apple section, native login),
`docs/compatibility.md`, `docs/compat/matrix.md`, `CHANGELOG.md`, roadmap;
`docs/superpowers/2026-11-16-plan-39a-implementation-record.md`.

- [x] **Step 1:** E2E: Playwright login through the fixture with form post; second login keeps the name; native exchange from Node; node-auth0 `connections.create({strategy:'apple'})`; auth0-cli `connections list/show`; secret scan.
- [x] **Step 2:** Docs (the guide names the Apple developer steps in our words and the LR39a limits).
- [ ] **Step 3:** Fast tier + `make e2e-apple`; record exit codes. Apple umbrella exit 0 (Task 8); controller owns the pending full local Go tier.
- [ ] **Step 4:** Push `plan-39a-apple`; record CI URL and failures.
- [ ] **Step 5:** Whole-branch review, fix wave, green CI, maintainer approval.
