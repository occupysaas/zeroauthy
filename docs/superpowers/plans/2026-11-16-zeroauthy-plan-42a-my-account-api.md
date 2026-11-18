# Plan 42a — My Account API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Auth0's My Account API (`/me/v1`) for a user's own
authentication methods and the tenant's factors, with activation through
the system resource server and user-subject client grants.

**Architecture:**
- **`internal/myaccount`** (new): router, bearer validation for the
  per-host `/me/` audience, problem-style errors, handlers.
- **`internal/myaccount/methods.go`** adapts the existing services:
  `internal/mfa` (TOTP, email, phone, recovery code, WebAuthn MFA),
  `internal/passkey` (passkeys), the password-change path used by reset
  (`internal/login` / `internal/dbconn`), and the Management API's
  authentication-method listing (one listing function shared by both APIs).
- **Activation** lives in `internal/tenantsetup` (system resource server
  creation) and `internal/apirules` (reserved identifier).

**Tech Stack:** Go 1.26.10 (no new module), Vue/TypeScript console,
Playwright 1.64.0 with a virtual WebAuthn authenticator,
`@auth0/auth0-spa-js` 2.28.3.

**Spec:** [Plan 42a design](../specs/2026-11-16-zeroauthy-my-account-api-design.md). § refers to it.

## Global Constraints

- **Toolchain/dependencies.** Go `1.26.10`; keep every pin.
- **Clean room.** Own words; the OpenAPI is the contract source.
- **Parity.** LR42a-1…7 and Y1–Y9 in **D-0210**; Y points in
  `docs/superpowers/plan-1-followups.md`.
- **Contract file.** Add `api/myaccount.yaml` (our own OpenAPI for the
  routes we serve, `x-source` per operation to the Auth0 OAS) and generate
  server types like `authapi`/`mgmtapi` (`make generate`).
- **Limits.** `auth_session` 5 min, single use; method name ≤ 100
  characters; request body ≤ 64 KiB (attestations included).
- **Never logged.** OTP codes, TOTP secrets, recovery codes, attestation
  objects, new passwords, bearer tokens.
- **Verification** per `AGENTS.md`: focused tests; final fast tier
  `TMPDIR=/dev/shm/za42a GOTMPDIR=/dev/shm/za42a go test -p 4 ./...` plus
  `make e2e-my-account`; push `plan-42a-my-account`; report CI.
- **Worktree.** `/mnt/nvme2/code/zeroauthy-plan42a`, branch
  `plan-42a-my-account`; record in
  `docs/superpowers/2026-11-16-plan-42a-implementation-record.md`.
- **Commits** signed off.

## Review Focus

1. **Cross-user `auth_session`:** user B verifying user A's `auth_session`
   → `404`/`400`, A's enrollment untouched. Task 5 `TestAuthSessionBoundToUser`.
2. **Audience per host:** a canonical-audience token on the custom domain
   (and the reverse) → `401`. Task 2 `TestMyAccountAudiencePerHost`.
3. **Client-credentials token** with a forged `sub` → `401`. Task 2
   `TestMyAccountRefusesClientTokens`.
4. **Password change** through `verify` runs history and breached-password
   checks and the `password-changed` effects. Task 6
   `TestMyAccountPasswordPolicy`.
5. **Last first factor** cannot be deleted. Task 7 `TestDeleteLastFirstFactor`.

---

## File boundaries and shared interfaces

```go
// internal/myaccount
type Handlers struct { Store store.Store; MFA *mfa.Service; Passkeys *passkey.Service; Passwords PasswordChanger; Keys *keys.Manager; Now func() time.Time; Log *slog.Logger }
type Caller struct{ TenantID, UserID, ClientID, Host string; Scopes []string }
func (h *Handlers) authenticate(r *http.Request) (*Caller, *Problem)
type Problem struct{ Type, Title, Detail string; Status int; Validation []ValidationError }
func writeProblem(w http.ResponseWriter, r *http.Request, p *Problem)

// shared listing (moved from internal/mgmt)
func authmethods.List(ctx context.Context, st store.Store, tid, userID string) ([]authmethods.Method, error)
type authmethods.Method struct{ ID, Type, Name string; CreatedAt time.Time; Usage []string; Extra map[string]any }

// internal/myaccount/session.go
func (h *Handlers) newAuthSession(ctx context.Context, c *Caller, typ string, sealed []byte) (string, error)
func (h *Handlers) takeAuthSession(ctx context.Context, c *Caller, raw string) (typ string, sealed []byte, err error) // single use
```

---

### Task 1: Contracts and decisions

**Files:** create `api/myaccount.yaml`; `internal/gen/myaccountapi` via
`make generate` (add the generator entry next to `authapi`);
`internal/apirules` (reserved identifier `https://<host>/me/` and its
scopes); `docs/compat/decisions.md` (D-0210);
`docs/superpowers/plan-1-followups.md` (Y1–Y9).

- [ ] **Step 1:** Write `api/myaccount.yaml` for the seven operations with `x-source`; `make generate`; stub handlers `501`; `go build ./...`.
- [ ] **Step 2:** D-0210; follow-ups.
- [ ] **Step 3:** Commit `docs: freeze Plan 42a contracts and D-0210`.

### Task 2: Activation, router and token validation

**Files:** `internal/tenantsetup` (create/delete the system resource
server), `internal/mgmt/resource_servers.go` (creating the reserved
identifier activates; rules for `is_system`), `internal/myaccount/router.go`,
`auth.go`, `problem.go`, tests; `internal/server/server.go` (mount on tenant
hosts); `internal/oauth` (refuse client credentials and token exchange for
the audience).

- [ ] **Step 1: Failing tests**
  - `TestActivateCreatesSystemAPI`: console/system API activation and `POST /resource-servers` with the identifier both produce the same system API with the §3 settings; delete deactivates and `/me/v1` answers `404`.
  - `TestMyAccountAudiencePerHost` (Review Focus 2).
  - `TestMyAccountRefusesClientTokens` (Review Focus 3); client-credentials grant for the audience → `access_denied`.
  - `TestMyAccountScopes`: each operation's scope enforced; missing → `403` problem body.
  - `TestProblemShape`: `type`, `status`, `title`, `detail`; `x-correlation-id` header.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(myaccount): activation, routing and token checks`.

### Task 3: Shared method listing, GET operations and factors

**Files:** create `internal/authmethods` (move the listing out of
`internal/mgmt/users_authentication_methods.go` or wherever it lives; the
Management API calls the shared function), `internal/myaccount/methods.go`,
`factors.go`, tests.

- [ ] **Step 1: Failing tests**
  - `TestListMethodsAllTypes`: a user with password, passkey, TOTP, phone, email and recovery code → six entries, IDs equal to the Management API's (LR42a-5).
  - `TestGetMethodOtherUser`: another user's method ID → `404`.
  - `TestFactorsList`: tenant with TOTP and email enabled, passkeys on the connection → `password`, `passkey`, `totp`, `email` with `usage`.
  - Management API authentication-method tests still pass unchanged.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(myaccount): list and read authentication methods and factors`.

### Task 4: `auth_session` store

**Files:** `internal/myaccount/session.go`, tests; reuse the Plan 33
challenge/ticket storage (sealed with the master key, TTL sweep).

- [ ] **Step 1:** Tests: single use; 5-min expiry with an injected clock; bound to user, client and type; tampered value → not found; the sealed payload never in logs.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(myaccount): enrollment sessions`.

### Task 5: OTP-style enrollments (TOTP, email, phone, recovery code)

**Files:** `internal/myaccount/enroll_otp.go`, tests; calls into
`internal/mfa` enrollment primitives (the same ones the hosted pages and
`/mfa/associate` use).

- [ ] **Step 1: Failing tests**
  - `TestEnrollTOTP`: start returns the TOTP data; verify with a code from the RFC 6238 test generator → method active; wrong code → `400` and attempt counted (Plan 33 throttle).
  - `TestEnrollEmail` / `TestEnrollPhone`: code sent through the fixture provider; verify activates; `voice` preference honoured.
  - `TestEnrollRecoveryCode`: code returned once; verify activates.
  - `TestEnrollDisabledFactor`: `400` (Y6).
  - `TestEnrollPush`: `400` (LR42a-2).
  - `TestAuthSessionBoundToUser` (Review Focus 1).
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(myaccount): TOTP, email, phone and recovery-code enrollment`.

### Task 6: WebAuthn, passkey and password

**Files:** `internal/myaccount/enroll_webauthn.go`, `enroll_password.go`,
tests; `internal/passkey`, `internal/webauthn` (per-host RP ID),
the password-change service.

- [ ] **Step 1: Failing tests**
  - `TestEnrollPasskey`: options use the host's RP ID; virtual authenticator attestation verifies; passkey on the chosen identity (`connection`, `identity_user_id`); limit reached → `409`.
  - `TestEnrollWebAuthnRoaming` / `Platform`: attachment in the options; stored as MFA WebAuthn.
  - `TestMyAccountPasswordPolicy` (Review Focus 4): start returns the policy; verify with a weak, reused or breached password → `400` with `validation_errors`; a good one changes it and applies the password-change session behaviour.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(myaccount): passkey, WebAuthn and password enrollment`.

### Task 7: Update and delete

**Files:** `internal/myaccount/methods.go`, tests.

- [ ] **Step 1: Failing tests**
  - `TestPatchName` (≤ 100 characters), `TestPatchPhonePreference`, `TestPatchUnknownField` → `400`.
  - `TestDeleteMethod`: removed from both APIs' listings; logs.
  - `TestDeleteLastFirstFactor` (Review Focus 5).
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(myaccount): update and delete authentication methods`.

### Task 8: Console, seed, E2E, docs, final verification

- [ ] **Step 1:** Console activation card and user-grant creation; Vitest; `console/dist`.
- [ ] **Step 2:** Seed `my_account_api.active` and user client grants; tests.
- [ ] **Step 3:** E2E lane `make e2e-my-account` (`run-m42a-my-account.sh`, Playwright + spa-js + raw requests); add to `.github/workflows/ci.yml`.
- [ ] **Step 4:** Docs: new `docs/my-account-api.md`; update `docs/mfa.md`, `docs/passkeys.md`, `docs/compatibility.md`, `docs/compat/matrix.md`, `CHANGELOG.md`, roadmap; implementation record.
- [ ] **Step 5:** Fast tier + `make e2e-my-account`; push `plan-42a-my-account`; record CI; whole-branch review, fix wave, green CI, maintainer approval.
