# Plan 33 — MFA I Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce Auth0-compatible multi-factor authentication. That means
OTP, email, recovery codes and WebAuthn, with policies, hosted prompts, the
Authentication API `mfa_required` flow, Actions control, the Guardian and
user authentication-method Management APIs, and console, seed and Deploy CLI
support.

**Architecture:** A new MFA repository (memory, SQL, gRPC capability v1)
holds tenant Guardian settings, user authenticators, short-lived tokens,
challenges, tickets and browser records. Primitives (TOTP, recovery codes,
codes) live in `internal/mfa`, and an in-tree WebAuthn verifier lives in
`internal/webauthn`. One decision function, `mfa.Decide`, gates both the
hosted `/authorize` flow (after post-login Actions, before issuing a code)
and the password grants (`mfa_required`). Hosted MFA pages and the
`/mfa/*` endpoints share one service, `mfa.Service`.

**Tech Stack:** Go 1.26.7, Node >=22.13, Vue/TypeScript, SQLite/PostgreSQL/MySQL,
protobuf/gRPC, pinned node-auth0, `@auth0/auth0-auth-js` 1.16.1, auth0-cli
1.37.0, auth0-deploy-cli 9.1.0, Playwright (CDP virtual authenticator). No
new Go module dependency.

**Spec:** [MFA I design](../specs/2026-11-02-zeroauthy-mfa-design.md). Read
it before executing any task. Section numbers below (§) refer to it.

## Global Constraints

- Use Go 1.26.7 and Node >=22.13; keep repository dependency pins; add no Go module (CBOR/COSE in-tree).
- Follow `CLEAN_ROOM.md`. Documentation is evidence; SDK/CLI/Terraform source is only a lead.
- Every ID and query is tenant-scoped; cross-tenant references behave as missing.
- TOTP: SHA-1, 6 digits, 30 s step, ±1 step, a used step is never accepted again.
- Recovery code: 24 uppercase alphanumerics (`A–Z0–9`), one active per user, replaced on use, stored hashed.
- Lifetimes: `mfa_token` 10 min; email code 5 min, 5 attempts, 6 digits; WebAuthn challenge 5 min;
  enrollment ticket 7 days; remember browser 30 days; confidence-score device window 30 days.
- Throttle: 10 wrong codes per user and factor per 15 min → `too_many_attempts` + `gd_otp_rate_limit_exceed`;
  5 MFA emails per user per 15 min; email resend after 30 s.
- IDs: authentication method `<type>|dev_` + 20 alphanumerics; enrollment `dev_` + 20 alphanumerics.
- WebAuthn: attestation `none`; algorithms ES256 (-7), RS256 (-257), EdDSA (-8); RP ID = serving host;
  CBOR depth ≤ 16, input ≤ 64 KiB, no indefinite lengths or tags.
- Codes, recovery codes, tokens, tickets and cookies are stored only as `secrets.HashToken`; TOTP and
  provider secrets are sealed with the master key; none appear in API responses (except the one-time
  displays the spec names), logs, events or console state.
- MFA never applies to `client_credentials` or `refresh_token`; required-but-impossible MFA fails closed.
- Providers (maintainer ruling 2026-11-02, spec §1): MFA, enrollment and reset emails go through the
  tenant's configured Plan 21 email provider (any of the nine plus `custom`), never one hard-coded provider.
  Stored SMS/phone provider configuration is JSON keyed by route with per-provider sealed secrets, so
  Plan 34 can add native non-Twilio providers without a migration. Plan 33 validates only Auth0's documented shapes.
- OTP is standard RFC 6238 and must work with any authenticator app (`otpauth://totp` URI and base32 secret, no vendor parameters).
- Migration `0033_mfa.sql` (renumber only if another migration lands first).
- Keep older gRPC plugins working; negotiate MFA v1 separately; missing capability returns 501
  `mfa_unavailable` on this plan's routes and the policy reads as `[]`.
- Plan 19's database hold applies only to Plan 19, not this plan.
- Add `x-source` to API operations and regenerate with `make generate`; never hand-edit generated
  Go/protobuf/TypeScript. `console/dist` is a committed build artifact.
- Work in an isolated worktree. Record commits, reviews, commands and actual results in
  `docs/superpowers/2026-11-02-plan-33-implementation-record.md`.
- Long suites follow `AGENTS.md`: start once, log to a file, one monitor, no polling more often than every 15 minutes.

## Review Focus

1. A user has an SSO session from an app that did not need MFA. The policy
   then changes to `all-applications`, or a second app's Action enables MFA.
   The second authorization must challenge. `prompt=none` must return
   `interaction_required`, never a code. Pinned in Tasks 8 and 9.
2. The same TOTP code or recovery code is submitted twice at once (two tabs,
   or a hosted page racing an `mfa-otp` grant). Exactly one may succeed, and
   the replayed step is rejected afterwards. Pinned in Tasks 3, 4 and 11.
3. An `mfa_token` is reused after success, presented by a different client,
   used after 10 minutes, or used to request a wider scope than the original
   grant. Each must be `invalid_grant`, and the bound request must win.
   Pinned in Task 11.
4. A WebAuthn assertion comes from a cloned authenticator (sign count not
   increasing), or from a credential registered on a custom domain but used
   on the canonical domain. Or the CBOR is truncated, deeply nested or
   oversized. Each must be rejected without a panic or unbounded allocation.
   Pinned in Tasks 2 and 10.
5. An operator disables the only factor a user is enrolled in while the
   policy is `all-applications`. The user must be sent to enroll in an
   enabled factor, or recover with a recovery code if that factor is
   enabled. If no enforced factor is enabled, the login must fail with
   `access_denied` and never skip MFA. Pinned in Task 8.

## File boundaries and shared interfaces

| Responsibility | Files |
| --- | --- |
| Contracts | new `internal/mfarules/{inventory.json,rules.go,rules_test.go}`; existing `api/management.yaml`, `api/authentication.yaml`, `docs/compat/{decisions,matrix}.md`, `docs/compat/observations/mfa.md`, `internal/logrules/inventory.json`, `internal/actionsrules/inventory.json` |
| Primitives | new `internal/mfa/{totp,recovery,codes,ids,qr}.go` |
| WebAuthn | new `internal/webauthn/{cbor,cose,clientdata,authdata,register,assert}.go` |
| Storage | new `internal/store/mfa.go`, `internal/store/memory/mfa.go`, `pkg/storetest/mfa.go`, `internal/store/sqlstore/mfa.go`, `internal/store/grpcstore/mfa.go`, migration 0033 ×3; existing `proto/store/v1/store.proto`, `internal/store/types.go` (`LoginSession.MFAAt`, `User.RememberBrowserEpoch`) |
| Decision and service | new `internal/mfa/{decide,service,throttle,email}.go` |
| Management API | new `internal/mgmt/{guardian,guardian_stored,guardian_tickets,user_auth_methods}.go`; existing user serializer, `internal/jobs/importer.go`, `internal/events/decorator.go` |
| Hosted login | new `internal/login/mfa.go`, `internal/login/mfa_webauthn.go`, templates `internal/ui/templates/mfa_*.html`, `internal/ui/static/mfa-webauthn.js`; existing `internal/authz/{flow,actions,continue}.go`, `internal/session/session.go`, i18n catalogs, branding prompt registry |
| Authentication API | new `internal/oauth/{grant_mfa,mfa_api}.go`; existing `internal/oauth/{grant_password,minter,handlers}.go`, `internal/clientrules` |
| Actions | existing `internal/actions/{triggers,event,engine,reset}.go`, `runner.mjs`, `internal/noderunner` |
| Console | new `console/src/pages/security/Mfa.vue`, `console/src/pages/users/UserMfa.vue`; existing `sections.ts`, `router.ts`, user detail, Actions editor hints, locales |
| Provisioning, E2E, docs | existing `internal/seed`, `tests/e2e/deploy-cli/manifest.json`; new `tests/e2e/{m33-mfa.spec,m33-mfa-node,m33-mfa-grants,m33-mfa-cli}.mjs`, `run-m33-mfa.sh`, Makefile `e2e-mfa`, `docs/mfa.md` |

Task 4 owns the storage contract. Add `Store.MFA() MFA` to every store and
transaction view, with an `UnimplementedMFA` stub returning
`ErrMFAUnavailable` until each driver lands.

```go
// internal/store/mfa.go. All ctx are context.Context.
type GuardianSettings struct {
	TenantID      string
	Factors       map[string]bool            // eight names from mfarules
	Policies      []string                   // [], ["all-applications"] or ["confidence-score"]
	Stored        map[string]json.RawMessage // route key → public JSON for §3 stored routes
	SealedSecrets map[string][]byte          // route key → sealed provider secret JSON
	Version       int
}
type Authenticator struct {
	TenantID, UserID, ID, Type, Name string // Type: totp|email|recovery-code|webauthn-roaming|webauthn-platform|phone
	Confirmed, Preferred             bool
	SealedSecret                     []byte // TOTP
	LastStep                         int64  // last accepted TOTP step
	CodeHash                         string // recovery code
	Email, Phone                     string
	CredentialID, PublicKey          []byte // WebAuthn; PublicKey is the COSE key
	RPID                             string
	SignCount                        uint32
	CreatedAt, LastAuthAt            time.Time
}
type MFAToken struct {
	TenantID, Hash, ClientID, UserID, Connection string
	Request                                      json.RawMessage // audience, scope, effects
	ExpiresAt                                    time.Time
}
type MFAChallenge struct {
	TenantID, ID, UserID, AuthenticatorID, Kind string // Kind: email|webauthn|oob
	CodeHash                                    string
	Challenge                                   []byte
	Attempts                                    int
	ExpiresAt                                   time.Time
}
type EnrollmentTicket struct {
	TenantID, Hash, UserID, Factor string
	AllowMultiple                  bool
	ExpiresAt                      time.Time
}
type MFABrowser struct {
	TenantID, Hash, UserID, Kind string // Kind: remember|device
	Epoch                        int
	ExpiresAt                    time.Time
}

type MFA interface {
	GetGuardian(ctx, tid string) (*GuardianSettings, error) // defaults when none stored
	PutGuardian(ctx, s *GuardianSettings, version int) error // ErrConflict on version mismatch

	CreateAuthenticator(ctx, a *Authenticator) error // ErrConflict on duplicate WebAuthn credential ID in tenant
	GetAuthenticator(ctx, tid, uid, id string) (*Authenticator, error)
	ListAuthenticators(ctx, tid, uid string) ([]Authenticator, error)
	UpdateAuthenticator(ctx, a *Authenticator) error // name, preferred, confirmed
	DeleteAuthenticator(ctx, tid, uid, id string) error
	DeleteUserAuthenticators(ctx, tid, uid string, types []string) error // nil = all
	AcceptTOTPStep(ctx, tid, uid, id string, step int64, at time.Time) error   // ErrPrecondition unless step > LastStep
	ReplaceRecoveryCode(ctx, tid, uid, oldHash, newHash string, at time.Time) error // ErrPrecondition unless current hash == oldHash ("" = none yet)
	AcceptSignCount(ctx, tid, uid, id string, count uint32, at time.Time) error // ErrPrecondition unless increasing (both zero allowed)

	CreateMFAToken(ctx, t *MFAToken) error
	ConsumeMFAToken(ctx, tid, hash, clientID string, now time.Time) (*MFAToken, error) // ErrNotFound if missing, expired, consumed or other client
	PeekMFAToken(ctx, tid, hash string, now time.Time) (*MFAToken, error)

	CreateChallenge(ctx, c *MFAChallenge) error
	GetChallenge(ctx, tid, id string, now time.Time) (*MFAChallenge, error)
	FailChallenge(ctx, tid, id string) (attempts int, err error)
	ConsumeChallenge(ctx, tid, id string, now time.Time) error // ErrPrecondition if consumed or expired

	CreateTicket(ctx, t *EnrollmentTicket) error
	ConsumeTicket(ctx, tid, hash string, now time.Time) (*EnrollmentTicket, error)

	PutBrowser(ctx, b *MFABrowser) error
	GetBrowser(ctx, tid, hash string, now time.Time) (*MFABrowser, error)
	BumpRememberEpoch(ctx, tid, uid string) error // also on store.User.RememberBrowserEpoch

	PurgeMFA(ctx, before time.Time, limit int) (int, error) // expired tokens, challenges, tickets, browsers
	DeleteUserMFA(ctx, tid, uid string) error
	DeleteTenantMFA(ctx, tid string) error
}
```

Decision and service contract (Tasks 3, 7, 8):

```go
// internal/mfa
type Requirement struct {
	Required, Enroll, AlwaysPrompt, AllowRemember bool
	Factors []string // allowed factor types, in preference order
	Reason  string   // "policy", "action", "confidence", "ticket"
}
type DecideInput struct {
	Settings      *store.GuardianSettings
	Effects       *actions.MFAEffects // nil when no Action asked
	Authenticators []store.Authenticator
	SessionMFAAt  time.Time
	RememberValid, KnownDevice bool
	CustomizeInActions bool // tenant customize_mfa_in_postlogin_action
}
func Decide(in DecideInput) (Requirement, error) // ErrNoFactor → access_denied (§4.6)

type Service struct { /* store, sealer, mailer, throttle, clock, log */ }
func (s *Service) BeginEnroll(ctx, tid, uid, factor string, rpID string) (*Enrollment, error)
func (s *Service) ConfirmEnroll(ctx, tid, uid string, e *Enrollment, proof Proof) (*Confirmed, error) // Confirmed.RecoveryCode set on first factor
func (s *Service) BeginChallenge(ctx, tid, uid, authenticatorID, rpID string) (*Challenge, error)
func (s *Service) Verify(ctx, tid, uid string, c *Challenge, proof Proof) error // ErrInvalidCode, ErrThrottled
func (s *Service) Recover(ctx, tid, uid, code string) (newCode string, err error)
```

```go
// internal/actions: produced by Task 12, consumed by Task 8
type MFAEffects struct {
	Provider             string // any|google-authenticator|guardian|none|duo; "" when challenge/enroll used
	AllowRememberBrowser bool
	Mode                 string // "", "challenge", "enroll"
	Factors              [][]string // challengeWith: [[first], additional...]; challengeWithAny: [[a,b,...]]
}
// Effects gains field MFA *MFAEffects
```

For each task: write the named tests, run the focused command and observe
the stated failure, implement, rerun to PASS, review the diff, then commit
only that task's files. Run commands from the worktree root.

### Task 1: Observation, wire contracts and decisions

**Files:** create `internal/mfarules/{inventory.json,rules.go,rules_test.go}`,
`docs/compat/observations/mfa.md` (observer session only), the
implementation record. Modify `api/management.yaml`, `api/authentication.yaml`,
`docs/compat/decisions.md` (D-0059), `docs/compat/matrix.md` and the
roadmap's Plan 33 entry.

**Interfaces:** produces `mfarules.Factors() []Factor` (`Factor{Name, Status string}`,
Status `enforced|stored|not_planned`, in Auth0's order), `mfarules.Route(op string) Route`,
`mfarules.MethodTypes() []MethodType` (`{Type string; Creatable bool; Fields []string; Secret []string}`),
`mfarules.Screens() map[string][]string` (prompt → screens), `mfarules.ActionMember(name) Member`,
`mfarules.DeployHandlers() map[string]string` (handler → `included`|`Plan 34`|`not_planned`), and
`mfarules.Limits` holding the Global Constraints numbers.

- [ ] The maintainer runs a separate observer session for M1–M9 (§2) on the
  dev tenant and commits `docs/compat/observations/mfa.md`. Implementers do
  not observe. Unanswered points keep the §9 local rulings and are listed as gaps.
- [ ] Write `TestMFAInventory`. Every §3 and §7 route has a source URL,
  scopes, parameters, body schema and errors. There are eight factors in
  Auth0's order, with `otp`, `email`, `recovery-code`, `webauthn-roaming` and
  `webauthn-platform` `enforced`, `sms` `stored` and `push-notification`/`duo`
  `not_planned`. `totp_secret` is marked secret. ID patterns are
  `^[a-z-]+\|dev_[A-Za-z0-9]{20}$` and `^dev_[A-Za-z0-9]{20}$`. The prompt
  table matches §5 exactly. All nine guardian Deploy CLI handlers are mapped.
- [ ] Write `TestPlan33LogCodes`. Every code in §8's emitted list has `plan:
  33` and status `emitted` in `internal/logrules/inventory.json` (Tasks 9–11
  flip them; until then this test is marked `t.Skip("flipped in Task 16")`
  with a list). SMS/voice codes name plan 34 and `gd_send_pn*` name `not_planned`.
- [ ] Run `go test ./internal/mfarules -count=1`; expect FAIL (package missing).
- [ ] Fill the inventory from §2 sources and observations. Write D-0059 with
  the ten §9 rulings, observation answers and gaps. Add every route to the
  two API documents with `x-source`. Move log codes to their new owners.
- [ ] Rerun; expect PASS. Run `make generate` and `go test ./api -count=1`; inspect generated diffs.
- [ ] Commit: `docs: freeze Plan 33 MFA contracts`.

### Task 2: WebAuthn verifier

**Files:** create `internal/webauthn/{cbor,cose,clientdata,authdata,register,assert}.go`
with `*_test.go` and `fuzz_test.go`.

**Interfaces:** produces

```go
type Registration struct{ CredentialID, PublicKey []byte; SignCount uint32; UV bool; AAGUID [16]byte }
type Expect struct{ Challenge []byte; Origin, RPID string; RequireUV bool }
func VerifyRegistration(clientDataJSON, attestationObject []byte, e Expect) (*Registration, error)
func VerifyAssertion(clientDataJSON, authenticatorData, signature, publicKey []byte, storedCount uint32, e Expect) (newCount uint32, err error)
var ErrSignCount, ErrRPID, ErrOrigin, ErrChallenge, ErrFlags, ErrMalformed error
```

- [ ] Write the tests. `TestRegistrationES256`, `TestRegistrationRS256` and
  `TestRegistrationEdDSA` use fixtures generated in-test by a software
  authenticator helper (`webauthntest.NewAuthenticator(alg)`) in
  `internal/webauthn/webauthntest`. Also write `TestRegistrationPackedAcceptedAsNone`,
  `TestRegistrationRejects` (wrong type, challenge, origin or RP ID hash,
  UP unset, UV unset when required), `TestAssertionSignCount` (equal
  non-zero count → `ErrSignCount`; 0/0 allowed — Review Focus 4),
  `TestAssertionWrongRPID`, `TestCBORLimits` (depth 17, 64 KiB + 1, an
  indefinite length and a tag → `ErrMalformed`) and `FuzzCBOR`/`FuzzAttestation`
  (no panic, bounded allocation).
- [ ] Run `go test ./internal/webauthn/... -count=1`; expect FAIL.
- [ ] Implement with `crypto/ecdsa`, `crypto/rsa` (PKCS#1 v1.5, SHA-256) and
  `crypto/ed25519`. Compare the origin exactly against `https://` + RPID
  (plus port in tests).
- [ ] Rerun; then `go test ./internal/webauthn -run '^$' -fuzz FuzzCBOR -fuzztime 60s`; expect PASS.
- [ ] Commit: `feat: verify WebAuthn registrations and assertions in-tree`.

### Task 3: MFA primitives

**Files:** create `internal/mfa/{totp,recovery,codes,ids,qr}.go` and tests.

**Interfaces:** produces `NewTOTPSecret() string` (20 random bytes, base32
without padding, 32 chars), `TOTPURI(issuer, account, secret string) string`,
`VerifyTOTP(secret, code string, now time.Time) (step int64, ok bool)`,
`NewRecoveryCode() string`, `NormalizeRecoveryCode(string) string` (strip
spaces and dashes, uppercase), `NewEmailCode() string` (6 digits),
`NewMethodID(typ string) string`, `NewEnrollmentID() string`, and
`QRSVG(text string) []byte` (byte mode, error correction M, an in-tree
encoder for versions 1–10).

- [ ] Write the tests. `TestTOTPRFC6238Vectors` uses the SHA-1 vectors at
  59 s, 1111111109 s and 1111111111 s, truncated to 6 digits.
  `TestTOTPWindow` accepts ±1 step and rejects ±2. `TestRecoveryCodeFormat`
  checks `^[A-Z0-9]{24}$` on 10,000 codes, all unique. Also write
  `TestNormalizeRecoveryCode`, `TestIDFormats` (the Task 1 patterns),
  `TestTOTPURI` (`otpauth://totp/<issuer>:<account>?secret=…&issuer=…`,
  escaped) and `TestQRSVGDecodes`, which decodes with an in-test reference
  decoder or compares against a committed golden SVG for a fixed URI.
- [ ] Run `go test ./internal/mfa -run 'TOTP|Recovery|IDFormats|QR' -count=1`; expect FAIL.
- [ ] Implement with `crypto/hmac`, `crypto/sha1`, `crypto/rand` and `encoding/base32`.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: add TOTP, recovery code and QR primitives`.

### Task 4: MFA storage contract and memory store

**Files:** create `internal/store/mfa.go`, `internal/store/memory/mfa.go`, `pkg/storetest/mfa.go`.
Modify `internal/store/store.go`, `internal/store/types.go`, memory `{memory,tx,clone}.go`,
every driver's stub, `pkg/storetest/storetest.go`, and the user and tenant deletion paths.

**Interfaces:** produces the storage contract above, `ErrMFAUnavailable`,
`LoginSession.MFAAt time.Time`, `User.RememberBrowserEpoch int` and
`Sessions.MarkMFA(ctx, tid, sessionID string, at time.Time) error`.

- [ ] Write the conformance cases. `MFAGuardianDefaults` covers all eight
  factors false and policies `[]`. Also: `MFAGuardianVersionConflict`,
  `MFAAuthenticatorCRUDTenantIsolation`, `MFAWebAuthnCredentialUnique`, and
  `MFATOTPStepReplay`, where two goroutines accept the same step and exactly
  one succeeds (Review Focus 2). `MFARecoveryReplaceRace` has two replaces
  with the same old hash and exactly one succeeds. Then `MFASignCountMonotonic`,
  `MFATokenConsumeOnce` (a second consume, another client and an expired
  token all give ErrNotFound), `MFAChallengeAttemptsAndExpiry`,
  `MFATicketSingleUse`, `MFARememberEpoch`, `MFAPurge`,
  `MFADeleteUserAndTenant` and `SessionMarkMFA`.
- [ ] Run `go test ./internal/store/memory -run 'MFA|SessionMarkMFA' -count=1`; expect FAIL.
- [ ] Implement memory with deep copies at the boundary; conditional methods hold the store lock.
- [ ] Rerun, and `go test ./internal/... -run '^$'`; expect PASS/compile.
- [ ] Commit: `feat: add MFA storage contract and memory store`.

### Task 5: SQL migration and SQL store

**Files:** create `internal/store/sqlstore/mfa.go`, `mfa_test.go`,
`migrations/{sqlite,postgres,mysql}/0033_mfa.sql`. Modify the session and
user SQL for the two new columns.

**Interfaces:** implements Task 4 with the six §9 tables plus
`users.remember_browser_epoch` and `login_sessions.mfa_at`. Indexes:
authenticators (tenant, user) and unique (tenant, credential_id) where it
is non-null. Tokens, challenges, tickets and browsers each get a primary
key on (tenant, hash/id) and an index on (expires_at).

- [ ] Write `TestMFAMigrationFrom32` (existing rows keep epoch 0 and null `mfa_at`)
  and `TestMFAConditionalUpdatesConcurrent` (TOTP step and recovery replace across two
  connections; exactly one wins per driver).
- [ ] Run `go test ./internal/store/sqlstore -run 'MFA' -count=1`; expect FAIL.
- [ ] Implement parameterized queries. Every conditional method is a
  single `UPDATE … WHERE` and checks rows affected.
- [ ] Run `./scripts/test-sql.sh -run 'MFA|SessionMarkMFA' -count=1 ./internal/store/sqlstore/...`;
  expect PASS on SQLite, PostgreSQL and MySQL with no skipped driver. Record each driver's result.
- [ ] Commit: `feat: persist MFA state in SQL`.

### Task 6: MFA v1 plugin capability

**Files:** create `internal/store/grpcstore/mfa.go` and test; modify
`proto/store/v1/store.proto`, grpcstore client/server/transaction wiring; `make generate`.

**Interfaces:** `store.MFASupporter{CheckMFASupport(ctx) error; MFASupported() bool}`,
mirroring `EventsSupporter`. Every Task 4 method is an RPC.

- [ ] Write `TestMFACapabilities`: a pre-MFA plugin keeps every feature and
  returns `ErrMFAUnavailable`, MFA v1 round trips, and a transient failure
  recovers. Write `TestMFARemoteConditionalUpdates`.
- [ ] Run `go test ./internal/store/grpcstore -run MFA -count=1`; expect FAIL.
- [ ] Add additive proto messages and RPCs; unknown-method errors are definitive, transport errors retryable.
- [ ] `make generate`, rerun focused tests and grpcstore conformance; expect PASS.
- [ ] Commit: `feat: add MFA storage plugin capability`.

### Task 7: MFA service, throttle and email delivery

**Files:** create `internal/mfa/{service,throttle,email}.go` and
`service_test.go`. Modify `internal/app/app.go` (construct the service) and
`internal/logscrub` (new secret key names).

**Interfaces:** produces `mfa.Service` from the contract, built with
`NewService(st store.Store, sealer secrets.Sealer, mail EmailSender, th protection.Throttle, log *slog.Logger, now func() time.Time)`.
`Enrollment{Factor, AuthenticatorID, Secret, URI string; WebAuthnOptions json.RawMessage; ChallengeID string}`,
`Challenge{ID, Factor, AuthenticatorID string; WebAuthnOptions json.RawMessage}`, and
`Proof{Code string; ClientDataJSON, AttestationObject, AuthenticatorData, Signature []byte; Origin string}`.
Errors: `ErrInvalidCode`, `ErrThrottled`, `ErrExpired`, `ErrNoFactor`.
It emits `gd_start_enroll`, `gd_enrollment_complete`, `gd_start_enroll_failed`,
`gd_start_auth`, `gd_auth_succeed`, `gd_auth_failed`, `gd_recovery_succeed`,
`gd_recovery_failed`, `gd_send_email`, `gd_otp_rate_limit_exceed`,
`gd_webauthn_*` and `gd_unenroll` through `logs.Recorder`.

- [ ] Write the tests. `TestEnrollTOTPThenVerify` checks that the first
  confirmation returns a recovery code and later ones do not.
  `TestEmailChallengeSendsTemplate` uses the `mfa_oob_code` template, a
  6-digit code and a 5-minute expiry. `TestEmailRequiresVerified` and
  `TestThrottleTenFailures` check that the 11th attempt is `ErrThrottled`,
  one `gd_otp_rate_limit_exceed` is logged, and a success resets the count.
  Also write `TestEmailSendLimit` (6th send in 15 min refused),
  `TestRecoverReplacesCode`, `TestWebAuthnEnrollAndChallenge` (with
  `webauthntest`), `TestRecoveryCodeNotOnlyFactor` and
  `TestNoSecretsInLogs`. That last test scans the recorded logs and slog
  output for the TOTP secret, codes, recovery code and challenge bytes.
- [ ] Run `go test ./internal/mfa -run 'Enroll|Email|Throttle|Recover|WebAuthn|Secrets' -count=1`; expect FAIL.
- [ ] Implement. Seal TOTP secrets with the existing master-key sealer. The
  throttle key is `mfa:<tenant>:<user>:<factor>` on Plan 19's store-backed throttle.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: add MFA enrollment and challenge service`.

### Task 8: The MFA decision and the hosted-flow gate

**Files:** create `internal/mfa/decide.go` and `decide_test.go`. Modify
`internal/authz/{flow,actions,continue}.go`, `internal/session/session.go`
and `internal/oauth/minter.go` (`amr`).

**Interfaces:** produces `mfa.Decide` from the contract. The gate is
`authz.(*Handlers).requireMFA(w, r, res, client, fr, sess, eff) (handled bool)`,
called in `approve` after post-login effects and before a code, token or
device approval is issued. When MFA is required and not satisfied, it seals
the requirement into the transaction and redirects to `/u/mfa?state=…`.
With `prompt=none` it returns `interaction_required`. Task 9's pages call
`authz.(*Handlers).MFAComplete(w, r, res, txn, sess)` after `Sessions.MarkMFA`
and resume. The minter adds `amr: ["mfa"]` when `sess.MFAAt` is set.

- [ ] Write the decision table tests in `TestDecide`: policy × effects ×
  session × remember × known-device. Cover `none` overriding
  `all-applications`, `challengeWith` ignoring remember, `confidence-score`
  never forcing enrollment, and `ErrNoFactor` when only disabled factors
  exist (Review Focus 5). Write `TestDecideEnrollWhenNoConfirmedFactor`,
  where a user enrolled only in a disabled factor gets `Enroll` with the
  enabled factors. Then the gate tests: `TestGateSSOSecondAppChallenges`
  and `TestGatePromptNoneInteractionRequired` (Review Focus 1),
  `TestGateNoFactorAccessDenied`, `TestGateSkipsAfterSessionMFA`,
  `TestGateDeviceFlow`, `TestGateUnavailableStoreIsPolicyNone` and
  `TestAMRClaim`.
- [ ] Run `go test ./internal/mfa ./internal/authz ./internal/oauth -run 'Decide|Gate|AMR' -count=1`; expect FAIL.
- [ ] Implement. Known-device and remember checks read the `za_mfa_rb`/`za_mfa_dev` cookies
  (HttpOnly, Secure, SameSite=Lax, host-only) and compare hashes and epoch.
- [ ] Rerun; then `go test ./internal/authz ./internal/login ./internal/oauth -count=1`; expect PASS.
- [ ] Commit: `feat: decide and gate MFA in the hosted flow`.

### Task 9: Hosted MFA pages for OTP, email and recovery code

**Files:** create `internal/login/mfa.go` and `mfa_test.go`, and
`internal/ui/templates/mfa_{options,otp_enroll,otp_challenge,email_challenge,recovery_enroll,recovery_challenge,result}.html`.
Modify the route registration, `internal/ui/text.go` (prompt and screen
registry), the i18n catalogs and the branding prompt list.

**Interfaces:** routes `GET/POST /u/mfa`, `/u/mfa-otp-enrollment`,
`/u/mfa-otp-challenge`, `/u/mfa-email-challenge`, `/u/mfa-recovery-code-enrollment`,
`/u/mfa-recovery-code-challenge` and `/u/mfa-enroll-ticket?ticket=`. Each
screen renders with the §5 prompt and screen name so Plan 22 custom text and
partials apply. Uses `mfa.Service` and `authz.MFAComplete`.

- [ ] Write the tests. `TestMFAOTPEnrollFlow` covers the QR, the code, the
  recovery code shown once with acknowledgement required, then resume with
  the session marked. Also: `TestMFAChallengePreferredFirst`,
  `TestMFATryAnotherMethod`, `TestMFAEmailResendAfter30s`, and
  `TestMFARememberBrowserCookie`, which checks that the cookie attributes
  are set only when allowed. `TestMFATicketEnrollNoPassword` covers single
  use and a 7-day expiry. Then `TestMFAPageWithoutRequirementRedirects`,
  `TestMFACSRF`, `TestMFACustomTextApplies` (a prompt override from Plan 22
  renders), `TestMFAShowFactorListFlag`, `TestMFALocalized`, and
  `TestMFAOTPConcurrentSubmit`, where two posts of the same code give one
  success and one failure (Review Focus 2).
- [ ] Run `go test ./internal/login ./internal/ui -run 'MFA' -count=1`; expect FAIL.
- [ ] Implement. `mfar` is logged when the gate redirects;
  `gd_send_email_verification`/`gd_auth_email_verification` are logged for
  email enrolment.
- [ ] Rerun; then `go test ./internal/login ./internal/ui ./internal/hostedlogin -count=1`; expect PASS.
- [ ] Commit: `feat: add hosted MFA pages for OTP, email and recovery codes`.

### Task 10: Hosted WebAuthn enrolment and challenge

**Files:** create `internal/login/mfa_webauthn.go` and test,
`internal/ui/templates/mfa_webauthn_{enroll,challenge,error,detect}.html`
and `internal/ui/static/mfa-webauthn.js` (no framework; base64url helpers
around `navigator.credentials`). Modify the CSP, if needed, to allow this
first-party script only.

**Interfaces:** routes `/u/mfa-detect-browser-capabilities`,
`/u/mfa-webauthn-roaming-enrollment`, `/u/mfa-webauthn-platform-enrollment`,
`/u/mfa-webauthn-roaming-challenge` and `/u/mfa-webauthn-platform-challenge`.
The RP ID comes from the request's resolved host (canonical or verified
custom domain, Plan 23 resolver). `allowCredentials` lists only methods
whose `RPID` matches.

- [ ] Write the tests. `TestWebAuthnRoamingEnrollAndChallenge` and
  `TestWebAuthnPlatformRequiresUV` use `webauthntest` posting the JSON the
  script would send. Also write `TestWebAuthnPlatformHiddenWithoutCapability`,
  `TestWebAuthnCustomDomainCredentialNotOfferedOnCanonical` and
  `TestWebAuthnClonedAuthenticatorRejected`, which logs
  `gd_webauthn_challenge_failed` (Review Focus 4). Then
  `TestWebAuthnCancelLogsRejected` (`gd_auth_rejected`) and
  `TestWebAuthnChallengeSingleUse`.
- [ ] Run `go test ./internal/login -run 'WebAuthn' -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: add hosted WebAuthn MFA`.

### Task 11: Authentication API — `mfa_required`, `/mfa/*` and MFA grants

**Files:** create `internal/oauth/{grant_mfa,mfa_api}.go` and tests. Modify
`internal/oauth/{grant_password,handlers,token}.go`, route registration,
discovery and the access-token audience check for the MFA API.

**Interfaces:** `resourceOwner` calls `mfa.Decide` after post-login
effects. When MFA is required, it returns `*Error{Status: 403, Code:
"mfa_required", Description: "Multifactor authentication required",
MFAToken: tok}`. The token's `Request` binds audience, scope, connection and
sealed effects. Grant handlers `mfaOTPGrant`, `mfaOOBGrant` and
`mfaRecoveryGrant` consume it and mint through the same path as the original
grant. Handlers `MFAAssociate`, `MFAChallenge`, `MFAListAuthenticators` and
`MFADeleteAuthenticator` sit on the tenant router. The built-in audience is
`https://<host>/mfa/` with scopes `enroll`, `read:authenticators` and
`remove:authenticators`.

- [ ] Write the tests. `TestPasswordGrantMFARequired` checks the exact
  error body. `TestAssociateOTPThenOTPGrant` checks that the first
  association returns `recovery_codes`. Then `TestAssociateEmailOOBAndGrant`,
  `TestRecoveryCodeGrantReturnsNewCode`, and `TestMFATokenReuse`, which
  covers a second use, another client, 10 min + 1 s, and an extra
  `scope`/`audience` in the grant ignored in favour of the bound request
  (Review Focus 3). Also: `TestMFAGrantNotInClientGrantTypes`
  (`unauthorized_client`), `TestAssociateSMSUnsupported`,
  `TestMFAAuthenticatorsWithMFATokenAndAPIToken`,
  `TestMFAAudienceClientCredentialsDenied`, `TestRefreshNeverMFA`,
  `TestMFAGrantFailureLogCodes` (`feotpft`, `feoobft`, `fercft`) and
  `TestMFAGrantThrottle`.
- [ ] Run `go test ./internal/oauth -run 'MFA|Associate|RecoveryCodeGrant|RefreshNeverMFA' -count=1`; expect FAIL.
- [ ] Implement. The client must have the matching grant type (`clientrules.GrantMFA*`).
- [ ] Rerun; then `go test ./internal/oauth -count=1`; expect PASS.
- [ ] Commit: `feat: add MFA to the Authentication API`.

### Task 12: Actions MFA members

**Files:** modify `internal/actionsrules/inventory.json`,
`internal/actions/{triggers,event,engine,reset}.go`, `internal/actions/runner.mjs`,
`internal/noderunner` and the existing fail-closed tests that assert
`unsupported_api`.

**Interfaces:** produces `actions.MFAEffects` and `Effects.MFA`. The
post-login event gains `user.enrolledFactors` and `authentication.methods`
entries `{name: "mfa", timestamp}` from the session. The reset trigger's
`challengeWith*` sets `Effects.MFA`, and `internal/login/reset.go` gates
reset completion on Task 9's challenge pages.

- [ ] Write the tests. `TestMultifactorEnableProviders` covers `any`,
  `google-authenticator`, `guardian` and `none`, plus `duo` failing with
  Auth0's error. Also write `TestChallengeWithRequiresTenantFlag`,
  `TestChallengeWithAndEnableConflict`, `TestChallengeWithAdditionalFactors`,
  `TestEnrollWithAny`, `TestPhoneFactorUnavailable`, `TestEnrolledFactorsInEvent`,
  `TestMFAMethodInEvent` and `TestResetPostChallengeChallengeWith`. Update the
  former `"multifactor": "unsupported_api"` expectations to the new behaviour.
- [ ] Run `ZA_REQUIRE_NODE=1 go test ./internal/actions ./internal/actionsrules ./internal/noderunner ./internal/login -run 'Multifactor|ChallengeWith|EnrollWith|EnrolledFactors|MFAMethod|PostChallenge' -count=1`; expect FAIL.
- [ ] Implement. Validate arguments against `mfarules.ActionMember` schemas;
  invalid arguments fail the execution as Auth0's `invalid_api_call`.
- [ ] Rerun; then `ZA_REQUIRE_NODE=1 go test ./internal/actions ./internal/noderunner -count=1`; expect PASS.
- [ ] Commit: `feat: let post-login Actions control MFA`.

### Task 13: Guardian and user authentication-method Management API

**Files:** create `internal/mgmt/{guardian,guardian_stored,guardian_tickets,user_auth_methods}.go`
and tests. Modify route registration, the user serializer (`multifactor`),
`internal/jobs/importer.go` (`mfa_factors`) and `internal/events/decorator.go`.

**Interfaces:** handlers for every §3 route with Task 1 scopes. Stored
routes validate against the OpenAPI schemas, seal secret fields, and log
`gd_tenant_update`/`gd_email_settings_update`. User routes use the Task 4
repository and the method shape from `mfarules.MethodTypes`. The decorator
intercepts `MFA()` writes that change the derived `multifactor` and emits
one `user.updated` per transaction.

- [ ] Write the tests. `TestGuardianFactorsListAndPut` covers eight names
  in order; storing `duo` and `push-notification` returns `{enabled:true}`.
  `TestGuardianPoliciesValidation` rejects two entries or an unknown value
  with 400. `TestGuardianStoredRoutesSecretsWriteOnly` covers the Twilio
  `auth_token` and push keys. Also: `TestEnrollmentGetDelete` and
  `TestEnrollmentTicket` (with `send_mail` and the `enrollment_email`
  template, and `factor` restricting the page). The auth-methods tests:
  `TestAuthMethodsCRUD` (POST totp/email/webauthn-roaming, PUT replace,
  PATCH name and preferred, DELETE one and all, paging with `include_totals`),
  `TestAuthMethodsTOTPSecretWriteOnly`, `TestAuthMethodsCrossTenant404`,
  `TestRecoveryCodeRegeneration`, `TestInvalidateRememberBrowser`,
  `TestDeleteMultifactorProvider`, `TestDeleteAuthenticators`,
  `TestUserMultifactorField`, `TestImportMFAFactors`,
  `TestMFAUnavailable501` and `TestUserUpdatedOnEnroll`.
- [ ] Run `go test ./internal/mgmt ./internal/jobs ./internal/events -run 'Guardian|Enrollment|AuthMethods|RecoveryCodeRegen|RememberBrowser|Multifactor|Authenticators|ImportMFA|MFAUnavailable|UserUpdatedOnEnroll' -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; then `go test ./internal/mgmt ./internal/jobs ./internal/events -count=1`; expect PASS.
- [ ] Commit: `feat: manage MFA through the Management API`.

### Task 14: Console — Multi-factor auth and the user MFA tab

**Files:** create `console/src/pages/security/Mfa.vue`,
`console/src/pages/users/UserMfa.vue` and tests. Modify `sections.ts`,
`router.ts`, the user detail tabs, the Actions editor type hints and
`console/src/locales/*`.

**Interfaces:** consumes Task 13 routes through the generated client.

- [ ] Write the tests. `Mfa.test.ts` covers the factor toggles, the
  stored-only and not-planned labels, the policy radio, the Adaptive note
  and the two tenant flags. `UserMfa.test.ts` covers listing, deleting one
  and all, regenerating (shown once and then cleared), invalidating
  remember browser and sending an invitation. Also test that a stale tenant
  reply is ignored and that `mfa_unavailable` shows a notice.
- [ ] Run `cd console && npm test -- --run`; expect FAIL for the new tests.
- [ ] Implement; all strings through the catalog.
- [ ] Rerun; then `make console`; expect PASS and a rebuilt `console/dist`.
- [ ] Commit: `feat: manage MFA in the console`.

### Task 15: Seed, Deploy CLI and operator guide

**Files:** modify `internal/seed` (types, apply and tests),
`tests/e2e/deploy-cli/manifest.json` and fixtures, and
`internal/deploymigration` if it lists handlers. Create `docs/mfa.md`.

**Interfaces:** seed keys `guardian.factors` (map name → bool) and
`guardian.policies`. Deploy handlers follow `mfarules.DeployHandlers()`.

- [ ] Write `TestSeedGuardian` and `TestSeedGuardianUnknownFactor` (400-style seed error),
  and add the included handlers' fixtures to the manifest.
- [ ] Run `go test ./internal/seed -run Guardian -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; then `make e2e-deploy`; expect PASS with the guardian handlers round-tripping.
- [ ] Write `docs/mfa.md`: factors and their status, policies including
  the confidence-score local ruling, hosted flow, remember browser, the
  Authentication API flow, Actions, lifetimes and throttles, WebAuthn RP ID
  and custom domains, logs, and local differences (D-0059).
- [ ] Commit: `feat: provision MFA through seed and Deploy CLI`.

### Task 16: End-to-end acceptance, record and final regression

**Files:** create `tests/e2e/{m33-mfa.spec,m33-mfa-node,m33-mfa-grants,m33-mfa-cli}.mjs`
and `tests/e2e/run-m33-mfa.sh`. Modify `Makefile` (`e2e-mfa`), the roadmap,
`docs/compat/matrix.md`, `docs/logs.md` (owners) and the implementation record.

- [ ] Write `m33-mfa.spec.mjs`, which covers the §10 journey first. It also
  covers WebAuthn roaming and platform with CDP
  `WebAuthn.addVirtualAuthenticator`, the custom-domain RP ID case, email
  and throttle, recovery, SSO-to-second-app with `prompt=none`, and the
  three Actions cases. The TOTP generator is an in-test RFC 6238
  implementation.
- [ ] Write `m33-mfa-grants.mjs` with `@auth0/auth0-auth-js` 1.16.1 and raw
  HTTP: `mfa_required` → associate → `mfa-otp`, `mfa-oob` email,
  `mfa-recovery-code`, and the three token-reuse failures.
- [ ] Write `m33-mfa-node.mjs` (node-auth0 `guardian.*`, user
  authentication methods, enrollments and recovery regeneration) and
  `m33-mfa-cli.mjs` (auth0-cli commands where they exist, otherwise `auth0
  api`). Both cover memory and SQLite; PostgreSQL and MySQL run through the
  runner's existing backend switch.
- [ ] Remove the `t.Skip` from `TestPlan33LogCodes`. Add a
  representative-secret scan of every log sink, event body and console
  response captured in the E2E run, failing on any TOTP secret, code,
  recovery code, `mfa_token` or ticket.
- [ ] Run `make e2e-mfa` once to find missing fixtures. Fix them through the
  owning task's code and tests and never weaken assertions.
- [ ] Final verification, sequentially where ports overlap, per `AGENTS.md`:
  - `ZA_REQUIRE_NODE=1 go test -race -timeout=50m ./...`
  - `./scripts/test-sql.sh -timeout=30m ./internal/store/sqlstore/...`
  - `make console` and `make check-sources`
  - `make e2e-mfa`, `make e2e`, `make e2e-actions`, `make e2e-actions-ii`, `make e2e-logs`,
    `make e2e-events`, `make e2e-domains`, `make e2e-deploy`
  - `make conformance`
  Expected: every selected suite passes. Report unavailable, skipped or
  timed-out suites as such, never as passing.
- [ ] Update the roadmap's Plan 33 entry and the matrix. Get a whole-branch
  review with the repository's review skill, fix correctness and security
  findings, and rerun the affected checks.
- [ ] Commit: `test: verify Plan 33 MFA end to end`.

## Dependency order and completion audit

Execution order: **1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16**.
Task 4 depends on 1. Tasks 5–6 depend on 4. Task 7 depends on 2–4. Task 8
depends on 7 and on `actions.MFAEffects` (Task 8 declares the type if Task
12 has not run yet; Task 12 fills it). Tasks 9–10 depend on 8. Task 11
depends on 7–8. Task 12 depends on 8. Task 13 depends on 4 and 7. Task 14
depends on 13. Task 15 depends on 13. Task 16 depends on all. Tasks 2 and 3
may run in parallel. Tasks 13 and 9–11 touch disjoint files, but route
registration, proto and store files are never edited concurrently.

| Spec requirement | Owning tasks |
| --- | --- |
| Evidence, observations, local rulings (§2, §9) | 1, 16 |
| Factors, policies, stored configuration, enrollments, tickets (§3) | 1, 13 |
| User authentication methods, `multifactor`, import (§3) | 13 |
| When MFA is required, remember browser, confidence-score, fail-closed (§4) | 8 |
| Hosted prompts, screens, throttling (§5) | 7, 9, 10 |
| WebAuthn verifier, RP ID (§6) | 2, 10 |
| Authentication API, MFA audience, grants (§7) | 11 |
| Actions members and events (§8) | 12 |
| Logs and secret scrubbing (§8) | 1, 7, 9–11, 16 |
| `user.updated` events (§8) | 13 |
| Storage, migration, plugin capability (§9) | 4, 5, 6 |
| Console (§9) | 14 |
| Seed, Deploy CLI (§9) | 15 |
| Acceptance and regression (§10) | 16 |

Passkeys as a first factor are out of scope (spec §1, ruling 10) and await
the maintainer's decision.

Planning self-review: every spec section maps to a task above. The storage,
decision and Actions-effects contracts are defined once here and used by
name later. Each Review Focus risk has a named test in its owning task. No
implementation, migration or product test was run while writing these
documents.
