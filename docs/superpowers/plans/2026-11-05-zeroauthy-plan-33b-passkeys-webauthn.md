# Plan 33b — Passkeys and WebAuthn MFA Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Auth0-compatible passkeys on database connections (hosted autofill
and button login, passkey signup, progressive and local enrollment, the
native Passkey APIs and grant) and WebAuthn MFA (`webauthn-roaming`,
`webauthn-platform`), with per-host relying party IDs, Management API,
Actions, logs, console, seed, Deploy CLI and E2E support.

**Architecture:** A pure verifier package `internal/webauthn` (bounded
CBOR/COSE, client data, authenticator data, registration and assertion
checks, options rendering, device classification) and an in-tree software
authenticator for tests. `internal/rpid` resolves the effective RP ID and
allowed origins per host. A `store.WebAuthn` repository (memory, SQL, gRPC
`webauthn.v1`) adds passkey creation with the 20-per-user limit, assertion
acceptance, passkey moves and snoozes on top of Plan 33's MFA rows.
`internal/passkey.Service` issues and consumes bound challenges and runs the
register/login/enroll ceremonies shared by the hosted pages
(`internal/login`), the native endpoints and grant (`internal/oauth`), and
the Management API. WebAuthn MFA extends `mfa.Service` and the hosted MFA
pages.

**Tech Stack:** Go 1.26.10 (standard library crypto only), Node 26 locally
(repository pin unchanged), Vue/TypeScript, SQLite/PostgreSQL/MySQL,
protobuf/gRPC, Playwright 1.64.0 with Chromium's CDP virtual authenticator,
pinned `@auth0/auth0-auth-js` 1.16.1, node-auth0 7.4.0, auth0-cli,
auth0-deploy-cli 9.1.0. **No new Go module.**

**Spec:** [Passkeys and WebAuthn MFA design](../specs/2026-11-05-zeroauthy-passkeys-webauthn-design.md).
Read it before executing any task. Section numbers (§) refer to it. §14a
(K1–K14 calls, R1, R2, R3) supersedes earlier wording wherever they differ.

## Global Constraints

- Go `1.26.10` (`GOTOOLCHAIN=go1.26.10` on every command); keep dependency and Node pins; **no new Go module** — CBOR, COSE, ECDSA, Ed25519 and RSA checks use the standard library.
- Follow `CLEAN_ROOM.md`. Every English catalog string, page text, console string and doc sentence is written in our own words; no Auth0 sentence is copied.
- Strict 1:1 with Auth0's documented behaviour; local rulings **LR33b-1…37**, controller calls K1–K14 and R1–R3 are recorded in **D-0062**; observe-later points **W1–W12** go to D-0062 and `docs/superpowers/plan-1-followups.md`.
- No fallback path relaxes an origin or RP ID check. Origins compare as exact serialized strings (scheme, host, port); `crossOrigin: true` and any `topOrigin` are refused on every ceremony.
- Never log, emit, return to Actions or return to the console any `clientDataJSON`, attestation object, authenticator data, signature, `auth_session`, raw challenge, `challenge_id` or user handle; public keys and credential IDs appear only where the Management API documents them.
- Challenges: 32 random bytes, single use by conditional update; hosted lifetime 5 minutes (`timeout` 300000); native `timeout` 60000 with the row expiring 10 s later; a failed verification consumes the challenge.
- Passkeys: 20 per user, enforced atomically in the store; error key `passkey-enrollment-max-allowed-reached`; user handle 32 random bytes per user reused across that user's passkeys.
- `pubKeyCredParams` `-8`, `-7`, `-257` in that order; `attestation: "none"`; `rp.name` equals `rp.id`.
- Hosted pages run WebAuthn only through the one in-tree script inlined with the existing CSP nonce; no `fetch`, no CSP or `Permissions-Policy` relaxation.
- Every passkey/WebAuthn path obeys MFA policy, Actions, blocked users, organizations, attack protection (R3 through `internal/protection`), bot policy and the hosted CSRF/transaction binding exactly like password logins.
- Migration `0035_webauthn.sql` ×3 dialects (latest is `0034_passwordless_phone.sql`), forward only, no existing row rewritten; expiring challenges and snoozes join the periodic purge sweep (`internal/app/sweeper.go`).
- gRPC: negotiate **`webauthn.v1`** by `WebAuthnCapabilities`, separately and latched like `phone.v1`; without it passkey options stay stored-only, WebAuthn factors are not offered, native endpoints answer 404, Management API passkey create answers 501 `webauthn_unavailable`, `mobile` stays ignored.
- New config fields carry doc comments; run `go generate ./internal/config` and commit the regenerated `docs/configuration.md`. API changes carry `x-source`; regenerate with `make generate`; never hand-edit generated Go, protobuf or TypeScript; `console/dist` is a committed build artifact.
- Tests use injected clocks for expiry and snooze windows. Concurrency tests assert outcomes (exactly one winner) and "returns while blocked" with generous deadlines (≥ 10 s); no wall-clock upper bound tighter than seconds.
- Plan 19's database-test hold does not apply to this plan. Before Task 5 run only memory-store and mock tests.
- Work in an isolated worktree. Record commits, reviews, commands, snapshot identity and actual results in `docs/superpowers/2026-11-05-plan-33b-implementation-record.md`.
- Long suites follow `AGENTS.md`: start once, log to a file, keep the process handle and exit status, one monitor, poll no more often than every 15 minutes, never rerun because a suite is quiet. Put `TMPDIR`/`GOTMPDIR` on a disk with space (`/tmp` is a small tmpfs here).

## Review Focus

1. **A request host carries a port, upper case or a trailing dot** (local
   and E2E hosts such as `sdk.e2e.test:9543`). The effective RP ID must be
   the bare lowercase hostname and the allowed origin must be
   `https://sdk.e2e.test:9543` exactly; otherwise every ceremony fails in
   development. Pinned in Task 7 (`TestRPIDHostWithPort`).
2. **A user completes autofill and clicks the passkey button, double-submits,
   or uses two tabs.** Exactly one assertion is accepted per challenge; the
   loser sees the generic `passkey-authentication-failed` with a fresh
   challenge on a usable page, never a 500 or a second session. Pinned in
   Task 9 (`TestHostedPasskeyDoubleSubmit`).
3. **The browser offers a passkey the server no longer accepts** (deleted by
   an operator, passkeys turned off on the connection, connection disabled
   for the client, RP ID changed). The login answers the generic failure on
   a working `login-id` page and logs `gd_webauthn_challenge_failed`; no
   detail reveals which case applied. Pinned in Task 9
   (`TestHostedPasskeyStaleCredential`).
4. **A browser without JavaScript or WebAuthn reaches the split signup.** The
   `passkey-enrollment` screen must still offer a working "create a
   password" path and never strand the user. Pinned in Task 10
   (`TestPasskeySignupWithoutScript`).
5. **Browsers that implement only WebAuthn Level 2** omit
   `authenticatorAttachment`, `response.transports` and
   `clientExtensionResults`, and some send `userHandle: null` on MFA
   assertions. Parsing succeeds, MFA assertions pass, and local enrollment is
   simply not offered. Pinned in Task 3 (`TestParseLevel2Shapes`) and Task 11
   (`TestLocalEnrollmentNotOfferedWithoutAttachment`).

## File boundaries and shared interfaces

| Responsibility | Files |
| --- | --- |
| Contracts | new `internal/webauthnrules/{inventory.json,rules.go,rules_test.go}`; existing `api/{management,authentication}.yaml`, `docs/compat/{decisions,matrix,changelog-review}.md`, `internal/{logrules,mfarules,actionsrules,brandingrules}/inventory.json`, `tests/e2e/deploy-cli/manifest.json`, `tests/e2e/playwright.config.mjs`, roadmap |
| Verifier | new `internal/webauthn/{cbor,cose,authdata,clientdata,credential,verify,options,device,errors}.go`, `internal/webauthn/webauthntest/authenticator.go`, fuzz corpus `internal/webauthn/testdata/fuzz/`; `internal/mgmt/mfa_cose.go` removed |
| Storage | new `internal/store/webauthn.go`, `internal/store/memory/webauthn.go`, `pkg/storetest/webauthn.go`, `internal/store/sqlstore/webauthn.go`, `internal/store/grpcstore/webauthn.go`, migration 0035 ×3; existing `internal/store/{store,types,mfa}.go`, `proto/store/v1/store.proto`, `internal/app/sweeper.go` |
| RP IDs and policy | new `internal/rpid/{rpid,origins}.go`, `internal/connrules/passkey.go`; existing `internal/config/config.go`, `internal/customdomain/rules.go`, `internal/seed/{seed,apply,validate}.go`, `internal/mgmt/custom_domains.go` |
| Ceremonies | new `internal/passkey/{service,challenge,signup}.go`; existing `internal/logscrub/scrub.go` |
| Hosted | new `internal/login/{passkey,passkey_signup,passkey_enroll,mfa_webauthn}.go`, templates `internal/ui/templates/{signup_id,signup_password,passkey_enrollment,mfa_detect,mfa_webauthn}.html`, `internal/ui/webauthn.js`; existing `internal/login/{login,identifier,mfa}.go`, `internal/authz/{handlers,mfa,mfa_reset_pass}.go`, `internal/session/{session,mfa}.go`, `internal/ui/templates/login_id.html`, `internal/i18n/locales`, `internal/server/server.go` |
| MFA | new `internal/mfa/webauthn.go`; existing `internal/mfa/{service,decide}.go`, `internal/oauth/mfa_api.go`, `internal/mgmt/{guardian,guardian_stored,guardian_tickets}.go`, `internal/actions/mfa.go` |
| Management API | existing `internal/mgmt/{user_auth_methods,user_identities,user_sessions,clients}.go`, `internal/clientrules/clientrules.go` |
| Native | new `internal/oauth/{passkey,grant_passkey}.go`, `internal/passkey/wellknown.go`; existing `internal/oauth/{token,request,grant_mfa}.go` |
| Actions, events | existing `internal/actions/{event,engine,mfa}.go`, `internal/actionsrules/inventory.json` |
| Console | new `console/src/pages/connections/PasskeyPanel.vue`, `console/src/pages/settings/RelyingPartyIds.vue`; existing `PasswordTab.vue`, `security/Mfa.vue`, `users/UserMfa.vue`, `applications/SettingsTab.vue`, locales |
| Provisioning, E2E, docs | existing `internal/seed`, `tests/e2e/deploy-cli/manifest.json`; new `tests/e2e/{m33b-spike.spec,m33b-passkeys.spec,m33b-native,m33b-node,m33b-cli}.mjs`, `tests/e2e/run-m33b-passkeys.sh`, Makefile `e2e-passkeys`, `docs/passkeys.md` |

Task 4 owns the storage contract. Add `Store.WebAuthn() WebAuthn` to every
store and transaction view with an `UnimplementedWebAuthn` stub returning
`ErrWebAuthnUnavailable` until each driver lands.

```go
// internal/store/webauthn.go. All ctx are context.Context.
var ErrWebAuthnUnavailable = errors.New("store: WebAuthn unavailable")

type WebAuthnSupporter interface { CheckWebAuthnSupport(ctx) error; WebAuthnSupported() bool }
type WebAuthnSnooze struct {
	TenantID, UserID, Kind, ScopeKey string // Kind: passkey-progressive|passkey-local|platform-remind|platform-refuse
	Until                            time.Time
}
type WebAuthn interface {
	GetAuthenticatorByCredentialID(ctx, tid string, credID []byte) (*Authenticator, error) // ErrNotFound
	CreatePasskey(ctx, a *Authenticator, limit int) error // ErrConflict (dup credential in tenant), ErrPrecondition (limit)
	CreateUserWithPasskey(ctx, u *User, a *Authenticator) error // one transaction; ErrConflict on user or credential
	// AcceptAssertion: ErrPrecondition unless count > stored or both are zero; writes BS (public_data) and last_auth_at.
	AcceptAssertion(ctx, tid, uid, id string, count uint32, backedUp bool, at time.Time) error
	MovePasskeys(ctx, tid, fromUID, toUID, identityUserID string) error // "" = all of fromUID's passkeys
	PutSnooze(ctx, s *WebAuthnSnooze) error // upsert by (tid, uid, kind, scope)
	GetSnooze(ctx, tid, uid, kind, scope string, now time.Time) (*WebAuthnSnooze, error) // ErrNotFound if none or expired
	HostTenantsUnder(ctx, suffix string, limit int) ([]string, error) // distinct tenant IDs owning a host binding equal to or under suffix
	PurgeWebAuthn(ctx, before time.Time, limit int) (int, error) // expired snoozes
}
// types.go additions
type AuthMethod struct{ Name, Type string; At time.Time } // Name per SessionAuthenticationSignal: pwd|passkey|federated|email|sms|mfa
// LoginSession.AuthMethods []AuthMethod; Client.Mobile *ClientMobile; Tenant.DomainRPIDs map[string]string (operator alias host → RP ID, R2)
// MFAChallenge.Binding []byte (JSON binding, Task 8); AuthenticatorTypes gains "passkey" (sorted)
type ClientMobile struct {
	IOS     *struct{ TeamID, AppBundleIdentifier string }
	Android *struct{ AppPackageName string; SHA256CertFingerprints []string }
}
```

`DeleteUserAuthenticators(ctx, tid, uid, nil)` changes meaning to every type
except `passkey`; `DeleteUserMFA` and tenant deletion still remove all.
Passkey authenticator public data adds `backup_eligible`, `backed_up`,
`aaguid`, `user_agent`, `transports`, `identity_user_id`, `user_handle`,
`attachment` to the allowlist.

Ceremony service contract (Task 8), consumed by Tasks 9–15:

```go
// internal/passkey
type Purpose string // "passkey-register"|"passkey-login"|"webauthn-register"|"webauthn-assert"
type Binding struct {
	Purpose                                     Purpose
	RPID                                        string
	Origins                                     []string
	TxnID, CookieHash                           string // hosted
	ClientID, Realm, Organization               string // native
	UserID                                      string // enrollment and MFA
}
type Issued struct{ ID, Session string; Challenge []byte; ExpiresAt time.Time } // Session: native auth_session (ID = HashToken(Session))
type UserDisplay struct{ Name, DisplayName string } // §4.5 user.name / user.displayName
type EnrollKind int                                  // Signup, Progressive, Local
var ErrCeremony = errors.New("passkey: ceremony failed") // wraps a bounded webauthn reason
func (s *Service) Issue(ctx, tid string, b Binding, ttl time.Duration) (*Issued, error)
func (s *Service) Take(ctx, tid, id string, want Binding) (challenge []byte, err error) // consumes first; ErrCeremony on missing/expired/mismatch
func (s *Service) Login(ctx, tid string, raw []byte, ch []byte, b Binding) (*LoginResult, error) // LoginResult{User *store.User; Method *store.Authenticator; Assertion *webauthn.Assertion}
func (s *Service) Enroll(ctx, tid string, u *store.User, identityUserID string, raw, ch []byte, b Binding, userAgent string) (*store.Authenticator, error)
func (s *Service) Signup(ctx, tid string, draft *store.User, raw, ch []byte, b Binding, userAgent string) (*store.User, *store.Authenticator, error)
func (s *Service) CreationOptions(ctx, tid string, u *store.User, display UserDisplay, rpID string, kind EnrollKind, ch []byte, timeout time.Duration) (webauthn.CreationOptions, error) // EnrollKind: Signup|Progressive|Local
func (s *Service) RequestOptions(rpID string, ch []byte, timeout time.Duration) webauthn.RequestOptions
func (s *Service) Effective(ctx, tid string, res tenant.Resolved, conn *store.Connection) (connrules.Policy, rpid.Result, bool, error)
```

For each task: write the named tests, run the focused command and observe
the stated failure, implement, rerun to PASS, review the diff, then commit
only that task's files. Run commands from the worktree root with
`GOTOOLCHAIN=go1.26.10`.

### Task 1: Freeze contracts, decisions and the virtual-authenticator spike

**Files:** create `internal/webauthnrules/{inventory.json,rules.go,rules_test.go}`,
`tests/e2e/m33b-spike.spec.mjs`, the implementation record. Modify
`api/management.yaml` (passkey `POST` create body, `ClientMobile*`,
passkey grant type enum, the two extension system routes from §9.2),
`api/authentication.yaml` (`/passkey/register`, `/passkey/challenge`, the
passkey grant fields), `docs/compat/decisions.md` (D-0062 skeleton and the
D-0039/D-0042/D-0059/D-0061 addenda), `docs/compat/changelog-review.md`
(review row, coverage 2026-10-30), `docs/compat/matrix.md`,
`internal/logrules/inventory.json` (owners and detail allowlists),
`internal/mfarules/inventory.json`, `internal/actionsrules/inventory.json`,
`internal/brandingrules/inventory.json` (the two
`reset-password-mfa-webauthn-*-challenge` screens),
`tests/e2e/deploy-cli/manifest.json` (handler reasons), `tests/e2e/playwright.config.mjs`,
the roadmap (Plan 40 loses actions-extensibility F5 per K11),
`docs/superpowers/plan-1-followups.md`.

**Interfaces:** produces `webauthnrules.Rules() []Rule` (`{ID, Source, Statement string}`),
`webauthnrules.Screens() map[string][]string` (prompt → screens),
`webauthnrules.TextKeys(screen string) []string`,
`webauthnrules.LogDetails(code string) []string`, and `webauthnrules.Limits`
with exactly: `MaxPasskeys 20`, `HostedChallengeTTL 5*time.Minute`,
`NativeTimeout 60*time.Second`, `NativeGrace 10*time.Second`,
`ProgressiveSnooze 30*24h`, `LocalSnooze 30*24h`, `PlatformRemind 14*24h`,
`PlatformRefuse 365*24h`, `NicknameMin 1`, `NicknameMax 20`,
`ChallengeBytes 32`, `UserHandleBytes 32`, `AttestationMax 64<<10`,
`ClientDataMax 16<<10`, `CredentialIDMax 1023`, `COSEMax 16<<10`,
`CBORDepth 16`, `CBORItems 1024`, `RPIDMax 255`. Every later task reads
these constants instead of literals.

- [ ] Re-fetch every §2 source as `<url>.md`; record the fetch date. Do not
  wait for tenant observation; each undocumented point keeps its LR and its W entry.
- [ ] Write `TestWebAuthnInventory`: every rule has a source URL from §2;
  `Screens()["passkeys"]` is `passkey-enrollment`, `passkey-enrollment-local`;
  `Screens()["mfa-webauthn"]` lists the nine §5.1 screens plus
  `reset-password-mfa-webauthn-platform-challenge` and
  `reset-password-mfa-webauthn-roaming-challenge`; `TextKeys("login-id")`
  contains `passkeyButtonText`; the §3.3 and §3.1 error keys are present;
  `Limits` equals the values above.
- [ ] Write `TestPlan33bLogCodes`: `gd_webauthn_enrollment_failed`,
  `gd_webauthn_challenge_failed`, `passkey_challenge_started`,
  `passkey_challenge_failed`, `sepkotpft`, `sepkoobft`, `sepkrcft`,
  `seotpft`, `seoobft`, `sercft` have owner `Plan 33b`; `gd_auth_rejected`
  is `not_planned`; `LogDetails` matches §8.2 exactly (`first_factor`,
  `failure_details`, `purpose`, `authentication_methods`, `authenticator`,
  `prompts`); status `emitted` is asserted in Task 19
  (`t.Skip("flipped in Task 19")` until then).
- [ ] Write `TestWebAuthnFactorsSupported` in `internal/actionsrules`:
  `webauthn-roaming` and `webauthn-platform` move to supported for
  `challengeWith`, `challengeWithAny`, `enrollWith`, `enrollWithAny`.
- [ ] Run `GOTOOLCHAIN=go1.26.10 go test ./internal/webauthnrules ./internal/actionsrules ./internal/logrules ./internal/mfarules ./internal/brandingrules -count=1`; expect FAIL.
- [ ] Fill the inventory. Write D-0062: evidence and fetch date, LR33b-1…37
  with cost if wrong, K1–K14 with the §14a calls (K9 GA without a flag, K11
  pulled forward, K14 reject), R1–R3, W1–W12, and the addenda in §16.
  Update `TestPlan33DeferredLogOwners` only where §8.2 moves an owner.
- [ ] Spike (§15): `m33b-spike.spec.mjs` starts an in-process Node HTTPS
  server for `spike.e2e.test` with a throwaway openssl certificate,
  launches Chromium with `--host-resolver-rules=MAP spike.e2e.test 127.0.0.1`,
  adds a CDP virtual authenticator (`ctap2`, `internal`, resident key, UV),
  and runs `create`, a button `get`, and a conditional `get` on an
  `autocomplete="username webauthn"` input. First with `ignoreHTTPSErrors`
  only; if WebAuthn refuses the context, relaunch with
  `--ignore-certificate-errors-spki-list=<SPKI sha256 base64 of the test cert>`.
  Change `testMatch` to `/m\d+[a-z]?-.*\.spec\.mjs/` so `m33b-*` specs run.
- [ ] Run `cd tests/e2e && ./node_modules/.bin/playwright test m33b-spike.spec.mjs --config playwright.config.mjs`;
  expected: `create` and button `get` pass under one recorded TLS mode. Record
  in the implementation record and D-0062 which TLS mode works and whether
  conditional mediation resolved (if not, Task 9 covers autofill by markup
  and server tests and Task 19 by the button path).
- [ ] Rerun the Go command; expect PASS (log status test skipped). Run
  `make generate`, `GOTOOLCHAIN=go1.26.10 go test ./api -count=1`, `make check-sources`.
- [ ] Commit: `docs: freeze Plan 33b passkey and WebAuthn contracts`.

### Task 2: Bounded CBOR and COSE

**Files:** create `internal/webauthn/{cbor,cose,errors}.go`, tests, fuzz
seed corpus; modify `internal/mgmt/user_auth_methods.go` so `validStoredCOSE`
calls `webauthn.ParseCOSEKey`; delete `internal/mgmt/mfa_cose.go`.

**Interfaces:** produces `webauthn.DecodeCBOR(b []byte, maxDepth, maxItems int) (any, error)`
(maps decode to `map[any]any` with `int64`/`string` keys; trailing bytes are
an error), `webauthn.DecodeCBORPrefix(b []byte) (v any, rest []byte, err error)`
(for authData extensions), `webauthn.ParseCOSEKey(raw []byte) (PublicKey, error)`
(`PublicKey{Alg int64; Key crypto.PublicKey}`), `webauthn.Reason(err error) string`
returning one of the bounded codes `parse`, `type`, `challenge`, `origin`,
`cross_origin`, `rp_id`, `user_present`, `user_verified`, `alg`, `key`,
`attestation`, `signature`, `user_handle`, `sign_count`,
`backup_eligibility`, `backup_state`, `too_large`.

- [ ] Write `TestCBORSubset` (integers, byte/text strings, arrays, maps,
  `false`/`true`/`null` decode; tags, floats, indefinite length, `undefined`,
  duplicate map keys, trailing bytes, depth 17 and item 1025 are refused with
  reason `parse`), `TestCOSEKeys` (OKP Ed25519 `-8`; EC2 P-256 `-7`, P-384
  `-35`, P-521 `-36` with an off-curve point refused; RSA `-257` and `-37`
  with modulus 2047 and 8193 bits refused and an even exponent refused;
  private label `-4` refused; > `COSEMax` refused with `too_large`),
  `TestStoredCOSESharesParser` (the existing `TestAuthMethodsRejectPrivateCOSE`
  still passes through `ParseCOSEKey`), and `FuzzDecodeCBOR`,
  `FuzzParseCOSEKey` (never panic; bounded allocation).
- [ ] Run `GOTOOLCHAIN=go1.26.10 go test ./internal/webauthn ./internal/mgmt -run 'CBOR|COSE' -count=1`; expect FAIL.
- [ ] Implement with explicit length checks before every allocation.
- [ ] Rerun; expect PASS. Run each fuzzer for 60 s
  (`go test ./internal/webauthn -run '^$' -fuzz FuzzDecodeCBOR -fuzztime 60s`) and keep new corpus entries.
- [ ] Commit: `feat: add bounded CBOR and COSE parsing for WebAuthn`.

### Task 3: Registration and assertion verification, options, device classification

**Files:** create `internal/webauthn/{authdata,clientdata,credential,verify,options,device}.go`,
`internal/webauthn/webauthntest/authenticator.go`, tests.

**Interfaces:** consumes Task 2. Produces exactly the §4.1 API
(`CreationOptions`, `RequestOptions`, `Expect`, `Registration`, `Assertion`,
`Stored`, `ParseCredentialJSON`, `VerifyRegistration`, `VerifyAssertion`)
plus `Expect.RequireUserHandle bool`, `Credential{ID, RawID []byte; Type, Attachment string; ClientDataJSON, AttestationObject, AuthenticatorData, Signature, UserHandle []byte; Transports []string}`,
`(CreationOptions) JSON() ([]byte, error)` and `(RequestOptions) JSON() ([]byte, error)`
(PublicKeyCredential*OptionsJSON, base64url), `webauthn.DeviceOf(userAgent string) Device`
(`Device{OS, Browser, Class string}`; `Key() string` = OS, plus browser on
macOS, plus class), and `webauthntest.New(opts Options) *Authenticator`
with `Create(opts CreationOptions, origin string) []byte` and
`Get(opts RequestOptions, origin string) []byte` returning §4.1 JSON, and
knobs `Alg`, `UV`, `BE`, `BS`, `Attachment`, `Format`, `SignCount`,
`OmitUserHandle`, `CrossOrigin`, `TopOrigin`, `TamperRPIDHash`.

- [ ] Write `TestVerifyRegistration` (table over §4.3: each alg `-8`, `-7`,
  `-257` accepted; `-35` refused at registration with reason `alg`; wrong
  type, challenge, origin, `crossOrigin: true`, any `topOrigin`, wrong
  `rpIdHash`, UP clear, UV clear with `RequireUV`, BS without BE, unparsed
  tail → their reasons; formats `none` (empty `attStmt` required), `packed`,
  `tpm`, `android-key`, `android-safetynet`, `fido-u2f`, `apple` accepted and
  recorded as `Format: "none"`; unknown format → `attestation`; AAGUID kept,
  all-zero allowed; credential ID of 1024 bytes → `too_large`).
- [ ] Write `TestVerifyAssertion`: valid for every key type including `-35`,
  `-36`, `-37` (LR33b-11); signature over `authData || SHA-256(clientDataJSON)`;
  `RequireUserHandle` with nil or different handle → `user_handle`;
  without it, nil passes and a different handle fails; sign count table:

```go
{stored: 0, got: 0, ok: true}, {stored: 0, got: 5, ok: true},
{stored: 5, got: 5, reason: "sign_count"}, {stored: 5, got: 4, reason: "sign_count"},
{stored: 5, got: 0, reason: "sign_count"}, {stored: 5, got: 6, ok: true},
```

  BE changed from stored → `backup_eligibility`; BS change accepted and
  reported; RFU flag bits ignored.
- [ ] Write `TestParseLevel2Shapes` (Review Focus 5): no
  `authenticatorAttachment`, no `transports`, no `clientExtensionResults`,
  `userHandle: null` all parse; `Attachment` is `""`; `id != rawId` refused;
  padded base64url accepted.
- [ ] Write `TestOptionsJSON` (algs in order `-8, -7, -257`;
  `attestation: "none"`; `rp.name == rp.id`; timeouts 300000 and 60000 in ms;
  each §4.5 row's `userVerification`, `residentKey`, `authenticatorAttachment`)
  and `TestDeviceOf` (Windows Chrome and Windows Edge share a key; macOS
  Safari and macOS Chrome differ; iPhone → `ios`/`phone`; iPad → `tablet`;
  Android non-Chrome → `other`).
- [ ] Run `GOTOOLCHAIN=go1.26.10 go test ./internal/webauthn/... -count=1`; expect FAIL.
- [ ] Implement; comparisons of challenges use `subtle.ConstantTimeCompare`;
  ECDSA via `ecdsa.VerifyASN1`.
- [ ] Rerun; expect PASS. Add `FuzzParseCredentialJSON` and
  `FuzzParseAuthData`; run 60 s each.
- [ ] Commit: `feat: verify WebAuthn registrations and assertions`.

### Task 4: WebAuthn storage contract and memory store

**Files:** create `internal/store/webauthn.go`, `internal/store/memory/webauthn.go`,
`pkg/storetest/webauthn.go`; modify `internal/store/{store,types,mfa}.go`
(contract above, `AuthenticatorTypes`, `DeleteUserAuthenticators` meaning),
memory `{memory,tx,clone,mfa,sessions,clients,tenants}.go`,
`pkg/storetest/storetest.go` (register `"WebAuthn"` in `Suites` and
`suiteOrder` after `"Phone"`), `internal/app/sweeper.go`.

**Interfaces:** produces the `store.WebAuthn` contract and type additions above.

- [ ] Write storetest cases: `CreatePasskeyLimit` (20 succeed, 21st →
  `ErrPrecondition`), `CreatePasskeyLimitConcurrent` (19 existing, 10
  goroutines → exactly one success; the test waits up to 10 s for all to
  return), `CredentialUniquePerTenant` (same ID in another tenant succeeds;
  same tenant → `ErrConflict` across passkey and `webauthn-roaming`),
  `CreateUserWithPasskeyAtomic` (credential conflict leaves no user),
  `AcceptAssertionCounter` (the Task 3 table at store level; concurrent two
  writers of count 7 over stored 6 → exactly one success),
  `AcceptAssertionWritesBackupStateAndLastAuth`, `MovePasskeysAllAndByIdentity`,
  `DeleteUserAuthenticatorsNilKeepsPasskeys`, `DeleteUserMFARemovesPasskeys`,
  `SnoozeUpsertAndExpiry`, `HostTenantsUnder` (exact and descendant hosts,
  no partial-label match: `ample.com` is not under `example.com`),
  `SessionAuthMethodsRoundTrip` (nil stays nil), `ClientMobileRoundTrip`,
  `TenantDomainRPIDsRoundTrip`, `ChallengeBindingRoundTrip`,
  `PurgeWebAuthnExpired`, `TenantIsolation` (every method with a foreign
  tenant behaves as missing). `internal/app` `TestSweepPurgesWebAuthn`.
- [ ] Run `GOTOOLCHAIN=go1.26.10 go test ./internal/store/... ./pkg/storetest ./internal/app -run 'WebAuthn|Sweep' -count=1` (memory only); expect FAIL.
- [ ] Implement memory with the existing transaction/clone conventions; the
  limit check and insert share one lock.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: add WebAuthn storage contract and memory store`.

### Task 5: Migration 0035 and SQL store

**Files:** create `internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0035_webauthn.sql`,
`internal/store/sqlstore/webauthn.go`, `internal/store/sqlstore/webauthn_test.go`;
modify session, client, tenant, MFA challenge read/write paths.

**Interfaces:** consumes Task 4.

- [ ] Migration: `sessions.auth_methods TEXT NULL`, `clients.mobile TEXT NULL`,
  `tenants.domain_rp_ids TEXT NULL` (R2 storage, added by this plan),
  `webauthn_snoozes (tenant_id, user_id, kind, scope_key, until, PRIMARY KEY (tenant_id,user_id,kind,scope_key))`
  with an index on `until`. Challenge bindings ride in the existing
  `mfa_challenges.data` JSON. No UPDATE of existing rows.
- [ ] Write `TestWebAuthnMigrationLeavesRows` (seed sessions, clients,
  tenants and MFA rows at 0034, migrate, rows byte-identical except new NULL
  columns) and run the storetest `WebAuthn` suite on each dialect.
- [ ] Run `./scripts/test-sql.sh -timeout=30m ./internal/store/sqlstore/... -run 'WebAuthn'`; expect FAIL.
- [ ] Implement. `CreatePasskey` counts and inserts in one transaction
  with the user row locked (`SELECT … FOR UPDATE` on PostgreSQL/MySQL,
  immediate transaction on SQLite) and relies on the existing deadlock retry;
  `AcceptAssertion` is one conditional `UPDATE … WHERE sign_count < ? OR (sign_count = 0 AND ? = 0)`.
- [ ] Rerun on all three dialects; expect PASS.
- [ ] Commit: `feat: persist passkeys, snoozes and session methods in SQL`.

### Task 6: `webauthn.v1` plugin capability

**Files:** modify `proto/store/v1/store.proto` (`WebAuthnCapabilities` and
the `WebAuthn` RPCs; new fields on session, client, tenant and MFA challenge
messages), create `internal/store/grpcstore/webauthn.go` and tests; modify
`internal/store/grpcstore/{client,server,codec}.go`, `cmd/zeroauthy-store-memory`.

**Interfaces:** consumes Task 4; capability name `webauthn.v1`; the client
latches the answer in a new `webauthnCap *orgCapState`.

- [ ] Write `TestWebAuthnCapabilityNegotiated` (memory plugin advertises it;
  the storetest `WebAuthn` suite passes over gRPC), `TestOldPluginWebAuthnUnavailable`
  (plugin without it: `WebAuthn()` methods return `ErrWebAuthnUnavailable`,
  new session/client/tenant fields are dropped on write and absent on read,
  existing MFA and phone calls keep working), and `TestWebAuthnCodecNotLogged`
  (challenge bytes and user handles cross the wire unchanged and never appear
  in captured slog output).
- [ ] Run `GOTOOLCHAIN=go1.26.10 go test ./internal/store/grpcstore -run WebAuthn -count=1`; expect FAIL.
- [ ] Implement; regenerate with `make generate`.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: add webauthn.v1 storage plugin capability`.

### Task 7: RP ID resolver, origin policy, shared-RP-ID setting and passkey prerequisites

**Files:** create `internal/rpid/{rpid,origins}.go`, `internal/connrules/passkey.go`
and tests; modify `internal/config/config.go` (+ regenerated
`docs/configuration.md`), `internal/customdomain/rules.go`,
`internal/mgmt/custom_domains.go`, `internal/seed/{seed,apply,validate}.go`
(`domains` entries accept a string or `{host, relying_party_identifier}`),
the system API router (prerequisites route).

**Interfaces:** consumes Tasks 4 and 6. Produces:

```go
// internal/config
type WebAuthn struct {
	// RestrictSharedRPIDs refuses relying party IDs that cover
	// server.base_domain or another tenant's host. Turn it on for shared
	// multi-tenant hosting.
	RestrictSharedRPIDs bool `koanf:"restrict_shared_rp_ids"`
}
// Security.WebAuthn WebAuthn `koanf:"webauthn"`; default false

// internal/rpid
type Kind string // "canonical"|"custom"|"operator"
type Result struct{ RPID, Origin string; Kind Kind; Valid bool; Problem string }
type Policy struct{ BaseDomain, SystemHost, OriginSuffix string; RestrictShared bool; Store store.Store }
func (p Policy) For(ctx context.Context, res tenant.Resolved) (Result, error)
func (p Policy) Validate(ctx context.Context, tenantID, host, rpID string) error // R1 rule; ErrInvalid with a fixed message
func NativeOrigins(r Result, c *store.Client) []string // LR33b-26
// internal/connrules
type PasskeyPolicy struct{ Enabled, Effective bool; ChallengeUI string; Progressive, Local bool }
type Unmet string // "universal_login","identifier_first","username_or_flexible","custom_db_import","password_enabled","strategy"
func Passkeys(conn *store.Connection, prompts map[string]any) (PasskeyPolicy, []Unmet)
```

- [ ] Write `TestRPIDFor`: canonical host → itself; verified custom domain
  without override → the domain; with `relying_party_identifier: example.com`
  → `example.com`; operator alias → itself or `Tenant.DomainRPIDs[host]`;
  a stored RP ID that is not a registrable suffix of the host → `Valid:
  false` (ceremonies fail closed; one WARN logged per resolution with tenant
  and host, never the challenge).
- [ ] Write `TestRPIDHostWithPort` (Review Focus 1): host `SDK.e2e.test.:9543`
  → `RPID == "sdk.e2e.test"`, `Origin == "https://sdk.e2e.test:9543"`; host
  without port → origin without port.
- [ ] Write `TestRPIDValidateShared` (R1): default off, RP ID
  `example.com` for custom domain `login.example.com` with base domain
  `id.example.com` is accepted; with `RestrictSharedRPIDs` it is refused, as
  is an RP ID covering another tenant's host (`HostTenantsUnder`); a public
  suffix (`co.uk`) and a non-ancestor are always refused; > 255 chars refused.
  The same rule runs on `POST`/`PATCH /custom-domains` (`400 invalid_body`)
  and on seeded alias RP IDs.
- [ ] Write `TestNativeOrigins`: request origin; `https://app.example.com`
  only when listed in `web_origins` and under the RP ID;
  `android:apk-key-hash:<base64url>` from fingerprint
  `AB:CD:…` (hex with colons, 32 bytes) per client; nothing else.
- [ ] Write `TestPasskeyPolicy` (table over §3.1: strategy not `auth0`,
  `universal_login_experience` not `new`, `identifier_first` false,
  `requires_username` without `attributes`, custom DB without import mode,
  `authentication_methods.password.enabled: false` → each its `Unmet`;
  all met with `passkey.enabled: true` → effective with D-0042 defaults
  `both`, true, true) and `TestPasskeyPrerequisitesRoute`
  (`GET /api/system/tenants/{tenant}/connections/{id}/passkey-prerequisites`
  → `{"effective":false,"unmet":["identifier_first"]}`; operator-only;
  foreign tenant → 404).
- [ ] Write `TestConfigWebAuthnRestrict` (default false; env and file
  override) and keep `TestReferenceUpToDate` green.
- [ ] Run `GOTOOLCHAIN=go1.26.10 go test ./internal/rpid ./internal/connrules ./internal/config ./internal/customdomain ./internal/mgmt ./internal/seed -run 'RPID|NativeOrigins|PasskeyPolicy|PasskeyPrereq|WebAuthnRestrict|Reference|Domain' -count=1`; expect FAIL.
- [ ] Implement; `go generate ./internal/config`.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: resolve relying party IDs per host and passkey prerequisites`.

### Task 8: Passkey ceremony service and secret scrubbing

**Files:** create `internal/passkey/{service,challenge,signup}.go` and
tests; modify `internal/logscrub/scrub.go`, `internal/app` wiring.

**Interfaces:** consumes Tasks 3, 4, 7. Produces the ceremony service
contract above.

- [ ] Write `TestIssueTakeSingleUse` (second `Take` → `ErrCeremony`; 20
  concurrent `Take`s → exactly one challenge returned), `TestTakeBinding`
  (each field of `Binding` mismatched → `ErrCeremony`; expired at
  `ExpiresAt` via injected clock → `ErrCeremony`; failed verification after
  `Take` leaves nothing reusable), `TestNativeSessionHashed` (the stored ID
  is `secrets.HashToken(Session)`; `Session` never stored),
  `TestLoginResolvesCredentialUser` (LR33b-16: typed identifier ignored;
  credential with another `rp_id` → `ErrCeremony`; blocked user →
  `identity.ErrUserBlocked`; sign-count regression → `ErrCeremony` with
  reason `sign_count`), `TestEnrollLimitAndExclude` (21st → error mapped to
  `passkey-enrollment-max-allowed-reached`; `CreationOptions` excludes the
  user's credentials for that RP ID only), `TestUserHandleReused` (second
  passkey of a user reuses the first handle; new user gets 32 bytes),
  `TestSignupCreatesPasswordlessUser` (empty password hash; user and passkey
  in one `CreateUserWithPasskey`), and `TestCreationOptionsUserNames`
  (`user.name` email > phone > username per connection; `displayName` is
  `name` else that identifier).
- [ ] Write `TestScrubWebAuthnKeys` in `internal/logscrub`: `authn_response`,
  `auth_session`, `attestationObject`, `authenticatorData`, `clientDataJSON`,
  `signature`, `userHandle`, `user_handle`, `challenge_id` are hidden at any
  depth and casing.
- [ ] Run `GOTOOLCHAIN=go1.26.10 go test ./internal/passkey ./internal/logscrub -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: add passkey ceremony service with bound challenges`.

### Task 9: Hosted passkey login and session methods

**Files:** create `internal/login/passkey.go`, `internal/ui/webauthn.js`;
modify `internal/login/{login,identifier}.go`, `internal/ui/templates/login_id.html`,
`internal/session/{session,mfa}.go`, `internal/ui` page data and CSP nonce
plumbing, `internal/i18n/locales` (English catalog), `internal/server/server.go`
(`POST /u/login/passkey`).

**Interfaces:** consumes Tasks 7, 8. Produces
`session.Manager.Start(ctx, w, r, t, userID, connection string, authTime time.Time, methods ...store.AuthMethod)`
(existing callers record `pwd`, `federated`, `email` or `sms`) and
`session.Manager.AddMethod(ctx, s *store.LoginSession, m store.AuthMethod) error`
(called with `{Name: "mfa", Type: factor}` wherever `MarkMFA` runs).

- [ ] Write `TestLoginIDPasskeyMarkup`: effective with `both` → input
  `autocomplete="username webauthn"`, the `za-webauthn` JSON (challenge ID,
  `RequestOptions` JSON with empty `allowCredentials`, `mediation`) and a
  button labelled from `passkeyButtonText`; `autofill` → no button; `button`
  → no `webauthn` autocomplete token; not effective (Task 7 table) → no
  passkey markup at all; the script is inline with the response's CSP nonce
  and the CSP header is unchanged from Plan 22's.
- [ ] Write `TestHostedPasskeyLogin`: a `webauthntest` assertion posted with
  `state`, `csrf`, `hosted_revision`, `challenge_id`, `credential` logs the
  user in; the session records `[{name: "passkey"}]`; `MFAAt` stays zero;
  the ID token has no `amr`; `s` carries
  `details.prompts[{name: "login-id", performed_amr: ["phr"]}]`; MFA policy
  `all-applications` with OTP enrolled still challenges; consent and
  organization rules still run.
- [ ] Write `TestHostedPasskeyDoubleSubmit` (Review Focus 2): the same
  challenge posted twice concurrently (and autofill then button) → exactly
  one 302 into the flow, the other renders `login-id` with
  `passkey-authentication-failed` and a new `challenge_id`; one session row.
- [ ] Write `TestHostedPasskeyStaleCredential` (Review Focus 3): credential
  deleted, passkeys disabled on the connection, connection disabled for the
  client, credential RP ID differs → each renders the same generic error
  body and logs `gd_webauthn_challenge_failed` with `first_factor: true` and
  a bounded `failure_details`; blocked user → `user-blocked`.
- [ ] Write `TestHostedPasskeyBinding`: challenge from another transaction,
  another browser cookie, another custom domain of the same tenant, another
  tenant's host, or with a forged `clientDataJSON.origin` → generic error;
  a host whose stored RP ID is invalid (Task 7 `Valid: false`) renders no
  passkey markup and a direct `POST /u/login/passkey` gets the hosted error
  page (R1).
- [ ] Write `TestHostedPasskeyAttackProtection` (R3): an existing brute-force
  block on (identity, connection, IP) refuses a valid passkey with the
  password path's blocked answer and log, before any session is created; a
  successful passkey login resets that identity's failure counter; a failed
  assertion spends the IP's suspicious-login budget through
  `protection.Service` (store-backed).
- [ ] Write `TestWebAuthnErrorNames`: `webauthn_error=NotAllowedError` →
  re-render without a log; an unknown name maps to `UnknownError`; the
  posted value is never echoed.
- [ ] Run `GOTOOLCHAIN=go1.26.10 go test ./internal/login ./internal/session ./internal/ui -run 'Passkey|LoginIDPasskey|WebAuthnError|SessionMethods' -count=1`; expect FAIL.
- [ ] Implement. Protection: `Begin` with `Flow: "login"`, `Identifier` =
  the resolved user's login identifier, after the assertion identifies the
  user; `Finish` with `success`; failed assertions call `RecordFailure` on
  the IP. The script aborts a pending conditional `get` before any other
  submit.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: log in with passkeys on hosted pages`.

### Task 10: Hosted passkey signup

**Files:** create `internal/login/passkey_signup.go`, templates
`signup_id.html`, `signup_password.html`, `passkey_enrollment.html`; modify
`internal/login/login.go` (signup routing per LR33b-15), invitation signup,
`internal/server/server.go` (`/u/signup/identifier`, `/u/signup/passkey`,
`/u/signup/password`), English catalog.

**Interfaces:** consumes Tasks 8, 9.

- [ ] Write `TestPasskeySignup`: effective → `/u/signup` redirects to
  `signup-id`; identifier and Plan 34 attribute fields; then
  `passkey-enrollment` with `createButtonText`, `usePasswordButtonText`,
  `backButtonText`; a `webauthntest` registration creates the user with an
  empty password hash and the passkey; `pre-user-registration` ran before
  the store write; `post-user-registration`, email verification, `ss` with
  `details.authentication_methods: ["passkey"]` and `user.created` follow;
  the session records `passkey`.
- [ ] Write `TestPasswordSignupLogsPwd`: an existing password signup's `ss`
  now carries `details.authentication_methods: ["pwd"]`.
- [ ] Write `TestPasskeySignupWithoutScript` (Review Focus 4): the
  `passkey-enrollment` page without script still renders a plain form whose
  "create a password" submit reaches `signup-password` and completes signup.
- [ ] Write `TestPasskeySignupRules`: not effective → the single Plan 22
  signup page (LR33b-15); invitation signup never shows the passkey choice
  (LR33b-32); `email-in-use` on an existing identifier; signup disabled, bot
  policy and organization rules apply; `passkey-enrollment-failure` on a
  failed ceremony with `gd_webauthn_enrollment_failed`; R3: the registration
  budget is spent before `email-in-use` is revealed; a passkey-only user's
  password login gets the normal wrong-credentials answer (LR33b-36).
- [ ] Run `GOTOOLCHAIN=go1.26.10 go test ./internal/login -run 'PasskeySignup|PasswordSignupLogsPwd' -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: sign up with passkeys on hosted pages`.

### Task 11: Progressive and local passkey enrollment

**Files:** create `internal/login/passkey_enroll.go`; modify
`internal/authz/{handlers,mfa}.go` (post-MFA prompt stage recorded in
internal param `za_pk_prompt`), `passkey_enrollment.html` (local variant),
`internal/server/server.go` (`/u/passkey-enrollment`, `/u/passkey-enrollment-local`),
English catalog.

**Interfaces:** consumes Tasks 4, 8, 9. Produces
`authz.PasskeyPrompt(ctx, res, txn, sess) (kind string, err error)` (`""`,
`progressive`, `local`), evaluated after MFA and before consent/redirect.

- [ ] Write `TestProgressiveEnrollmentOffered`: after a password login (and
  after MFA when required) with `progressive_enrollment_enabled`, no passkey
  for this RP ID, fewer than 20, not snoozed → `passkey-enrollment`; not
  offered after a passkey or federated login, with a passkey for this RP ID,
  or with 20 passkeys; `continueButtonText` skips for this login only;
  `checkboxText` stores a `passkey-progressive` snooze for 30 days scoped to
  the RP ID (injected clock: offered again on day 31); success logs
  `gd_enrollment_complete` with `details.authenticator.type: "passkey"`.
- [ ] Write `TestLocalEnrollmentOffered`: after a passkey login whose
  assertion had `authenticatorAttachment: "cross-platform"` and a page
  report of a user-verifying platform authenticator → `passkey-enrollment-local`
  with `authenticatorAttachment: "platform"` and `excludeCredentials` for
  the RP ID; "don't show again" snoozes 30 days for this browser (hashed
  device cookie scope).
- [ ] Write `TestLocalEnrollmentNotOfferedWithoutAttachment` (Review Focus
  5): an assertion with no attachment → no local prompt.
- [ ] Write `TestEnrollmentPromptBinding`: the redirect cannot proceed while
  `za_pk_prompt` is unanswered; a direct GET of the enrollment URL without a
  pending prompt, from another browser, or before MFA completes → the
  session-expired page; back/refresh after completion → session-expired page.
- [ ] Run `GOTOOLCHAIN=go1.26.10 go test ./internal/login ./internal/authz -run 'Enrollment' -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: offer progressive and local passkey enrollment`.

### Task 12: WebAuthn MFA with security keys

**Files:** create `internal/mfa/webauthn.go`, `internal/login/mfa_webauthn.go`,
templates `mfa_detect.html`, `mfa_webauthn.html`; modify
`internal/mfa/{service,decide}.go`, `internal/login/mfa.go`,
`internal/mgmt/{guardian,guardian_stored,guardian_tickets}.go` (factors
enforced; UV setting system route), `internal/mfarules/inventory.json`
(`webauthn-roaming` → enforced), `internal/actions/mfa.go`,
`internal/server/server.go` (the `/u/mfa-detect-browser-capabilities` and
`/u/mfa-webauthn-*` paths), English catalog.

**Interfaces:** consumes Tasks 3, 4, 7, 8. Produces
`mfa.Service.BeginWebAuthnEnroll(ctx, tid, uid, factor string, rp rpid.Result, display passkey.UserDisplay) (*Enrollment, webauthn.CreationOptions, error)`,
`mfa.Service.ConfirmWebAuthnEnroll(ctx, tid, uid string, e *Enrollment, raw []byte, name, userAgent string) (*Confirmed, error)`,
`mfa.Service.BeginWebAuthnChallenge(ctx, tid, uid, factor string, rp rpid.Result, device webauthn.Device) (*Challenge, webauthn.RequestOptions, error)`,
`mfa.Service.VerifyWebAuthn(ctx, tid, uid string, c *Challenge, raw []byte) error`,
`mfa.RoamingUV(g *store.GuardianSettings) string` (`discouraged` default,
`preferred`, `required`), and `DecideInput.WebAuthn` (`{Available, Platform bool; RPID string; Device webauthn.Device}`).

- [ ] Write `TestRoamingUVSettingRoute`:
  `GET /api/system/tenants/{tenant}/guardian/factors/webauthn-roaming/settings`
  → `{"user_verification":"discouraged"}` by default; `PUT` accepts only
  `discouraged`, `preferred`, `required`; stored at
  `GuardianSettings.Stored["webauthn-roaming/settings"]`; operator-only; no
  `/api/v2` route exists.
- [ ] Write `TestDecideWebAuthnFilters`: authenticators for another RP ID are
  unusable (only-foreign-RP user → enrollment, LR33b-5); WebAuthn factors are
  offered only when the capability result says `webauthn`; no result (no
  script) → unavailable.
- [ ] Write `TestHostedRoamingEnrollAndChallenge`: detect page first; enroll
  with `authenticatorAttachment: "cross-platform"`, `residentKey:
  "discouraged"`, UV per setting; nickname screen accepts 1–20 characters
  (0 and 21 refused, LR33b-31); `gd_enrollment_complete` with
  `authenticator.type: "webauthn-roaming"`; first enrollment shows the
  recovery code; challenge lists only the user's roaming credentials for the
  RP ID; remember browser (`rememberMeText`) works as for OTP and does not
  satisfy `challengeWith*`; `user.updated` fires when `multifactor` changes.
- [ ] Write `TestRoamingUVRequired`: setting `required` → a UV-less assertion
  fails with `gd_webauthn_challenge_failed` (`first_factor: false`) and
  `gd_auth_failed`; a UV-less (FIDO-1-style) registration is refused.
- [ ] Write `TestWebAuthnThrottle`: failures count in Plan 33's per-user,
  per-factor throttle; the 11th failure in 15 minutes renders
  `too-many-webauthn-challenge-attempts-error` (injected clock).
- [ ] Write `TestWebAuthnTicketAndActions`: enrollment ticket with
  `factor: webauthn-roaming` enrolls once; `challengeWith({type:
  "webauthn-roaming"})`, `enrollWith`, `api.multifactor.enable("any")` and
  `api.multifactor.enable("guardian")` include the factor; "try another method" lists other factors and the
  recovery code.
- [ ] Run `GOTOOLCHAIN=go1.26.10 go test ./internal/mfa ./internal/login ./internal/mgmt ./internal/actions -run 'WebAuthn|Roaming' -count=1`; expect FAIL.
- [ ] Implement, reusing Plan 33's challenge rows (`webauthn-register`,
  `webauthn-assert` kinds through `passkey.Service`), throttle and proof commit.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: add WebAuthn security-key MFA`.

### Task 13: Device biometrics, reset-password screens and the MFA API

**Files:** modify `internal/mfa/{webauthn,decide}.go`,
`internal/login/mfa_webauthn.go`, `internal/authz/mfa_reset_pass.go`,
`internal/oauth/mfa_api.go`, `internal/mfarules/inventory.json`
(`webauthn-platform` → enforced), console-free warning data in the Guardian
GET for the only-enabled case.

**Interfaces:** consumes Task 12.

- [ ] Write `TestPlatformProgressiveEnrollment`: after a successful OTP
  challenge on a browser that reported a platform authenticator and no
  platform enrollment of this device class → `mfa-webauthn-platform-enrollment`
  with `continueButtonText`, `snoozeEnrollmentButtonText`,
  `refuseAddingDeviceText`, `skipAddingDeviceText`; default name
  "<browser> on <OS>"; "Remind me later" snoozes 14 days per device key,
  "Not on this device" 365 days (cookie and table), "Not now" this login only.
- [ ] Write `TestPlatformRules` (LR33b-19/20): `PUT /guardian/factors/webauthn-platform`
  with `enabled: true` alone succeeds; the factor is offered only to a user
  with another confirmed factor (explicit `enrollWith` or ticket without one
  → the other factor first); a platform authenticator is challenged only
  when its stored `user_agent` maps to the request's device key; a second
  enrollment of the same class is refused; UV is always required.
- [ ] Write `TestResetPasswordWebAuthnChallenge`: `password-reset-post-challenge`
  with `challengeWith` a WebAuthn factor renders
  `reset-password-mfa-webauthn-roaming-challenge` /
  `reset-password-mfa-webauthn-platform-challenge` and completes the reset.
- [ ] Write `TestMFAAPIWebAuthn` (LR33b-21): `GET /mfa/authenticators` lists
  confirmed WebAuthn authenticators with `authenticator_type`
  `webauthn-roaming`/`webauthn-platform`; `DELETE` removes them;
  `/mfa/associate` with those types and `/mfa/challenge` for their IDs give
  the existing unsupported-type error; passkeys never appear.
- [ ] Run `GOTOOLCHAIN=go1.26.10 go test ./internal/mfa ./internal/login ./internal/authz ./internal/oauth -run 'Platform|ResetPasswordWebAuthn|MFAAPIWebAuthn' -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: add device-biometrics MFA and WebAuthn reset challenges`.

### Task 14: Management API passkeys, linking, sessions and clients

**Files:** modify `internal/mgmt/{user_auth_methods,user_identities,user_sessions,clients}.go`,
`internal/clientrules/clientrules.go` (`GrantPasskey =
"urn:okta:params:oauth:grant-type:webauthn"` in `GrantTypes`; `mobile`
validation), `resourceview` session projection.

**Interfaces:** consumes Tasks 4, 7, 8.

- [ ] Write `TestPasskeyMethodsList`: `GET /users/{id}/authentication-methods`
  includes passkeys with exactly the §9.1 fields; `credential_device_type`
  is `multi_device` iff BE, else `single_device`; `credential_backed_up` = BS;
  IDs match `^passkey\|dev_[A-Za-z0-9]{20}$`; rows with another RP ID are listed.
- [ ] Write `TestPasskeyMethodsCreate` (LR33b-23/29): `POST` `type: "passkey"`
  requires `key_id` and a valid COSE `public_key`; RP ID defaults to the
  default custom domain's effective RP ID else the canonical host;
  `identity_user_id` must name one of the user's database identities;
  21st → `400 invalid_body`; duplicate `key_id` in tenant → `409`; store
  without `webauthn.v1` → `501 webauthn_unavailable`.
- [ ] Write `TestPasskeyMethodsPatchDelete`: rename (`name`) and delete one;
  `DELETE /users/{id}/authentication-methods` keeps passkeys and removes
  WebAuthn MFA; `PUT` keeps passkeys; `DELETE /users/{id}/authenticators`,
  `GET /users/{id}/enrollments` and `multifactor` exclude passkeys and
  include WebAuthn MFA (`auth_method` = factor name); passkey changes fire no
  event (LR33b-33).
- [ ] Write `TestLinkMovesPasskeys` (LR33b-24): linking moves the secondary's
  passkeys to the primary before the secondary is deleted, in one
  transaction; a passkey login then resolves to the primary; unlinking moves
  passkeys whose `identity_user_id` is that identity back.
- [ ] Write `TestSessionAuthMethodsView`: session view returns recorded
  methods; legacy sessions keep `[{name: "pwd"}]`.
- [ ] Write `TestClientMobileAndPasskeyGrant`: `mobile` stored and returned,
  validated per `ClientMobile*` (fingerprint format, team ID, bundle ID);
  the passkey grant type accepted; old plugin → `mobile` ignored.
- [ ] Run `GOTOOLCHAIN=go1.26.10 go test ./internal/mgmt ./internal/clientrules -run 'Passkey|LinkMoves|SessionAuthMethods|ClientMobile' -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; expect PASS. `make generate`.
- [ ] Commit: `feat: manage passkeys and client mobile settings`.

### Task 15: Native Passkey APIs, the passkey grant and association files

**Files:** create `internal/oauth/{passkey,grant_passkey}.go`,
`internal/passkey/wellknown.go` and tests; modify `internal/oauth/token.go`
(grant map; not in `orgLessGrants`), `internal/oauth/request.go`
(`authn_response` as a JSON object is re-serialized to a string),
`internal/oauth/grant_mfa.go` (success codes), `internal/server/server.go`
(the two `.well-known` routes and CORS preflights for `/passkey/*`).

**Interfaces:** consumes Tasks 7, 8, 12, 14.

- [ ] Write `TestPasskeyRegisterEndpoint`: on a custom domain or operator
  alias, a first-party client with the grant gets exactly
  `{auth_session, authn_params_public_key}` with §4.5 values and
  `timeout: 60000`; unknown `user_profile` key, existing user under any
  identifier, connection requiring signup verification, missing realm with
  no defaultable connection, `name` of 301 characters, `given_name` of 151,
  or 11 `user_metadata` fields → `400 invalid_request`; canonical host or a
  host with an invalid stored RP ID → `400 invalid_request`; the general
  limiter answers `429 too_many_requests`; third-party client or missing grant → `400 invalid_request`;
  bad secret → `401 invalid_client`; store without `webauthn.v1` or no
  effective connection → `404 {"error":"not_found"}`; R3: the registration
  budget is spent before the existence answer; `passkey_challenge_started`
  with `purpose: "register"`.
- [ ] Write `TestPasskeyChallengeEndpoint`: returns
  `{auth_session, authn_params_public_key: {challenge, timeout, rpId, userVerification: "preferred"}}`;
  realm defaulting per §7.1; organization required when
  `organization_usage: require`.
- [ ] Write `TestPasskeyGrant`: register and login with `authn_response` as
  a JSON object (JSON body) and as a string (form body); tokens issued;
  post-login Action sees `protocol: "oauth2-webauthn"` and `passkey` in
  `event.authentication.methods`; `s` with `performed_amr: ["phr"]`; signup
  logs `ss` with `["passkey"]` and runs both registration Actions; reused,
  expired, other-client or other-realm `auth_session` and every verification
  failure → `400 invalid_grant` with one fixed description and
  `passkey_challenge_failed` (`purpose`, bounded reason); blocked user →
  `invalid_grant` "user is blocked"; refresh tokens per normal rules; not in
  discovery `grant_types_supported`.
- [ ] Write `TestPasskeyGrantMFA`: enrolled OTP user → `mfa_required` with an
  `mfa_token`; `mfa-otp` then logs `sepkotpft`, `mfa-oob` `sepkoobft`,
  recovery `sepkrcft`; after a password `mfa_token` the same grants log
  `seotpft`, `seoobft`, `sercft` (LR33b-28).
- [ ] Write `TestNativeOriginReplay`: a registration made for tenant A's
  domain replayed to tenant B, to another custom domain of A, or with an
  origin not in `web_origins` → `invalid_grant`; an Android key-hash origin
  of the client succeeds.
- [ ] Write `TestAssociationFiles` (LR33b-27, R2): on a verified custom domain
  and an operator alias, `/.well-known/apple-app-site-association` →
  `{"webcredentials":{"apps":["TEAMID.com.example.app"]}}` and
  `/.well-known/assetlinks.json` → one statement per Android client with
  relation `delegate_permission/common.get_login_creds`; only first-party
  clients with the grant; `404` when none and on the canonical host;
  `application/json`, `Cache-Control: max-age=300`, no redirect.
- [ ] Run `GOTOOLCHAIN=go1.26.10 go test ./internal/oauth ./internal/passkey -run 'Passkey|NativeOrigin|AssociationFiles' -count=1`; expect FAIL.
- [ ] Implement; add the routes to `api/authentication.yaml` per Task 1 and `make generate`.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: add native Passkey APIs and the passkey grant`.

### Task 16: Actions event members and events

**Files:** modify `internal/actions/{event,engine,mfa}.go`, `runner.mjs`
only if member typing requires it, `internal/actionsrules/inventory.json`.

**Interfaces:** consumes Tasks 4, 9 (session `AuthMethods`).

- [ ] Write `TestAuthenticationMethodsFromSession` (K11): methods list the
  session's first factor `pwd`, `passkey`, `federated`, `email` or `sms` with
  its timestamp, then `mfa` when `MFAAt` is set; a legacy session without a
  record lists only `mfa` as today; never `webauthn` (K13).
- [ ] Write `TestEnrolledFactorsWebAuthn`: confirmed `webauthn-roaming` and
  `webauthn-platform` listed; passkeys never listed (LR33b-12).
- [ ] Write `TestSkipMFAAfterPasskeyAction`: an Action calling
  `api.multifactor.enable("none")` when `passkey` is in the methods skips the
  MFA challenge for a passkey login and not for a password login.
- [ ] Run `GOTOOLCHAIN=go1.26.10 ZA_REQUIRE_NODE=1 go test ./internal/actions -run 'AuthenticationMethods|EnrolledFactorsWebAuthn|SkipMFAAfterPasskey' -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; expect PASS. Run `ZA_REQUIRE_NODE=1 go test ./internal/actions -count=1`.
- [ ] Commit: `feat: expose passkey and WebAuthn data to Actions`.

### Task 17: Console

**Files:** create `console/src/pages/connections/PasskeyPanel.vue`,
`console/src/pages/settings/RelyingPartyIds.vue`; modify
`connections/PasswordTab.vue`, `security/Mfa.vue`, `users/UserMfa.vue`,
`applications/SettingsTab.vue`, `custom-domains/DomainDetail.vue`,
`sections.ts`/`router.ts`, locales.

- [ ] Write component tests: passkey panel shows the three `challenge_ui`
  choices and both enrollment checkboxes, renders the prerequisites list from
  the Task 7 route with a link per item, and blocks enabling while any is
  unmet; MFA page drops the "stored for Plan 33b" labels, shows the
  security-key UV select (Never, If supported, Required) bound to the
  extension route, and warns when device biometrics is the only enabled
  factor; Relying party IDs lists every host with its effective RP ID, marks
  invalid ones (R1), and warns before an RP ID edit; user MFA tab lists
  WebAuthn authenticators and a Passkeys section (name, RP ID, synced,
  backed up, AAGUID, created, last used; rename, delete) and never requests
  or renders `public_key` or `user_handle`; application settings show the
  Passkey grant checkbox and Device Settings; each request captures the
  tenant and drops stale replies; every string goes through the catalog.
- [ ] Run `make console`; expect FAIL.
- [ ] Implement in the occupysaas hybrid style of existing pages.
- [ ] Rerun `make console`; expect PASS; commit rebuilt `console/dist`.
- [ ] Commit: `feat: manage passkeys and WebAuthn in the console`.

### Task 18: Seed, Deploy CLI and docs

**Files:** modify `internal/seed` (`guardian.webauthn_roaming.user_verification`,
client `mobile` and the passkey grant, alias `relying_party_identifier`
from Task 7), `tests/e2e/deploy-cli/manifest.json` and handler map; create
`docs/passkeys.md`; update `docs/mfa.md`, `docs/custom-domains.md`,
`docs/logs.md`, `docs/actions.md`, `docs/attack-protection.md`,
`docs/deploy-cli.md`, `docs/compat/matrix.md`, `docs/superpowers/plan-1-followups.md`.

- [ ] Write seed tests: UV setting applied and validated; client `mobile` and
  grant round-trip; alias RP ID validated by the R1 rule; a store without
  `webauthn.v1` reports the seeded passkey fields as unsupported rather than
  dropping them silently. Deploy CLI manifest tests: clients (`mobile`,
  grant), connections (passkey options), `customDomains`
  (`relying_party_identifier`) and `guardianFactors` round-trip with the
  pinned 9.1.0; the UV setting is recorded as having no Auth0 handler.
- [ ] Write `docs/passkeys.md` (prerequisites, RP IDs and custom domains,
  `restrict_shared_rp_ids`, UI choices, enrollment prompts, native setup and
  association files, limits, differences with LR numbers) and
  `TestPasskeysGuideCitesKnownRulings` in `internal/webauthnrules` (every
  LR33b number cited in `docs/passkeys.md` exists in D-0062).
- [ ] Run `GOTOOLCHAIN=go1.26.10 go test ./internal/seed ./internal/webauthnrules ./tests/e2e/deploy-cli/... -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; expect PASS. `make check-sources`.
- [ ] Commit: `feat: provision passkeys through seed and Deploy CLI; document them`.

### Task 19: End-to-end acceptance, record and final regression

**Files:** create `tests/e2e/{m33b-passkeys.spec,m33b-native,m33b-node,m33b-cli}.mjs`,
`tests/e2e/run-m33b-passkeys.sh`; modify `Makefile` (`e2e-passkeys` and
`.PHONY`), `internal/webauthnrules/rules_test.go` (remove the skip),
`internal/logrules/inventory.json` (status `emitted`), the roadmap,
`docs/compat/matrix.md`, the record.

- [ ] Write `run-m33b-passkeys.sh` modelled on `run-m33-mfa.sh`: one test
  root CA whose SAN covers `sdk.e2e.test`, two `*.domains.e2e.test` custom
  domains (Plan 23 fixtures), a second tenant host, `callback.e2e.test` and
  `system.e2e.test`; backends `${E2E_M33B_BACKENDS:-sqlite memory}` with
  PostgreSQL/MySQL through the existing SQL-test DSNs; lanes
  `${E2E_M33B_LANES:-browser native sdk cli audit}`; the TLS mode Task 1
  recorded (if SPKI pinning, compute the hash with
  `openssl x509 -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`
  and pass it through `E2E_CHROMIUM_ARGS`, read by `playwright.config.mjs`);
  logs and the stored-sink dump under `$E2E_M33B_WORK`.
- [ ] Write `m33b-passkeys.spec.mjs` covering §15 journeys 1–7 and 11–12
  with CDP virtual authenticators: synced platform passkeys
  (`ctap2`/`internal`, `defaultBackupEligibility` and `defaultBackupState`
  true), `cable` for hybrid, `usb` with and without UV, `u2f` for FIDO-1,
  and `WebAuthn.getCredentials`/`addCredential` to clone with a lower sign
  count. Autofill through conditional mediation only if Task 1 recorded it
  works; otherwise the button path, and the record says so.
- [ ] Write `m33b-native.mjs` (§15 journey 9 with `@auth0/auth0-auth-js`
  1.16.1 and raw JSON bodies; credentials from a browser page on an allowed
  web origin), `m33b-node.mjs` (journeys 8 and 10 with node-auth0 7.4.0, raw
  HTTP where its types lack `passkey`, Deploy CLI round trip), `m33b-cli.mjs`
  (auth0-cli `auth0 api`).
- [ ] Add the representative-secret audit (journey 11): every log sink, event
  body, Action log, execution record and console response is scanned for the
  run's `auth_session`, challenges, client data, attestation objects,
  signatures and user handles; any hit fails.
- [ ] Add `e2e-passkeys: ./tests/e2e/run-m33b-passkeys.sh` to the Makefile.
  Remove the `t.Skip` from `TestPlan33bLogCodes` and flip the ten codes to
  `emitted`.
- [ ] Run `make e2e-passkeys` once to find missing fixtures; fix them
  through the owning task's code and tests, never by weakening assertions.
- [ ] Final verification, one command at a time in this order, each started
  once with output to a log under the record's directory, its exit status
  kept, monitored per `AGENTS.md` (one monitor, no polling more often than
  every 15 minutes):
  - `GOTOOLCHAIN=go1.26.10 ZA_REQUIRE_NODE=1 go test -race -timeout=60m ./...`
  - `./scripts/test-sql.sh -timeout=90m ./internal/store/sqlstore/...`
  - `make console`
  - `make check-sources`
  - `go generate ./... && git diff --exit-code`
  - `make e2e-passkeys`
  - `make e2e-mfa`
  - `make e2e-passwordless`
  - `make e2e`
  - `make e2e-domains`
  - `make e2e-deploy`
  - `make e2e-actions`
  - `make e2e-actions-ii`
  - `make e2e-logs`
  - `make e2e-events`
  - `make conformance` (passkeys off by default)
  Expected: every selected suite passes. Record the commit, command, log
  path, exit code, failures and skips for each. Report unavailable, skipped
  or timed-out suites as such, never as passing.
- [ ] Update the roadmap's Plan 33b entry and the matrix. Get a whole-branch
  review with the repository's review skill, fix correctness and security
  findings (§12 list), and rerun only the affected checks.
- [ ] Commit: `test: verify Plan 33b passkeys and WebAuthn MFA end to end`.

## Dependency order and completion audit

Execution order: **1–19**. Task 2 may run in parallel with Task 1. Task 3
depends on 2. Task 4 depends on 1. Tasks 5 and 6 depend on 4. Task 7 depends
on 4 and 6. Task 8 depends on 3, 4, 7. Tasks 9–11 depend on 8 and run in
order. Task 12 depends on 8; Task 13 on 12. Task 14 depends on 4, 7, 8.
Task 15 depends on 12 and 14. Task 16 depends on 9. Tasks 17–18 depend on
7–16. Task 19 depends on all. `internal/server/server.go`, proto, store and
locale files are never edited concurrently.

| Spec requirement | Owning tasks |
| --- | --- |
| Evidence, inventory, D-0062, changelog, spike (§2, §13, §14, §14a, §16) | 1 |
| Connection passkey policy and prerequisites, LR33b-1/2/3 (§3.1, §9.2) | 7, 17 |
| RP IDs and origins, LR33b-4/5, R1, R2 (§3.2, §7.3) | 7, 18 |
| Hosted passkey login, LR33b-16/17, R3 (§3.3, §5.2) | 9 |
| Hosted passkey signup, LR33b-15/32/36 (§3.4) | 10 |
| Progressive and local enrollment, LR33b-13/14 (§3.5, §5.3) | 11 |
| Verifier, parser bounds, LR33b-6…11/34 (§4) | 2, 3, 8 |
| Session record (§5.4) | 4, 9, 14 |
| WebAuthn MFA, LR33b-18…22/30/31 (§6) | 12, 13 |
| Native Passkey APIs and grant, LR33b-25…28 (§7) | 15 |
| Actions, K11/K13, LR33b-12 (§8.1) | 12, 15, 16 |
| Logs and scrubber (§8.2) | 1, 8, 9–15, 19 |
| Events, LR33b-33 (§8.3) | 12, 14 |
| Management API, linking, clients, LR33b-23/24/29 (§9) | 7, 12, 14 |
| Storage, migration, `webauthn.v1` (§10) | 4, 5, 6 |
| Console, seed, Deploy CLI, docs (§11) | 17, 18 |
| Security review focus (§12) | 3, 7–9, 14, 15, 19 |
| Acceptance and regression (§15) | 19 |

Planning self-review: every spec section maps to a task above; the store,
ceremony and RP ID contracts are defined once and used by name later. Each
Review Focus risk has a named test in its owning task. Two storage additions
are this plan's, not the spec's: `tenants.domain_rp_ids` (R2 needs a place
for alias RP IDs) and `WebAuthn.HostTenantsUnder` (R1's strict rule needs
another tenant's hosts); both ride `webauthn.v1`. LR33b-35 (`passkeys`
partials stored only) needs no code. No implementation, migration or
product test was run while writing this plan.
