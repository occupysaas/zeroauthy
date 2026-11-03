# Plan 34 — Passwordless and Phone Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Auth0-compatible passwordless login (email/SMS codes, email magic
links, the passwordless OTP grant), phone messaging through Twilio, Amazon
SNS or an Action, SMS and voice MFA, phone identifiers on database
connections and phone password reset, with Management API, console, seed,
Deploy CLI and E2E support.

**Architecture:** One `phone.Sender` interface with native Twilio and SNS
adapters and an Action-backed adapter; `phone.Dispatcher` picks the
sender per Auth0's routing table and renders templates. A new
`store.Phone` repository (memory, SQL, gRPC Phone v1) holds providers,
templates, passwordless codes and magic-link tokens. `passwordless.Service`
issues and verifies codes and links for `/passwordless/start`, the hosted
`login-passwordless` prompt and the OTP grant. SMS/voice MFA and phone
reset reuse `mfa.Service` and the Plan 21 reset path with the dispatcher.

**Tech Stack:** Go 1.26.7, Node >=22.13, Vue/TypeScript, SQLite/PostgreSQL/MySQL,
protobuf/gRPC, pinned node-auth0 7.4.0, `@auth0/auth0-auth-js` 1.16.1,
auth0-cli 1.37.0, auth0-deploy-cli 9.1.0, Playwright. No new Go module.

**Spec:** [Passwordless and phone design](../specs/2026-11-03-zeroauthy-passwordless-phone-design.md).
Read it before executing any task. Section numbers (§) refer to it.

## Global Constraints

- Go 1.26.7, Node >=22.13; keep dependency pins; **no new Go module** (Twilio is HTTPS + Basic auth; SNS uses the in-tree SigV4 signer moved out of `internal/email/providers/ses.go`).
- Follow `CLEAN_ROOM.md`. Default template bodies and console text are written in our own words.
- Strict 1:1 with Auth0; local rulings marked (LR) and recorded in **D-0060**; `sns` is a marked extension provider name.
- `twilio`, `custom`, `auth0`, `phone-message-hook` keep Auth0's meaning. (LR) Guardian `auth0` sends through the tenant branding phone provider; none configured → fail closed.
- Provider endpoints are fixed. Only `ZA_TEST_PHONE_ENDPOINTS` with `ZA_TEST_MODE=1` redirects adapters to local fakes, with a startup warning.
- A provider "works" when configured and not disabled (native) or when its trigger has a deployed, bound Action (`custom`, `phone-message-hook`). Only working providers make a factor or SMS connection offerable; send-time failures are delivery failures.
- OTPs, magic-link tokens and verification codes are stored only as `secrets.HashToken`; provider credentials (`auth_token`, SNS secret, `twilio_token`, gateway secrets) are sealed with the master key, write-only, and key-name scrubbed at every log sink. No full phone number in logs/events; masking per Task 1.
- Codes are single use with conditional-update attempt/replay checks (as Plan 33). A new start replaces the previous code for the same tenant, connection and identifier.
- Magic links and reset codes are consumed on the final submit, never on a GET.
- Phone numbers are E.164. Existing user phone data is never rewritten by migration; enabling `attributes.phone_number.identifier.active` runs the conflict pre-check (§7) and refuses on invalid or duplicate numbers.
- Passwordless obeys MFA (incl. the Plan 33 MFA-API-audience rule), attack protection, bot policy, blocked users, Actions and organizations exactly like password login.
- Migration `0034_passwordless_phone.sql` ×3 dialects; all expiring rows join the periodic purge sweep.
- gRPC: negotiate **Phone v1** separately; older plugins report it unsupported and the features return 501 `phone_unavailable`.
- Plan 19's database-test hold does not apply to this plan.
- Add `x-source` to API operations and regenerate with `make generate`; never hand-edit generated Go/protobuf/TypeScript. `console/dist` is a committed build artifact.
- Work in an isolated worktree. Record commits, reviews, commands and actual results in `docs/superpowers/2026-11-03-plan-34-implementation-record.md`.
- Long suites follow `AGENTS.md`: start once, log to a file, one monitor, poll no more often than every 15 minutes. Put `TMPDIR`/`GOTMPDIR` on a disk with space (`/tmp` is a small tmpfs here).

## Review Focus

1. A user starts passwordless twice (two tabs, or the hosted page and
   `/passwordless/start`) and enters the first code. Only the latest code is
   valid; the first returns the wrong-code error and counts as an attempt.
   Two concurrent submissions of the latest code: exactly one succeeds.
   Pinned in Tasks 4 and 10.
2. An email security scanner opens the magic link before the user. The user's
   later click must still log them in once; a second use must fail. Pinned in
   Tasks 10 and 11.
3. An attacker floods SMS to one number or many numbers from one IP
   (toll fraud). Send budgets per identifier and per IP, country-code
   allow/deny, and bot policy must stop it on both the API and hosted paths,
   logging `limit_phone`. Pinned in Tasks 10 and 11.
4. A passwordless login for a user with enrolled MFA, a blocked user, or a
   user outside a required organization. Each must be treated exactly as a
   password login would (challenge, `unauthorized`, org error), including via
   the OTP grant (`mfa_required`). Pinned in Tasks 10 and 11.
5. The operator switches the tenant phone provider (Twilio → SNS → custom)
   while codes are outstanding, or deletes the provider. Outstanding codes
   stay valid; new sends use the new provider; with no working provider the
   SMS factor and SMS connection are not offered and start fails closed with
   Auth0's error. Pinned in Tasks 9 and 12.

## File boundaries and shared interfaces

| Responsibility | Files |
| --- | --- |
| Contracts | new `internal/phonerules/{inventory.json,rules.go,rules_test.go}`; existing `api/{management,authentication}.yaml`, `docs/compat/{decisions,matrix}.md`, `internal/logrules/inventory.json`, `internal/actionsrules/inventory.json`, `internal/tenantrules/inventory.go`, `internal/brandingrules/inventory.json` |
| Primitives | new `internal/phone/{e164,mask}.go`, `internal/passwordless/codes.go`; new `internal/awssig/sigv4.go` (moved from SES) |
| Senders | new `internal/phone/{sender,twilio,sns,action,dispatcher,templates,testendpoints}.go`; existing `internal/config` |
| Storage | new `internal/store/phone.go`, `internal/store/memory/phone.go`, `pkg/storetest/phone.go`, `internal/store/sqlstore/phone.go`, `internal/store/grpcstore/phone.go`, migration 0034 ×3; existing `proto/store/v1/store.proto`, `internal/store/types.go` (`User.PhoneNormalized`) |
| Management API | new `internal/mgmt/{phone_providers,phone_templates,phone_protection}.go`; existing `internal/connrules`, connection handlers, guardian handlers, tenant settings, user serializer |
| Actions | existing `internal/actions/{triggers,event,engine}.go`, new `internal/actions/phone.go`, `runner.mjs` |
| Passwordless | new `internal/passwordless/{service,start,link}.go`, `internal/oauth/grant_passwordless.go`, `internal/login/passwordless.go`, templates `internal/ui/templates/passwordless_*.html` |
| MFA phone | existing `internal/mfa/{service,decide}.go`, new `internal/mfa/phone.go`, existing `internal/login/mfa.go`, `internal/oauth/{mfa_api,grant_mfa}.go` |
| Identifiers and reset | existing `internal/login/{identifier,login,reset}.go`, `internal/connrules/password.go`, new `internal/connrules/phone_precheck.go` |
| Console | new `console/src/pages/connections/Passwordless*.vue`, `console/src/pages/branding/Phone{Providers,Templates}.vue`; existing MFA page, database connection page, user detail, locales |
| Provisioning, E2E, docs | existing `internal/seed`, `tests/e2e/deploy-cli/manifest.json`; new `tests/e2e/phone-fakes/` (Go fake Twilio/SNS/gateway server), `tests/e2e/{m34-passwordless.spec,m34-grants,m34-node,m34-cli}.mjs`, `run-m34-passwordless.sh`, Makefile `e2e-passwordless`, `docs/{passwordless,phone-providers}.md` |

Task 4 owns the storage contract. Add `Store.Phone() Phone` to every store
and transaction view with an `UnimplementedPhone` stub returning
`ErrPhoneUnavailable` until each driver lands.

```go
// internal/store/phone.go. All ctx are context.Context.
type PhoneProvider struct {
	TenantID, ID, Name string          // Name: twilio|custom|sns
	Disabled           bool
	Configuration      json.RawMessage // public: sid, default_from, mssid, delivery_methods, region, sender_id, sms_type
	SealedCredentials  []byte          // auth_token / SNS access key + secret
	CreatedAt, UpdatedAt time.Time
}
type PhoneTemplate struct {
	TenantID, ID, Type string // Type per phonerules (otp_verify, otp_enroll, change_password, blocked_account, password_breach)
	Disabled           bool
	Content            json.RawMessage // from, body.text, body.voice, syntax
	Customizable       bool
	CreatedAt, UpdatedAt time.Time
}
type PasswordlessCode struct {
	TenantID, ConnectionID, Identifier string // Identifier: lowercased email or E.164
	ClientID, Kind                     string // Kind: code|link
	CodeHash                           string
	Request                            json.RawMessage // sealed authParams for links
	Attempts                           int
	ExpiresAt, CreatedAt               time.Time
}
type Phone interface {
	ListPhoneProviders(ctx, tid string) ([]PhoneProvider, error)
	GetPhoneProvider(ctx, tid, id string) (*PhoneProvider, error)
	CreatePhoneProvider(ctx, p *PhoneProvider) error // ErrConflict if tenant already has one (Auth0: one provider)
	UpdatePhoneProvider(ctx, p *PhoneProvider) error
	DeletePhoneProvider(ctx, tid, id string) error

	ListPhoneTemplates(ctx, tid string) ([]PhoneTemplate, error) // defaults merged by caller
	GetPhoneTemplate(ctx, tid, id string) (*PhoneTemplate, error)
	PutPhoneTemplate(ctx, t *PhoneTemplate) error
	DeletePhoneTemplate(ctx, tid, id string) error

	PutPasswordlessCode(ctx, c *PasswordlessCode) error // replaces any row for (tid, connection, identifier, kind)
	FailPasswordlessCode(ctx, tid, conn, ident, kind string, now time.Time) (attempts int, err error)
	ConsumePasswordlessCode(ctx, tid, conn, ident, kind, hash string, maxAttempts int, now time.Time) (*PasswordlessCode, error) // ErrPrecondition unless hash matches, unexpired, attempts < max
	PeekPasswordlessLink(ctx, tid, hash string, now time.Time) (*PasswordlessCode, error)

	FindUsersByPhone(ctx, tid, connection, e164 string) ([]User, error)
	PurgePhone(ctx, before time.Time, limit int) (int, error)
	DeleteTenantPhone(ctx, tid string) error
}
```

Sender and dispatcher contract (Tasks 3 and 9):

```go
// internal/phone
type Message struct {
	TenantID, To, DeliveryMethod string // DeliveryMethod: text|voice
	Type                         string // otp_verify|otp_enroll|change_password|blocked_account|password_breach|passwordless
	Body, From                   string
	Code, Locale                 string // for Action events only; never logged
	UserID, ClientID             string
}
type Result struct{ ProviderMessageID string }
type ErrorClass string // invalid_number|unreachable|rate_limited|provider_auth|unsupported_delivery|transient
type SendError struct{ Class ErrorClass; Err error }
type Sender interface{ Send(ctx context.Context, m Message) (Result, error) }

type Route struct{ Purpose string; ConnectionID string } // Purpose: mfa|passwordless|reset|verify
type Dispatcher struct{ /* store, sealer, action runner, http client, clock, log */ }
func (d *Dispatcher) Working(ctx context.Context, tid string, r Route) (bool, error)
func (d *Dispatcher) Send(ctx context.Context, tid string, r Route, m Message) (Result, error)
```

Passwordless service contract (Task 10):

```go
// internal/passwordless
type StartInput struct {
	TenantID, ClientID, Connection, Email, PhoneNumber, Send string // Send: code|link
	AuthParams url.Values
	IP, UserAgent, Locale string
}
type StartResult struct{ ID, Email, PhoneNumber string; Verified bool }
func (s *Service) Start(ctx context.Context, in StartInput) (*StartResult, error)
func (s *Service) VerifyCode(ctx context.Context, tid, clientID, connection, identifier, code string) (*store.User, error) // creates the user unless disable_signup
func (s *Service) VerifyLink(ctx context.Context, tid, token string) (*LinkGrant, error) // consumes; LinkGrant carries user and sealed authParams
```

For each task: write the named tests, run the focused command and observe
the stated failure, implement, rerun to PASS, review the diff, then commit
only that task's files. Run commands from the worktree root with
`GOTOOLCHAIN=go1.26.7`.

### Task 1: Wire contracts and decisions

**Files:** create `internal/phonerules/{inventory.json,rules.go,rules_test.go}`,
the implementation record. Modify `api/management.yaml`, `api/authentication.yaml`,
`docs/compat/decisions.md` (D-0060), `docs/compat/matrix.md`,
`internal/logrules/inventory.json`, `internal/actionsrules/inventory.json`,
the roadmap's Plan 34 entry, `docs/superpowers/plan-1-followups.md`.

**Interfaces:** produces `phonerules.ConnectionOptions(strategy string) Schema`,
`phonerules.Route(op string) Route`, `phonerules.TemplateTypes() []TemplateType`
(`{Type string; Default Content; Variables []string}`), `phonerules.ProviderNames() []Provider`
(`{Name string; Extension bool; DeliveryMethods []string}`), `phonerules.Routing() []RoutingRule`,
`phonerules.Screens() map[string][]string`, `phonerules.ActionTrigger(id string) Trigger`,
`phonerules.MaskPhone(e164 string) string` rule data, and `phonerules.Limits`
(OTP length/lifetime/attempts, link lifetime, send budgets).

- [ ] Do not wait for observation (Plan 32/33 ruling). Each open point gets a
  local ruling and is listed as gap P1–Pn in D-0060 and the follow-ups file.
- [ ] Write `TestPhoneInventory`: every §3–§7 route has a source URL, scopes,
  parameters, body schema and errors; `email` and `sms` connection option
  schemas list sealed fields (`twilio_token`, `gateway_authentication.secret`);
  provider names are `twilio`, `custom` (Auth0) and `sns` (`Extension: true`,
  delivery `text` only); every template type has a default written in our
  words and its variables; `Routing()` covers MFA, passwordless, reset and
  verify for consolidated on/off and Guardian `auth0`/`twilio`/`phone-message-hook`.
- [ ] Write `TestPlan34LogCodes`: `cs`, `cls`, `fepotpft`, `gd_send_sms`,
  `gd_send_sms_failure`, `gd_send_voice`, `gd_send_voice_failure`,
  `gd_phone_settings_update`, `limit_phone`, `limit_signup_otp`, `scpn`,
  `fcpn` and every other passwordless code Task 1 finds have `plan: 34`;
  status `emitted` is asserted in Task 16 (`t.Skip("flipped in Task 16")` until then).
- [ ] Write `TestPhoneTriggersSupported` in `internal/actionsrules`: `send-phone-message`
  and `custom-phone-provider` move from deferred `"34"` to supported with
  their event/api member lists.
- [ ] Run `go test ./internal/phonerules ./internal/actionsrules -count=1`; expect FAIL.
- [ ] Fill the inventory from §2 sources. Write D-0060: the (LR) list
  (Guardian `auth0` routing, `sns` extension, provider "working" definition,
  fixed endpoints and test flag, existing-phone-data pre-check, numbers from
  Task 1), and gaps P1–Pn. Add every route with `x-source` to the API documents.
- [ ] Rerun; expect PASS. Run `make generate` and `go test ./api -count=1`.
- [ ] Commit: `docs: freeze Plan 34 passwordless and phone contracts`.

### Task 2: Phone and code primitives

**Files:** create `internal/phone/{e164,mask}.go`, `internal/passwordless/codes.go`,
`internal/awssig/sigv4.go` and tests; modify `internal/email/providers/ses.go`
to use `awssig`.

**Interfaces:** produces `phone.NormalizeE164(raw, defaultRegion string) (string, error)`
(strips spaces, dashes, parentheses; requires `+` or a default region; 8–15
digits; `ErrInvalidPhone`), `phone.CountryCode(e164 string) string` (ISO
3166 alpha-2 from an in-tree calling-code table), `phone.Mask(e164 string) string`
(Task 1 rule), `passwordless.NewCode(length int) string` (digits, `crypto/rand`),
`passwordless.NewLinkToken() string` (32 random bytes, base64url),
`awssig.Sign(req *http.Request, body []byte, region, service, keyID, secret string, now time.Time)`.

- [ ] Write `TestNormalizeE164` (table: `+1 (415) 555-0100` → `+14155550100`;
  `0044…` rejected without region; 16 digits rejected), `TestCountryCode`
  (`+44…` → `GB`, `+1…` → `US`/`CA` per table rule from Task 1),
  `TestMaskPhone`, `TestNewCodeLength` (lengths 4–10, digits only, 10,000
  samples spread across all digits), and move `TestSESSigV4ReferenceVector`
  to `internal/awssig` unchanged.
- [ ] Run `go test ./internal/phone ./internal/passwordless ./internal/awssig ./internal/email/... -count=1`; expect FAIL.
- [ ] Implement; SES keeps its existing tests green through `awssig`.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: add E.164, code and shared SigV4 primitives`.

### Task 3: Phone senders: Twilio, SNS and test endpoints

**Files:** create `internal/phone/{sender,twilio,sns,testendpoints}.go` and
tests; create `tests/e2e/phone-fakes/` (a Go server faking Twilio Messages
and Calls, SNS Publish and an SMS gateway, recording requests to a JSON
log); modify `internal/config` for `ZA_TEST_MODE` and `ZA_TEST_PHONE_ENDPOINTS`.

**Interfaces:** consumes Task 2. Produces `phone.NewTwilio(cfg TwilioConfig, hc *http.Client) Sender`
(`TwilioConfig{SID, AuthToken, DefaultFrom, MessagingServiceSID string}`),
`phone.NewSNS(cfg SNSConfig, hc *http.Client) Sender`
(`SNSConfig{Region, AccessKeyID, Secret, SenderID, SMSType string}`), and
`phone.Endpoints` (`Twilio, SNS string`, defaults the vendor URLs;
overridden only by `config.TestPhoneEndpoints()`).

- [ ] Write `TestTwilioTextRequest` (POST `/2010-04-01/Accounts/{SID}/Messages.json`,
  Basic auth `SID:AuthToken`, form `To`, `Body`, and `From` or
  `MessagingServiceSid`), `TestTwilioVoiceRequest` (Calls API with TwiML
  `<Say>` whose text is XML-escaped), `TestTwilioErrorClasses` (Twilio error
  codes 21211 → `invalid_number`, 20003 → `provider_auth`, 429 →
  `rate_limited`, 5xx → `transient`), `TestSNSPublishSigned` (Action
  `Publish`, `PhoneNumber`, `Message`, `MessageAttributes` for sender ID and
  SMS type, valid SigV4 header), `TestSNSVoiceUnsupported`
  (`unsupported_delivery`, no request made), `TestTestEndpointsRequireTestMode`
  (`ZA_TEST_PHONE_ENDPOINTS` without `ZA_TEST_MODE=1` → config error), and
  `TestSenderNeverLogsSecrets` (captured slog contains no token, secret,
  body code or full number).
- [ ] Run `go test ./internal/phone ./internal/config -count=1`; expect FAIL.
- [ ] Implement with the SSRF-guarded HTTP client from Plan 32 and a 10 s
  bound; no redirects.
- [ ] Rerun; expect PASS. `go build ./tests/e2e/phone-fakes`.
- [ ] Commit: `feat: add Twilio and SNS phone senders`.

### Task 4: Phone storage contract and memory store

**Files:** create `internal/store/phone.go`, `internal/store/memory/phone.go`,
`pkg/storetest/phone.go`. Modify `internal/store/store.go`, `internal/store/types.go`
(`User.PhoneNormalized string`), memory `{memory,tx,clone}.go`, the
`UnimplementedPhone` stub, user write paths (set `PhoneNormalized` when the
number normalizes; leave empty otherwise), `internal/app` purge sweep.

**Interfaces:** produces the `store.Phone` contract above.

- [ ] Write storetest cases: `ProviderOnePerTenant`, `ProviderSecretsRoundTripSealed`,
  `TemplateCRUD`, `CodeReplacedByNewStart`, `CodeConsumeOnceConcurrent`
  (20 goroutines, exactly one success), `CodeAttemptLimit` (max attempts →
  `ErrPrecondition` even with the right hash), `CodeExpired`,
  `LinkPeekDoesNotConsume`, `FindUsersByPhoneUsesNormalized`,
  `PurgePhoneExpired`, `TenantIsolation` (every method with a foreign tenant
  behaves as missing). `internal/app` `TestSweepPurgesExpiredPhoneRecords`.
- [ ] Run `go test ./internal/store/memory ./internal/app -run 'Phone' -count=1`; expect FAIL.
- [ ] Implement memory with the existing transaction/clone conventions.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: add phone storage contract and memory store`.

### Task 5: SQL migration and SQL store

**Files:** create `internal/store/sqlstore/migrations/{sqlite,postgres,mysql}/0034_passwordless_phone.sql`,
`internal/store/sqlstore/phone.go` and tests.

**Interfaces:** consumes Task 4.

- [ ] Tables: `phone_providers` (unique `tenant_id`), `phone_templates`
  (unique `tenant_id, type`), `passwordless_codes` (primary key
  `tenant_id, connection_id, identifier, kind`; index `tenant_id, code_hash`
  for links; index `expires_at`); column `users.phone_normalized` with a
  non-unique index `(tenant_id, connection, phone_normalized)`. No UPDATE of
  existing user rows.
- [ ] Write `TestPhoneMigrationLeavesUserData` (seed users with odd and
  duplicate numbers at 0033, migrate, rows byte-identical except the new
  null column) and run the shared storetest suite against SQL.
- [ ] Run `./scripts/test-sql.sh -timeout=30m ./internal/store/sqlstore/... -run 'Phone'`; expect FAIL.
- [ ] Implement; consume/fail are conditional single-statement updates.
- [ ] Rerun on all three dialects; expect PASS.
- [ ] Commit: `feat: persist passwordless and phone state in SQL`.

### Task 6: Phone v1 plugin capability

**Files:** modify `proto/store/v1/store.proto`, `internal/store/grpcstore/phone.go`
(new), the plugin server/negotiation, `cmd/zeroauthy-store-memory`.

**Interfaces:** consumes Task 4; capability name `phone.v1`.

- [ ] Write `TestPhoneCapabilityNegotiated` (memory plugin advertises
  `phone.v1`; the storetest phone suite passes over gRPC),
  `TestOldPluginPhoneUnavailable` (a plugin without the capability →
  `ErrPhoneUnavailable`, routes 501 `phone_unavailable`), and codec tests
  that sealed credentials and code hashes cross the wire unchanged and are
  never logged.
- [ ] Run `go test ./internal/store/grpcstore -run Phone -count=1`; expect FAIL.
- [ ] Implement; regenerate with `make generate`.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: add Phone v1 storage plugin capability`.

### Task 7: Phone providers, templates, protection and tenant settings APIs

**Files:** create `internal/mgmt/{phone_providers,phone_templates,phone_protection}.go`
and tests; modify route registration, `internal/tenantrules/inventory.go`
(the four phone settings from inert to enforced), tenant settings handler.

**Interfaces:** consumes Tasks 1, 3, 4. Produces nothing new for later
tasks beyond stored data.

- [ ] Write `TestPhoneProviderCRUD` (Auth0 bodies; `credentials` never
  returned; second create → Auth0's conflict error; `sns` accepted with its
  extension schema; unknown name rejected), `TestPhoneProviderTry` (sends
  one message through the fake sender; obeys send budget),
  `TestPhoneTemplatesDefaultsAndReset`, `TestPhoneTemplateTry`,
  `TestPhoneProviderProtection` (the routes and shapes from Task 1),
  `TestTenantPhoneSettingsEnforced` (`country_codes`, `phone_consolidated_experience`,
  `enforce_client_authentication_on_passwordless_start`,
  `disable_management_api_sms_obfuscation` validated and readable by
  `tenant.Settings`), scopes and live grant checks for each route.
- [ ] Run `go test ./internal/mgmt -run 'Phone|TenantPhone' -count=1`; expect FAIL.
- [ ] Implement; log `sapi`/`fapi` with credentials scrubbed.
- [ ] Rerun; expect PASS. `make generate`.
- [ ] Commit: `feat: manage phone providers, templates and protection`.

### Task 8: Passwordless connections

**Files:** modify `internal/connrules/connrules.go` (accept `email`, `sms`),
new `internal/connrules/passwordless.go`, connection handlers and serializer.

**Interfaces:** produces `connrules.PasswordlessOptions` (`Email *EmailOptions`,
`SMS *SMSOptions`, `TOTP{Length, TimeStep int}`, `DisableSignup`,
`BruteForce bool`, `AuthParams map[string]string`) read by Tasks 9–11.

- [ ] Write `TestPasswordlessConnectionCreate` (both strategies, Auth0 option
  schema and defaults from Task 1, name rule), `TestSMSConnectionSecretsSealed`
  (`twilio_token`, gateway secret write-only, survive PATCH without being
  resent), `TestSMSGatewayURLValidated` (https only, no private IPs at
  validation; dial-time check stays in Task 9), `TestDatabaseOptionsRejectedOnPasswordless`.
- [ ] Run `go test ./internal/connrules ./internal/mgmt -run 'Passwordless|SMSConnection|SMSGateway' -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: add email and SMS passwordless connections`.

### Task 9: Dispatcher and phone Actions

**Files:** create `internal/phone/{dispatcher,templates,action}.go`,
`internal/actions/phone.go`; modify `internal/actions/{triggers,event,engine}.go`,
`runner.mjs`, `internal/app` wiring.

**Interfaces:** consumes Tasks 1–4, 8. Produces `phone.Dispatcher`
(contract above), `actions.Engine.RunPhoneProvider(ctx, in PhoneInput) error`,
`actions.Engine.RunSendPhoneMessage(ctx, in PhoneInput) error`.

- [ ] Write `TestDispatcherRouting` (table from `phonerules.Routing()`:
  consolidated on/off × purpose × Guardian selected provider × SMS
  connection `twilio`/`sms_gateway`), `TestDispatcherGuardianAuth0UsesBranding`
  and `...FailsClosedWithoutProvider` (`Working` false, `gd_send_sms_failure`),
  `TestDispatcherWorkingDefinition` (custom without bound Action → false;
  bound → true; runner down at send → `SendError{transient}`),
  `TestProviderSwitchKeepsCodes` (Review Focus 5),
  `TestTemplateRenderVariables`, `TestSMSGatewayJWTAndSSRF` (signed body per
  Task 1; private IP at dial refused), and in `internal/actions`
  `TestCustomPhoneProviderEvent`/`TestSendPhoneMessageEvent` (members per
  Task 1; code present in the event, absent from Action logs and execution
  records).
- [ ] Run `go test ./internal/phone ./internal/actions -run 'Dispatcher|Phone|SMSGateway|Template' -count=1`; expect FAIL.
- [ ] Implement; Actions run on the Plan 27/28 Node runner with tenant secrets.
- [ ] Rerun; expect PASS. Run `go test ./internal/actions -count=1` (Node required).
- [ ] Commit: `feat: route phone messages through providers and Actions`.

### Task 10: Passwordless service, `/passwordless/start`, magic links and the OTP grant

**Files:** create `internal/passwordless/{service,start,link}.go`,
`internal/oauth/grant_passwordless.go` and tests; modify `internal/oauth/handlers.go`,
`internal/clientrules` (grant type), discovery per Task 1.

**Interfaces:** consumes Tasks 2, 4, 8, 9, Plan 21 mailer, Plan 19
protection, Plan 33 `mfa.Decide`. Produces the passwordless service contract above.

- [ ] Write `TestStartEmailCode`, `TestStartSMSCode` (fake sender; `cs`
  logged with masked identifier), `TestStartLink` (`cls`),
  `TestStartRequiresEnabledConnection`, `TestStartClientAuthEnforced` (flag
  on: confidential client without secret refused; public client allowed),
  `TestStartCountryCodes` (deny list and allow list), `TestStartSendBudget`
  (per identifier and per IP → `too_many_requests`, `limit_phone`),
  `TestStartReplacesPreviousCode` and `TestConcurrentVerifyOneWins` (Review
  Focus 1), `TestLinkScannerDoesNotConsume` (Review Focus 2),
  `TestLinkReuseFails`, `TestBruteForceBlocksIdentifier`.
  Grant: `TestPasswordlessGrantIssuesTokens`, `TestPasswordlessGrantSignupAndDisableSignup`,
  `TestPasswordlessGrantMFARequired` (enrolled user → `mfa_required`; MFA API
  audience rule), `TestPasswordlessGrantBlockedUser`, `TestPasswordlessGrantRefusalLogsFepotpft`,
  `TestPasswordlessGrantRunsActions` (pre-registration on signup, post-login).
- [ ] Run `go test ./internal/passwordless ./internal/oauth -run 'Start|Link|Passwordless|BruteForce|Concurrent' -count=1`; expect FAIL.
- [ ] Implement. Email uses the connection body or the code-based template
  per Task 1 (§8); SMS uses the dispatcher.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: add passwordless start, magic links and the OTP grant`.

### Task 11: Hosted passwordless login

**Files:** create `internal/login/passwordless.go`, templates
`internal/ui/templates/passwordless_{identifier,code,link_sent,link_confirm}.html`;
modify `internal/login/identifier.go` (route to passwordless connections),
`internal/authz` flow, i18n catalogues, branding prompt registry.

**Interfaces:** consumes Task 10.

- [ ] Write `TestHostedEmailCodeLogin` (new user signup and existing user),
  `TestHostedSMSCodeLogin`, `TestHostedResendObeysBudget`,
  `TestHostedMagicLinkSameBrowser` (behaviour per Task 1),
  `TestHostedLinkScannerGet` (Review Focus 2), `TestHostedPasswordlessBotPolicy`
  (`challenge_passwordless_policy`), `TestHostedPasswordlessMFAChallenge`,
  `TestHostedPasswordlessOrganization`, `TestHostedPasswordlessPromptNone`,
  `TestIdentifierFirstRoutesToPasswordless`, and a template test that every
  new i18n key exists in the English catalogue.
- [ ] Run `go test ./internal/login ./internal/authz -run 'Passwordless|IdentifierFirstRoutes' -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: add hosted passwordless login`.

### Task 12: SMS and voice MFA

**Files:** create `internal/mfa/phone.go`; modify `internal/mfa/{service,decide}.go`,
`internal/login/mfa.go`, MFA templates, `internal/oauth/{mfa_api,grant_mfa}.go`,
guardian handlers (sms/phone factors enforced, `gd_phone_settings_update`),
user authentication-method serializer (obfuscation), `internal/mfarules`
(`sms` → enforced), `internal/actions/mfa.go`.

**Interfaces:** consumes Tasks 9 and Plan 33 `mfa.Service`. Produces
`mfa.Service.BeginPhoneEnroll(ctx, tid, uid, phone, method string) (*Enrollment, error)`
(method `sms`|`voice`).

- [ ] Write `TestPhoneFactorOfferedOnlyWithWorkingProvider` (Review Focus 5),
  `TestHostedSMSEnrollAndChallenge`, `TestHostedVoiceChallenge`,
  `TestHostedSwitchSMSVoice` (only when message-types allow both),
  `TestEnrollCountryCodes`, `TestMFAAssociateOOBSMS`, `TestMFAChallengeOOBVoice`,
  `TestMFAOOBGrantSMS`, `TestPhoneThrottleShared` (hosted and grant share
  the budget; `limit_phone`), `TestSendFailureLogsGdSendSMSFailure`,
  `TestEnrollmentsObfuscatePhone` (and not when
  `disable_management_api_sms_obfuscation`), `TestChallengeWithPhone`
  (`api.authentication.challengeWith({type:"phone"})`), and
  `TestSNSVoiceUnavailable` (voice not offered when the provider is `sns`).
- [ ] Run `go test ./internal/mfa ./internal/login ./internal/oauth ./internal/mgmt ./internal/actions -run 'Phone|SMS|Voice|OOB|Obfuscate' -count=1`; expect FAIL.
- [ ] Implement, reusing Plan 33's challenge, attempt budget and proof commit.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: add SMS and voice MFA`.

### Task 13: Phone identifiers, phone password reset and code-based email templates

**Files:** create `internal/connrules/phone_precheck.go`; modify
`internal/connrules/password.go` (attributes/precedence enforced),
connection PATCH handler, `internal/login/{identifier,login,reset}.go`,
signup flow, user update paths (`scpn`/`fcpn`, `user.updated`),
`internal/emailrules` usage of `*_by_code` templates.

**Interfaces:** consumes Tasks 4, 9. Produces
`connrules.PhonePrecheck(ctx, st store.Store, tid, connection string) ([]PhoneConflict, error)`
(`PhoneConflict{UserIDs []string; Reason string}` — `invalid` or `duplicate`; numbers masked).

- [ ] Write `TestEnablePhoneIdentifierRefusedOnConflicts` (invalid and
  duplicate numbers → Auth0-shaped 400 with the conflict list; nothing
  enabled; no user row changed), `TestEnablePhoneIdentifierSucceedsClean`,
  `TestPhoneUniqueOnWriteAfterEnable` (concurrent writes of one number: one
  wins), `TestLoginByPhoneAndPassword`, `TestSignupWithPhoneVerification`
  (`otp_verify` SMS; `limit_signup_otp`), `TestPhoneChangeLogsScpnAndEvent`,
  `TestPhoneChangeFailureLogsFcpn`, `TestResetByPhone` (code sent with
  `change_password`; consumed on submit, not GET; password policy, breach
  check, `password-reset-post-challenge` Action and MFA still apply),
  `TestCodeBasedEmailTemplatesUsed` (per Task 1).
- [ ] Run `go test ./internal/connrules ./internal/login ./internal/mgmt ./internal/emailrules -run 'Phone|ResetByPhone|CodeBased' -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; expect PASS.
- [ ] Commit: `feat: add phone identifiers and phone password reset`.

### Task 14: Console

**Files:** create `console/src/pages/connections/Passwordless{Email,SMS}.vue`,
`console/src/pages/branding/Phone{Providers,Templates}.vue`; modify
`sections.ts`, `router.ts`, the MFA page (SMS/voice factor, message types),
database connection page (phone identifier with pre-check conflict display),
user detail (phone, phone MFA), locales.

- [ ] Write component tests: provider forms for Twilio, SNS and Custom (Action
  picker; credentials write-only, never prefilled), template editor preview
  and try, passwordless connection settings and test send, MFA SMS/voice
  toggles disabled with an explanation when no provider works, conflict list
  rendering on a refused phone-identifier enable, and an API projection test
  that list views never request credentials (Plan 33 client-secret lesson).
- [ ] Run `make console` (typecheck, lint, tests); expect FAIL.
- [ ] Implement in the occupysaas hybrid style used by existing pages.
- [ ] Rerun `make console`; expect PASS; commit rebuilt `console/dist`.
- [ ] Commit: `feat: manage passwordless and phone in the console`.

### Task 15: Seed, Deploy CLI and operator guides

**Files:** modify `internal/seed`, `tests/e2e/deploy-cli/manifest.json` and
its handlers map; create `docs/passwordless.md`, `docs/phone-providers.md`
(routing table, SNS setup, example `custom-phone-provider` Actions for
Vonage, Azure Communication Services and SNS); update `docs/mfa.md`,
`docs/logs.md`, `docs/tenant-settings.md`, `docs/attack-protection.md`,
`docs/deploy-cli.md`.

- [ ] Write seed tests: passwordless connections, phone provider with
  credentials from the existing secret-reference mechanism, templates,
  Guardian phone settings, and the phone-identifier pre-check applied to
  seeded enables. Deploy CLI manifest tests: the Guardian phone handlers and
  `attackProtection` (phone-provider-protection) move to included when the
  pinned client round-trips them; otherwise record the gap, never adapt.
- [ ] Write `TestExampleActionsCompile` that builds each example Action in
  the docs with the Actions build pipeline.
- [ ] Run `go test ./internal/seed ./tests/e2e/deploy-cli/... -count=1`; expect FAIL.
- [ ] Implement.
- [ ] Rerun; expect PASS. `make check-sources`.
- [ ] Commit: `feat: provision passwordless and phone through seed and Deploy CLI`.

### Task 16: End-to-end acceptance, record and final regression

**Files:** create `tests/e2e/{m34-passwordless.spec,m34-grants,m34-node,m34-cli}.mjs`,
`tests/e2e/run-m34-passwordless.sh`; modify `Makefile` (`e2e-passwordless`),
the roadmap, `docs/compat/matrix.md`, `docs/logs.md` (owners), the record.

- [ ] Write `m34-passwordless.spec.mjs` covering spec §10 items 1–3, 5–7
  through the browser with phone-fakes and the local mailbox; the runner
  sets `ZA_TEST_MODE=1` and `ZA_TEST_PHONE_ENDPOINTS`.
- [ ] Write `m34-grants.mjs` (`@auth0/auth0-auth-js` 1.16.1 and raw HTTP: §10
  item 4), `m34-node.mjs` and `m34-cli.mjs` (§10 item 8), on memory and
  SQLite; PostgreSQL and MySQL through the runner's backend switch, with the
  stored SQL sink dump populated for those lanes too (Plan 33 gap).
- [ ] Remove the `t.Skip` from `TestPlan34LogCodes`. Add the representative
  secret scan (§10 item 9) over every log sink, event body, Action log and
  console response, failing on any OTP, link token, provider credential or
  unmasked phone number.
- [ ] Run `make e2e-passwordless` once to find missing fixtures; fix them
  through the owning task's code and tests, never by weakening assertions.
- [ ] Final verification, sequentially where ports overlap, per `AGENTS.md`:
  - `ZA_REQUIRE_NODE=1 go test -race -timeout=50m ./...`
  - `./scripts/test-sql.sh -timeout=90m ./internal/store/sqlstore/...`
  - `make console` and `make check-sources`
  - `make e2e-passwordless`, `make e2e-mfa`, `make e2e`, `make e2e-actions`,
    `make e2e-actions-ii`, `make e2e-logs`, `make e2e-events`, `make e2e-domains`, `make e2e-deploy`
  - `make conformance`
  Expected: every selected suite passes. Report unavailable, skipped or
  timed-out suites as such, never as passing.
- [ ] Update the roadmap's Plan 34 entry and the matrix. Get a whole-branch
  review with the repository's review skill, fix correctness and security
  findings, and rerun the affected checks.
- [ ] Commit: `test: verify Plan 34 passwordless and phone end to end`.

## Dependency order and completion audit

Execution order: **1–16**. Task 2 may run in parallel with 1. Tasks 3 and 4
depend on 2. Tasks 5–6 depend on 4. Task 7 depends on 1, 3, 4. Task 8 depends
on 1. Task 9 depends on 3, 4, 8. Task 10 depends on 9. Task 11 depends on 10.
Task 12 depends on 9. Task 13 depends on 4, 9. Tasks 14–15 depend on 7–13.
Task 16 depends on all. Route registration, proto and store files are never
edited concurrently.

| Spec requirement | Owning tasks |
| --- | --- |
| Rulings, evidence, D-0060 (§1, §2) | 1 |
| Passwordless connections (§3) | 8 |
| `/passwordless/start`, codes, links, OTP grant (§3) | 2, 10 |
| Hosted passwordless (§3) | 11 |
| Sender interface, Twilio, SNS, endpoints, working definition (§4) | 3, 9 |
| Routing, templates, `try` (§4) | 7, 9 |
| Phone Actions and examples (§5) | 9, 15 |
| SMS and voice MFA (§6) | 12 |
| Phone identifiers, existing data pre-check, phone reset (§7) | 4, 5, 13 |
| Code-based email templates (§8) | 10, 13 |
| Tenant settings, protection, budgets (§1 item 10) | 7, 10 |
| Logs and events (§1 item 11) | 1, 9–13, 16 |
| Storage, plugin capability (§9) | 4, 5, 6 |
| Console (§9) | 14 |
| Seed, Deploy CLI, docs (§9) | 15 |
| Acceptance and regression (§10) | 16 |

Planning self-review: every spec section maps to a task above. The storage,
sender, dispatcher and passwordless contracts are defined once here and used
by name later. Each Review Focus risk has a named test in its owning task.
No implementation, migration or product test was run while writing these
documents.
