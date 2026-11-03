# Plan 34 — Passwordless and phone

**Date:** 2026-11-03. **Status:** design; not implemented.

**Predecessor:** [Plan 33 MFA](2026-11-02-zeroauthy-mfa-design.md). Roadmap
entry: [management roadmap, Plan 34](2026-10-19-zeroauthy-management-roadmap-design.md).
Release position: first plan after v1.0 ([v1 scope](2026-11-02-zeroauthy-v1-release-scope.md) §4).
Read the [clean-room policy](../../../CLEAN_ROOM.md), the [MFA guide](../../mfa.md),
the [email guide](../../email.md), the [Actions guide](../../actions.md), the
[logs guide](../../logs.md) and the [attack protection guide](../../attack-protection.md).

## 1. Outcome and scope

An operator can let users sign in without a password, by a code sent by
email or SMS or by an email magic link, and can use the phone as a factor
and as an identifier, the way Auth0 does. Text and voice messages go through
Twilio, through Amazon SNS, or through an Action that calls any other service.

**Maintainer rulings (2026-11-03):**

- **Whole scope in one plan.** Passwordless first, but SMS and voice MFA,
  phone password reset and phone identifiers all ship in Plan 34. "It may
  take longer, but it will be worth it." Voice is lower priority than SMS
  and may be the last thing finished, but it is in scope.
- **Providers.** Twilio is required, because it is Auth0's primary provider
  and `twilio` must mean what it means in Auth0. zeroauthy must not be locked
  in to one vendor: **Amazon SNS** ships as the first native extension
  provider. More SMS/phone providers (Vonage, Azure Communication Services)
  and more mail providers are wanted later but are not part of this plan.
  The `custom` provider (the `custom-phone-provider` Action) covers every
  other service now.

**Rule:** strict 1:1 with Auth0's documented behaviour. A local ruling is
made only where Auth0 depends on its own infrastructure (its built-in SMS
sender), or leaves a value unstated. Each local ruling is marked **(LR)** and
recorded in **D-0060**. The SNS provider is a marked zeroauthy extension.

### In scope

1. **Passwordless connections:** strategies `email` and `sms` on
   `/api/v2/connections`, with Auth0's documented options.
2. **Authentication API:** `POST /passwordless/start` (`send: code|link`),
   the magic-link verification redirect, and the grant
   `http://auth0.com/oauth/grant-type/passwordless/otp` on `/oauth/token`.
3. **Hosted login:** the `login-passwordless` prompt and its screens
   (`login-passwordless-email-code`, `login-passwordless-email-link`,
   `login-passwordless-sms-otp`), signup on first login unless
   `disable_signup`, and identifier-first routing to passwordless connections.
4. **Phone providers:** `/api/v2/branding/phone/providers` (`twilio`,
   `custom`, and the extension `sns`), including `try`;
   `/api/v2/branding/phone/templates` (CRUD, `reset`, `try`).
5. **Phone Actions:** the `send-phone-message` and `custom-phone-provider`
   triggers (deferred by Plan 28), with tested example Actions.
6. **MFA by SMS and voice:** the Guardian `sms` and `phone` factors go live:
   `/guardian/factors/sms|phone/*` configuration stored by Plan 33 now drives
   delivery; hosted enrollment and challenge; `/mfa/associate` and
   `/mfa/challenge` with `oob` over `sms` and `voice`; the `mfa-oob` grant;
   Actions `challengeWith` and `enable` with phone factors.
7. **Phone identifiers on database connections:** the `attributes`
   (flexible identifiers) option for `phone_number` stops being stored-only:
   login by phone number and password, signup with phone verification by
   SMS code, and `precedence`.
8. **Phone password reset:** a reset code by SMS for database users who
   sign in with a phone number.
9. **Code-based email templates:** `verify_email_by_code`,
   `auth_email_by_code`, `reset_email_by_code` (stored since Plan 21) go live
   where Auth0 uses them.
10. **Tenant settings and protection made live:** `phone_consolidated_experience`,
    `country_codes` (`list`, `mode`), `enforce_client_authentication_on_passwordless_start`,
    `disable_management_api_sms_obfuscation`, the passwordless bot policy
    (`challenge_passwordless_policy`), the phone-provider-protection
    Management API (which unblocks Deploy CLI's attack-protection handler),
    passwordless brute-force protection, and phone send budgets.
11. **Logs and events:** `cls`, `cs`, `fepotpft` and the other passwordless
    codes; `gd_send_sms`, `gd_send_sms_failure`, `gd_send_voice`,
    `gd_send_voice_failure`, `gd_phone_settings_update`; `limit_phone`,
    `limit_signup_otp`; `scpn`, `fcpn`; `user.updated` for phone changes.
12. **Console, seed, Deploy CLI, storage, plugin capability, E2E.**

### Not in scope

- Vonage, Azure Communication Services and any other native SMS provider;
  new mail providers. Tracked as follow-ups; the provider interface (§4)
  must make each a single adapter.
- Auth0's legacy endpoints `/passwordless/verify` and `/oauth/ro` (deprecated
  by Auth0); Lock and classic-login widget behaviour.
- WhatsApp or other non-SMS channels; push MFA; Duo.
- Real SMS delivery in tests. No test sends a real message.

### Anti-goals

- A provider name, credential or behaviour that changes the meaning of an
  Auth0 value. `twilio`, `custom`, `auth0` and `phone-message-hook` keep
  Auth0's meaning everywhere.
- Any OTP, magic-link token, verification code, provider credential or full
  phone number in a log line, event body, Action log or console response.
  Phone numbers in logs follow Auth0's masking (Task 1 freezes the rule).
- A passwordless path that bypasses MFA, attack protection, bot detection,
  blocked users, Actions or organization rules that a password login obeys.
- Lock-in: no Twilio-specific field in storage outside the Twilio adapter's
  sealed configuration.

## 2. Evidence and compatibility rules

Task 1 reviews these public sources and freezes the contract in
`internal/phonerules/inventory.json` and **D-0060**:

| Contract | Primary source |
| --- | --- |
| Connection options for `email` and `sms` | [Management API OpenAPI](https://auth0.com/docs/oas/management/v2/management-api-oas.json) `connections` (`ConnectionOptionsEmail`, `ConnectionOptionsSMS`), [Passwordless connections](https://auth0.com/docs/authenticate/passwordless) |
| `/passwordless/start`, magic link, OTP grant | [Authentication API: Passwordless](https://auth0.com/docs/api/authentication#passwordless), [Embedded passwordless with the grant](https://auth0.com/docs/authenticate/passwordless/implement-login/embedded-login) |
| Universal Login passwordless | [Passwordless with Universal Login](https://auth0.com/docs/authenticate/passwordless/implement-login/universal-login), prompt/screen names in [Customize text](https://auth0.com/docs/customize/login-pages/universal-login/customize-text-elements) and `internal/brandingrules/inventory.json` |
| Phone providers and templates | Management API OpenAPI `branding/phone/providers`, `branding/phone/templates`; [Configure phone messaging providers](https://auth0.com/docs/customize/phone-messages) |
| Phone Actions | [send-phone-message trigger](https://auth0.com/docs/customize/actions/explore-triggers/mfa-notifications-trigger), [custom-phone-provider trigger](https://auth0.com/docs/customize/phone-messages/configure-phone-messaging-providers) event/api objects |
| SMS and voice MFA | [SMS/voice factor](https://auth0.com/docs/secure/multi-factor-authentication/multi-factor-authentication-factors/configure-sms-voice-notifications-mfa), Guardian OpenAPI routes, [MFA API](https://auth0.com/docs/secure/multi-factor-authentication/manage-mfa-auth0-apis) (`oob_channels`) |
| Flexible identifiers and phone reset | [Flexible identifiers and attributes](https://auth0.com/docs/authenticate/database-connections/flexible-identifiers-and-attributes), [Password reset by phone](https://auth0.com/docs/authenticate/database-connections/password-reset) |
| Tenant settings and protection | OpenAPI `tenants/settings`, `attack-protection`; [Bot detection](https://auth0.com/docs/secure/attack-protection/bot-detection) |
| Logs | [Log event type codes](https://auth0.com/docs/deploy-monitor/logs/log-event-type-codes), logs schema |
| Twilio wire API | Twilio's public REST docs (Messages, Calls with TwiML `<Say>`) |
| SNS wire API | AWS SNS `Publish` (Query API, SigV4) public docs |
| Phone formats | ITU-T E.164 |

Task 1 freezes: every route's scopes, parameters, bodies, limits and errors;
connection option schemas and defaults; the passwordless OTP length, lifetime,
attempt limit and reuse rule; magic-link lifetime and same-browser rule;
phone template types and default bodies (written in our own words, never
copied); delivery method names (`text`, `voice`); Action event/api members;
log codes and their fields; and the masking rule for phone numbers.

Points the documents leave open go to permitted firewalled observation on the
maintainer's tenant by a separate observer session
(`docs/compat/observations/passwordless-phone.md`). Following the Plan 32/33
ruling, observation is **optional**: Task 1 makes a local ruling for each
open point, lists it as a gap (**P1–Pn**) in D-0060 and the follow-ups file,
and implementation proceeds. Expected open points: `/passwordless/start`
response bodies and errors per strategy; OTP attempt limit and lockout
interplay with brute-force protection; magic-link behaviour in another
browser; `limit_phone` budgets; phone masking in `GET /users` and logs; user
ID format for passwordless users.

General rules hold (as Plan 33 §2): tenant-scoped IDs, live operator grant
checks, strict body parsing, pagination conventions, `x-source` entries,
regenerated API/protobuf/console outputs, Go 1.26.7 and Node ≥22.13, pinned
dependencies. **No new Go module:** Twilio is plain HTTPS with Basic auth;
SNS reuses the SigV4 signer already used by the SES email transport (move it
to a shared internal package rather than copy it).

## 3. Passwordless connections and the Authentication API

### Connections

`POST/PATCH /api/v2/connections` accept `strategy: "email"` and
`strategy: "sms"` with Auth0's option schemas (Task 1). The connection
**names** `email` and `sms` follow Auth0's rule for passwordless connections
(Task 1 freezes whether other names are accepted). Notable options:

- **email:** `email.{from, subject, syntax, body}` (Liquid, rendered by the
  Plan 21 renderer), `totp.{length, time_step}`, `disable_signup`,
  `brute_force_protection`, `authParams` (defaults merged into magic links).
- **sms:** `from`, `syntax` (`md_with_macros` or `liquid`), `template`,
  `totp`, `disable_signup`, `brute_force_protection`, `provider`
  (`twilio` or `sms_gateway`), `twilio_sid`, `twilio_token`,
  `messaging_service_sid`, `gateway_url`, `gateway_authentication`,
  `forward_req_info`. Credentials (`twilio_token`, gateway secrets) are
  sealed with the master key and never returned, like Plan 33's provider
  secrets. With `phone_consolidated_experience` on, the connection's own
  Twilio fields are ignored in favour of the tenant phone provider (§4);
  Task 1 freezes exactly which fields that setting overrides.
- **sms_gateway** posts Auth0's documented JSON body to `gateway_url`, signed
  as a JWT when `gateway_authentication` is set. The outbound request goes
  through the same SSRF-guarded HTTP client used by webhooks (Plan 32):
  checked IPs at dial time, no redirects, bounded time.

Users from these connections have Auth0's identity shape (`provider:
"email"`/`"sms"`, `user_id` per Task 1), `email_verified`/`phone_verified`
true after a successful login, and are searchable, importable and
exportable like other users. Account linking and the Plan 25 email-account
rules apply.

### `/passwordless/start`

Body: `client_id`, client authentication (`client_secret`, or the client's
configured method), `connection`, `email` or `phone_number`, `send`
(`code`, or `link` for email), `authParams`. Rules:

- The connection must be enabled for the client. Unknown users are created
  on verification, not on start, unless `disable_signup` (then start fails
  per Task 1 for unknown users) — creation happens only after a valid code.
- **Client authentication:** when the tenant flag
  `enforce_client_authentication_on_passwordless_start` is on, confidential
  clients must authenticate; public clients are unaffected (Task 1 confirms).
- **Bot detection:** `challenge_passwordless_policy` applies to the hosted
  flow; the API path obeys Auth0's documented rule (Task 1).
- **Country codes:** an SMS start to a number outside the tenant's
  `country_codes` allow list (or inside its deny list) is refused with
  Auth0's error.
- **Send budget:** a per-identifier and per-IP budget backed by the Plan 19
  protection repository; exhaustion logs `limit_phone` (SMS) or the email
  equivalent and returns `too_many_requests`.
- Each send logs `cs` (code) or `cls` (link). Failed delivery logs the
  documented failure code. The response body follows Task 1.

### Codes and links

- **OTP:** numeric, `totp.length` digits (default per Task 1), valid for
  `totp.time_step`/documented lifetime, single use, hashed at rest, a bounded
  number of attempts; a new start replaces the previous code for that
  identifier and connection. Attempt and replay checks are conditional
  database updates, as in Plan 33.
- **Brute force:** with `brute_force_protection`, repeated wrong codes for
  one identifier block it per Plan 19's rules and log the documented code.
- **Magic link:** an opaque one-time token bound to tenant, connection,
  client, identifier and the sealed `authParams`. Opening it (the
  verification redirect path frozen in Task 1) verifies, then continues the
  authorization as if the code had been entered: it lands on the client's
  `redirect_uri` with the requested response. The same-browser rule follows
  Auth0's Universal Login behaviour (Task 1; open point if undocumented).
  Link scanners must not burn the link: a GET only renders a confirm page
  or verifies idempotently without consuming the token until the final
  step (learned from Plan 33 review I5).

### The OTP grant

`grant_type=http://auth0.com/oauth/grant-type/passwordless/otp` with
`client_id`, client authentication per the client, `realm` (`email`/`sms`),
`username`, `otp`, `audience`, `scope`. The client must have the grant type
enabled (`grant_types` includes it). A correct code creates the user if
needed (respecting `disable_signup`), runs pre-/post-registration and
post-login Actions, and goes through the same MFA decision as password
grants (`mfa_required` when MFA applies; Plan 33's MFA-API-audience rule
included). Refusals log `fepotpft` and return Auth0's errors
(`invalid_grant` with documented descriptions). The grant is advertised in
discovery only if Auth0 advertises it (Task 1).

### Hosted login

`/authorize` with `connection=email|sms`, or identifier-first routing,
reaches the `login-passwordless` prompt. Screens: enter identifier → code
entry (or "check your email" for links), resend with the send budget,
"use another method". Organizations, consent, MFA, Actions (`post-login`,
`pre-user-registration`) and `prompt=none` behave as for other connections.
Text uses the existing i18n catalogue; new keys get English text in our own
words and the same translation path as earlier prompts.

## 4. Phone messaging

### One sender interface

A `phone.Sender` interface takes a rendered message (`to` in E.164,
`delivery_method` `text`|`voice`, body, message type, tenant and context) and
returns a provider message ID or a classified error (`invalid_number`,
`unreachable`, `rate_limited`, `provider_auth`, `transient`). Adapters:

| Provider name | Auth0 meaning | zeroauthy |
| --- | --- | --- |
| `twilio` | Built-in Twilio | Native adapter: Messages API for `text`, Calls API with TwiML `<Say>` for `voice`; `sid`, `auth_token` (sealed), `default_from` or `mssid` |
| `custom` | `custom-phone-provider` Action | Runs the tenant's deployed Action (§5) |
| `sns` | — (extension) | Native adapter: SNS `Publish` to a phone number, SigV4; `region`, access key ID, secret (sealed), optional sender ID and `SMSType`. `text` only; `voice` reports unsupported delivery |

Credentials are sealed with the master key, never returned, and scrubbed by
key name at every log sink. A provider is always tenant-scoped; there is no
process-wide fallback sender.

**(LR) No zeroauthy-owned SMS service.** Auth0's Guardian
`selected-provider: auth0` means Auth0's own sender. zeroauthy has none, so
`auth0` sends through the tenant's branding phone provider; with no provider
configured, delivery fails closed with `gd_send_sms_failure` and the factor
is not offered to new enrollments. Recorded in D-0060.

### Routing

- **Branding phone provider** (`/branding/phone/providers`): the tenant's
  single active provider for MFA, passwordless and phone password reset
  when `phone_consolidated_experience` is on, and for Guardian `auth0`.
- **Guardian selected provider:** `twilio` uses the Guardian Twilio
  configuration Plan 33 stores; `phone-message-hook` runs the
  `send-phone-message` Action; `auth0` as above.
- **SMS connection:** its own `provider` settings unless the consolidated
  experience overrides them.

Task 1 freezes this routing table from Auth0's documents and writes it into
the operator guide.

**When a provider counts as working** (builder's call, recorded here):
a native provider (`twilio`, `sns`) works when it is configured and not
`disabled`; an Action-backed provider (`custom`, `phone-message-hook`)
works when its trigger has a deployed, bound Action. Only a working
provider lets a factor or SMS connection be offered. A failure at send time
(provider error, Node runner unavailable, Action error) is a delivery
failure: it logs the documented failure code, returns Auth0's error, and
does not change what is offered.

**Provider endpoints are fixed** (builder's call, recorded here). Tenants
cannot set a Twilio or SNS base URL; adapters use the vendor's public
endpoints. For acceptance tests only, a process-level setting
(`ZA_TEST_PHONE_ENDPOINTS`, honoured only when an explicit
`ZA_TEST_MODE=1` is also set, and logged as a warning at startup; no such flag exists
yet, so the plan adds it) redirects adapters to
local fakes. This keeps provider credentials from being pointed at an
arbitrary host.

### Templates

`/branding/phone/templates` types (Task 1; expected `otp_verify`,
`otp_enroll`, `change_password`, `blocked_account`, `password_breach`) with
`content.{from, body.text, body.voice, syntax}`, `disabled`, `reset` and
`try`. Default bodies are written in our own words. Guardian
`/guardian/factors/sms/templates` (`enrollment_message`,
`verification_message`) apply when the consolidated experience is off.
Rendering uses the Plan 21 Liquid renderer with the documented variables
(`code`, `friendly_name`, `locale` and others per Task 1).

### `try`

`POST /branding/phone/providers/{id}/try` and `.../templates/{id}/try` send
one real message through the configured provider to the given number and
return Auth0's response. They obey the send budget and log the result.

## 5. Actions

- **`custom-phone-provider`**: event members `notification` (message type,
  recipient, `as_text`, `as_voice`, `delivery_method`, `code`, `locale`,
  …), `user`, `client`, `request`, `tenant`; `api.notification.drop` per
  Task 1. Executes on the Plan 27/28 Node runner with tenant-isolated
  secrets. Retry follows the documented rule using Plan 28 durable jobs only
  if Auth0 retries; otherwise a failure is a delivery failure.
- **`send-phone-message`**: the Guardian `phone-message-hook` trigger, with
  Auth0's documented event (`message_options`, `recipient`, `text`, `code`,
  `action`, `language`, …).
- Both triggers become creatable and bindable; `internal/actionsrules`
  moves them from deferred to supported.
- **Examples:** `docs/phone-providers.md` ships tested example
  `custom-phone-provider` Actions for Vonage and Azure Communication Services
  (and SNS, for operators who prefer an Action), each exercised in E2E
  against a fake endpoint.
- Post-login members from Plan 33 now accept phone factors:
  `api.authentication.challengeWith({type: "phone", options: {preferredMethod}})`
  and `api.multifactor.enable` with phone allowed; `event.authentication.methods`
  records `sms`/`voice`/`phone_number` as Auth0 does.

## 6. MFA by SMS and voice

Builds on Plan 33's service (`internal/mfa`), reusing its challenge,
attempt-budget, throttle and proof-commit machinery. Phone authenticators
use the existing `phone` type and `PhoneMethod` field.

- **Factors:** `PUT /guardian/factors/sms` and `/phone` enable enforcement;
  `/guardian/factors/phone/message-types` (`sms`, `voice`) controls which
  delivery methods users may choose. A factor without a working provider is
  not offered (fail closed, as Plan 33 with email).
- **Hosted:** enrollment screens (enter number with country picker
  respecting `country_codes`, receive code, confirm; recovery code on first
  enrollment) and challenge screens (send, resend with budget, switch
  sms/voice when both are allowed, "try another method"). Prompt/screen
  names per the branding inventory.
- **API:** `/mfa/associate` with `authenticator_types:["oob"]`,
  `oob_channels:["sms"|"voice"]`, `phone_number`; `/mfa/challenge` with
  `challenge_type: "oob"`; the `mfa-oob` grant with `binding_code`. The
  Plan 33 rule that MFA API tokens require MFA for enrolled users holds.
- **Management:** `GET /users/{id}/enrollments` and authentication methods
  show phone enrollments; phone numbers are obfuscated unless
  `disable_management_api_sms_obfuscation` (Task 1 freezes the mask).
- **Throttle:** code sends per user and factor share the Plan 33 throttle
  plus `limit_phone`; wrong-code limits reuse Plan 33's budget.
- **Logs:** `gd_send_sms`, `gd_send_sms_failure`, `gd_send_voice`,
  `gd_send_voice_failure`, `gd_phone_settings_update`, plus Plan 33's
  enrollment and auth codes with the phone factor.

## 7. Phone identifiers and phone password reset

- **Flexible identifiers:** database connection
  `attributes.phone_number.{identifier.active, signup.status,
  signup.verification.active}` and `precedence` become enforced (stored-only
  since D-0042). Users sign in with phone number and password; signup can
  require a phone number, verified by an `otp_verify` SMS code before the
  account is created. `limit_signup_otp` caps verification sends.
  Phone numbers are normalized to E.164 and unique per connection like email.
- **Existing phone data (maintainer ruling 2026-11-03: check when enabled).**
  Until now `phone_number` was stored unchecked, so tenants may hold
  non-E.164 values or duplicates within a connection. Migration 0034 adds
  structures only and **never rewrites user data**, so upgrades cannot fail
  on old data. Turning on `attributes.phone_number.identifier.active` for a
  connection (PATCH, seed or Deploy CLI) runs a pre-check: every user's
  number in that connection is normalized to E.164 in memory; if any number
  is invalid or two users share one, the change is refused with a conflict
  list (user IDs only, numbers masked), and nothing is enabled. Once
  enabled, every new or changed number is normalized on write and uniqueness
  is enforced by the store under the user lock (an application-level check,
  so the three dialects behave the same; a database unique index is added
  only on the normalized column that new writes populate). Existing values
  are normalized lazily on their next write or by the pre-check's fix-up
  guidance in the operator guide.
- **Profile changes:** setting or changing `phone_number` through the
  Management API or hosted flows logs `scpn`/`fcpn` and emits `user.updated`
  (Plan 32 catalog). Verification state resets on change per Auth0.
- **Password reset by phone:** for users whose identifier is a phone
  number, the hosted reset flow sends a `change_password` SMS code, verifies
  it, then sets the password through the existing Plan 21 reset path
  (password policy, breach detection, `password-reset-post-challenge`
  Action, MFA challenge from Plan 33). Ticket and code consumption happen on
  submit, never on GET.

## 8. Code-based email templates

`verify_email_by_code`, `auth_email_by_code` and `reset_email_by_code` are
used where Auth0 uses them (Task 1 freezes exactly when: e.g. passwordless
email codes use `auth_email_by_code` when the consolidated/new experience
applies, otherwise the connection's own email body). Email delivery stays on
the Plan 21 provider, so all ten existing mail providers work unchanged.

## 9. Storage, plugins, console, provisioning

- **Migration 0034** (SQLite, PostgreSQL, MySQL): passwordless codes and
  link tokens (hashed, expiring, attempt-counted, indexed by tenant +
  connection + identifier and by tenant + user), phone providers (one row
  per provider, sealed credentials), phone templates, phone send-budget
  state if not covered by the Plan 19 protection store, and any user phone
  identifier index required for unique lookup. All expiring rows join the
  periodic purge sweep (Plan 33 review I1).
- **Store contract** in `internal/store` with memory, SQL, gRPC plugin
  implementations and `pkg/storetest` contract cases. New gRPC methods go in
  a separately negotiated **Phone v1** plugin capability; older plugins
  report it unsupported and the features fail closed with a clear error.
- **Console:** passwordless connection pages (email and SMS settings, test
  send), a Phone providers page (Twilio, SNS, Custom with Action picker, try),
  phone templates editor with preview and try, SMS/voice under
  Multi-factor auth, phone identifier options on database connections,
  user detail phone fields and phone MFA enrollments. Secrets are write-only.
- **Seed** and **Deploy CLI:** connections with the new strategies, phone
  providers (credentials via the existing secret-reference mechanism),
  phone templates, the Guardian phone handlers left as Plan 34 by Task 13 of
  Plan 33, and the phone-provider-protection attack-protection handler
  (Deploy CLI's `attackProtection` handler moves from tool-unsupported to
  supported if the pinned client allows; otherwise the gap is recorded, not
  adapted around).
- **Docs:** `docs/passwordless.md`, `docs/phone-providers.md`, updates to
  `docs/mfa.md`, `docs/logs.md`, `docs/tenant-settings.md`,
  `docs/attack-protection.md`, `docs/compat/matrix.md`, D-0060.

## 10. Acceptance and completion

A fresh tenant run by `make e2e-passwordless` (production app, SQLite and
memory; PostgreSQL/MySQL through the runner's backend switch) with a fake
Twilio API, a fake SNS API, a fake SMS gateway and the existing local
mailbox shows:

1. Email code login through hosted pages for a new user (signup) and an
   existing user; resend; wrong code; expiry; brute-force block.
2. Email magic link to a client callback; a scanner-style GET does not burn
   the link; reuse fails.
3. SMS code login through Twilio, then switch the tenant provider to SNS and
   repeat; then to `custom` with an example Action; then `sms_gateway`.
4. The OTP grant with `@auth0/auth0-auth-js` (pinned) and raw HTTP,
   including `mfa_required` when MFA applies and `enforce_client_authentication_on_passwordless_start`.
5. SMS MFA enrollment and challenge (hosted and API); voice challenge
   through Twilio's fake Calls API; SNS voice reports unsupported.
6. Phone-number login and signup with phone verification on a database
   connection; phone password reset.
7. Country-code deny, send budget exhaustion (`limit_phone`), bot policy.
8. node-auth0 (pinned) for connections, phone providers/templates, Guardian
   phone routes and phone-provider-protection; auth0-cli where commands exist.
9. A representative-secret scan of every log sink, event body, Action log
   and console response: no OTP, link token, provider credential or
   unmasked phone number.

Final regression (sequential where ports overlap, per `AGENTS.md`): the
full Go race suite, `./scripts/test-sql.sh` on all three dialects, `make
console`, `make check-sources`, `make e2e-passwordless`, `make e2e-mfa`,
`make e2e`, the Actions, logs, events, domains and deploy E2E targets, and
`make conformance`. Then a whole-branch review with fixes. Results are
reported as they happened: skipped, unavailable or failed suites are never
called passing.
