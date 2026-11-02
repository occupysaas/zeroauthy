# Plan 33 — MFA I

**Date:** 2026-11-02. **Status:** design; not implemented.

**Predecessor:** [Event streams](2026-11-01-zeroauthy-event-streams-design.md),
done locally on main. Roadmap entry: [management roadmap §3, Plan 33](2026-10-19-zeroauthy-management-roadmap-design.md).
Read the [clean-room policy](../../../CLEAN_ROOM.md), the [Actions guide](../../actions.md),
the [logs guide](../../logs.md), the [event streams guide](../../event-streams.md)
and the [custom domains guide](../../custom-domains.md).

## 1. Outcome and scope

An operator can require a second factor the way Auth0 does. They turn on
factors and pick a policy in the Management API or the console. Users enrol
and are challenged on the hosted login pages. Native and server clients use
the Authentication API's `mfa_required` flow. Post-login Actions can demand,
skip or customize MFA. Operators manage each user's authentication methods.

**Rule:** strict 1:1 with Auth0's documented behaviour (maintainer ruling,
reaffirmed for Plan 32). This spec makes a local ruling only where Auth0
depends on its own apps or vendors, or leaves a value unstated. Each local
ruling is marked and recorded in **D-0059**.

**Maintainer ruling (2026-11-02): message providers.** Behaviour should
match Auth0, but zeroauthy is not tied to Twilio as Auth0 is. Twilio is
supported, along with several SMS and email providers for MFA and
password resets.

- **Email:** this already holds. Plan 21's provider supports `smtp`,
  `sendgrid`, `mailgun`, `mandrill`, `sparkpost`, `ses`, `azure_cs`,
  `ms365`, `resend` and a `custom` Action. MFA email codes, enrollment
  emails and password-reset emails in this plan go through whichever
  provider the tenant configured. Nothing in this plan is specific to one
  provider.
- **SMS and voice:** delivery is Plan 34. That plan now ships **native**
  SMS providers beyond Twilio. Candidates are Amazon SNS, Vonage and Azure
  Communication Services, with the final list set in Plan 34's Task 1. It
  keeps `custom-phone-provider` Actions for anything else. Auth0's
  documented values (`twilio`, `auth0`, `phone-message-hook`, `custom`) keep
  their meaning. Extra provider names are a marked zeroauthy extension.
  This reverses the roadmap's "native non-Twilio providers would be a
  deviation" note.
- **Effect on Plan 33:** the stored `/guardian/factors/sms|phone/*`
  configuration routes here accept and return Auth0's documented shapes
  only. Plan 34 extends their validation with the extension providers. No
  Plan 33 table or enum stops that: provider configuration is stored as JSON
  keyed by route, with sealed secrets per provider.

**Authenticator apps:** the `otp` factor is standard RFC 6238 TOTP. It
works with any authenticator app on any platform (Google Authenticator,
Microsoft Authenticator, Authy, 1Password, Bitwarden and others) and needs
no vendor app. That is why OTP is the first factor in this plan's journey.
Auth0's Guardian push factor, which needs Auth0's own app, is not needed
for cross-platform second factors.

Included:

- Factors `otp`, `email`, `recovery-code`, `webauthn-roaming` and
  `webauthn-platform` (WebAuthn with a platform authenticator as a second
  factor), enforced end to end.
- Policies `all-applications`, `confidence-score` and never (`[]`).
- `/api/v2/guardian/*`: factors, policies, enrollments, enrollment tickets,
  and the SMS/phone/push/Duo configuration endpoints. Those are stored and
  returned only; Plan 34 delivers SMS and voice.
- User endpoints: `/users/{id}/authentication-methods` (all eight
  operations), `GET /users/{id}/enrollments`, `DELETE /users/{id}/authenticators`,
  `DELETE /users/{id}/multifactor/{provider}`, `POST /users/{id}/recovery-code-regeneration`,
  `POST /users/{id}/multifactor/actions/invalidate-remember-browser`, and
  `multifactor` on the user object.
- Hosted login MFA prompts (`mfa`, `mfa-otp`, `mfa-email`,
  `mfa-recovery-code`, `mfa-webauthn`), enrolment tickets and remember-browser.
- Authentication API: `mfa_required`, `/mfa/associate`, `/mfa/challenge`,
  `GET`/`DELETE /mfa/authenticators`, the `mfa-otp`, `mfa-oob` and
  `mfa-recovery-code` grants, and the MFA API audience.
- Actions: `api.multifactor.enable`, `api.authentication.challengeWith`,
  `challengeWithAny`, `enrollWith` and `enrollWithAny`, plus
  `event.user.enrolledFactors` and `mfa` in `event.authentication.methods`,
  in post-login. `challengeWith`/`challengeWithAny` also run in
  `password-reset-post-challenge`.
- `amr: ["mfa"]` in ID tokens after a second factor; the deferred `gd_*`,
  `mfar` and MFA-grant failure log codes; `user.updated` events when
  `multifactor` changes; import of `mfa_factors`; storage, migration, plugin
  capability, console, seed and Deploy CLI.

Excluded:

- SMS, voice and phone delivery go to Plan 34. Their configuration is stored here.
- `push-notification` (needs Auth0's Guardian app) and `duo` (needs a vendor
  contract) are not planned (roadmap §5). They can be stored and enabled, but
  the server never offers them.
- **Passkeys as a first factor:** the database connection's
  `authentication_methods.passkey`, `passkey_options`, and passkey signup
  and login screens. The roadmap put them in Plan 33. This spec moves them
  to a follow-up, **Plan 33b — Passkeys**, because of size (roadmap §6). Plan
  33b reuses this plan's WebAuthn verifier and storage. Until then the
  options stay stored-only, as in D-0042. **This needs the maintainer's
  agreement**; see §9.
- `acr_values` and the `acr` claim go to Plan 41. The My Account API goes to
  Plan 42. Real risk signals for `confidence-score` go to Plan 40 (§5).

## 2. Evidence and compatibility rules

Public references to review in Task 1:

| Contract | Primary source |
| --- | --- |
| Guardian and user-method routes, bodies, scopes | [Management API OpenAPI](https://auth0.com/docs/oas/management/v2/management-api-oas.json) (`guardian`, `users/{id}/authentication-methods`, `enrollments`, `multifactor`, `recovery-code-regeneration`, `authenticators`) |
| Factors, policies, remember browser | [Multi-factor authentication](https://auth0.com/docs/secure/multi-factor-authentication), [Enable MFA](https://auth0.com/docs/secure/multi-factor-authentication/enable-mfa), [MFA factors](https://auth0.com/docs/secure/multi-factor-authentication/multi-factor-authentication-factors) (OTP, email, recovery codes, WebAuthn with security keys and with device biometrics) |
| Adaptive MFA | [Adaptive MFA](https://auth0.com/docs/secure/multi-factor-authentication/adaptive-mfa) |
| Authentication API MFA | [Authentication API: Multi-factor authentication](https://auth0.com/docs/api/authentication#multi-factor-authentication), [MFA API](https://auth0.com/docs/secure/multi-factor-authentication/manage-mfa-auth0-apis), [Resource owner password flow with MFA](https://auth0.com/docs/secure/multi-factor-authentication/authenticate-using-ropg-flow-with-mfa) |
| Actions | [post-login API object](https://auth0.com/docs/customize/actions/explore-triggers/signup-and-login-triggers/login-trigger/post-login-api-object) (`multifactor`, `authentication`), [Customize MFA selection](https://auth0.com/docs/secure/multi-factor-authentication/customize-mfa/customize-mfa-selection-universal-login), [event object](https://auth0.com/docs/customize/actions/explore-triggers/signup-and-login-triggers/login-trigger/post-login-event-object) |
| Enrollment tickets and email | [Enrollment emails](https://auth0.com/docs/secure/multi-factor-authentication/auth0-guardian/create-custom-enrollment-tickets), email templates `enrollment_email` and `mfa_oob_code` (Plan 21) |
| Universal Login prompts and screens | [Customize Universal Login text](https://auth0.com/docs/customize/login-pages/universal-login/customize-text-elements) (prompt and screen names) |
| Logs | [Log event type codes](https://auth0.com/docs/deploy-monitor/logs/log-event-type-codes), [logs schema](https://auth0.com/docs/oas/tenant-logs/logs-schema.json) |
| User import | [Bulk user import database schema](https://auth0.com/docs/manage-users/user-migration/bulk-user-imports/bulk-user-import-database-schema-and-examples) (`mfa_factors`) |
| WebAuthn and TOTP | W3C WebAuthn Level 2, RFC 6238, RFC 4226, RFC 8949 (CBOR), RFC 8152 (COSE) |

Task 1 freezes into `internal/mfarules/inventory.json` and decision
**D-0059**: every route's scopes, parameters, bodies, limits and errors;
the factor list with each factor's status (`enforced`, `stored`,
`not_planned`); the authentication method types and ID formats; the Actions
members and their argument schemas; the hosted prompt and screen names; and
the numbers below.

Points the documents leave open go to permitted firewalled observation on
the maintainer's dev tenant (CLEAN_ROOM.md). A separate observer session does
this and writes `docs/compat/observations/mfa.md`. Implementers must not
observe the same area. Observation points:

- **M1** Authentication method and enrollment ID formats, `GET
  /users/{id}/authentication-methods` for a user with OTP, email, WebAuthn and
  a recovery code, and the matching `GET /users/{id}/enrollments` and user
  `multifactor` values.
- **M2** What `PUT /guardian/factors/{name}` returns for `push-notification`,
  `duo` and `sms` on a tenant without providers. Whether policies accept
  `confidence-score` without an add-on.
- **M3** The enrolment ticket's lifetime, URL path, one-time use, and the
  result when the user is already enrolled.
- **M4** Lifetimes: `mfa_token`, the email challenge code, and the
  remember-browser period. Code lengths: email code and recovery code.
- **M5** Throttling: how many wrong OTP, email or recovery codes trigger
  `gd_otp_rate_limit_exceed` or `too_many_attempts`, and for how long.
- **M6** Authorize with `prompt=none` when MFA is required and not satisfied:
  the error code.
- **M7** Whether the email factor is offered when other factors exist, and
  whether verified email counts as an implicit enrollment.
- **M8** The `/mfa/associate` and `/mfa/challenge` responses for OTP and
  email, and the `mfa-recovery-code` grant's `recovery_code` in the response.
- **M9** When `user.updated` fires for MFA changes (catalog events): on
  enrolment, deletion and recovery-code regeneration.

**Maintainer ruling (2026-11-02):** observation is not needed for a good
1.0. The local rulings below ship, and each open point is listed as a gap in
D-0059 and in the follow-ups file
(`docs/superpowers/plan-1-followups.md`). Observation may happen later; it
changes behaviour only where Auth0 is shown to differ.

General rules hold. Every ID is tenant-scoped, and cross-tenant references
behave as missing. Keep Management API authentication, live operator grant
checks, strict body parsing and pagination conventions. Publish `x-source`
entries and regenerate the API, protobuf and console outputs. Use Go 1.26.7
and Node >=22.13, and keep dependency pins. **No new Go module:** CBOR and
COSE decoding for WebAuthn is a small in-tree package (§6). TOTP uses
`crypto/hmac`.

## 3. Factors, policies and the Management API

### Factors

`GET /guardian/factors` (`read:guardian_factors`) returns all eight names
in Auth0's order: `{name, enabled, trial_expired}`. `PUT
/guardian/factors/{name}` (`update:guardian_factors`) takes `{enabled}` and
returns `{enabled}`.

| Factor | Status in Plan 33 |
| --- | --- |
| `otp` | enforced: TOTP, RFC 6238, SHA-1, 6 digits, 30 s step, ±1 step accepted, a used step cannot be reused; works with any authenticator app |
| `email` | enforced: a 6-digit code sent with the `mfa_oob_code` template; requires a verified email |
| `recovery-code` | enforced: one active code per user, 24 uppercase alphanumerics, stored hashed, replaced on use |
| `webauthn-roaming` | enforced: security keys (cross-platform authenticators) |
| `webauthn-platform` | enforced: device biometrics (platform authenticators), offered only after the browser reports a user-verifying platform authenticator |
| `sms` | stored; Plan 34 |
| `push-notification`, `duo` | stored, not planned; never offered |

`recovery-code` cannot be someone's only factor. It is generated during the
user's first enrollment of another factor and shown once, as Auth0 does.
Enabling a stored-only factor follows M2. The local default is to accept and
store it. The console then shows "stored; not offered at login" next to it.

### Policies

`GET`/`PUT /guardian/policies` (`read:mfa_policies`/`update:mfa_policies`)
take and return an array: `["all-applications"]`, `["confidence-score"]`
or `[]`. Other values and more than one entry are 400.

### Stored configuration (Plan 34 and not planned)

These routes take and return Auth0's shapes and are validated against the
OpenAPI schemas. Provider secrets (Twilio `auth_token`, push credentials,
Duo keys) are sealed with the master key and never returned.

- `/guardian/factors/sms/templates`, `/guardian/factors/phone/templates`
- `/guardian/factors/sms/providers/twilio`, `/guardian/factors/phone/providers/twilio`
- `/guardian/factors/sms/selected-provider`, `/guardian/factors/phone/selected-provider`
- `/guardian/factors/phone/message-types`
- `/guardian/factors/push-notification/{providers/apns,providers/fcm,providers/fcmv1,providers/sns,selected-provider}`
- `/guardian/factors/duo/settings`

### Enrollments and tickets

- `GET`/`DELETE /guardian/enrollments/{id}` (`read:`/`delete:guardian_enrollments`)
  return and remove one confirmed authenticator. The response has Auth0's
  enrollment shape: `id`, `status`, `name`, `identifier`, `phone_number`,
  `enrolled_at` and `last_auth`.
- `POST /guardian/enrollments/ticket` (`create:guardian_enrollment_tickets`)
  takes `{user_id, email?, send_mail?, email_locale?, factor?,
  allow_multiple_enrollments?}` and returns `{ticket_id, ticket_url}`. The
  ticket URL opens a hosted enrolment page for that user without asking
  for a password. It is single use, lasts 7 days (local, pending M3) and is
  stored hashed. `send_mail` sends the `enrollment_email` template.
  `factor` limits the page to one factor.

### User authentication methods

| Route | Scope |
| --- | --- |
| `GET /users/{id}/authentication-methods?page&per_page&include_totals` | `read:authentication_methods` |
| `POST /users/{id}/authentication-methods` | `create:authentication_methods` |
| `PUT /users/{id}/authentication-methods` (replace all) | `update:authentication_methods` |
| `DELETE /users/{id}/authentication-methods` | `delete:authentication_methods` |
| `GET`/`PATCH`/`DELETE /users/{id}/authentication-methods/{authentication_method_id}` | read/update/delete |
| `GET /users/{id}/enrollments` | `read:users` |
| `DELETE /users/{id}/authenticators` | `delete:guardian_enrollments` |
| `DELETE /users/{id}/multifactor/{provider}` (`duo`, `google-authenticator`) | `update:users` |
| `POST /users/{id}/recovery-code-regeneration` | `update:users` |
| `POST /users/{id}/multifactor/actions/invalidate-remember-browser` | `update:users` |

An authentication method has Auth0's shape: `id`, `type`, `confirmed`,
`name`, `created_at`, `last_auth_at`, `preferred_authentication_method`,
`authentication_methods`, plus `email` (email), `key_id`,
`public_key` and `relying_party_identifier` (WebAuthn). `POST` accepts the
documented creatable types for this plan: `totp` with `totp_secret`, `email`
with `email`, and `webauthn-roaming` with `key_id`, `public_key` and
`relying_party_identifier`. `phone` is stored for Plan 34 and never used
for a challenge. Methods created through the API are `confirmed`. A
`totp_secret` is write-only. IDs follow M1; the local default is
`<type>|dev_<20 alphanumerics>` (for example `totp|dev_…`), with
enrollment IDs `dev_<20 alphanumerics>`.

The user object gains `multifactor`. It is derived from confirmed methods
(local default pending M1: `["guardian"]` when any method other than
recovery-code exists). `GET /users` search does not index it. Deleting a
user, or the tenant, deletes their methods, tickets and remember-browser
records. Linking accounts keeps the primary user's methods, as Auth0 does.

### Import

Plan 18 accepted `mfa_factors` and ignored them. Now the import job creates
confirmed `totp` (`secret`, base32) and `email` (`value`) methods, and stores
`phone` for Plan 34. Invalid factors fail that user's row with Auth0's
import error shape. Exports never contain authentication methods.

## 4. When MFA is required

A single function, `mfa.Decide`, answers "must this login do MFA, and which
factors?" for the hosted flow and for the Authentication API. Its inputs
are the tenant's policy, the post-login Action effects, the session's MFA
state, the remember-browser cookie and the user's methods.

1. If an Action called `api.multifactor.enable("none")`, MFA is skipped
   for this login, whatever the policy.
2. If an Action called `api.multifactor.enable(provider, {allowRememberBrowser})`,
   or `api.authentication.challengeWith*`/`enrollWith*`, MFA is required.
3. Otherwise `all-applications` requires MFA on every login and every SSO
   authorization. `[]` never requires it.
4. `confidence-score` has no Auth0 risk engine here. **Local ruling:**
   confidence is low on a browser that has not completed a login for this
   user in the last 30 days (a per-user device cookie, hashed in storage).
   Otherwise it is high. Low confidence challenges users who already have a
   confirmed factor and never forces enrollment. Plan 40 replaces this with
   real risk signals.
5. MFA already done counts as satisfied. That is the session's `mfa` method
   from the same session, or a valid remember-browser cookie when remember
   browser is allowed. Exceptions: `challengeWith*` and `enrollWith*` always
   prompt, as Auth0 documents. Remember browser is allowed by default under
   a policy and when an Action passes `allowRememberBrowser: true`. It lasts
   30 days (local, pending M4). Invalidating it changes a per-user epoch, so
   existing cookies stop counting.
6. A user with no confirmed enforced factor is sent to enrollment. Ticket
   enrolment works the same way. If no enforced factor is enabled while MFA
   is required, the login fails with `access_denied` and the description
   "MFA is required but no factor is enabled" (local; Auth0 blocks
   enabling the policy without a factor in the dashboard only). This is
   never a silent bypass.

`mfa.Decide` runs after post-login Actions, before tokens or codes are
issued. MFA never applies to `client_credentials` or `refresh_token`. It
applies to `authorization_code` through the hosted flow, `password` and
`password-realm` (as `mfa_required`) and device flow (hosted). With
`prompt=none`, an unsatisfied requirement returns `interaction_required`
(local, pending M6). It never returns tokens.

## 5. Hosted login

### Prompts

New pages under `/u/` follow Auth0's prompt and screen names, so Plan 22's
custom text and partials apply to them:

| Prompt | Screens |
| --- | --- |
| `mfa` | `mfa-detect-browser-capabilities`, `mfa-begin-enroll-options`, `mfa-enroll-result`, `mfa-login-options` |
| `mfa-otp` | `mfa-otp-enrollment-qr`, `mfa-otp-enrollment-code`, `mfa-otp-challenge` |
| `mfa-email` | `mfa-email-challenge`, `mfa-email-list` |
| `mfa-recovery-code` | `mfa-recovery-code-enrollment`, `mfa-recovery-code-challenge` |
| `mfa-webauthn` | `mfa-webauthn-roaming-enrollment`, `mfa-webauthn-platform-enrollment`, `mfa-webauthn-roaming-challenge`, `mfa-webauthn-platform-challenge`, `mfa-webauthn-error`, `mfa-webauthn-not-available-error` |

Behaviour:

- **Enrolment:** list enabled enforced factors, or skip the list when
  `mfa_show_factor_list_on_enrollment` is false and one factor fits, or
  when an Action named it. OTP shows a QR code (the `otpauth://` URI rendered
  as an in-tree SVG with no new dependency) and the base32 secret. After the
  first factor the recovery code is shown once and must be acknowledged.
- **Challenge:** the user's preferred method first, with "try another
  method" to the others and to the recovery code. Email sends the code when
  the screen opens and allows a resend after 30 s.
- **Remember browser:** a checkbox, shown when allowed, sets an HttpOnly,
  Secure, SameSite=Lax cookie scoped to the hosted login host.
- **Session:** success records `mfa` with its time on the login session.
  `amr` then includes `mfa` in ID tokens issued through that session.
- The tenant's `guardian_mfa_page` custom page stays stored-only, as in
  Plan 22. Universal Login always renders.

All new strings go through the i18n catalogs. Pages carry CSRF protection
and reuse the transaction state of the login flow. An MFA page reached
without a pending requirement redirects to `/authorize/resume` with
`invalid_request`.

### Throttling

Wrong codes (OTP, email, recovery) count per user and factor in Plan 19's
store-backed throttle. **Local ruling (pending M5):** after 10 failures in
15 minutes, further attempts fail with `too_many_attempts` and log
`gd_otp_rate_limit_exceed`. The count resets on success. Email sends are
limited to 5 per user per 15 minutes. Each email code lives 5 minutes
(local, pending M4) and allows at most 5 attempts.

## 6. WebAuthn

`internal/webauthn` verifies registrations and assertions. It contains:

- A bounded CBOR decoder (RFC 8949 subset: maps, arrays, byte and text
  strings, integers, simple values; depth ≤ 16, input ≤ 64 KiB, no
  indefinite lengths, no tags), fuzzed.
- COSE keys: EC2 P-256 (`-7`, ES256), RSA (`-257`, RS256) and OKP Ed25519
  (`-8`, EdDSA), parsed into `crypto` keys.
- Registration: the client data type, challenge and origin are checked. The
  RP ID hash matches. The UP flag is set, and the UV flag too for
  `webauthn-platform`. Attestation conveyance is `none`. A `packed` or other
  format statement is accepted but not verified, and recorded as `none`
  (local ruling; Auth0 documents no attestation policy). Credential IDs are
  unique per tenant.
- Assertion: signature over `authenticatorData || SHA-256(clientDataJSON)`,
  with the same checks. The sign count must increase when either side is
  non-zero. Otherwise the assertion is rejected and `gd_webauthn_challenge_failed`
  is logged with reason `sign_count`.
- Challenges are 32 random bytes, bound to the transaction, single use, and
  expire after 5 minutes.

**RP ID:** the host serving the hosted page, either the canonical domain or
a verified custom domain (Plan 23 stored the custom-domain behaviour but did
not enforce it). Each credential stores its RP ID. Challenges list only
credentials whose RP ID matches the current host. A user who has only
credentials for another host sees the other methods and recovery, as a
browser would.

## 7. Authentication API

- **`mfa_required`:** the `password` and `password-realm` grants answer
  403 `{"error":"mfa_required","error_description":"Multifactor
  authentication required","mfa_token":"…"}` when `mfa.Decide` requires
  MFA. The `mfa_token` is opaque, 10 minutes (pending M4), stored hashed,
  and bound to tenant, client, user, connection, audience, scope and the
  Action effects. It is consumed by the first successful MFA grant.
- **`POST /mfa/associate`** (bearer `mfa_token`, or an MFA API token with
  `enroll`) takes `authenticator_types: ["otp"]` (returns `secret`,
  `barcode_uri`, `recovery_codes` on first enrollment) or `["oob"]` with
  `oob_channels: ["email"]` and `email` (returns `oob_code`,
  `binding_method: "prompt"`). `sms`, `voice` and `auth0` channels return
  Auth0's unsupported-channel error until Plan 34 (`auth0` push: not planned).
- **`POST /mfa/challenge`** takes `mfa_token`, `client_id`, client
  authentication, `challenge_type` (`"otp"`, `"oob"`, `"otp oob"`) and
  `authenticator_id`. It returns `{challenge_type:"otp"}`, or
  `{challenge_type:"oob", oob_code, binding_method:"prompt"}` and sends the
  email.
- **`GET /mfa/authenticators`** and **`DELETE /mfa/authenticators/{id}`**
  accept an `mfa_token` (read only) or an access token for the MFA API with
  `read:authenticators` or `remove:authenticators`.
- **Grants** (each must be in the client's `grant_types`):
  `http://auth0.com/oauth/grant-type/mfa-otp` (`mfa_token`, `otp`),
  `…/mfa-oob` (`mfa_token`, `oob_code`, `binding_code`) and
  `…/mfa-recovery-code` (`mfa_token`, `recovery_code`). The recovery-code
  grant returns the new `recovery_code` next to the tokens. Wrong codes are
  `invalid_grant` and count toward §5 throttling. Failures log `fertft`,
  `feotpft`, `feoobft` and `fercft` as the frozen log inventory defines.
- **MFA API audience:** `https://{host}/mfa/`, where host is the canonical
  or a verified custom domain. It is a built-in API that is not listed in
  `/api/v2/resource-servers`. Its scopes are `enroll`,
  `read:authenticators` and `remove:authenticators`. User grants may request
  it. `client_credentials` for it is `access_denied`.
- The `/oauth/token` discovery metadata lists the three grants under
  `grant_types_supported` only if Auth0's discovery document does
  (Task 1 checks).

## 8. Actions, logs, events

**Actions.** These move from `unsupported` to `supported` in
`internal/actionsrules/inventory.json`:

- `api.multifactor.enable(provider, options?)`. Providers are `any` (all
  enabled enforced factors), `google-authenticator` (`otp`), `guardian`
  (enabled enforced factors except email; push is not planned), `none`
  (skip) and `duo` (fails the login with Auth0's error for an unconfigured
  provider, because Duo is not planned). `allowRememberBrowser` defaults to
  false.
- `api.authentication.challengeWith(factor, {additionalFactors?})`,
  `challengeWithAny(factors)`, `enrollWith(factor, {additionalFactors?})`
  and `enrollWithAny(factors)`. Factor objects are `{type}` with
  `otp`, `email`, `recovery-code`, `webauthn-roaming`,
  `webauthn-platform`, and `phone`/`push-notification` (which fail the login
  as unavailable). These members require tenant
  `customize_mfa_in_postlogin_action: true` (stored since Plan 19). Without
  it they fail with Auth0's message. They cannot be mixed with
  `multifactor.enable` in the same execution.
- `event.user.enrolledFactors` (`[{type, options?}]`) and `mfa` entries in
  `event.authentication.methods` after MFA. Because MFA runs after the
  Action, the `mfa` entry appears on later logins in the same session and
  after `api.redirect` continuations, as Auth0 documents.
- `password-reset-post-challenge` gains `challengeWith` and `challengeWithAny`.
  The reset completes only after the challenge.

**Logs.** These codes move from deferred to emitted in the frozen log
inventory: `gd_start_auth`, `gd_auth_succeed`, `gd_auth_failed`,
`gd_auth_rejected` (WebAuthn cancel), `gd_start_enroll`,
`gd_start_enroll_failed`, `gd_enrollment_complete`, `gd_unenroll`,
`gd_update_device_account`, `gd_recovery_succeed`, `gd_recovery_failed`,
`gd_send_email`, `gd_send_email_verification`, `gd_auth_email_verification`,
`gd_otp_rate_limit_exceed`, `gd_tenant_update`, `gd_email_settings_update`,
`gd_webauthn_challenge_failed`, `gd_webauthn_enrollment_failed`, `mfar`,
and the grant failures listed in §7. `gd_send_sms*`, `gd_send_voice*` and
`gd_phone_settings_update` are re-deferred to Plan 34.
`gd_send_pn*` are not planned. Secrets never enter a log line. Plan 31's
key-name scrubber gains `otp`, `totp_secret`, `secret`, `recovery_code`,
`binding_code`, `oob_code`, `mfa_token` and `ticket` values (the maintainer
rule: secrets never in logs).

**Events.** The Plan 32 decorator emits `user.updated` when a user's
derived `multifactor` value changes (pending M9). It does not fire for
`last_auth_at` or sign-count updates.

## 9. Storage, console, provisioning, decisions

**Storage.** Migration `0033_mfa.sql` (SQLite, PostgreSQL, MySQL) adds:

| Table | Holds |
| --- | --- |
| `guardian_settings` | per tenant: factor flags, policies, stored provider/template JSON, sealed provider secrets, version |
| `mfa_authenticators` | tenant, user, id, type, name, confirmed, preferred, sealed TOTP secret, last TOTP step, hashed recovery code, email, phone, WebAuthn credential ID, public key (COSE), RP ID, sign count, created/last-auth times |
| `mfa_tokens` | hashed token, tenant, client, user, bound request JSON, expiry, consumed |
| `mfa_challenges` | id, tenant, user, authenticator, kind (email code, WebAuthn challenge, OOB), hashed code, attempts, expiry, consumed |
| `mfa_enrollment_tickets` | hashed ticket, tenant, user, factor, allow-multiple, expiry, consumed |
| `mfa_browsers` | hashed cookie, tenant, user, kind (`remember`, `device`), epoch, expiry |

The table also adds `remember_browser_epoch` to users and `mfa_at` to login
sessions. Codes, recovery codes, tokens, tickets and cookies are stored as
`secrets.HashToken` values. TOTP secrets and provider secrets are sealed
with the master key. Single use and replay protection come from
conditional updates (`consumed = false`, `last_step < step`, `sign_count < n`).
The memory store matches. A separately negotiated **MFA v1** gRPC capability
carries the repository. Without it, MFA routes return 501
`mfa_unavailable`, the policy reads as `[]`, and older plugins keep working.

**Console.** A **Multi-factor auth** page under Security: factor toggles
(stored-only and not-planned factors labelled), policy (Never, Always,
Adaptive with the local-ruling note), "Show factor list on enrollment" and
"Customize MFA in post-login Actions". The SMS/phone/push settings forms
say "stored for Plan 34" or "not available". The user detail page gets an
**MFA** tab: methods with type, name, enrolled and last used; delete one or
all; regenerate the recovery code (shown once); invalidate remember-browser;
send an enrollment invitation. The Actions editor's type hints include the
new members. Requests capture the tenant and drop stale replies. All
strings go through the catalog.

**Seed and Deploy CLI.** Seed may declare `guardian.factors` and
`guardian.policies`. The pinned Deploy CLI handlers that this plan's routes
can serve move from `excluded` to `included` in
`tests/e2e/deploy-cli/manifest.json` and round trip. Task 1 maps each of the
nine guardian handlers to routes. Handlers that need Plan 34 delivery keep
their owner as Plan 34. Authentication methods are never exported.

**Decisions (local rulings, D-0059):**

1. Push and Duo are stored, enable-able and never offered. SMS and phone are
   stored for Plan 34, which adds native non-Twilio SMS providers as a
   marked extension (maintainer ruling 2026-11-02, §1). MFA and reset email
   uses any configured Plan 21 email provider.
2. `confidence-score` uses a 30-day new-device signal until Plan 40.
3. Lifetimes: `mfa_token` 10 min; email code 5 min with 5 attempts; WebAuthn
   challenge 5 min; enrollment ticket 7 days; remember browser 30 days.
4. Throttle: 10 wrong codes per user and factor per 15 min; 5 emails per 15 min.
5. Recovery code: 24 uppercase alphanumerics, one active, replaced on use.
6. WebAuthn attestation `none`; ES256, RS256, EdDSA; RP ID = serving host.
7. Required MFA with no enabled enforced factor fails closed (`access_denied`).
8. `prompt=none` with unsatisfied MFA returns `interaction_required`.
9. ID formats `<type>|dev_<20>` and `dev_<20>`; `multifactor: ["guardian"]`.
10. Passkeys as a first factor are split out to Plan 33b (**maintainer
    confirmation required**; if declined, Plan 33 gains a passkey task
    group before acceptance and the WebAuthn verifier is already shared).

## 10. Acceptance and completion

- **Journey first.** On the production SQLite fixture an operator enables
  OTP and sets `all-applications`. A browser signup enrols TOTP through the
  QR page, using a TOTP generator in the test, and saves the recovery code.
  It logs out and logs in, and is challenged. It ticks remember browser and
  is not challenged on the next login. The operator invalidates remember
  browser and the next login challenges again. The ID token has `amr:
  ["mfa"]`.
- WebAuthn roaming and platform enrolment and challenge pass with
  Playwright's virtual authenticator (CDP). A custom-domain credential is not
  offered on the canonical domain. A cloned authenticator (lower sign count)
  is rejected.
- Email factor: the code arrives at the test mailbox and validates. A wrong
  code ×10 triggers throttling and `gd_otp_rate_limit_exceed`. The
  recovery code logs in once, a new one is shown, and the old one fails.
- An SSO session from an app without MFA (policy `[]`) gets challenged at a
  second app after the policy changes to `all-applications`. `prompt=none`
  returns `interaction_required`.
- Actions: `api.multifactor.enable("any")` with policy `[]` challenges,
  `enable("none")` with `all-applications` skips, and `challengeWith({type:"otp"})`
  prompts even with remember browser. `enrolledFactors` is correct.
- Authentication API with pinned `@auth0/auth0-auth-js` 1.16.1 and raw
  HTTP: password grant → `mfa_required` → associate OTP → `mfa-otp` grant
  succeeds. `mfa-oob` with email and `mfa-recovery-code` succeed. Reusing an
  `mfa_token`, using it from another client, or using it after expiry is
  `invalid_grant`.
- node-auth0 `guardian.*` and `users.*AuthenticationMethods`/enrollments/
  recovery regeneration, auth0-cli (raw `auth0 api` where no command exists)
  and the Deploy CLI guardian round trip agree with stored state on memory,
  SQLite, PostgreSQL and MySQL.
- Logs carry the §8 codes with no secret values. A representative-secret
  scan of all sinks finds no TOTP secret, code, recovery code, `mfa_token` or
  ticket. `user.updated` fires on enrolment.
- MFA v1 capability matrix: an old plugin keeps working with MFA unavailable.
- OIDF local conformance (Basic, Config, Form Post) still passes with MFA
  off, the default.
- Run the focused tests, the full Go race suite, all three SQL drivers, the
  console tests and the affected E2E lanes, following AGENTS.md for long
  suites. Report every actual result and every check not run.

Writing this spec and its plan does not mean anything is implemented or
passing.
