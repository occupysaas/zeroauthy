# Multi-factor authentication

Plan 33 supports authenticator apps, verified-email codes and recovery codes.
Configure a tenant in **Security → Multi-factor auth**, through the Guardian
Management API, or with seed configuration. Start by enabling `otp`, `email`
and `recovery-code`, then choose a policy. Enabling a factor alone does not
require users to enroll.

| Factor | Current behavior |
| --- | --- |
| `otp` | Enforced. Standard RFC 6238 TOTP works with any authenticator app. |
| `email` | Enforced. Sends a six-digit code to the user's verified email. |
| `recovery-code` | Enforced fallback after another factor is enrolled. |
| `sms` / phone configuration | SMS and voice enrollment/challenges through the configured phone route. |
| `webauthn-roaming`, `webauthn-platform` | Stored for Plan 33b, after 1.0. No WebAuthn challenge or passkey login. |
| `push-notification`, `duo` | Configuration is stored; delivery is not planned and these factors are never offered. |

The factor API lists eight names; `phone` is a method/configuration type,
not a ninth toggle. Turning on a stored factor does not make it usable. A
required login with no enabled usable factor fails with `access_denied`.
Recovery codes cannot be a user's only initial factor.

## Configure policies and seed

Guardian policies are exactly one of these JSON arrays:

| Value | Effect |
| --- | --- |
| `[]` | Never require MFA by tenant policy. Actions can still require it. |
| `["all-applications"]` | Require MFA for user login and SSO authorization, unless the session or an allowed remembered browser already satisfies it. |
| `["confidence-score"]` | Challenge an already enrolled user on a new device. Never force enrollment from this policy alone. |

**Adaptive is a local rule, not an Auth0 risk score.** A per-user browser
device signal counts as known for 30 days after a completed login. A browser
outside that window has low confidence. Plan 40 will add risk signals.

A minimal seed configuration is:

```yaml
tenants:
  - name: example
    guardian:
      factors:
        otp: true
        email: true
        recovery-code: true
      policies: [all-applications]
```

Only known factor names and boolean values are accepted. Policies accept
only `[]`, `[all-applications]`, or `[confidence-score]`. Omitted Guardian
configuration, omitted policy fields and omitted factor flags preserve
existing values. `policies: []` explicitly clears enforcement; `otp: false`
explicitly disables OTP. An empty factors map does not clear other flags.
Null is invalid. Applying the same configuration does not advance its
Guardian version. All changes join the seed transaction; a later failure
rolls them back. In `create_only` mode, an existing tenant's MFA settings
are preserved. Existing API-owned tenants retain the normal seed ownership
protection.

For the equivalent API setup, use `PUT /api/v2/guardian/factors/otp` with
`{"enabled":true}`, enable email/recovery similarly, then `PUT
/api/v2/guardian/policies` with `["all-applications"]`. Reading/writing flags
requires `read:guardian_factors` / `update:guardian_factors`; policies require
`read:mfa_policies` / `update:mfa_policies`. Configure the tenant's email
provider before enabling email as the available factor.

## Hosted login and recovery

After primary authentication and post-login Actions, hosted login either
continues, prompts for an enrolled factor, or starts enrollment. No OAuth
code or tokens are issued until the required proof succeeds. The device
authorization flow uses the same hosted check. Unsatisfied `prompt=none`
returns `interaction_required`.

For OTP enrollment, scan the QR code with any authenticator app or enter the
base32 secret manually. The QR contains a standard `otpauth://totp` URI,
without vendor parameters. Enter a code to confirm enrollment. OTP uses
SHA-1, six digits, 30-second steps, and accepts the adjacent step on either
side for clock drift. A step already used for that method cannot be used
again. Keep the server and authenticator clocks synchronized.

Email requires an existing verified email address. The code screen sends
the first message and permits a resend after 30 seconds. The existing
verified address is eligible for enrollment; it is not automatically an
already confirmed MFA method.

First enrollment displays one recovery code once. Store it securely before
acknowledging the screen. A recovery code contains 24 uppercase letters and
digits. Only one is active per user; using it consumes it and displays its
replacement once. The server stores hashes, so an operator cannot retrieve
an existing code. The user's MFA tab can regenerate it, delete methods,
invalidate remembered browsers, or send an enrollment invitation.

The `flags.mfa_show_factor_list_on_enrollment` tenant setting controls the
enrollment choice screen. The `mfa`, `mfa-otp`, `mfa-email`, and
`mfa-recovery-code` prompts use the custom-text/partial system. The legacy
`guardian_mfa_page` remains stored configuration; the hosted flow renders
its own pages.

Enrollment invitations use a single-use ticket that lasts seven days. A
standalone ticket enrolls a factor and renders a result; it does not sign
the recipient into SSO or issue OAuth credentials. Password-reset Actions
may also require a proof; completing a reset challenge does not create SSO.

## Remember a browser

When allowed, the hosted checkbox sets a Secure, HttpOnly, SameSite=Lax
cookie scoped to the login host. The server stores only its hash and binds
it to the tenant, user, expiry and user's remember-browser epoch. It lasts
30 days. The user MFA tab's invalidation action changes that epoch, making
old cookies ineffective. Deleting/replacing enrolled factors also
invalidates the relevant remembered state.

Policy-driven MFA allows remember browser by default. An Action using
`multifactor.enable` must pass `allowRememberBrowser: true` to allow it;
the Action default is false. `challengeWith*` and `enrollWith*` always
prompt even if the session or cookie previously satisfied MFA. The
30-day confidence-score device signal and the remember-browser proof are
separate records with separate purposes.

## Authentication API clients

For password/password-realm clients, add the MFA grants your application
uses to its allowed `grant_types`:

- `http://auth0.com/oauth/grant-type/mfa-otp`
- `http://auth0.com/oauth/grant-type/mfa-oob`
- `http://auth0.com/oauth/grant-type/mfa-recovery-code`

The client flow is:

1. Submit the normal password grant to `/oauth/token`. A required proof
   returns HTTP 403 with `error: "mfa_required"` and an opaque `mfa_token`.
   Keep that token in transient client state and never log it.
2. Read `/mfa/authenticators` with bearer `mfa_token` to choose a method.
   To enroll OTP, call `/mfa/associate` with
   `{"authenticator_types":["otp"]}`. It returns the one-time `secret`,
   `barcode_uri`, and first-enrollment `recovery_codes`. To enroll email,
   use `authenticator_types: ["oob"]`, `oob_channels: ["email"]` and the
   verified `email`; retain the returned `oob_code` and prompt for the email
   code. The bearer token binds enrollment to its pending transaction.
3. For an existing method, call `/mfa/challenge` with `mfa_token`,
   `client_id`, `authenticator_id` and `challenge_type` (`otp`, `oob`, or
   `otp oob`), using the client's normal authentication. OTP returns its
   challenge type; email also returns `oob_code` and
   `binding_method: "prompt"`.
4. Submit the corresponding MFA grant to `/oauth/token` with the same
   `mfa_token` and client authentication. OTP uses `otp`; email uses
   `oob_code` and `binding_code`; recovery uses `recovery_code`. A successful
   proof consumes the token, issues the originally bound grant, and retains
   its audience, scope and Action effects. Wrong proofs do not consume the
   token, but do consume attempt budgets.

A successful recovery grant returns a new one-time `recovery_code` alongside
the tokens. Successful **first email enrollment** also returns
`recovery_code` when that enrollment creates it: this is an explicit local
response extension so the new recovery code can actually be saved. It is
never displayed again by reading the method or replaying the grant.

An access token for the built-in audience `https://<login-host>/mfa/` can
manage methods using `enroll`, `read:authenticators`, and
`remove:authenticators`. The host must be canonical or verified. This API
is not a stored resource server and is not listed in the API catalog.
An `mfa_token` grants read access to authenticators but cannot delete them;
method deletion requires the appropriate MFA API token. MFA never applies
to `client_credentials` or `refresh_token`, and client credentials cannot
obtain an MFA API audience token. SMS, voice and push OOB enrollment are
unavailable in this milestone.

The three MFA grants are implemented but are **not advertised in OIDC
`grant_types_supported`**. Upstream discovery evidence remains unresolved;
do not interpret the omission as a runtime grant prohibition.

## Actions

Post-login Actions can call:

```js
exports.onExecutePostLogin = async (event, api) => {
  api.multifactor.enable('any', { allowRememberBrowser: true });
};
```

`any` considers enabled enforced factors; `google-authenticator` selects
OTP; `guardian` considers enabled enforced factors except email; `none`
skips MFA for that login, including a tenant policy requirement. `duo`
fails because Duo is unavailable.

For explicit factor selection, enable the tenant's
`customize_mfa_in_postlogin_action` setting and use
`api.authentication.challengeWith({type:'otp'})`, `challengeWithAny`,
`enrollWith`, or `enrollWithAny`. Challenges require an enabled, already
enrolled eligible factor and do not enroll one automatically. Enrollment
requires an enabled factor not already enrolled; recovery code cannot be
a first enrollment target. Unsupported WebAuthn and push selections
fail the login. Do not mix these calls with `multifactor.enable` in one
execution.

`event.user.enrolledFactors` is available in post-login. The post-login
`event.authentication.methods` includes prior session MFA; the first proof
runs after the initial Action, so that Action does not yet see its result.
`password-reset-post-challenge` supports `challengeWith` and
`challengeWithAny`, with completion gating the password change. That
trigger does not expose `event.user.enrolledFactors`.

## Email providers, lifetimes and throttles

MFA, enrollment invitations and reset email use the tenant's configured
Plan 21 provider: any of the nine native providers or `custom`. Set that
provider and the `mfa_oob_code` / `enrollment_email` templates through the
existing email administration flow. Custom email delivery follows the
existing sealed Action job queue. No provider is hard-coded for MFA.
SMS/phone providers remain route-keyed configuration with individually
sealed credentials. Native Twilio, the consolidated SNS extension and Action
providers are described in [phone providers](phone-providers.md).

| Limit | Local runtime value |
| --- | --- |
| `mfa_token` | 10 minutes; first successful grant consumes it |
| Email code | Six digits, five minutes, at most five proof attempts |
| Enrollment ticket | Seven days, single use |
| Remember browser | 30 days |
| Confidence-score device signal | 30 days |
| Incorrect codes | 10 per user and factor per 15 minutes |
| MFA email sends | Five per user per 15 minutes |
| Email resend delay | 30 seconds |

Exceeding the wrong-code throttle returns `too_many_attempts` and records
`gd_otp_rate_limit_exceed`. The per-challenge email attempt budget is
independent of that shared per-user/factor budget. Recovery codes and OTP
steps are single use even when requests race or use different server
processes. Provider secrets and TOTP seeds are sealed under the master key;
proofs, tokens, tickets, browser cookies and recovery codes are hashed.

Guardian phone OTP length and expiration settings control phone challenges.
Guardian email OTP and session/remember settings retain their Plan 33 runtime
boundaries: storing them does not change email proof format, cookie lifetime
or policy/Action remember eligibility.

## Deploy CLI and troubleshooting

The pinned Deploy CLI 9.1.0 round-trips eight Guardian configuration
handlers: `guardianFactors`, `guardianFactorTemplates`, `guardianPolicies`,
`guardianPhoneFactorSelectedProvider`, `guardianPhoneFactorMessageTypes`,
`guardianPhoneFactorSettings`, `guardianEmailFactorSettings`, and
`guardianSettings`. All four YAML/directory and generated/preserved-ID cells
pass with exact public fields and repeat import.

**`guardianFactorProviders` cannot be exported by the Deploy CLI itself.**
Its exporter (unchanged in 9.1.0 and 9.2.0) reads `provider.data`, but its
node-auth0 7.x SDK returns the provider body directly, so the export is an
empty list against any server, Auth0 included. The server's documented
provider GET/PUT work and are tested directly. Back up provider settings with
the Management API instead. The handler is marked `tool-unsupported`, and the
E2E lane fails once an upgraded CLI stops reading `provider.data`, so it can
be re-included (D-0059).

Use the user's MFA tab and tenant logs to investigate a failed login.
`gd_start_auth`, `gd_auth_succeed`, `gd_auth_failed`, `gd_start_enroll`,
`gd_start_enroll_failed`, `gd_enrollment_complete`, `gd_unenroll`,
`gd_update_device_account`, `gd_recovery_succeed`, `gd_recovery_failed`,
`gd_send_email`, `gd_send_email_verification`, `gd_auth_email_verification`,
`gd_otp_rate_limit_exceed`, `gd_tenant_update`, `gd_email_settings_update`
and `mfar` cover MFA activity and administration. Grant failures use
`fertft`, `feotpft`, `feoobft`, and `fercft`. WebAuthn rejection logs remain
Plan 33b; SMS/voice logs remain Plan 34; push delivery logs are not planned.
Codes, credentials, recovery codes and tokens must never appear in logs.

With an older gRPC plugin lacking the separately negotiated MFA v1
capability, MFA routes return 501 `mfa_unavailable`, policy reads return
`[]`, and unrelated plugin operations continue to work. Upgrade the plugin
before provisioning or enforcing MFA.

## Compatibility and provenance

These are zeroauthy's local defaults. [D-0059](compat/decisions.md#d-0059--mfa-contracts-and-local-rulings)
records the unobserved M1–M9 gaps and known differences: 30-day device
confidence, fixed lifetimes/throttles, stored unsupported factor flags,
24-character replacement recovery codes, fail-closed handling,
`prompt=none`, local method IDs (`<type>|dev_` plus 20 alphanumerics), and
derived `multifactor: ["guardian"]`. Public examples use shorter IDs and
public ROPG documentation describes a different replenishing attempt
budget. None of these local rules is claimed as an observed upstream
result. First-email-enrollment `recovery_code` is the local response
extension described above. Discovery advertisement remains unresolved.
WebAuthn and passkeys await Plan 33b after 1.0.

The contract is based on the [public Management API description](https://auth0.com/docs/oas/management/v2/management-api-oas.json),
[Authentication API reference](https://auth0.com/docs/api/authentication),
[ROPG MFA documentation](https://auth0.com/docs/secure/multi-factor-authentication/authenticate-using-ropg-flow-with-mfa),
[post-login Action API](https://auth0.com/docs/customize/actions/explore-triggers/signup-and-login-triggers/login-trigger/post-login-api-object),
and [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238).
See the [design](superpowers/specs/2026-11-02-zeroauthy-mfa-design.md) and
`internal/mfarules` for the frozen route, factor and log inventories.

## SMS and voice delivery

Guardian `sms` enables phone enrollment and challenges with the `phone`
authenticator type. Enrollment verifies ownership using an out-of-band code;
voice reads the code aloud. The phone provider, permitted message types and
OTP settings must allow the requested method. A post-login Action can request
`challengeWith({type: "phone", options: {preferredMethod: "sms"}})` (or
`voice`). Missing providers and unsupported delivery methods fail closed.
A new code replaces the previous code and bounded verification attempts are
atomic. Recovery codes and remembered sessions follow the existing MFA rules.

[Phone providers](phone-providers.md) explains consolidated-provider priority,
Guardian Twilio/phone-message-hook selection and tested custom Action
examples. Management enrollment reads follow the tenant's obfuscation flag;
logs always mask phone numbers.
