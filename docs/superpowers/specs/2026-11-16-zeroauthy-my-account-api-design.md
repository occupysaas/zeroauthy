# Plan 42a — My Account API (authentication methods and factors)

**Date:** 2026-11-16. **Status:** implemented 2026-11-25 on `plan-42a-my-account` ([record](../2026-11-16-plan-42a-implementation-record.md)); plan-branch CI and maintainer approval pending.

**Roadmap entry:** [management roadmap, Plan 42](2026-10-19-zeroauthy-management-roadmap-design.md)
(full; split by the [parallel paths](2026-11-13-zeroauthy-parallel-paths-design.md)
into **U1** = this, U2 = My Organization API). Depends on Plans 30, 33 and
33b (merged). Read the [clean-room policy](../../../CLEAN_ROOM.md),
`AGENTS.md`, the [MFA guide](../../mfa.md), the [passkeys guide](../../passkeys.md),
D-0059 and D-0062, and `internal/access` (subject-type authorization).

## 1. Outcome and scope

A signed-in user's application calls `https://<tenant host>/me/v1/...` with
an access token for the audience `https://<tenant host>/me/` and manages the
user's own authentication methods: list them, enroll a passkey, a
WebAuthn security key or platform authenticator, TOTP, email, phone or
recovery code, verify the enrollment, rename it, change the phone delivery
preference, change the password, and delete methods. `GET /me/v1/factors`
lists what the tenant allows. Operators activate the API per tenant and
control which applications may use it with user-subject client grants.

**Rule:** strict 1:1 with Auth0's documented behaviour (memory: Auth0 parity
first), from Auth0's machine-readable My Account OpenAPI
(`https://auth0.com/docs/oas/myaccount/myaccount-api-oas.json`, version
1.0, read 2026-11-16) and the My Account guide. Local rulings **LR42a-n** and
observation points **Y1–Yn** go in **D-0210** (U1 block D-0210–0219).

### In scope (GA operations in the OpenAPI)

| Operation | Scope |
|---|---|
| `GET /me/v1/authentication-methods` | `read:me:authentication_methods` |
| `POST /me/v1/authentication-methods` (start enrollment, `202`) | `create:me:authentication_methods` |
| `GET /me/v1/authentication-methods/{id}` | `read:me:authentication_methods` |
| `PATCH /me/v1/authentication-methods/{id}` (`name`, `preferred_authentication_method`) | `update:me:authentication_methods` |
| `DELETE /me/v1/authentication-methods/{id}` | `delete:me:authentication_methods` |
| `POST /me/v1/authentication-methods/{id}/verify` (finish enrollment) | `create:me:authentication_methods` |
| `GET /me/v1/factors` (EA, but read-only and needed by every UI; LR42a-1) | `read:me:factors` |

Enrollment types (OpenAPI `FactorTypeEnum`): `password`, `passkey`,
`webauthn-platform`, `webauthn-roaming`, `totp`, `phone`, `email`,
`push-notification`, `recovery-code`.

### Not in scope

- **Connected accounts** (`/me/v1/connected-accounts/*`): Token Vault, P6
  (Plan 43).
- **Consents and consent signing keys** (Early Access).
- **Profile** (`GET/PATCH /me/v1/profile`, beta): tracked, not built
  (roadmap §6 rule for pre-GA members).
- **Authentication Assurance "Default Policy"** (Early Access: 2FA within 15
  minutes for My Account tokens). Operators get the same through post-login
  Actions (`api.authentication.challengeWith`, Plan 33), as Auth0 documents
  for custom requirements.
- **`push-notification`** enrollment: Guardian push is not planned
  (roadmap §5); `POST` with that type answers `400` "factor not enabled"
  (LR42a-2).
- DPoP-bound tokens (roadmap §5).

### Anti-goals

- **Acting on another user.** Every operation acts on the token's `sub` in
  the token's tenant; no path or body field names a user. A token for
  another audience, another tenant or a client-credentials token is `401`.
- **Silent factor takeover.** A started enrollment is bound to the user, the
  client and an `auth_session` value with a short lifetime (5 min,
  LR42a-3); verifying requires the same token subject. Email and phone
  enrollments prove possession by OTP before they become active.
- **Lockout by deletion.** Deleting the user's last first-factor method
  (password on a database user without a passkey, or the only passkey on a
  passkey-only user) is refused (`409`, Y1), so the API cannot remove every
  way to sign in.
- **Password policy bypass.** A password change through `verify` runs the
  connection's complete password policy, history, breached-password and
  attack protection checks (Plan 19), exactly like a reset.
- **Secrets in logs.** OTP codes, TOTP secrets, recovery codes, attestation
  objects and new passwords never appear in logs (memory: secrets never in
  logs).

## 2. Evidence

- My Account OpenAPI 1.0 (above): servers `https://{host}/me/v1` ("custom or
  canonical host name"); security `Bearer-DPoP`; operations, scopes and
  lifecycle marks as in §1; request variants `Create*AuthenticationMethod`
  (`passkey`/`password` with optional `connection` and `identity_user_id`,
  `email` with `email`, `phone` with `phone_number` and
  `preferred_authentication_method` `sms`|`voice`); `202` responses
  (passkey: `auth_session` + WebAuthn `authn_params_public_key`; password:
  `id`, `auth_session`, `policy` with `complexity`, `profile_data`,
  `history`, `dictionary`; others: `id`, `auth_session`, plus the
  factor-specific data such as the TOTP URI — read the per-type schemas at
  build time); `Verify*AuthenticationMethod` (`auth_session` plus
  `authn_response`, `new_password` or `otp_code`); `UpdateAuthenticationMethodRequestContent`;
  `ErrorResponse` (`type`, `status`, `title`, `detail`, `validation_errors[]`)
  with `x-correlation-id` and `traceparent` headers.
- My Account guide `/docs/manage-users/my-account-api` (activation from the
  APIs page; audience `https://{yourDomain}/me/`; Authorization Code with or
  without PKCE, Resource Owner Password and native passkey flows only, no
  Client Credentials; scopes; user flows `require_client_grant`, client
  flows `deny_all`; final permissions = application policy ∩ RBAC ∩ consent;
  custom domain must be used consistently; WebAuthn enrollment limits).

## 3. Activation and access

- **Activation:** creating the system resource server for the tenant:
  identifier `https://<canonical host>/me/`, name `Auth0 My Account API`
  (Y2: Auth0's name), `is_system: true`, scopes as §1,
  `subject_type_authorization: {user: {policy: require_client_grant},
  client: {policy: deny_all}}` (Plan 30 access model), `allow_offline_access:
  true` (Y3). Done by a console button and by `POST /api/v2/resource-servers`
  with that identifier (LR42a-4); deleting it deactivates.
- **Custom domains:** a token requested on a custom domain uses audience
  `https://<custom domain>/me/` and is accepted only on that host (Plan 23
  per-host audience pattern); the canonical audience only on the canonical
  host (documented "same domain throughout").
- **Tokens:** issued by the authorization-code grant (with PKCE), the
  password grants and the native passkey grant (Plan 33b); client
  credentials and token exchange are refused for this audience
  (`access_denied`, documented). Refresh tokens and MRRT (Plan 48) work as
  for any API.
- **Scopes:** capped by the user-subject client grant (`require_client_grant`),
  RBAC (Plan 26) when enabled on the API, and consent for third-party
  clients (Plan 9).

## 4. Operations

### 4.1 Listing and reading

- The list merges, in one shape per type (OpenAPI `AuthenticationMethod*`):
  the user's password (one per database identity), passkeys and WebAuthn
  keys (Plan 33b), TOTP, email, phone and recovery-code enrollments
  (Plan 33/34). Each has `id`, `type`, `created_at`, `usage` and the
  type's fields (`name`, `phone_number` masked as Auth0 masks it — Y4,
  `email` masked likewise).
- IDs: the Plan 33 Management API authentication-method IDs, so the same
  method has the same ID on both APIs (LR42a-5).

### 4.2 Enrollment

| Type | Start (`202`) | Verify |
|---|---|---|
| `passkey` | WebAuthn creation options for a discoverable credential (Plan 33b, RP ID per host) | `authn_response` attestation → passkey stored on the identity (`connection`/`identity_user_id` select the identity when the user has several database identities) |
| `webauthn-platform` / `webauthn-roaming` | creation options with the attachment and the tenant's security-key settings | attestation → MFA WebAuthn method |
| `totp` | `id`, `auth_session`, `barcode_uri`/`manual_input_code` as the OpenAPI's TOTP response (Y5) | `otp_code` |
| `email` | sends a code to `email` (Plan 21 provider; template `mfa_oob_code`) | `otp_code` |
| `phone` | sends SMS or voice per `preferred_authentication_method` (Plan 34 providers) | `otp_code` |
| `recovery-code` | generates the code, returned once in the response (Y5) | `auth_session` only |
| `password` | returns the connection's password `policy` | `new_password` → password changed with every Plan 19 check; sessions and refresh tokens follow the tenant's password-change behaviour (Plan 17); `password-changed` back-channel logout initiator (Plan 41a) |
| `push-notification` | `400` (LR42a-2) | — |

- A factor that the tenant has not enabled (Plan 33 Guardian factors) is
  refused with `400` (`type` "factor not enabled", Y6).
- `auth_session` is opaque, single use, bound to user, client and type, and
  expires after 5 minutes (LR42a-3).
- Enrollment limits from Plan 33b (WebAuthn per-user limits) apply; over the
  limit → `409` (Y1).
- Logs: the Plan 33 MFA enrollment log types (`gd_enrollment_complete` and
  peers) with the My Account client ID; password change logs `scp` (Y7).

### 4.3 Update and delete

- `PATCH`: `name` for passkeys/WebAuthn/TOTP (≤ 100 characters, LR42a-6);
  `preferred_authentication_method` for phone. Other fields `400`.
- `DELETE`: removes the method; the last-first-factor guard (anti-goal);
  deleting the last MFA method of a user under an "always" MFA policy is
  allowed (Auth0 lets users re-enroll at next login, Y8).

### 4.4 Factors

`GET /me/v1/factors` → `{factors: [{type, usage}]}` for the factors the
tenant enables (Plan 33 Guardian factors, passkeys on the user's
connection, `password` for database connections), `usage` per the OpenAPI
`Usage` enum (Y9).

### 4.5 Errors

`application/problem+json`-style body per `ErrorResponse` (`type`, `status`,
`title`, `detail`, `validation_errors`), with `x-correlation-id` (zeroauthy's
request ID) and `traceparent` echo when present. Rate limits: the general
Authentication API limiter group for the tenant (Plan 45 subset), with
`x-ratelimit-*` headers.

## 5. Storage, console, seed, tests

- **Storage:** `auth_session` records reuse the Plan 33 enrollment-ticket /
  challenge storage (sealed, TTL); no new table expected. If none fits, one
  migration numbered at merge.
- **Router:** new `internal/myaccount` package mounted at `/me/v1/` on tenant
  hosts (canonical and custom domains), with its own error writer.
- **Console:** APIs page "My Account API" activation card; application →
  APIs tab lets operators create the user-subject client grant.
- **Seed:** `my_account_api: {active: true}` tenant flag (local seed
  shorthand that creates the system resource server, LR42a-7) and user
  client grants.
- **Deploy CLI:** the system resource server is excluded like the
  Management API's (Plan 20 rules).
- **Tests:** per-operation handler tests (scopes, wrong audience, wrong
  host, client-credentials token, cross-user `auth_session`), enrollment
  flows end to end with Plan 33's TOTP generator and a virtual WebAuthn
  authenticator, password change policy checks, last-factor guard.
- **E2E** `make e2e-my-account` (new lane): Playwright login with PKCE
  through `@auth0/auth0-spa-js` 2.28.3 requesting the My Account audience,
  then fetch calls enrolling TOTP and a virtual passkey, renaming and
  deleting; a raw request suite for errors.

## 6. Local rulings and observation points

| ID | Ruling |
|---|---|
| LR42a-1 | `GET /factors` (EA) is built; it is read-only and needed by any UI. |
| LR42a-2 | `push-notification` enrollment answers `400`. |
| LR42a-3 | `auth_session` lives 5 minutes, single use. |
| LR42a-4 | Activation = the system resource server's existence. |
| LR42a-5 | Method IDs equal the Management API's. |
| LR42a-6 | Method names ≤ 100 characters. |
| LR42a-7 | Seed shorthand `my_account_api.active`. |

Observe later (`docs/superpowers/plan-1-followups.md`):

- **Y1** Status and wording for limits and the last-factor guard.
- **Y2** The system resource server's name.
- **Y3** `allow_offline_access` default for it.
- **Y4** Masking of phone numbers and emails in method listings.
- **Y5** TOTP and recovery-code `202` response members.
- **Y6** Error for a disabled factor.
- **Y7** Log types for My Account enrollments and password changes.
- **Y8** Deleting the last MFA method under an "always" policy.
- **Y9** `usage` values per factor.

## 7. Decisions needed from the maintainer

None blocking. The seed shorthand (LR42a-7) is a local extension; the
maintainer may prefer seeding the resource server explicitly.
