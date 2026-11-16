# Plan 41a — OIDC protocol extras, back-channel logout, global token revocation and logout certification

**Date:** 2026-11-16. **Status:** design; not implemented.

**Roadmap entry:** [management roadmap, Plan 41](2026-10-19-zeroauthy-management-roadmap-design.md)
(full, split by the [parallel paths](2026-11-13-zeroauthy-parallel-paths-design.md)
into P3 = this, P4 = Dynamic Client Registration, P5 = CIBA). Track P,
after P1 (Plan 35, merged); runs after P2 (Plan 48) in the track order but
touches different code, and its spec may be written before P2 lands. Read
the [clean-room policy](../../../CLEAN_ROOM.md), `AGENTS.md`, the
[conformance guide](../../conformance.md) (non-compliant switches,
certification steps), D-0013, D-0035, D-0036, D-0063 and the Plan 12
follow-ups in `docs/superpowers/plan-1-followups.md`.

## 1. Outcome and scope

zeroauthy closes the Plan 12 conformance gaps, adds Auth0's logout
features, and gets the next OpenID certification profiles:

- **ID token and userinfo claims:** the `address` and `phone` scopes, the
  remaining standard `profile` claims, the `claims` request parameter, and
  `acr` / `acr_values` with Auth0's multi-factor policy value (step-up).
- **Client `oidc_support`** (newer Auth0 client field) restricting OIDC use
  and the OIDC scopes a client may request.
- **ID token signing per client:** `jwt_configuration.alg` `HS256` (client
  secret) and `PS256` join `RS256`; discovery lists them, as Auth0's does.
  This settles Plan 35 open point 3.
- **RFC 8707 `resource`:** the tenant's `resource_parameter_profile:
  compatibility` makes `resource` an alias of `audience` (stored only today).
- **`redirect_uri` optional at `/authorize`:** decision in §6.
- **OIDC Back-Channel Logout** (`oidc_logout` on clients, initiators,
  session metadata, `sslo`/`fslo` logs, discovery flags).
- **Global token revocation** (Okta Universal Logout; moved here from
  Plan 36): `POST /oauth/global-token-revocation/connection/{connectionName}`.
- **Certification:** new local conformance plans (RP-Initiated Logout is
  certified-ready already; add Back-Channel Logout OP, the `client_secret_post`
  variant of Basic and Form Post), the expected-file updates, and the
  maintainer-run submission steps (§8).

**Rule:** strict 1:1 with Auth0's documented behaviour (memory: Auth0 parity
first). Where OpenID specifications and Auth0 differ, the maintainer's
standing ruling applies: **spec-compliant by default, Auth0's behaviour behind
`ZEROAUTHY_COMPAT__NONCOMPLIANT_<BEHAVIOUR>`** (conformance guide). Local
rulings **LR41a-n** and observation points **L1–Ln** go in **D-0080** (P3
block D-0080–0089).

### In scope

1. Scopes and claims (§3).
2. `claims` request parameter (§3.3).
3. `acr_values` and `acr` (§4).
4. `oidc_support` (§3.4).
5. Client ID-token signing algorithms (§5).
6. `resource` compatibility profile (§6.1) and the `redirect_uri` question
   (§6.2).
7. Back-channel logout (§7.1–7.4).
8. Global token revocation (§7.5).
9. Conformance plans, expected files, certification steps (§8).
10. Console, seed, Deploy CLI, docs, tests (§9).

### Not in scope

- **OIDC Front-Channel Logout.** Auth0 does not offer it (its discovery has
  no `frontchannel_logout_supported`; no client field exists). Not built;
  the certification covers RP-Initiated and Back-Channel Logout only
  (LR41a-1). The maintainer may add it later as a marked extension.
- **OIDC Session Management** (`check_session_iframe`): not offered by
  Auth0.
- Dynamic Client Registration and CIMD (P4), CIBA (P5), Token Vault (P6).
- FAPI profiles: Auth0's FAPI support needs mTLS/PAR/JAR combinations
  (mTLS not planned, roadmap §5).
- Implicit and Hybrid OP profiles: only if Auth0 behaviour passes; checked
  in Task 1 and recorded as a decision either way (§8).
- Session Transfer Tokens (`session_transfer` on clients, Native to Web SSO):
  a newer Auth0 feature on no plan yet; recorded as a new follow-up for the
  roadmap (LR41a-2), not built here.
- DPoP (roadmap §5).

### Anti-goals

- **Logout tokens to the wrong place.** A logout token is sent only to the
  client's own registered `backchannel_logout_urls` entry, only for sessions
  the client took part in, and never follows redirects.
- **SSRF through logout URLs.** The sender uses the outbound network policy
  used by log streams (HTTPS only, public addresses only unless the operator
  policy allows private ones; no Auth0 or zeroauthy tenant hosts, LR41a-9).
- **Unauthenticated revocation.** Global token revocation accepts only a JWT
  signed by the connection's upstream issuer keys with the documented
  audience; anything else is `401` and revokes nothing.
- **Claims beyond consent.** The `claims` parameter never yields a claim the
  scopes and consent would not otherwise allow (OIDC Core §5.5 lets the OP
  decline), and never exposes `app_metadata`/`user_metadata` beyond what
  Actions add.
- **`HS256` key reuse.** An HS256 ID token is keyed with the client secret
  only; a client without a secret (public, `private_key_jwt`-only) cannot
  choose HS256.
- **Secrets in logs.** Logout tokens, revocation JWTs and client secrets
  never appear in logs (memory: secrets never in logs).

## 2. Evidence

Read 2026-11-16:

- Auth0 discovery (a public tenant's `/.well-known/openid-configuration`):
  `scopes_supported` includes `phone`, `address`; `claims_supported` lacks
  `acr`/`amr`; no `claims_parameter_supported`; `id_token_signing_alg_values_supported`
  `["HS256","RS256","PS256"]`; `backchannel_logout_supported: true`,
  `backchannel_logout_session_supported: true`;
  `global_token_revocation_endpoint` `https://<tenant>/oauth/global-token-revocation/connection/{connectionName}`
  with `global_token_revocation_endpoint_auth_methods_supported`
  `["global-token-revocation+jwt"]`; `request_parameter_supported: false`
  (zeroauthy already deviates deliberately since Plan 35: JAR is supported).
- Back-channel logout: `/docs/authenticate/login/logout/back-channel-logout`,
  `.../configure-back-channel-logout` (POST `logout_token`; claims `iss`,
  `sub`, `aud`, `iat`, `exp` = `iat` + 120 s, `jti`, `events` with
  `http://schemas.openid.net/event/backchannel-logout`, `sid`; no `nonce`;
  5 s response timeout; `200` success, `400` → no further requests for that
  session; logs `sslo` / `fslo`; receiver must be public HTTPS, no Auth0
  subdomains), `.../oidc-back-channel-logout-initiators` (`rp-logout`,
  `idp-logout` required; `password-changed`, `session-expired`,
  `session-revoked`, `account-deleted`, `email-identifier-changed`; mode
  `custom` default, `all` includes future initiators).
- Management OpenAPI: `Client.oidc_logout` (`backchannel_logout_urls`,
  "currently only one URL is allowed", format
  `absolute-https-uri-with-placeholders-or-empty`;
  `backchannel_logout_initiators {mode, selected_initiators}` with the enum
  also listing `mfa-phone-unenrolled`, `account-deactivated`,
  `profile-changed`; `backchannel_logout_session_metadata {include}`),
  `Client.oidc_support {is_allowed, allow_all_scopes, allowed_scopes[profile|email|address|phone]}`,
  `TenantOIDCLogoutSettings.rp_logout_end_session_endpoint_discovery`
  (default `true`), `TenantSettings.resource_parameter_profile`
  (`audience` | `compatibility`, default `audience`).
- Step-up: `/docs/secure/multi-factor-authentication/step-up-authentication`
  (`acr_values=http://schemas.openid.net/pape/policies/2007/06/multi-factor`,
  `acr` and `amr` in the ID token) — read again at build time.
- Global token revocation: Okta Universal Logout pages linked from the OIDC
  connection page ("Global Token Revocation revokes Auth0 sessions and
  refresh tokens and can trigger back-channel logout"); read at build time.
- OpenID specs: Core 1.0 §5.1, §5.4, §5.5, §2 (`acr`); Back-Channel Logout
  1.0; RP-Initiated Logout 1.0; RFC 8707; Global Token Revocation draft
  (`draft-parecki-oauth-global-token-revocation`).
- Conformance suite `release-v5.3.3` plan names (`oidcc-backchannel-rp-initiated-logout-certification-test-plan`,
  `oidcc-basic-certification-test-plan` with `client_auth_type=client_secret_post`).

## 3. Scopes, claims and `oidc_support`

### 3.1 `profile`

All OIDC Core `profile` claims: `name`, `family_name`, `given_name`,
`middle_name`, `nickname`, `preferred_username`, `profile`, `picture`,
`website`, `gender`, `birthdate`, `zoneinfo`, `locale`, `updated_at`.
Sources: the user's root attributes where zeroauthy has them (name,
nickname, picture, given/family name, `updated_at`); the others from the
federated identity's profile data (Plan 24/36 mapping) when present;
otherwise omitted (Auth0 includes only what the profile has, LR41a-3). This
closes D-0036's `oidcc-scope-profile` warning only if the conformance user
carries the values. The seed sets only the root attributes the Management
API allows (`given_name`, `family_name`, `nickname`, `picture`, `name`); no
local-only profile field is invented. The warning stays accepted for the
claims a database user cannot carry (L1).

### 3.2 `address` and `phone`

- `phone` → `phone_number`, `phone_number_verified` from the user's root
  `phone_number` / `phone_verified` (Plan 34 phone identifiers).
- `address` → `address` (OIDC structured object) from the user's root
  `address` attribute when a federated profile set it, else omitted (L2:
  Auth0's source for `address`).
- Both join `scopes_supported` (Auth0 lists them) and the claim list.

### 3.3 The `claims` parameter

- Accepted at `/authorize`, `/oauth/par` and inside JAR request objects:
  JSON with `userinfo` and `id_token` members per Core §5.5, `null` or
  `{essential, value, values}` per claim, ≤ 4 KiB (LR41a-4).
- Requested claims are added to the ID token or userinfo response when the
  user has them and the claim is a standard claim the scopes' consent covers
  (or `sub`, `auth_time`, `acr`); others are ignored (OP may decline).
  `essential` never fails the request (Core allows that).
- `acr` with `essential: true` and `values` behaves like `acr_values` (§4).
- Auth0 does not document `claims`. Supporting it is additive (Auth0 ignores
  unknown parameters), so it is on by default and discovery says
  `claims_parameter_supported: true`. `ZEROAUTHY_COMPAT__NONCOMPLIANT_IGNORE_CLAIMS_PARAMETER=1`
  restores Auth0's silence (LR41a-5).

### 3.4 `oidc_support`

- `null`/absent: today's behaviour (OIDC allowed, all scopes).
- `is_allowed: false`: `openid` is dropped from requests (no ID token, no
  userinfo for that client's access tokens; L3: Auth0's exact error, local:
  `openid` removed silently, matching how unknown scopes are dropped).
- `allowed_scopes` (mutually exclusive with `allow_all_scopes`, `400` when
  both): only those of `profile email address phone` are honoured; the rest
  are dropped before consent.
- Validation per the OpenAPI `Post`/`Patch` schemas (`is_allowed` required).

## 4. `acr_values` and `acr`

- Supported value: `http://schemas.openid.net/pape/policies/2007/06/multi-factor`
  (Auth0's step-up value). Discovery `acr_values_supported` lists it
  (stored-only tenant field since Plan 19 becomes the effective list,
  LR41a-6).
- A request with that value forces MFA on this login (Plan 33 prompts),
  even with tenant MFA policy `never` and inside an existing SSO session
  whose `amr` lacks `mfa` (step-up).
- The ID token carries `acr` = that value and `amr` containing `mfa` when
  MFA was performed in this session; without the request, `acr` is omitted
  (Auth0 adds `acr` only when requested, L4).
- Unknown `acr_values` entries are ignored; if none is supported, the login
  proceeds without step-up and no `acr` is returned (Core: voluntary).
- `claims` `acr` essential with the multi-factor value = same as
  `acr_values`.
- Post-login Actions already see `event.transaction.acr_values`; no change.
- Conformance: `oidcc-ensure-request-with-acr-values-succeeds` warning is
  expected to clear.

## 5. ID token signing per client

- `jwt_configuration.alg`: `RS256` (default), `PS256`, `HS256`.
- `HS256` signs ID tokens with the client secret (the secret's UTF-8 bytes;
  `jwt_configuration.secret_encoded` is stored-only and documented as
  legacy, LR41a-7); refused (`400`) for clients without a secret or with
  `token_endpoint_auth_method: none`, or whose only method is
  `private_key_jwt`.
- `PS256` uses the tenant signing key as Plan 35's API signing does.
- Discovery `id_token_signing_alg_values_supported`
  `["HS256","RS256","PS256"]` (Auth0's list), resolving Plan 35 point 3.
- Access tokens keep their API's `signing_alg` (Plan 35); userinfo is JSON.
- Logout tokens (§7) are always `RS256` with the tenant key (L5).

## 6. `resource` and `redirect_uri`

### 6.1 `resource_parameter_profile`

- `audience` (default): `resource` is ignored, as today.
- `compatibility`: at `/authorize`, `/oauth/par` and `/oauth/token`, a single
  `resource` value is read as `audience` when `audience` is absent; when both
  are present and differ, `invalid_request` (LR41a-8, L6); several
  `resource` values: `invalid_target` (RFC 8707) — L6 records the Auth0
  answer to observe.

### 6.2 `redirect_uri` optional at `/authorize`

Auth0's reference lists `redirect_uri` as optional and falls back to a
registered callback (L7: which one). OIDC Core requires it for OIDC
requests. Ruling per the standing rule: **required by default**
(spec-compliant); `ZEROAUTHY_COMPAT__NONCOMPLIANT_OPTIONAL_REDIRECT_URI=1`
uses the client's first registered callback when it is omitted and the
client has exactly one non-wildcard callback (LR41a-10). This is the first
non-compliant switch; the startup warning that the conformance guide plans
is built here.

## 7. Logout

### 7.1 Client settings

- `oidc_logout.backchannel_logout_urls`: 0 or 1 absolute HTTPS URL (the
  OpenAPI says only one), ≤ 2048 bytes; placeholders `{organization_name}`
  and `{organization_id}` allowed (L8: Auth0's placeholder set; local list
  from the client callback placeholders zeroauthy already supports).
- `backchannel_logout_initiators`: absent → `{mode: custom,
  selected_initiators: [rp-logout, idp-logout]}`; `custom` requires
  `selected_initiators` and must include both required values (`400`
  otherwise); `all` covers every initiator zeroauthy emits now and later.
- `backchannel_logout_session_metadata.include`: when `true`, the logout
  token carries `session_metadata` (Plan 48's metadata; until Plan 48 lands
  it is `{}`, L9).
- Tenant `oidc_logout.rp_logout_end_session_endpoint_discovery` (default
  `true`): when `false`, discovery omits `end_session_endpoint` (the
  endpoint keeps working).

### 7.2 Initiators zeroauthy emits

| Initiator | Trigger in zeroauthy |
|---|---|
| `rp-logout` | `/oidc/logout` and `/v2/logout` ending a session |
| `idp-logout` | global token revocation (§7.5) and SAML/WS-Fed IdP logout later |
| `password-changed` | password change or reset that ends sessions (Plan 17/19 paths) |
| `session-expired` | the session sweeper removing an expired session (idle or absolute) |
| `session-revoked` | `DELETE /sessions/{id}`, `DELETE /users/{id}/sessions`, `POST /sessions/{id}/revoke` (Plan 48) |
| `account-deleted` | user deletion |
| `email-identifier-changed` | email change through the Management API or My Account (P/U tracks) |
| `account-deactivated`, `mfa-phone-unenrolled`, `profile-changed` | in the OpenAPI enum but undocumented: accepted in configuration, never emitted (LR41a-11, L10) |

### 7.3 Sending

- For each ended session, every client in the session's client list that
  has a back-channel URL and subscribes to the initiator gets one logout
  token: `iss`, `aud` = client ID, `iat`, `exp` = `iat` + 120 s, `jti`,
  `events`, `sid` (always, since every session has one), `sub` (always,
  LR41a-12), optional `session_metadata`; header `typ: logout+jwt` (Back-Channel
  Logout 1.0 §2.4 recommends it; Auth0's sample expects `JWT` — L11; local:
  `logout+jwt` default, `ZEROAUTHY_COMPAT__NONCOMPLIANT_LOGOUT_TOKEN_TYP_JWT=1`
  for `JWT`).
- Delivery through the durable job queue (Plan 28) so it survives restarts:
  POST `application/x-www-form-urlencoded` `logout_token=...`, 5 s timeout,
  no redirects. `200`/`204` → `sslo`. Timeout, network error or `5xx` →
  retried with backoff for up to 10 minutes (L12: Auth0's retry policy; the
  token's `exp` caps useful retries — a retry mints a fresh token, LR41a-13),
  then `fslo`. `400` or other `4xx` → `fslo`, no retry (documented).
- The session ends locally first; delivery never blocks the user's logout.

### 7.4 Discovery

`backchannel_logout_supported: true`, `backchannel_logout_session_supported:
true`; `frontchannel_*` absent.

### 7.5 Global token revocation

- `POST /oauth/global-token-revocation/connection/{connectionName}` for
  `oidc` and `okta` connections (Plan 36).
- Authentication: `Authorization: Bearer <JWT>` with
  `typ: global-token-revocation+jwt` (L13), signed by a key from the
  connection's pinned upstream JWKS, `iss` = the connection's pinned issuer,
  `aud` = the tenant issuer URL (L13), `exp` required and ≤ 5 min ahead,
  `jti` single-use (Plan 35's replay table pattern, keyed by connection).
- Body `{"sub_id": {"format": "iss_sub", "iss": ..., "sub": ...}}` (or the
  `email` format) per the draft; the subject resolves to the user through
  the connection's federated identity index only.
- Effect: end every session of the user (initiator `idp-logout`), revoke
  every refresh token (offline and online), and log it with the log types
  the Auth0 logs schema defines for it, read at build time (L14; no type is
  invented).
- Answers: `204` on success and for an unknown subject (no oracle),
  `400` malformed, `401` bad token, `404` unknown or non-OIDC connection
  (LR41a-14).
- Discovery: `global_token_revocation_endpoint` (with the literal
  `{connectionName}`) and its auth methods.

## 8. Conformance and certification

- **Task 1 check:** run the hosted-suite plan list at `release-v5.3.3` and
  record which of Implicit OP and Hybrid OP pass with Auth0 behaviour
  (zeroauthy already issues `token`/`id_token` response types; see D-0036).
  Add the passing ones to the local `make conformance` plans; record the
  others with the reason.
- **New local plans:** Back-Channel Logout OP
  (`oidcc-backchannel-rp-initiated-logout-certification-test-plan`), the
  `client_secret_post` variants of Basic and Form Post.
- **Expected files:** remove the D-0036 entries this plan fixes
  (`oidcc-claims-essential`, `oidcc-ensure-request-with-acr-values-succeeds`,
  `oidcc-scope-address/-phone/-all`, and `oidcc-scope-profile` if the seed
  user can carry the claims). Any new warning goes through the triage
  process (conformance guide) before it is listed.
- **Certification steps** (maintainer's hands, §5 of the conformance
  guide): same kit, one more droplet run with the new plans, signed
  declaration listing Back-Channel Logout OP and RP-Initiated Logout OP;
  the throwaway-secrets rule stays. The plan prepares the seed and the
  checklist; it does not submit.
- The seed for the certification clients gains `oidc_logout` URLs pointing
  at the suite's back-channel receiver.

## 9. Storage, console, seed, Deploy CLI, tests

### 9.1 Storage

- Clients gain `oidc_logout` and `oidc_support` (JSON columns; one
  migration, numbered at merge), `jwt_configuration.alg`.
- Tenant settings gain the `oidc_logout` object (tenant settings are JSON
  already; check `sqlstore`).
- Global token revocation `jti` reuse: the Plan 35 `client_assertion_jtis`
  table keyed by a `kind` column, or a new table if that table has no room
  (builder's choice, §10).
- gRPC: fields carried as JSON blobs on existing messages; capability
  `oidc_logout.v1` gates writes of the new client fields (LR41a-15).

### 9.2 Console

- Application → Sessions/Logout: back-channel URL, initiators (all /
  selected with the two required ones fixed on), session metadata switch;
  OIDC support panel; ID token algorithm selector (HS256 disabled without a
  secret).
- Tenant settings → Advanced: RP logout discovery switch, resource parameter
  profile.
- Logs: `sslo`/`fslo` render with their client and URL host.

### 9.3 Seed and Deploy CLI

- Seed: `oidc_logout`, `oidc_support`, `jwt_configuration.alg`.
- Deploy CLI 9.1.0 clients handler carries `oidc_logout`; four-cell round
  trip adds it.

### 9.4 Tests and E2E

- Unit: claims-parameter parser and selection table; `oidc_support`
  filtering; acr step-up decisions; HS256/PS256 ID tokens verified with
  `go-jose`; resource-profile table; initiator subscription table; logout
  token shape; global token revocation auth table (wrong `iss`, wrong `aud`,
  replayed `jti`, expired, unknown connection, `alg: none`).
- Integration: one logout → N clients, each once, with retries on `503` and
  none on `400`; restart in the middle of delivery (durable job).
- E2E `make e2e-logout` (new lane `run-m41a-logout.sh`): `express-openid-connect`
  3.4.0 (Auth0's Express SDK, already pinned in `tests/e2e/package.json`,
  LR41a-16) receives
  back-channel logout; Playwright step-up with `acr_values`; node-auth0
  client CRUD with `oidc_logout`; a fixture Okta-like IdP sends a global
  token revocation.
- `make conformance` with the new plans.

## 10. Local rulings and observation points

| ID | Ruling |
|---|---|
| LR41a-1 | No Front-Channel Logout (Auth0 has none). |
| LR41a-2 | Session Transfer Tokens recorded as a new roadmap follow-up. |
| LR41a-3 | Profile claims only from attributes the user has. |
| LR41a-4 | `claims` ≤ 4 KiB. |
| LR41a-5 | `claims` on by default; compat switch to ignore it. |
| LR41a-6 | `acr_values_supported` = the multi-factor value. |
| LR41a-7 | HS256 uses the secret's UTF-8 bytes. |
| LR41a-8 | `resource` ≠ `audience` → `invalid_request`. |
| LR41a-9 | Logout URLs follow the log-stream outbound policy. |
| LR41a-10 | `redirect_uri` required; compat switch for Auth0's fallback. |
| LR41a-11 | Undocumented initiators accepted, not emitted. |
| LR41a-12 | Logout tokens carry both `sub` and `sid`. |
| LR41a-13 | Each retry mints a fresh logout token. |
| LR41a-14 | Global token revocation answers `204` for unknown subjects. |
| LR41a-15 | `oidc_logout.v1` plugin capability gates the new client fields. |
| LR41a-16 | The logout receiver is the already pinned `express-openid-connect` 3.4.0; no new pin. |

Observe later (`docs/superpowers/plan-1-followups.md`):

- **L1** Whether the extra profile claims can be set on a database user.
- **L2** Auth0's source for `address`.
- **L3** Auth0's answer for `openid` with `oidc_support.is_allowed: false`.
- **L4** Whether Auth0 emits `acr` without `acr_values`.
- **L5** Logout token signing algorithm.
- **L6** `resource` with `audience`, and several `resource` values.
- **L7** Which callback Auth0 uses when `redirect_uri` is omitted.
- **L8** Logout URL placeholders.
- **L9** `session_metadata` claim name and shape in the logout token.
- **L10** The three undocumented initiators.
- **L11** Logout token `typ`.
- **L12** Auth0's retry policy for back-channel logout.
- **L13** Global token revocation JWT `typ`, `aud` and body formats.
- **L14** Global token revocation log types.

## 11. Decisions needed from the maintainer

1. Front-Channel Logout: confirm "not built" (LR41a-1).
2. The `optional redirect_uri` switch (LR41a-10) and the logout-token `typ`
   switch (§7.3): confirm spec-compliant defaults.
3. Certification run timing (needs the droplet and the maintainer's
   signature).

## 12. Left to the builder

- Where the claims selection lives (`internal/claims` is the natural home).
- The `jti` table for global token revocation.
- Job payload shape for logout delivery.
