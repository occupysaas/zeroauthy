# Plan 39a — Sign in with Apple (web and native)

**Date:** 2026-11-16. **Status:** implementation complete on `plan-39a-apple`; final plan verification, review and CI tracked in the [record](../2026-11-16-plan-39a-implementation-record.md).

**Roadmap entry:** [management roadmap, Plan 39](2026-10-19-zeroauthy-management-roadmap-design.md)
("short, Apple full"); [parallel paths](2026-11-13-zeroauthy-parallel-paths-design.md)
item **S1** (track S, first item; depends on Plan 24's federation core,
merged). S2 (Plan 39b) adds the remaining social providers and the Google
and Facebook native exchanges on the framework built here. Read the
[clean-room policy](../../../CLEAN_ROOM.md), `AGENTS.md`, the
[Plan 24 social connections design](2026-10-26-zeroauthy-social-connections-design.md),
the [social connections guide](../../social-connections.md), the
[Plan 35 spec](2026-11-08-zeroauthy-client-credentials-jar-token-exchange-design.md)
(token exchange grant) and `internal/federation/inventory.json`.

## 1. Outcome and scope

An operator creates an `apple` connection with the Apple Services ID, Team
ID, Key ID and the `.p8` signing key. Users sign in with Apple from the
hosted login page (web flow). A native iOS app that already holds an Apple
authorization code exchanges it at `/oauth/token` for zeroauthy tokens
(native social login), as Auth0's iOS SDK does. Apple's specifics are
handled: the client secret is a short-lived ES256 JWT that zeroauthy signs,
the callback is a form post, the name arrives only on the first
authorization, emails may be private relay addresses, and
`email_verified` arrives as a string.

**Rule:** strict 1:1 with Auth0's documented behaviour (memory: Auth0 parity
first). Apple's own documentation defines the wire protocol. Every behaviour
traces to an Auth0 page, the Management OpenAPI, Apple's developer
documentation, or a local ruling (**LR39a-n**) in **D-0170** (S1 block
D-0170–0179). Observation points **A1–An** (§8).

### In scope

1. **`apple` strategy** (OpenAPI `ConnectionOptionsApple`): `client_id`
   (Services ID), `team_id`, `kid`, `app_secret` (PEM, write-only, sealed),
   `name`, `email`, `scope`, `freeform_scopes`, `set_user_root_attributes`,
   `upstream_params` (stored-only, Plan 24 policy), `non_persistent_attrs`
   (stored-only).
2. **Web flow:** `/authorize?connection=apple` and the login-page button →
   Apple `/auth/authorize` with `response_mode=form_post` when `name` or
   `email` is requested → `POST /login/callback` (shared with Plan 36's
   front-channel callback) → code exchange with the generated client secret
   → ID token validation against Apple's JWKS → profile.
3. **Native flow:** `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
   with `subject_token_type=http://auth0.com/oauth/token-type/apple-authz-code`,
   `subject_token` = the Apple authorization code, optional `user_profile`,
   for clients with `native_social_login.apple.enabled: true` and
   `mobile.ios.app_bundle_identifier` set.
4. **Client fields** `native_social_login` (`apple`, `facebook`, `google`
   each `{enabled}`) and `mobile.ios.team_id` / `app_bundle_identifier`
   become stored and returned (today accepted and ignored, D-0039);
   `apple` becomes enforced here, `facebook`/`google` in S2.
5. **Profile:** `apple|<sub>` identity, `isSocial: true`; name from the first
   authorization's `user` form field (web) or `user_profile` (native);
   `email`, `email_verified` (string or boolean), `is_private_email`
   in the identity profile data.
6. **Console, seed, Deploy CLI, docs, tests.**

### Not in scope

- Auth0 developer keys (Auth0 lets a connection run without the operator's
  own Apple credentials): zeroauthy has no Apple account to lend; `client_id`,
  `team_id`, `kid` and `app_secret` are required (LR39a-1).
- Apple server-to-server notifications (email relay disabled, consent
  revoked, account deleted): Auth0 documents none; not built (LR39a-2, A1).
- Calling Apple's token revocation on user deletion or unlink: not
  documented as Auth0 behaviour; zeroauthy stores Apple's refresh token
  readable with `read:user_idp_tokens` so the application can revoke
  (LR39a-3, A2).
- Google and Facebook native exchanges and the other social providers (S2).
- Sign in with Apple on Android/web views beyond the standard web flow.

### Anti-goals

- **Account takeover via relay or unverified email.** No automatic linking
  by email (Plan 24 rule); `email_verified` false or a string other than
  `"true"` is false.
- **Trusting the `user` form field.** The posted name is accepted only on the
  callback of the attempt that requested `name`, after the ID token
  validated, and it never overrides an ID-token claim; it carries only `name.firstName`, `name.lastName`
  (bounded) and is ignored on later logins (Apple sends it once).
- **Native code from another app.** The native exchange's Apple ID token
  `aud` must equal the client's `mobile.ios.app_bundle_identifier`; a code
  minted for another bundle is refused.
- **Signing key exposure.** `app_secret` is sealed at write, never returned,
  logged or exported; the generated client secret JWT is never logged.
- **Secrets in logs** generally (memory: secrets never in logs).

## 2. Evidence

Read 2026-11-16:

- Management OpenAPI `ConnectionOptionsApple` (fields above; `app_secret`
  "must be a PEM"; `email` "User has the option to obfuscate the email with
  Apple's relay service"), `NativeSocialLoginApple` (`enabled`, default
  `false`, "allow signing in natively using an Apple authorization code"),
  `ClientMobileiOS` (`team_id`, `app_bundle_identifier`).
- Auth0 `/docs/authenticate/identity-providers/social-identity-providers/apple-native`
  (Native Social Login switch, iOS App ID; connection Team ID, Client Secret
  Signing Key, Key ID; the app exchanges the Apple authorization code at
  `/oauth/token`; Auth0 exchanges it with Apple and builds the identity;
  "Avoid using a nonce"; Apple returns requested name/email only on the
  first response).
- Auth0 Authentication API token exchange for native social
  (`/docs/api/authentication/token-exchange-for-native-social/token-exchange-native-social`:
  `subject_token`, `subject_token_type`, `client_id`, `audience`, `scope`,
  `user_profile` JSON `{name:{firstName,lastName}}` for native iOS). The
  Apple `subject_token_type` value is the one Auth0's iOS SDK sends
  (`http://auth0.com/oauth/token-type/apple-authz-code`), A3.
- Apple developer documentation: "Generate and validate tokens"
  (`https://appleid.apple.com/auth/token`, client secret JWT: header `alg
  ES256`, `kid`; claims `iss` = Team ID, `iat`, `exp` ≤ 15777000 s (six
  months), `aud` = `https://appleid.apple.com`, `sub` = client ID),
  "Incorporating Sign in with Apple into other platforms" (authorize
  endpoint, `response_mode=form_post` required when scopes are requested,
  the one-time `user` JSON form field), "Authenticating users with Sign in
  with Apple" (ID token claims `email`, `email_verified`, `is_private_email`,
  `real_user_status`, `nonce_supported`), discovery
  `https://appleid.apple.com/.well-known/openid-configuration`, JWKS
  `https://appleid.apple.com/auth/keys`.

## 3. Connection

- Validation in `internal/federation/rules/apple.go`, one authority for API,
  seed and console:
  - `client_id`: 1–255 characters, reverse-DNS style allowed; required;
    immutable after creation (it binds identities, LR39a-4).
  - `team_id`, `kid`: exactly 10 uppercase alphanumerics (Apple's format,
    LR39a-5).
  - `app_secret`: a PKCS#8 PEM EC P-256 private key; required on create;
    omitted on PATCH preserves; empty/null refused; sealed; a key that
    fails to parse is `400`.
  - `scope` / `name` / `email`: `name` and `email` booleans (default
    `true`) build the scope; an explicit `scope` must equal the computed one
    (Plan 24 rule) or contain only `name`, `email`; `freeform_scopes` other
    than `name`/`email` refused (Apple has no others, LR39a-6).
- Changing `team_id`, `kid` or `app_secret` increments `FederationRevision`.
- Fixed Apple endpoints (as Google's in Plan 24): authorize
  `https://appleid.apple.com/auth/authorize`, token `/auth/token`, JWKS
  `/auth/keys`, issuer `https://appleid.apple.com`; overridable only by the
  test fixture hook (like `GoogleOverride`).

## 4. Client secret

- An ES256 JWT, header `kid` = option `kid`, claims `iss` = `team_id`,
  `iat` = now, `exp` = now + 5 minutes (zeroauthy signs per exchange; the
  six-month maximum is never needed, LR39a-7), `aud` =
  `https://appleid.apple.com`, `sub` = the Services ID (web) or the bundle
  ID (native).
- Cached for at most 4 minutes per (connection revision, `sub`) to avoid
  re-signing on bursts.
- Sent as `client_secret` with `client_id` = `sub` in the token request body
  (`client_secret_post`).

## 5. Web flow

1. Start: `response_type=code`, `response_mode=form_post` (whenever `name`
   or `email` is requested; `query` otherwise), `scope`, `state`, `nonce`
   (web only; native avoids it, documented), PKCE S256 (A4: Apple's PKCE
   support; sent when Apple's metadata lists S256, else omitted, the
   Plan 36 `auto` rule).
2. Callback: `POST /login/callback` with `code`, `state`, optional `user`
   (JSON) and `error`. The same route as Plan 36's front-channel callback;
   whichever plan merges first adds it, the other reuses it (LR39a-8). The
   attempt cookie uses `SameSite=None; Secure` for Apple attempts (cross-site
   POST).
3. Exchange the code; validate the ID token (`iss`, `aud` = Services ID,
   `exp`, `iat`, `nonce`, signature from Apple's JWKS with the Plan 24 key
   cache).
4. Profile (§7) and the Plan 24 identity/provisioning pipeline.

## 6. Native flow

- Only when `subject_token_type` is the Apple type; this type is reserved
  (Plan 35 already refuses `http://auth0.com…` for custom profiles), so it
  never reaches the custom token exchange Action.
- Preconditions: client has `native_social_login.apple.enabled: true` and
  `mobile.ios.app_bundle_identifier`; an `apple` connection is enabled for
  the client (if several, the first usable in the store's `LOWER(name), id` order,
  LR39a-9); otherwise `invalid_request` "Native Social Login is not
  enabled for this client" (A5: Auth0's wording).
- Client authentication: public native clients (`none`) as Auth0 allows for
  this grant; confidential clients authenticate as usual.
- Exchange the code with Apple using `client_id` = bundle ID and the client
  secret JWT with `sub` = bundle ID; validate the ID token with `aud` =
  bundle ID; no nonce.
- `user_profile` (optional JSON, ≤ 1 KiB): `name.firstName`,
  `name.lastName` used like the web `user` field.
- Then the normal user-token issuance: post-login Actions with
  `event.connection.strategy = apple` and `event.transaction.protocol`
  `oauth2-token-exchange` (A6), MFA policy as for other token grants
  (Plan 33 rules), organizations as for the authorization code grant when
  `organization` is sent.
- Errors from Apple (`invalid_grant`, expired code) → `invalid_grant`
  "Error from Apple connection" style local wording (A5).
- Logs: the success and failure types come from the Auth0 logs schema at
  build time (A7). If it has no native-social type, the Plan 35 token
  exchange pair is used. No type is invented.

## 7. Profile

| User field | Source |
|---|---|
| `user_id` | `apple|<sub>` |
| `email` | ID token `email` |
| `email_verified` | ID token `email_verified` (`true` or `"true"` → true; else false) |
| `name`, `given_name`, `family_name` | first authorization's `user`/`user_profile` name; later logins keep the stored values (Apple sends nothing), regardless of `set_user_root_attributes` (LR39a-10) |
| `nickname` | local part of the email when present, else `sub` prefix (Plan 24 normalization) |
| `identities[0].profileData` | `is_private_email`, `real_user_status` |
| upstream tokens | Apple `access_token`, `refresh_token` (sealed; `read:user_idp_tokens`) |

## 8. Local rulings and observation points

| ID | Ruling |
|---|---|
| LR39a-1 | No developer keys; credentials required. |
| LR39a-2 | No Apple server-to-server notification endpoint. |
| LR39a-3 | No automatic Apple token revocation; tokens readable for the app. |
| LR39a-4 | `client_id` immutable. |
| LR39a-5 | `team_id` and `kid` format checked. |
| LR39a-6 | Only `name` and `email` scopes. |
| LR39a-7 | Client secret JWT lives 5 minutes. |
| LR39a-8 | `POST /login/callback` shared with Plan 36. |
| LR39a-9 | Native exchange picks the client's first enabled Apple connection. |
| LR39a-10 | Apple names are kept after the first login. |

Observe later (`docs/superpowers/plan-1-followups.md`):

- **A1** Whether Auth0 consumes Apple server notifications.
- **A2** Whether Auth0 revokes Apple tokens on user deletion.
- **A3** The Apple `subject_token_type` value.
- **A4** PKCE towards Apple.
- **A5** Native-exchange error wording.
- **A6** `event.transaction.protocol` for native exchanges.
- **A7** Log types for native social exchanges.

## 9. Storage, console, seed, Deploy CLI, tests

- **Storage:** migration 0037 adds typed client native-social persistence.
  Connection options and sealed secrets use Plan 24's columns;
  `native_social_login` uses a typed JSON column. `mobile` already persists
  through Plan 33b. Check migration numbering against main before merge. Plugins:
  the existing federation capability covers `apple`; client fields ride the
  existing client message (proto fields added, absent fields read as
  `null`).
- **Console:** Social → Apple create/detail (Services ID, Team ID, Key ID,
  `.p8` upload/paste, name/email switches); Application → Device settings:
  Native Social Login (Apple), iOS Team ID and bundle ID.
- **Seed:** the strategy and client fields; `app_secret` from a file or
  environment reference only, like other seed secrets.
- **Deploy CLI:** `apple` connections in the four-cell round trip
  (`app_secret` reinjected as other secrets), client fields round-trip.
- **Tests:** rules table; client-secret JWT shape and caching; web flow
  against a fixture Apple provider (form post with and without `user`,
  string and boolean `email_verified`, private relay email); native
  exchange (enabled/disabled, wrong bundle `aud`, Apple error, `user_profile`
  name on first login only); E2E `make e2e-apple` (new lane) with
  Playwright through the fixture and a raw native exchange from Node,
  node-auth0 connection CRUD, auth0-cli `connections` commands.
