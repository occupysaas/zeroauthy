# Plan 36 — Enterprise OIDC connections (`oidc`, `okta`, Entra extras, connection keys)

**Date:** 2026-11-16. **Status:** design; not implemented.

**Roadmap entry:** [management roadmap, Plan 36](2026-10-19-zeroauthy-management-roadmap-design.md)
("short"); [parallel paths](2026-11-13-zeroauthy-parallel-paths-design.md)
item **F1** (track F, first item; no open dependency: Plans 24 and 25 are
merged). Read the [clean-room policy](../../../CLEAN_ROOM.md), `AGENTS.md`
(CI for plan branches), the [Plan 24 social connections design](2026-10-26-zeroauthy-social-connections-design.md),
the [Plan 25 email-account design](2026-10-26-zeroauthy-email-account-connections-design.md),
the [social connections guide](../../social-connections.md) and
`internal/federation/inventory.json` (the frozen Plan 24 option contract).

## 1. Outcome and scope

An operator creates an enterprise OpenID Connect connection to a workforce
identity provider (any OIDC provider, or Okta by its domain), the way Auth0's
`oidc` and `okta` strategies work. The connection can use the back channel
(authorization code, today's Plan 24 subset) or the front channel
(`id_token` posted to `/login/callback`). It can find the provider by
discovery or by explicitly configured endpoints. It can map upstream claims
onto the user profile, read the provider's userinfo endpoint, authenticate to
the provider with a signed client assertion instead of a secret, and accept
encrypted ID tokens. The keys for that are managed through
`/api/v2/connections/{id}/keys`. Users whose email domain matches a
connection's `domain_aliases` are sent to that connection from the
identifier-first login page (home realm discovery). `waad` connections gain
`domain_aliases` and home realm discovery too.

**Rule:** strict 1:1 with Auth0's documented behaviour (memory: Auth0 parity
first). Every behaviour traces to an Auth0 docs page or the Management API
OpenAPI (§2), an RFC or OIDC specification, or a numbered local ruling
(**LR36-n**, §9) recorded in **D-0120** (the F1 block D-0120–0129 from the
parallel-paths design). Tenant observation is optional, as in Plans 32–35.
Each undocumented point gets a local answer now and an "observe later" entry
(**V1–Vn**, §9).

**Size:** the roadmap's "short". Everything builds on Plan 24's federation
core (`internal/federation`): attempts, pinned endpoints, discovery and JWKS
caches, ID token validation, profile normalization, identity index and sealed
token storage. No new subsystem; one new store repository (connection keys).

### In scope

1. **`oidc` options completed** (OpenAPI `ConnectionOptionsOIDC`):
   1. `type: front_channel` (Auth0's default when `type` is omitted, LR36-1)
      alongside `back_channel`.
   2. Explicit endpoints when no `discovery_url` is given: `issuer`,
      `authorization_endpoint`, `token_endpoint`, `jwks_uri`,
      `userinfo_endpoint`, and `oidc_metadata` (stored metadata that wins
      over discovery when non-empty).
   3. `attribute_map` (`mapping_mode` `bind_all` | `use_map`, `attributes`,
      `userinfo_scope`) with the `${context.tokenset.*}`,
      `${context.userinfo.*}` and `${context.connection.*}` template forms.
   4. `connection_settings.pkce` `auto` | `S256` | `plain` | `disabled`
      (today only `auto`/`s256`).
   5. `send_back_channel_nonce` `false` accepted (today rejected).
   6. `token_endpoint_auth_method` `client_secret_post` | `private_key_jwt`,
      `token_endpoint_auth_signing_alg`, `token_endpoint_jwtca_aud_format`.
   7. `id_token_signed_response_algs` (allowlist) and
      `id_token_encrypted_response_alg` / `id_token_encrypted_response_encs`.
   8. `enable_pushed_authorization_requests` and
      `pushed_authorization_request_endpoint` (upstream PAR, RFC 9126).
   9. `domain_aliases`, `tenant_domain` (stored), `icon_url`,
      `non_persistent_attrs`, `set_user_root_attributes`, `upstream_params`
      (still stored-only, as Plan 24).
2. **`okta` strategy** (OpenAPI `ConnectionOptionsOkta`): the same options as
   `oidc` back channel plus `domain`, minus `discovery_url` and `bind_all`.
   Issuer and discovery derive from `domain` (§3.2).
3. **Connection keys**: `GET /api/v2/connections/{id}/keys`,
   `POST /api/v2/connections/{id}/keys`,
   `POST /api/v2/connections/{id}/keys/rotate` for `oidc` and `okta`
   (signing and encryption keys). `samlp` joins in Plan 37 (F2) on the same
   repository.
4. **Home realm discovery** on the identifier-first login page from
   `domain_aliases` of enabled `oidc`, `okta` and `waad` connections (§5).
5. **Entra extras** for `waad`: `domain_aliases` (today rejected) and home
   realm discovery. Nothing else from Plan 25's rejected list moves (§1 Not
   in scope).
6. **`DELETE /api/v2/connections/{id}/users?email=`** for database
   connections (OpenAPI `delete_users_by_email`).
7. **`GET /api/v2/connections/{id}/status`**: the route exists and answers as
   Auth0 does for a connection that is not AD/LDAP (LR36-9). The AD/LDAP
   meaning arrives with F5 (Plan 38a).
8. **Console, seed, Deploy CLI, docs:** enterprise connection create/detail
   pages for `oidc` and `okta` (the Plan 16 preview under
   `console/src/pages/connections/enterprise` becomes live), a Keys tab,
   Login Experience (domains, button), seed-file support, Deploy CLI round
   trip of the new strategies, operator guide `docs/enterprise-connections.md`.

### Not in scope

- `dpop_signing_alg`: DPoP is in the roadmap's "not planned" list (§5). A
  non-null value is refused with `400` (LR36-6).
- `id_token_session_expiry_supported`: stored, not enforced (session expiry
  from the upstream needs the logout work of P3/Plan 41a).
- Okta Universal Logout and global token revocation
  (`/oauth/global-token-revocation/...`): moves to P3 (Plan 41a, logout).
- Okta Express Configuration (`express_configuration` clients, OIN
  provisioning): needs SCIM and self-service profiles, moves to F4.
- Entra Graph extras (`ext_groups`, `ext_profile`, `ext_nested_groups`,
  `api_enable_*`, `basic_profile`, `use_wsfed`): stay rejected. Groups land
  with directory groups in F4; `use_wsfed` with F3.
- SAML keys on the keys API: F2 adds `samlp` to the same routes.
- Identifier-first for organizations' own home realm discovery: Plan 30's
  discovery domains already route organization members; this plan does not
  change them (§5 says how the two meet).
- Connected accounts and Token Vault (P6).

### Anti-goals

- **Account takeover by email.** A front-channel or mapped profile never
  links to an existing user by email. Identity is the connection ID plus the
  upstream `sub`, exactly as Plan 24 (no change to the identity index).
- **Mapping over protected fields.** `attribute_map` never writes
  `user_id`, `identities`, `app_metadata`, `email_verified` unless the
  documented restricted-claims rule allows it (§4.3), `blocked`,
  `logins_count`, `last_login` or any zeroauthy-internal field.
- **Token confusion on the front channel.** A posted `id_token` is accepted
  only with the attempt's `state`, the exact `nonce`, an allowed signing
  algorithm and the pinned issuer; `alg: none` and `HS*` are always refused.
  A posted `code` on a front-channel attempt is refused.
- **Private keys leaving the server.** Connection private keys are sealed
  with the master key, never returned by any API, console page, seed export
  or Deploy CLI export, and never logged.
- **Secrets in logs.** Client assertions, ID tokens, userinfo bodies and
  upstream tokens never appear in logs, log streams or Action logs (memory:
  secrets never in logs). Add the new key names to the key-name scrub.
- **HRD as an enumeration oracle.** Home realm discovery answers only from
  the email domain, never from whether a user exists.
- **SSRF through endpoints.** Every configured or discovered URL goes through
  the existing federation `NetworkPolicy` (HTTPS only, no private ranges
  unless the operator's policy allows them, size and time limits).

## 2. Evidence

Auth0 pages and machine-readable sources, read 2026-11-16:

- Management OpenAPI: `https://auth0.com/docs/oas/management/v2/management-api-oas.json`
  — schemas `ConnectionOptionsOIDC`, `ConnectionOptionsOkta`,
  `ConnectionTypeEnumOIDC` (`back_channel` | `front_channel`, default
  `front_channel`), `ConnectionAttributeMapOIDC` / `...Okta`,
  `ConnectionMappingModeEnumOIDC` (`bind_all` | `use_map`),
  `ConnectionMappingModeEnumOkta` (`basic_profile` | `use_map`),
  `ConnectionConnectionSettingsPkceEnum` (`auto` | `S256` | `plain` |
  `disabled`), `ConnectionDomainAliases` (≤ 1000 items, DNS names or URIs,
  ≤ 256 characters), `PostConnectionKeysAlgEnum` / `RotateConnectionKeysSigningAlgEnum`
  (`RS256` `RS384` `RS512` `PS256` `PS384` `ES256` `ES384`),
  `ConnectionIdTokenEncryptedResponseAlgEnum` (`RSA-OAEP-256` `RSA-OAEP-384`
  `RSA-OAEP-512` `ECDH-ES` `ECDH-ES+A128KW` `ECDH-ES+A192KW` `ECDH-ES+A256KW`),
  operations `get_keys`, `post_keys`, `post_rotate`, `get_status`,
  `delete_users_by_email`.
- OIDC enterprise connections: `/docs/authenticate/identity-providers/enterprise-identity-providers/oidc`
  (front channel uses `response_type=id_token` with `response_mode=form_post`;
  back channel uses `code`; scopes must include `openid`; discovery documents
  limited to 128 KB; dashboard requires discovery, the API allows explicit
  URLs).
- PKCE and claim mapping: `/docs/authenticate/identity-providers/enterprise-identity-providers/configure-pkce-claim-mapping-for-oidc`.
- Okta Workforce connections: `/docs/authenticate/identity-providers/enterprise-identity-providers/okta`
  (read again at build time; the current page is about Express
  Configuration).
- Identifier-first and home realm discovery:
  `/docs/authenticate/login/auth0-universal-login/identifier-first`
  (enterprise connections, up to 1000 domains, match redirects to the IdP,
  no match continues to the password step).
- Connection keys: the three OpenAPI operations' descriptions (keys exist
  only for Okta, OIDC and SAML; encryption keys only for OIDC and Okta;
  `POST` is `409` once keys exist; rotating signing keys requires
  `private_key_jwt`; rotating encryption keys requires
  `id_token_encrypted_response_alg`).
- RFCs: 7523 (JWT client assertions), 9126 (PAR), 7516/7518 (JWE), OIDC
  Core 1.0 §3.2 (implicit `id_token`), OAuth 2.0 Form Post Response Mode.

## 3. Strategies and options

### 3.1 `oidc`

The `internal/federation/rules` validation keeps one authority. Changes
against the frozen Plan 24 inventory (inventory version 2):

| Option | Today | Plan 36 |
|---|---|---|
| `type` | `back_channel` only; `front_channel` rejected | both; omitted means `front_channel` (LR36-1) |
| `discovery_url` | required, immutable | optional when the explicit endpoint set is complete; immutable once set |
| `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `userinfo_endpoint` | rejected | accepted; required as a set when `discovery_url` is absent (`token_endpoint` only for back channel); HTTPS absolute URLs |
| `oidc_metadata` | rejected | accepted object (≤ 128 KiB, LR36-3); when non-empty it wins over discovery and is validated like a discovery document |
| `client_secret` | required | required for back channel with `client_secret_post`; not required (and refused, LR36-2) for front channel; optional with `private_key_jwt` |
| `scope` / `scopes` | `scopes` string required | `scope` is the documented space-separated string (OpenAPI); Plan 24's `scopes` stays accepted as an alias read-side compatible (V3) |
| `connection_settings.pkce` | `auto`, `s256` | `auto`, `S256` (case-insensitive, stored as sent), `plain`, `disabled` (§3.4) |
| `send_back_channel_nonce` | `true` only | boolean; default `true`; `false` omits the nonce on the back channel and skips nonce validation there; the front channel always uses a nonce |
| `token_endpoint_auth_method` | fixed (basic/post from discovery) | `null` keeps Plan 24's discovery choice; `client_secret_post` or `private_key_jwt` |
| `token_endpoint_auth_signing_alg` | rejected | one of the key algorithms; required with `private_key_jwt` (default `RS256`, V5) |
| `token_endpoint_jwtca_aud_format` | — | `issuer` (default) or `token_endpoint` |
| `id_token_signed_response_algs` | — | allowlist from `RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES384 ES512`; `null` means any of them; `none`/`HS*` never |
| `id_token_encrypted_response_alg` / `_encs` | — | §6.3 |
| `enable_pushed_authorization_requests`, `pushed_authorization_request_endpoint` | — | §3.5 |
| `attribute_map` | rejected | §4 |
| `domain_aliases` | rejected | §5 |
| `tenant_domain`, `useOauthSpecScope`, `non_persistent_attrs` | rejected / unknown | stored, not enforced (LR36-7) |
| `dpop_signing_alg` | unknown | non-null refused (LR36-6) |

Identity format stays `oidc|<connection-name>|<sub>` and `isSocial: false`.
Front and back channel produce the same identity for the same `sub`, so
switching `type` keeps users.

Changing `type`, endpoints, `oidc_metadata`, `token_endpoint_auth_method`,
the signing or encryption settings, the PKCE mode, scopes or the attribute
map is an effective authentication change: it increments
`FederationRevision`, so pending attempts of the old revision fail, as
today. `discovery_url` and `issuer` stay immutable after creation (the
pinned issuer guards the identity index).

### 3.2 `okta`

- `domain` is required: a DNS host name (no scheme, path or port), ≤ 253
  characters, lower-cased. Issuer is `https://<domain>`; discovery is
  `https://<domain>/.well-known/openid-configuration` (V1: Okta custom
  authorization servers `/oauth2/<id>` are reachable only through explicit
  `issuer` + endpoints).
- Back channel only (the OpenAPI type enum is `back_channel`).
- `attribute_map.mapping_mode` is `basic_profile` (default, the Plan 24
  standard claim normalization) or `use_map`; `bind_all` is refused, as the
  PKCE and claim mapping page states.
- Identity format `okta|<connection-name>|<sub>` (V2), `isSocial: false`.
- `domain` is immutable after creation (it pins the issuer).

### 3.3 `waad`

Only `domain_aliases` moves from rejected to accepted, with the shared HRD
validation (§5). The Plan 25 authority, tenant and identity rules are
unchanged.

### 3.4 PKCE modes

- `auto`: use `S256` when the provider's metadata lists it in
  `code_challenge_methods_supported`; `plain` when it lists only `plain`;
  no PKCE when the field is absent (LR36-4, V4).
- `S256` / `plain`: always sent with that method.
- `disabled`: no PKCE.
- Front channel never uses PKCE (no code).
- `plain` and `disabled` are documented values and are accepted for parity;
  the console marks them "weaker" and the guide says so. No zeroauthy-only
  refusal.

### 3.5 Upstream PAR

With `enable_pushed_authorization_requests: true` (back channel only, LR36-5),
the attempt start POSTs the authorization parameters to
`pushed_authorization_request_endpoint` (or the metadata's
`pushed_authorization_request_endpoint`), authenticated with the
connection's token endpoint method, and redirects the browser with only
`client_id` and `request_uri`. A PAR failure fails the attempt with the
existing upstream-error page; it never falls back to a front-channel request.

## 4. Profiles and attribute mapping

### 4.1 Sources

- `context.tokenset`: the validated ID token claims, plus `access_token`
  (the documented member).
- `context.userinfo`: the provider's userinfo response, fetched only when the
  map references `context.userinfo` (bounded by the inventory limits;
  `sub` must equal the ID token `sub`, otherwise the login fails).
- `context.connection.id` and `context.connection.strategy`.

### 4.2 Modes

- **Default (no `attribute_map`)** and Okta `basic_profile`: Plan 24's
  standard claim normalization, unchanged.
- **`bind_all`** (`oidc` only): every ID token claim (and userinfo claim when
  `userinfo_scope` is set) becomes a profile attribute of the same name,
  except restricted claims, which are dropped without failing the login (as
  documented). Non-root claims go to the user's root profile attributes the
  way Auth0's user profile shows federated attributes: the identity's
  `profileData` (V6).
- **`use_map`**: only the mapped attributes are set. Each value is a literal,
  a `${...}` reference, or a concatenation. A reference to a missing claim
  yields an empty string inside a concatenation and omits the attribute when
  it is the whole value (LR36-8).

### 4.3 Restricted claims and targets

The restricted list follows Auth0's documented restricted claims (the
"restricted claims" page, read at build time; V7). Map keys that are
restricted or zeroauthy-internal are refused at write time with `400`.
`email_verified` may be mapped only from a boolean upstream value.

### 4.4 Template grammar

- `${` path `}` where path is `context.tokenset.<name>`,
  `context.userinfo.<name>`, `context.connection.id`,
  `context.connection.strategy`; `<name>` is a claim name (letters, digits,
  `_`, `-`, `:`, `.`, `/` — a dot is part of the name, not traversal,
  because IdPs use URL claim names; V8).
- No other expression, function, escaping or nesting. Unknown roots are
  refused at write time.
- Limits: 100 attributes, 1024 bytes per template, result values bounded by
  the existing profile limits.
- Evaluation is pure Go (no JavaScript runner).

## 5. Home realm discovery

- Applies on the identifier-first page (`/u/login/identifier`, Plan 22)
  when the identifier is an email address.
- Candidates: enterprise connections (`oidc`, `okta`, `waad`; later `samlp`,
  `adfs`, `ad`) enabled for the client, with `domain_aliases`. Matching is
  exact on the lower-cased ASCII (IDNA) domain after the last `@`; no
  wildcard or subdomain matching (V9).
- One match: the flow starts that connection's upstream attempt with
  `login_hint` set to the email (LR36-10) and skips the password step.
- Several matches: the first in the client's connection order (Plan 15's
  enabled-client order, then connection name) wins (LR36-11, V9).
- No match: today's password step.
- Organizations: when the transaction has an organization, only that
  organization's enabled connections are candidates, and Plan 30's discovery
  domains are checked first (they already route members; unchanged).
- `domain_aliases` validation: ≤ 1000 entries, each a DNS name or URI per the
  OpenAPI pattern, ≤ 256 characters, lower-cased and de-duplicated on write.
  A domain may appear on several connections (Auth0 does not document a
  uniqueness rule).
- Identifier + password single-screen login does not use HRD (documented).
- `/authorize?connection=` and `login_hint` behave as today.

## 6. Connection keys

### 6.1 Resource

```
GET  /api/v2/connections/{id}/keys          read:connections_keys
POST /api/v2/connections/{id}/keys          create:connections_keys
POST /api/v2/connections/{id}/keys/rotate   create:connections_keys + update:connections_keys
```

- Strategies: `oidc`, `okta` (and `samlp` in F2). Others: `400`
  (V10: exact message).
- Key object: `kid`, `cert` (self-signed X.509 PEM, from `internal/keycert`),
  `pkcs` (PKCS#7 PEM), `current`, `next`, `previous`, `current_since`,
  `fingerprint` (SHA-1 colon hex, as the OpenAPI example), `thumbprint`
  (SHA-1 upper hex), `algorithm`, `key_use` (`signing` | `encryption`),
  `subject_dn` (`CN=<tenant domain>` style, V11).
- `POST` body `{key_use, signing_alg, encryption_alg}` (all optional;
  `key_use` defaults to `signing`, `signing_alg` to `RS256`,
  `encryption_alg` to `id_token_encrypted_response_alg` or `RSA-OAEP-256`).
  `409` when keys of that use already exist. `201` lists all keys.
- `rotate`: signing requires `token_endpoint_auth_method: private_key_jwt`;
  encryption requires `id_token_encrypted_response_alg`; otherwise `400`.
  The current key becomes `previous`; the `next` key (or a new one) becomes
  `current`; a fresh `next` key is made. `201` returns the new current key
  (OpenAPI response).
- Key types: RSA 2048 for `RS*`/`PS*` and `RSA-OAEP*`; P-256 / P-384 for
  `ES256`/`ES384` and P-256 for `ECDH-ES*` (LR36-12).
- A connection's keys are created lazily on the first use if the operator
  switches to `private_key_jwt` or sets an encryption algorithm without
  calling `POST` first (V12), so a connection never runs without a key.

### 6.2 `private_key_jwt` to the provider

The token request (and PAR request) carries
`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
and a JWT: `iss` = `sub` = `client_id`, `aud` = issuer or token endpoint per
`token_endpoint_jwtca_aud_format`, `jti` random, `iat`, `exp` = `iat` + 60 s,
header `kid` of the current signing key and `alg`
`token_endpoint_auth_signing_alg`. Auth0 documents only the keys API for
handing the public key to the provider, so operators register the `cert`
with the provider; zeroauthy publishes no new JWKS URL (LR36-13).

### 6.3 Encrypted ID tokens

With `id_token_encrypted_response_alg` set, the ID token must be a JWE
(compact, 5 parts) encrypted to a current or previous encryption key; its
`enc` must be in `id_token_encrypted_response_encs` when that list is
non-empty (`A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`, `A128GCM`,
`A192GCM`, `A256GCM`). An unencrypted ID token is refused when encryption is
configured (LR36-14). The decrypted payload is a JWS validated as today.
go-jose v4 (already in `go.mod`) does both.

## 7. Front channel

- Start: `response_type=id_token`, `response_mode=form_post`, `scope`,
  `state`, `nonce` (always), `client_id`, `redirect_uri` =
  `<origin>/login/callback`, plus `login_hint` from HRD.
- Callback: new `POST /login/callback` (form post) next to today's `GET`.
  The handler reads `state`, `id_token`, `error`, `error_description` from
  the form, then runs the same `FlowService.Complete` path with a
  `FrontChannelIDToken` instead of a code. The cookie binding of Plan 24
  needs `SameSite=None; Secure` for a cross-site POST; the attempt cookie for
  front-channel attempts is set that way (LR36-15), all others are
  unchanged.
- No upstream access or refresh token exists; identity token storage stores
  nothing for front-channel logins (`identities[].access_token` absent).
- `bind_all`/`use_map` with `context.userinfo` on the front channel: refused
  at write time (there is no access token to call userinfo; LR36-16).

## 8. Storage, console, seed, Deploy CLI, tests

### 8.1 Storage

- New repository `store.ConnectionKeys`: `List(tid, connID)`,
  `Create(tid, connID, use, keys []ConnectionKey)` (ErrConflict when that use
  already has keys), `Rotate(tid, connID, use, newNext ConnectionKey, now)`
  (atomic: previous dropped, current→previous, next→current, new next),
  `DeleteForConnection`. Private keys sealed (`keys.Seal...`), public cert
  stored in the clear.
- Migration (number taken at merge time; next free is 0037):
  `connection_keys` table in three dialects; `ON DELETE CASCADE` from
  connections; forward only.
- gRPC: capability `connection_keys.v1`, negotiated and latched like
  `client_credentials.v1`. Without it the keys API answers `501` and
  `private_key_jwt` / encryption options are refused on write.
- No change to the federation attempt table beyond a `ResponseType` field in
  `FederationEndpoints` (front/back) and `PARRequestURI` not stored (one
  request).

### 8.2 Console

- Enterprise → OpenID Connect and Okta: create (discovery URL or domain,
  channel, client ID/secret), Settings (endpoints shown from metadata,
  scopes, PKCE, client authentication), Mapping (mode, JSON editor with the
  template help, userinfo scope), Keys (list, create, rotate with
  confirmation, copy `cert`), Login Experience (domains, button name/logo,
  `show_as_button`).
- Microsoft (waad) social detail gains the Login Experience domains field.

### 8.3 Seed and Deploy CLI

- Seed: the new strategies and options; keys are never seeded (created on
  the destination, LR36-17).
- Deploy CLI 9.1.0 `connections` handler exports `oidc`/`okta` options; the
  four-cell round trip adds an `oidc` and an `okta` connection and drops them
  from `AUTH0_EXCLUDED`. Keys are not part of the Deploy CLI model.

### 8.4 Tests and E2E

- Unit: rules (every option row in §3.1), template grammar fuzz test, PKCE
  `auto` matrix, front-channel validation table, JWE accept/refuse table,
  client assertion shape, HRD matching.
- storetest: keys create/conflict/rotate atomicity, cascade on connection
  delete, one rotate winner under concurrency.
- E2E `make e2e-enterprise-oidc` (new lane, `run-m36-enterprise-oidc.sh`),
  reusing `tests/e2e/social/provider` (extended with front-channel form post,
  `private_key_jwt` verification against the published `cert`, JWE ID
  tokens, PAR and userinfo):
  - Playwright: HRD from identifier-first to the fixture IdP and back;
    front-channel login; back-channel `private_key_jwt` login; mapped profile
    visible in the console.
  - node-auth0 7.4.0: `connections.create` for `oidc`/`okta`,
    `connections.keys.get/create/rotate`, `connections.deleteUserByEmail`,
    `connections.checkStatus`.
  - auth0-cli 1.37.0: `auth0 api` for the keys routes.
  - Deploy CLI four-cell round trip.
  - Representative-secret scan of logs.

## 9. Local rulings and observation points

| ID | Ruling |
|---|---|
| LR36-1 | Omitted `type` on `oidc` means `front_channel` (OpenAPI default). Existing Plan 24 connections were all stored with `back_channel`, so no stored connection changes meaning; the migration writes `type: back_channel` explicitly into any stored `oidc` options that lack it. |
| LR36-2 | `client_secret` on a front-channel connection is refused with `400`, so an unused secret is never stored. |
| LR36-3 | `oidc_metadata` and discovery documents are capped at 128 KiB (documented discovery limit). |
| LR36-4 | PKCE `auto` without `code_challenge_methods_supported` sends no PKCE. |
| LR36-5 | Upstream PAR is back channel only. |
| LR36-6 | `dpop_signing_alg` non-null → `400` (DPoP not planned, roadmap §5). |
| LR36-7 | `tenant_domain` (oidc/okta), `useOauthSpecScope`, `non_persistent_attrs` are stored, not enforced, marked in the console. |
| LR36-8 | Missing claims in `use_map`: whole-value reference omits the attribute; inside a concatenation it becomes empty. |
| LR36-9 | `GET /connections/{id}/status` for a non-AD connection answers `404` with the "connection not found or offline" shape of the OpenAPI 404, until F5. |
| LR36-10 | HRD forwards the email as `login_hint`. |
| LR36-11 | Several HRD matches: the client's enabled-connection order wins. |
| LR36-12 | Key types per algorithm as in §6.1; RSA 2048. |
| LR36-13 | No JWKS URL is published for connection keys; operators register the `cert`. |
| LR36-14 | With encryption configured, an unencrypted ID token is refused. |
| LR36-15 | Front-channel attempt cookies use `SameSite=None; Secure`. |
| LR36-16 | Userinfo references are refused on front-channel connections. |
| LR36-17 | Connection keys are never seeded or exported. |

Observe later (copied into `docs/superpowers/plan-1-followups.md`):

- **V1** Okta custom authorization servers through `domain`.
- **V2** `okta` identity `user_id` format.
- **V3** Whether `scopes` is still accepted by Auth0 as an alias of `scope`.
- **V4** PKCE `auto` when metadata omits `code_challenge_methods_supported`.
- **V5** Default `token_endpoint_auth_signing_alg`.
- **V6** Where `bind_all` non-root claims appear on the user.
- **V7** The exact restricted-claims list for mapping.
- **V8** Claim names containing dots in templates.
- **V9** HRD subdomain matching and multiple matches.
- **V10** Keys API message for unsupported strategies.
- **V11** `subject_dn` format.
- **V12** Lazy key creation when `private_key_jwt` is set first.
- **V13** Delete-by-email when several users of one connection share the
  email (local: all are deleted) and the answer for an unknown email
  (local: `204`).

## 10. Left to the builder

- File layout inside `internal/federation` for the template evaluator and
  the JWE step.
- Console component split.
- Whether HRD lookups use an in-memory index per tenant or a store query
  (bounded by 1000 aliases × enabled connections either way).
