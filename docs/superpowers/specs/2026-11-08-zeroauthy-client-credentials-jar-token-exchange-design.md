# Plan 35 — Client credentials, `private_key_jwt`, JAR and custom token exchange

**Date:** 2026-11-08. **Status:** design; not implemented.

**Roadmap entry:** [management roadmap, Plan 35](2026-10-19-zeroauthy-management-roadmap-design.md)
("short"); [v1 release scope §3–4](2026-11-02-zeroauthy-v1-release-scope.md).
Read the [clean-room policy](../../../CLEAN_ROOM.md), `AGENTS.md` (CI for plan
branches), [D-0035](../../compat/decisions.md) (request objects refused, lifted
here), D-0041 (resource-server signing), the [Actions guide](../../actions.md),
the [attack protection guide](../../attack-protection.md) and the
[logs guide](../../logs.md).

## 1. Outcome and scope

An operator registers a public key on an application. The application then
authenticates to `/oauth/token` and the other client-authenticated endpoints
with a signed JWT (`private_key_jwt`) instead of a client secret. With the same
kind of credential, the application signs its `/authorize` and `/oauth/par`
requests (JAR), and the operator can require signed requests. An operator
creates a token exchange profile that binds a `subject_token_type` to a
`custom-token-exchange` Action. An application then trades an external token
for zeroauthy tokens through the RFC 8693 grant, and the Action decides which
user the tokens are for. APIs can also use `HS256` (with a signing secret) and
`PS256` access tokens.

**Rule:** strict 1:1 with Auth0's documented behaviour (memory: Auth0 parity
first). Every behaviour traces to an Auth0 docs page (§2), the Management API
OpenAPI, an RFC, or a numbered local ruling (**LR35-n**, §9) recorded in
**D-0063**. Tenant observation is optional, as in Plans 32–34. Each
undocumented point gets a local answer now and an "observe later" entry
(**C1–Cn**, §9).

**Size:** the roadmap's "short". The client-authentication core (§3), JAR (§4)
and token exchange (§5) build on existing code: `internal/oauth/clientauth.go`,
`internal/authz` request parsing, PAR, the grant table, the Actions runner and
Plan 19's suspicious-IP buckets. They need no new subsystem.

### In scope

1. **Client credentials resource.** `/api/v2/clients/{id}/credentials`: list,
   create, get, patch (`expires_at` only), delete. Types `public_key` and
   `x509_cert`. Algorithms `RS256`, `RS384`, `PS256`.
2. **Client settings.** `client_authentication_methods.private_key_jwt.credentials`,
   `signed_request_object` (`required`, `credentials`), and
   `token_exchange.allow_any_profile_of_type`. Each is accepted on client
   create and patch (inline credential creation included, as Auth0 documents)
   and returned on read.
3. **`private_key_jwt` client authentication** at `/oauth/token` (every grant
   that authenticates a confidential client), `/oauth/revoke`, `/oauth/par`
   (LR35-1), `/mfa/challenge` and `/passwordless/start`.
4. **JAR.** A signed `request` parameter at `/authorize` and `/oauth/par`.
   `signed_request_object.required` is enforced. D-0035 is lifted: discovery
   now advertises request-object support. Unsigned (`alg: none`) request
   objects stay refused (LR35-4).
5. **Token exchange profiles.** `/api/v2/token-exchange-profiles`: list
   (checkpoint pagination), create, get, patch (`name`, `subject_token_type`),
   delete. The deletion guard on bound Actions is included.
6. **Custom token exchange.** The grant
   `urn:ietf:params:oauth:grant-type:token-exchange` at `/oauth/token` with a
   profile's `subject_token_type`. The `custom-token-exchange` Action trigger
   (deferred by Plan 28) supports the documented event and `api` members
   (§5.3). Then post-login runs, then tokens are issued.
7. **Custom token exchange attack protection.** The stored
   `suspicious-ip-throttling` stage `pre-custom-token-exchange` becomes live
   (Plan 19 owner). `api.access.rejectInvalidSubjectToken` counts against the
   source IP.
8. **Logs.** `secte` / `fecte`. `fcpk`-style client-authentication failure
   types, where the logs schema has them, are reused rather than invented.
9. **Resource-server signing.** `signing_alg` `HS256` (with `signing_secret`,
   generated when absent) and `PS256` join `RS256`. This lifts D-0041's
   RS256-only rule.
10. **Console, seed, Deploy CLI, docs.** Credentials and authentication method
    on the application page, and token exchange profiles. Seed-file support
    for credentials and profiles. A Deploy CLI round trip of the client fields
    and `tokenExchangeProfiles`, where Deploy CLI 9.1.0 has a handler. Operator
    guides.
11. **Plan 33b follow-ups (MFA cleanup).** The deferred review minors, as
    behaviour-neutral refactors with existing tests as the guard:
    1. MFA is evaluated once per finish/approve, not twice.
    2. The five copies of the `webauthn.v1` capability check become one helper.
    3. The DOMException name list is shared by the page scripts.
    4. Native passkey options use the configured ceremony timeout, not a
       literal `60000`.
    5. The challenge table is no longer used as KV storage. The one consumer
       gets a purpose-built column or table, decided at planning.
    6. A login page view no longer writes to the database when nothing
       changed.

    If any of them turns out not to be behaviour-neutral, the plan defers it
    again rather than growing (maintainer: keep MFA follow-ups small).

### Not in scope

- `cert_subject_dn` credentials, `tls_client_auth` and
  `self_signed_tls_client_auth` (mTLS). Refused with `400` until a later
  decision (roadmap §5).
- RAR (`authorization_details`).
- Auth0's other exchange types in the logs schema (on-behalf-of, `idjag_*`,
  `jwt_bearer_*`). They stay unlisted.
- `api.transaction.setMetadata` and `event.transaction.metadata` (Early
  Access). Refused as unknown members.
- `token_quota` on clients and organizations, and its quota headers. They
  move to Plan 48 (*my call*: token-lifetime and token-policy work already
  lives there).
- The RFC 8707 `resource` alias and CIMD client registration (Plan 41).
- **Actions MFA ordering.** A later `enable('none')` after an earlier
  challenge: the maintainer ruled (2026-11-08) to leave it as is.
- JWE access tokens (`token_encryption`) and DPoP / `proof_of_possession`.
  They stay null-only.
- Enterprise-plan gating. zeroauthy has no plans. Every feature is available
  to every tenant.

### Anti-goals

- **Client-assertion replay.** A `jti` accepted once must never be accepted
  again within the assertion's lifetime. The replay store is shared by every
  replica (store-backed, not process memory).
- **Signature algorithm downgrade.** Algorithms come from the credential, never
  from the JWT header alone. `none`, `HS*` and `ES*` assertions are refused. A
  header `alg` different from the credential's `alg` is refused.
- **Cross-client keys.** A credential is bound to one client. Verifying an
  assertion for client A never tries client B's keys.
- **Secrets in logs.** Client assertions, request objects, subject tokens and
  `signing_secret` never appear in logs, log streams or Action logs. Apply the
  key-name scrub at every log sink (memory: secrets never in logs).
- **Leaking which check failed.** Every client-authentication failure returns
  the same `invalid_client` description, as `clientauth.go` already does. The
  reason goes to the server log only.
- **A token exchange Action across tenants.** An Action runs in its own
  tenant's process only (memory: Actions tenant trust domain).

## 2. Evidence

Auth0 pages, read 2026-11-08:

- private_key_jwt: `/docs/get-started/authentication-and-authorization-flow/authenticate-with-private-key-jwt`
  and `/docs/get-started/applications/configure-private-key-jwt`.
- Credentials API: `/docs/api/management/v2/clients/post-credentials` and its
  siblings (get, list, patch, delete). Read the siblings at build time.
- JAR: `/docs/get-started/authentication-and-authorization-flow/authorization-code-flow/authorization-code-flow-with-jar`
  and `/docs/get-started/applications/configure-jar`.
- Custom token exchange: `/docs/authenticate/custom-token-exchange` (and its
  `configure-custom-token-exchange` and `cte-attack-protection` pages), the
  trigger page, and the event and api object references.
- Profiles API: `/docs/api/management/v2/token-exchange-profiles/*`.
- API settings: `/docs/get-started/apis/api-settings`.

RFC 7523 (JWT client assertions), RFC 9101 (JAR), RFC 8693 (token exchange),
RFC 7638 (JWK thumbprint, for generated `kid`s).

Black-box clients (memory: black-box Auth0 repos), all already pinned:

- `@auth0/auth0-auth-js` 1.16.1: `clientAssertionSigningKey` and
  `exchangeToken`. It covers the client-credentials, refresh and
  token-exchange lanes. node-auth0 7.4.0 has `clientAssertionSigningKey` only
  on `ManagementClient`.
- node-auth0 7.4.0: the credentials and token-exchange-profiles managers.
- auth0-cli 1.37.0.
- Deploy CLI 9.1.0, which has a `tokenExchangeProfiles` handler.

No version bump is planned. A bump needs the maintainer's approval.

## 3. Credentials and `private_key_jwt`

### 3.1 Credential resource

- **Create** (`create:client_credentials`). Body fields: `credential_type`
  (required; `public_key` | `x509_cert`; `cert_subject_dn` → 400, out of
  scope), `name` (≤128, default `""`), `pem`, `alg` (default `RS256`),
  `parse_expiry_from_cert`, `expires_at`, `kid`. Additional properties → 400.
- **`pem`.** An SPKI or PKCS#1 RSA public key, or an X.509 certificate. RSA
  modulus 2048–4096 bits. Anything else → 400 `invalid_body`.
- **`kid`.** Matches `^[0-9a-zA-Z-_]{10,64}$`. When absent, it is the RFC 7638
  thumbprint (base64url SHA-256).
- **Expiry.** `parse_expiry_from_cert` needs a certificate and excludes
  `expires_at`. Without either, the credential never expires (the docs' text
  wins over the OpenAPI's sample default; LR35-2).
- **Response fields.** `id` (`cred_` + random), `name`, `kid`, `alg`,
  `credential_type`, `thumbprint_sha256`, `created_at`, `updated_at`,
  `expires_at`. The PEM is never returned (C1: observe whether Auth0 returns
  it).
- **Limit.** At most **two** credentials per client. A third → 400 (C2: exact
  status and message).
- **Patch** (`update:credentials`). Only `expires_at` changes. Any other field
  → 400.
- **Delete.** Removes the credential and detaches it from both client
  settings. A client left with `private_key_jwt` and no credential cannot
  authenticate (C3: whether Auth0 refuses the delete instead).
- **Scopes.** `read:client_credentials`, `create:client_credentials`,
  `update:client_credentials` / `update:credentials`, and
  `delete:client_credentials`, as the OpenAPI lists them. Add them to the
  Management API scope inventory and the console's API grant UI.

### 3.2 Client settings

- `client_authentication_methods`: `{"private_key_jwt": {"credentials":
  [{"id": "cred_…"}]}}` or `null`. Inline `{credential_type, name, pem, alg}`
  entries on create/patch create the credential (configure page).
  `tls_client_auth` / `self_signed_tls_client_auth` → 400.
- **Mutual exclusion.** Setting `private_key_jwt` requires
  `token_endpoint_auth_method: null` in the same request or already stored.
  The pair is otherwise refused with 400 (C4: Auth0's exact behaviour).
  Reverting means `client_authentication_methods: null` plus a
  `token_endpoint_auth_method`.
- `signed_request_object`: `{required: bool, credentials: [{id}]}`, also with
  inline creation.
- `token_exchange`: `{allow_any_profile_of_type: ["custom_authentication"]}`.
  Other values → 400. Only first-party, OIDC-conformant clients may set it
  (LR35-6: refuse at write time; C5).
- Credentials referenced by a setting must belong to the client.
- The configure page warns against reusing one key for JAR and
  private_key_jwt. This is advice, not enforcement (local: allowed).

### 3.3 Verifying an assertion

`authenticateClient` gains a fourth method, `private_key_jwt`, selected when
the form carries `client_assertion_type =
urn:ietf:params:oauth:client-assertion-type:jwt-bearer`.

- **Combining methods.** Combined with Basic auth or `client_secret` → 400
  `invalid_request` (one method only, as today). With a `client_id` that
  differs from the assertion's `iss`/`sub` → 400.
- **Size limits.** The assertion is at most 2048 bytes. `iss`, `sub` and `jti`
  are at most 64 characters, and `alg` at most 16.
- **Header.** `alg` ∈ {RS256, RS384, PS256} and equal to the credential's
  `alg`. An optional `kid` selects a credential. Without one, try each of the
  client's `private_key_jwt` credentials that are unexpired and have the same
  `alg`.
- **Claims.**
  - `iss` = `sub` = client_id.
  - `aud` = the issuer URL with its trailing slash, for the host that received
    the request (canonical or custom domain).
  - LR35-3: also accept the exact URL of the endpoint that received the
    assertion. RFC 7523 allows it and several SDKs send it.
  - `exp` is required. `exp` − (`iat` or now) ≤ 5 minutes.
  - `iat`/`nbf` are optional, with 10 s leeway.
  - `jti` is required and single-use.
- **Replay.** `jti` is recorded per tenant and client until `exp` plus leeway,
  in the store (new table, migration 0036), with an expiry sweep. A duplicate →
  `invalid_client`.
- **Errors.** Every failure gives `401 invalid_client` with the shared
  description. Server logs carry the reason, never the assertion.
- **Logs.** The grant's existing failure log types apply. Note where the logs
  schema has a client-authentication-specific type (C6).
- **Effect on the rest of the request.** None. After authentication the
  client is handled exactly as a secret-authenticated confidential client,
  including grants, organizations and rate limits.

## 4. JAR (signed request objects)

- **Parsing.** `/authorize?request=<JWS>&client_id=…` and `/oauth/par` with
  `request` (the client authenticates with any of its methods).
  - `typ` ∈ {absent, `JWT`, `jwt`, `oauth-authz-req+jwt`}. LR35-5: accept
    absent too, since the docs list only two values and RFC 9101 recommends
    rather than requires.
  - `alg` ∈ {RS256, RS384, PS256}, matching a `signed_request_object`
    credential (selected by `kid` when present).
  - `none` → `request_not_supported` stays (LR35-4).
- **Claims.**
  - `iss` = client_id, and `client_id` equals the query's `client_id`.
  - `aud` = the issuer URL with its trailing slash.
  - `exp` in the future, `nbf` in the past (each with leeway), `iat` optional.
  - `jti` ≤ 64 bytes. LR35-7: single-use like a client assertion, from the
    same replay table.
  - Lifetime cap: 60 minutes (C7, the docs are silent).
- **Merging.** Parameters inside the object take precedence over the query
  (docs). The merged set is validated exactly like a plain authorize request,
  `redirect_uri` registration included.
- **Errors.** A bad signature or claims → `invalid_request_object`, delivered
  like other authorize errors (to the registered `redirect_uri` with `state`
  when they can be trusted, otherwise the error page). At PAR → `400
  invalid_request_object`.
- **`signed_request_object.required`.** An authorize or PAR request without a
  valid signed `request` → `invalid_request`. A `request_uri` from PAR
  satisfies it only when the pushed request was itself signed.
- **`request_uri` from other sources** (not PAR) stays unsupported:
  `request_uri_not_supported`, as today.
- **Discovery.**
  - `request_parameter_supported: true`.
  - `request_object_signing_alg_values_supported: ["RS256","RS384","PS256"]`.
  - `token_endpoint_auth_methods_supported` adds `private_key_jwt`.
  - `token_endpoint_auth_signing_alg_values_supported` gets the same three
    algorithms.
  - Update D-0035 and the conformance expected-skips (the unsigned request
    object module still passes by refusal).

## 5. Custom token exchange

### 5.1 Profiles

- **Fields.**
  - `name`: 3–50 characters.
  - `subject_token_type`: 8–100 characters, beginning `https://` or `urn:`.
    Reserved prefixes are refused: `http(s)://auth0.com`, `http(s)://okta.com`,
    `urn:ietf`, `urn:auth0`, `urn:okta`.
  - `action_id`: a deployed Action with trigger `custom-token-exchange`.
  - `type`: `custom_authentication`.
  - Additional properties → 400.
- **Uniqueness.** `subject_token_type` is unique per tenant → 409.
- **Immutability.** `action_id` cannot change after create.
- **Limit.** C8: the docs give no number. Local limit: 100 per tenant, with
  the documented 403 "limit of entities" response.
- **Ids.** `tep_` + random.
- **Errors.** The documented 400 messages: "Action is not deployed", "Action
  must have supported_triggers: custom-token-exchange", "Action not found".
- **Action deletion guard.** Deleting an Action bound to a profile is refused
  (the existing Actions delete returns a 400 conflict-style error; C9 for the
  exact wording).
- **Scopes.** `read:`, `create:`, `update:` and `delete:token_exchange_profiles`.

### 5.2 The grant

- **Request.** `POST /oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
  `subject_token`, `subject_token_type`, and optional `audience`, `scope`,
  `organization`, `actor_token`, `actor_token_type`, `requested_token_type`.
- **Client.** It must be first-party, OIDC-conformant, have `token_exchange`
  allowing `custom_authentication`, and authenticate with its registered
  method. Public clients (SPA, native) may use it with
  `token_endpoint_auth_method: none` (the attack-protection page anticipates
  them; C10).
- **Profile and API checks.**
  - Unknown `subject_token_type` → `400 invalid_request`.
  - The target API must allow skipping consent → otherwise `403
    access_denied` (C11: exact error).
- **Throttling.** The suspicious-IP stage `pre-custom-token-exchange` (default
  10 attempts, a 600000 ms rate) is checked before the Action. When blocked →
  `429 too_many_attempts` with the documented description.
- **Order.** Run the profile's Action (§5.3). Exactly one of
  `setUserById`/`setUserByConnection` must have been called, else
  `server_error`-class failure (C12). Then run post-login with the documented
  restrictions: `challengeWith`/`enrollWith`, `api.redirect.*` and
  `api.prompt.*` fail the exchange. Then issue tokens: access token, ID token
  when `openid` is in scope, and a refresh token under the usual
  `offline_access` and API rules, except none when `setActor` was used.
- **`act` claim.** When `setActor` was called, the access token carries an
  RFC 8693 `act` claim (nested up to 5 actors, ≤5 custom string, number or
  boolean properties per level).
- **Logs.** `secte` (with `actor` when set) and `fecte`. Login counters and
  `last_login` update as for any login (C13).

### 5.3 Trigger `custom-token-exchange`

- **Event.**
  - `client` (`client_id`, `metadata`, `name`).
  - `organization` (when requested and valid).
  - `request` (`geoip`, `hostname`, `ip`, `language`, `method`,
    `user_agent`; `body` empty, as the docs list).
  - `resource_server.identifier`.
  - `tenant.id`.
  - `transaction` (`subject_token`, `subject_token_type`, `actor_token`,
    `actor_token_type`, `actor_token_user` when the actor token is a valid
    same-tenant zeroauthy ID token, `requested_scopes`,
    `requested_token_type`).
  - `secrets`.
- **API.**
  - `access.deny(code, reason)` → the exchange fails with that error code
    (400).
  - `access.rejectInvalidSubjectToken(reason)` → `invalid_request` plus one
    throttle count.
  - `authentication.setUserById(id)`: the user must exist in this tenant.
  - `authentication.setUserByConnection(name, attrs, {creationBehavior,
    updateBehavior})`.
    - The attributes are the documented list, with `user_id` required.
    - Defaults are `create_if_not_exists` / `none` (C14).
    - Once the user exists, a changed `email`, `email_verified`, `phone`,
      `phone_verified` or `username` → error.
    - A custom DB in import mode supports only `setUserById`.
  - `authentication.setOrganization(idOrName)`.
  - `authentication.setActor(actor)`.
  - `user.setAppMetadata` / `setUserMetadata` (`null` deletes the key).
  - `cache.get` / `set` / `delete`, as in other triggers.
- **Plumbing.** The trigger joins `internal/actionsrules/inventory.json` (it
  is already listed as known), the runner's trigger table, the console's
  trigger list and the Deploy CLI trigger mapping. The trigger runs
  synchronously, before post-login.

## 6. Resource-server signing

- `signing_alg` ∈ {`RS256`, `HS256`, `PS256`}.
- **`HS256`.** Signs access tokens with the API's `signing_secret`. When the
  API is created with HS256 and no secret, generate a 32-byte random one
  (base64url). A supplied secret must be at least 16 characters (C15).
- **Secret storage and exposure.** The secret is sealed like client secrets.
  Read returns it (Auth0 returns it on read; C16).
- **`PS256`.** Signs with the tenant's RSA signing key. `/userinfo` and the
  tenant's own verifiers (`Keys.Verify`) accept PS256 as well as RS256 from
  that key.
- **`/userinfo` audience** (LR35-9, *my call*). An `openid`-scoped token for an
  HS256 API carries no `{issuer}userinfo` audience. The tenant cannot verify a
  secret-signed token, and no new trust path is added that looks up an API's
  secret by audience. RS256 and PS256 tokens keep the audience (C18).
- **JWKS.** Lists keys only, never secrets. The tenant key's JWK keeps
  `alg: RS256` (*my call*, believed to match Auth0; C19). If the E2E check with
  the pinned strict verifiers (`jose`, `jwks-rsa`) rejects PS256 against it,
  the builder drops `alg` from the JWK instead and records that in D-0063.
- **Changes after creation.** The api-settings page says the algorithm cannot
  be changed after creation. LR35-8: the Management API patch still accepts
  it, because the OpenAPI allows it and the dashboard limit is a UI rule.
  Tokens are signed with the current value (C17).
- **Supersedes** D-0041's RS256-only text in `management.yaml` and the
  compatibility matrix.

## 7. Storage

Migration **0036** (SQLite, PostgreSQL, MySQL) and the memory store:

- `client_credentials` (tenant, client, id, type, name, kid, alg, public key
  DER, thumbprint, expires_at, timestamps).
- `client_assertion_jtis` (tenant, client, jti hash, expires_at). It holds
  JAR `jti`s too.
- The client columns `client_authentication_methods`,
  `signed_request_object`, `token_exchange`.
- `token_exchange_profiles`.
- The resource-server column `signing_secret_sealed`.

**Plugin stores.** Gate everything behind a new store capability
`client_credentials.v1`, as `webauthn.v1` was. A store without it refuses the
new Management API writes with 501 and never selects `private_key_jwt`.

## 8. Console, seed, Deploy CLI, docs, tests

- **Console.**
  - Application → Credentials: list keys, add a PEM, remove a key, set the
    expiry.
  - Application → authentication method picker gains "Private Key JWT".
  - Application → "Require signed requests (JAR)".
  - Application → custom token exchange toggle.
  - Actions → Token Exchange Profiles (list, create, rename, delete).
  - API settings: algorithm choice at create; the HS256 secret shown once and
    revealable afterwards.
  - Rebuild `console/dist`.
- **Seed.** Clients accept `credentials` and the three settings. A top-level
  `token_exchange_profiles`.
- **Deploy CLI.** Round-trip the client fields. Round-trip
  `tokenExchangeProfiles` (9.1.0 has a handler).
- **Docs.**
  - New `docs/client-authentication.md` (private_key_jwt, JAR) and
    `docs/token-exchange.md`.
  - Update `actions.md`, `attack-protection.md`, `logs.md`,
    `compatibility.md` and the matrix.
  - D-0063 with the LR35 rulings. Amend D-0035 and D-0041.
- **Tests.**
  - Unit and contract tests per package.
  - SQL tests for migration 0036 on all three databases.
  - A new E2E suite `e2e-client-auth`:
    - auth0-auth-js with `clientAssertionSigningKey` for client credentials
      and refresh.
    - Verifying HS256 and PS256 access tokens with
      `express-oauth2-jwt-bearer`.
    - A JAR authorize plus PAR journey in Playwright.
    - A custom token exchange round trip with a deployed Action, a throttle
      lockout, an actor chain, and a refresh-token absence check.
    - The auth0-cli and Deploy CLI lanes where supported.
    - A representative-secret audit of the logs.
  - Add the suite to the CI matrix.
  - Optional: run the OIDF Basic plan's `private_key_jwt` client-auth variant
    (Plan 41 owns certification).

## 9. Local rulings and observation points

| Id | Ruling |
| --- | --- |
| LR35-1 | `/oauth/par` accepts `private_key_jwt` (not listed on Auth0's supported-endpoints page; PAR authenticates like the token endpoint per RFC 9126) |
| LR35-2 | No `expires_at` and no `parse_expiry_from_cert` → never expires (docs text over OpenAPI sample default) |
| LR35-3 | Assertion `aud` accepts the issuer URL with trailing slash **and** the exact endpoint URL |
| LR35-4 | Unsigned (`alg: none`) request objects stay refused with `request_not_supported` |
| LR35-5 | JAR `typ` may be absent |
| LR35-6 | `token_exchange` refused at write time for third-party or non-OIDC-conformant clients |
| LR35-7 | JAR `jti`, when present, is single-use |
| LR35-8 | `signing_alg` may be changed by Management API patch |
| LR35-9 | HS256 API tokens omit the `/userinfo` audience; PS256 and RS256 keep it |

Observe later, with a local answer meanwhile (§3–6):

- C1: whether the credential PEM is returned.
- C2: the error for a third credential.
- C3: deleting an attached credential.
- C4: `private_key_jwt` alongside a non-null `token_endpoint_auth_method`.
- C5: the `token_exchange` write rule.
- C6: the client-authentication log type.
- C7: the JAR lifetime cap.
- C8: the profile limit.
- C9: the Action delete wording.
- C10: public clients using custom token exchange.
- C11: the consent-skip error.
- C12: neither setUser call made.
- C13: login counters after an exchange.
- C14: the setUserByConnection defaults.
- C15: the minimum HS256 secret length.
- C16: whether the secret is returned on read.
- C17: tokens after a `signing_alg` change.
- C18: the `/userinfo` audience on HS256 tokens.
- C19: the JWK `alg` for PS256 signing.

## 10. Left to the builder

- Package layout:
  - Assertion verification probably lives beside `clientauth.go`, with a
    small JOSE helper shared with JAR. Prefer the JOSE library already in
    `go.mod`.
  - Credential parsing goes in its own package.
- Task order. A natural split: storage and credentials API → `private_key_jwt`
  → JAR → resource-server signing → profiles → grant and trigger →
  throttling and logs → console, seed and Deploy CLI → 33b cleanup →
  acceptance.
- Exact error wording where §9 lists an observation point, and the purpose
  table for item 11.5.
