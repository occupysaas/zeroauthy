# zeroauthy — Sub-project 1 Design: Core, Authentication API, Hosted Login

- **Status:** Draft, awaiting review
- **Date:** 2026-10-13
- **Scope:** sub-project 1 of 4

## 1. Purpose

zeroauthy is an open-source, clean-room identity server that is wire-compatible with Auth0. "Drop-in" means an application that uses Auth0's open-source SDKs switches to zeroauthy by changing only the configured domain (and client credentials). No code changes and no SDK forks are needed.

The project's selling point is breadth of compatibility. That makes the wire contract the product: it is written down first, enforced in tests, and every behavior is traceable to a public source.

### 1.1 Sub-project decomposition

| # | Sub-project | Depends on |
|---|-------------|------------|
| **1** | **Core platform, Authentication API, hosted login** (this document) | none |
| 2 | Extensibility & federation: passwordless, MFA API, social/enterprise connections, Actions (embedded JS runtime), custom claims | 1 |
| 3 | Management API v2 (own spec-first contract), Organizations, admin console (Vue 3 SPA, §7.1) | 1 |
| 4 | SAML and WS-Federation | 1, 2 |

Each sub-project gets its own spec, plan, and implementation cycle.

### 1.2 Success criteria for sub-project 1

These clients work against zeroauthy unmodified, with only the domain and client credentials changed:

1. **auth0-spa-js / auth0-react:**
   - `loginWithRedirect` with PKCE
   - `getTokenSilently`, both with refresh tokens (rotation) and with the hidden-iframe `response_mode=web_message` + `prompt=none`
   - `logout`
2. **nextjs-auth0:** login, session, access token retrieval, logout.
3. **@auth0/auth0-auth-js `AuthClient`** (current) **and node-auth0 `auth0/legacy` `AuthenticationClient`** (v4 API): client credentials, refresh, password (realm), signup, change password, as each SDK supports them.
   - `oauth.passwordGrant` (including realm), `oauth.clientCredentialsGrant`, `oauth.refreshTokenGrant`
   - `database.signUp`, `database.changePassword`
4. **express-oauth2-jwt-bearer:** validates access tokens issued by zeroauthy.
5. **OpenID Foundation conformance suite:** passes the *Basic OP*, *Config OP* and PKCE test plans.

## 2. Clean-room policy

The policy lives in `CLEAN_ROOM.md` at the repo root and is restated in the PR template. In summary:

- **Allowed sources:**
  - Auth0's public documentation (`auth0.com/docs`)
  - The Apache-2.0 `aminya/auth0-openapi` description, attributed in `NOTICE`
  - IETF RFCs and OpenID Foundation specifications
  - Auth0's open-source SDKs, used only as black-box test clients
- **Prohibited:**
  - Decompiling, disassembling or inspecting Auth0 server software or proprietary assets
  - Probing live Auth0 tenants, except for firewalled Management API observation (below)
  - Capturing the Auth0 dashboard or hosted pages
  - Copying Auth0 UI templates, stylesheets, images or product copy
  - Using Auth0 trademarks beyond nominative "Auth0-compatible" statements
- **Firewalled Management API observation** (sub-project 3 onward): an *observer* calls documented Management API endpoints on a tenant they own and writes behavioral notes in their own words to `docs/compat/observations/`. *Implementers* work only from public docs and those notes. No verbatim messages, no credentials or personal data, no dashboard capture. The maintainer has accepted the terms-of-service risk; see `CLEAN_ROOM.md`.
- **Provenance:**
  - Every OpenAPI operation carries an `x-source` extension listing the public URL(s) it was derived from.
  - Behaviors that are not documented are resolved using RFC/OIDC semantics. Each such resolution gets an entry in `docs/compat/decisions.md`.
  - Known gaps are listed in `docs/compat/matrix.md`.

## 3. Architecture

A single static Go binary, `zeroauthy`, with these subcommands:

| Command | Purpose |
|---------|---------|
| `serve` | Run the HTTP server |
| `migrate` | Apply storage migrations for the configured driver |
| `seed` | Apply a declarative seed file (tenants, clients, APIs, connections, users) |
| `keys rotate` | Create a new signing key for a tenant and demote the current one to "previous" |

### 3.1 Package layout

```
cmd/zeroauthy/                 CLI entrypoint
api/authentication.yaml        hand-written OpenAPI 3.1 contract (source of truth)
internal/gen/authapi/          oapi-codegen output: types + chi ServerInterface (generated, committed)
internal/server/               router, middleware: tenant resolution, CORS, CSRF, rate limit,
                               request IDs, /docs (Scalar UI), /openapi.yaml, /healthz
internal/config/               koanf: YAML file + ZEROAUTHY_* env overrides; seed file loader
internal/tenant/               Host / custom-domain → tenant resolution and caching
internal/jose/                 signing keys (go-jose/v4), JWKS, envelope encryption at rest
internal/oauth/                /authorize, /oauth/token (grant handlers), /oauth/revoke,
                               /oauth/par, /oauth/device/code
internal/oidc/                 discovery, id_token construction, /userinfo, logout endpoints
internal/login/                hosted pages (/u/*), login sessions, html/template + embed
internal/identity/             connection strategies: database, custom-db bridge; password hashing
internal/email/                Mailer interface; SMTP and log (dev) implementations
internal/store/                repository interfaces, domain types, Tx
internal/store/memory/         in-memory driver
internal/store/sqlstore/       shared SQL driver with sqlite, postgres, mysql dialects + migrations
internal/store/grpcstore/      out-of-process driver host (hashicorp/go-plugin)
proto/store/v1/                gRPC protocol for external drivers
pkg/storetest/                 exported storage conformance suite (used by plugin authors)
web/templates/, web/static/    original templates and CSS, embedded in the binary
tests/e2e/                     docker-compose: SDK sample apps + Playwright; OIDF suite runner
```

`storetest` lives under `pkg/` rather than `internal/` because third-party plugin authors must be able to import it.

### 3.2 Request flow

```
request → request-id → tenant resolution → (CORS for API endpoints | CSRF for /u/* forms)
        → rate limit → [contract validation in tests] → handler → store / jose / identity
```

Tenant resolution maps the `Host` header to a tenant through the tenant's domain list. The default form is `{tenant}.{base_domain}`, and verified custom domains are also accepted. An unknown host returns `404`. Every store call carries the resolved `TenantID`, so no handler can query across tenants.

## 4. Data model (sub-project 1)

All entities are tenant-scoped (`tenant_id` is part of every key) except `Tenant` itself.

| Entity | Key fields |
|--------|-----------|
| Tenant | id, name, domains[], friendly_name, branding (logo URL, primary color), session lifetimes, default audience, default directory (connection name for password grant) |
| Client (application) | client_id, secrets[] (hashed, with created/expires for rotation), app_type (spa, regular_web, native, non_interactive), callbacks[], allowed_logout_urls[], web_origins[], allowed_origins[], grant_types[], token_endpoint_auth_method, refresh_token config (rotation, reuse interval, lifetimes), id_token lifetime, enabled connections[] |
| ResourceServer (API) | id, identifier (audience), name, scopes[], signing_alg (RS256), token_lifetime, token_lifetime_for_web, allow_offline_access, skip_consent_for_verifiable_first_party_clients |
| ClientGrant | client_id, audience, scopes[] (authorizes client_credentials) |
| Connection | id, name, strategy (`auth0` database, `custom-db`), enabled_clients[], options (password policy, require username, disable signup, custom-db endpoint config, import mode) |
| User | user_id (`auth0\|<id>` form for database users), email, email_verified, username, phone, name fields, picture, app_metadata, user_metadata, blocked, created/updated, last_login, logins_count |
| Identity | user_id, connection, provider, provider user id, credential (password hash, hash algorithm) |
| LoginSession | id, user_id, authenticated_at, amr, connection, expires, idle_expires, client_ids[] (used for logout and `prompt=none`) |
| AuthorizationCode | code hash, client_id, redirect_uri, user_id, session_id, scope, audience, nonce, PKCE challenge + method, auth_time, expires (single-use) |
| RefreshToken | token hash, family_id, client_id, user_id, session_id, scope, audience, rotated_at, revoked, expires, idle_expires |
| DeviceCode | device_code hash, user_code, client_id, scope, audience, status, user_id, interval, expires |
| PushedAuthRequest | request_uri, client_id, params, expires |
| SigningKey | kid, tenant_id, alg, status (next / current / previous / revoked), encrypted private key, public JWK, created |

Token secrets (codes, refresh tokens, device codes) are stored as SHA-256 hashes, never in plaintext.

## 5. Storage bridge

### 5.1 Layer 1: internal repository interfaces

`internal/store` defines narrow interfaces per aggregate: `Tenants`, `Clients`, `ResourceServers`, `ClientGrants`, `Connections`, `Users`, `Sessions`, `AuthCodes`, `RefreshTokens`, `DeviceCodes`, `PARs`, `SigningKeys`. A `Store` aggregates them and offers `WithTx(ctx, func(Store) error)`.

Each operation that has to be atomic is a single method that drivers implement atomically, for example:
- `AuthCodes.Consume`: single use
- `RefreshTokens.Rotate`: rotation plus reuse detection
- `DeviceCodes.Poll`

Correctness therefore does not depend on callers composing transactions.

The driver is selected by DSN:

| DSN | Driver |
|-----|--------|
| `memory://` | in-memory (tests, demos) |
| `sqlite:///path/zeroauthy.db` | `modernc.org/sqlite` (pure Go; keeps the binary CGO-free) |
| `postgres://…` | `pgx/v5` |
| `mysql://…` | `go-sql-driver/mysql` |
| `plugin:///path/to/binary?arg=…` | external gRPC driver |

`sqlstore` holds hand-written SQL shared across dialects. A small dialect type covers placeholders, upsert syntax, JSON columns, and `RETURNING` support. Migrations are embedded per dialect and applied by `zeroauthy migrate`, or at `serve` start when `storage.auto_migrate: true`.

### 5.2 Layer 2: external driver plugins

`proto/store/v1` mirrors the repository interfaces as a gRPC service. `grpcstore` launches the plugin binary through `hashicorp/go-plugin`, handshakes, and adapts the gRPC client to the `store.Store` interface. Transactions are not offered across the plugin boundary; plugins must implement the atomic methods themselves. Plugin authors run `pkg/storetest` against their driver; CI runs it against a sample plugin backed by the memory driver.

### 5.3 Layer 3: legacy user-store bridge (`custom-db` connection)

This is the equivalent of Auth0's Custom Database Connections, built on webhooks. Each connection configures a base URL and an HMAC signing secret. zeroauthy sends a signed JSON `POST` to these operations:

| Operation | Purpose |
|-----------|---------|
| `login` | Verify credentials, return the user profile |
| `get_user` | Look up by email or username (signup checks, password reset) |
| `create` | Create a user in the legacy store |
| `verify` | Mark the email as verified |
| `change_password` | Set a new password |
| `delete` | Remove the user |

Request and response details:
- Requests carry `X-Zeroauthy-Signature` (HMAC-SHA256 over timestamp + body) and `X-Zeroauthy-Timestamp`.
- Responses are JSON profiles.
- Webhook calls have a timeout of 5 s by default.

**Import mode:** when enabled (`options.import_mode: true`), a user who logs in successfully is copied into zeroauthy's store with their password re-hashed. Later logins use the local store, so the legacy database can be retired gradually. A JS-script variant comes with the Actions runtime in sub-project 2.

## 6. Authentication API

The full contract is in `api/authentication.yaml`.

### 6.1 Endpoints in scope

| Endpoint | Notes |
|----------|-------|
| `GET /.well-known/openid-configuration` | Per-tenant discovery document |
| `GET /.well-known/jwks.json` | Current, next and previous public keys |
| `GET /authorize` | See 6.2 |
| `POST /oauth/token` | See 6.3 |
| `POST /oauth/revoke` | Revokes a refresh token (and its family). RFC 7009 semantics: `200` even when the token is unknown. |
| `POST /oauth/par` | RFC 9126; returns `request_uri` + `expires_in` |
| `POST /oauth/device/code` | RFC 8628; returns `device_code`, `user_code`, `verification_uri(_complete)`, `expires_in`, `interval` |
| `GET\|POST /userinfo` | Bearer access token whose audience includes `https://{domain}/userinfo`; returns OIDC standard claims according to scope |
| `GET /v2/logout` | Ends the session; redirects to `returnTo` only if it matches the client's (or tenant's) allowed logout URLs |
| `GET\|POST /oidc/logout` | OIDC RP-Initiated Logout (`id_token_hint`, `post_logout_redirect_uri`, `state`, `client_id`, `logout_hint`) |
| `POST /dbconnections/signup` | Creates a database (or custom-db) user; returns the created user profile |
| `POST /dbconnections/change_password` | Sends a reset email (single-use link, 24 h). Matches by email address only. An unknown user gets the same 200 plain-text answer and no email, as the auth0-auth-js README documents (the maintainer chose this over the API reference's 404; D-0018); the hosted 'Forgot password?' page behaves the same way. |

**Deferred:** `/passwordless/*`, `/mfa/*`, `/samlp/*`, `/wsfed/*`, `/oidc/register`, `/co/authenticate`, `/login/callback`.

**Never implemented** (deprecated by Auth0): `/oauth/ro`, `/delegation`, `/tokeninfo`, `/oauth/access_token`, `/users/{id}/impersonate`.

### 6.2 `/authorize`

**Parameters:**

| Parameter | Handling |
|-----------|----------|
| `response_type` | `code`, `id_token`, `token id_token` |
| `client_id`, `redirect_uri`, `scope`, `state`, `nonce` | Standard OIDC |
| `audience` | Selects the resource server; if absent, the tenant default audience is used |
| `response_mode` | `query`, `fragment`, `form_post`, `web_message` |
| `prompt` | `none` or `login` |
| `max_age` | Standard OIDC |
| `connection` | Picks the connection |
| `screen_hint` | `signup` |
| `login_hint` | Pre-fills the login form |
| `code_challenge`, `code_challenge_method` | `S256`; `plain` is rejected |
| `request_uri` | From PAR |
| `organization`, `invitation` | Accepted but rejected with `invalid_request` until sub-project 3 |
| unknown parameters | Ignored, which keeps SDK telemetry parameters working |

**Validation order:**
1. `client_id` exists.
2. `redirect_uri` exactly matches a registered callback. Wildcard subdomains are supported in the documented form.
3. If either check fails, render an error page and do not redirect.
4. All other errors redirect to the client using the selected `response_mode`.

**Flow:**
1. If a valid login session exists and no re-authentication is forced, issue the response directly.
2. Otherwise redirect to `/u/login?state=<transaction>`, unless `prompt=none` was requested, in which case return the error `login_required`.

**`web_message`:** returns an HTML page that `postMessage`s `{type: "authorization_response", response: {...}}` to the client's registered web origin. It is used for silent authentication inside an iframe. Session cookies are `SameSite=None; Secure` so they reach the iframe.

**Consent:** first-party clients skip consent. Third-party clients see a consent page for the requested scopes, and the grant is remembered.

### 6.3 `/oauth/token`

Bodies are accepted as `application/x-www-form-urlencoded` or `application/json`.

**Client authentication** follows the client's `token_endpoint_auth_method`:
- `client_secret_post`
- `client_secret_basic`
- `none`: public clients, which must use PKCE for `authorization_code`

**Grants:**

| grant_type | Behavior |
|------------|----------|
| `authorization_code` | Consumes the code once. Checks `redirect_uri` and the PKCE verifier. Returns `access_token`, `id_token` (if `openid`), `refresh_token` (if `offline_access` and allowed), `token_type: Bearer`, `expires_in`, `scope`. A reused code revokes the tokens issued from it. |
| `refresh_token` | With rotation enabled, issues a new refresh token and invalidates the old one. Reuse outside the configured leeway revokes the whole family. Scopes may be narrowed. |
| `client_credentials` | Requires a ClientGrant for the `audience`; scopes are capped by that grant. |
| `password` | Uses the tenant's default directory connection. |
| `http://auth0.com/oauth/grant-type/password-realm` | `realm` names the connection. |
| `urn:ietf:params:oauth:grant-type:device_code` | Returns `authorization_pending` or `slow_down` while waiting, `expired_token`, and `access_denied`. |

### 6.4 Tokens

**Issuer:** `https://{tenant domain}/` (with trailing slash). Tokens are signed with the tenant's current RS256 key, and the `kid` is in the header.

**Access token (JWT) claims:**

| Claim | Value |
|-------|-------|
| `iss`, `sub`, `iat`, `exp` | Standard |
| `aud` | The API identifier. Becomes an array when `openid` is requested, adding `https://{domain}/userinfo`. |
| `azp` | Client ID |
| `scope` | Space-delimited |
| `gty` | Present for non-interactive grants, e.g. `client-credentials`, `password` |

For `client_credentials`, `sub` is `{client_id}@clients`.

**ID token claims:** `iss`, `sub`, `aud` (client_id), `iat`, `exp`, `auth_time`, `nonce`, `sid`, `at_hash`/`c_hash` where required, and profile/email claims according to scope.

**Opaque access tokens:** issued when there is no audience and only `openid` scopes are requested. They are valid only at `/userinfo`.

**Lifetimes:** taken from client and resource-server configuration. Defaults: access token 86400 s, id token 36000 s.

### 6.5 Errors

API endpoints return JSON `{ "error": "...", "error_description": "..." }`.

| Status | Errors |
|--------|--------|
| 400 | `invalid_request`, `invalid_grant`, `unsupported_grant_type`, `invalid_scope` |
| 401 | `invalid_client` (with `WWW-Authenticate` when Basic auth was used) |
| 403 | `unauthorized_client`, `access_denied` |
| 429 | `too_many_requests` |

`/dbconnections/*` use the error shapes documented for those endpoints.

## 7. Hosted login (`/u/*`)

Server-rendered `html/template` pages embedded in the binary, with progressive enhancement and no JS build step. Pages:
- `/u/login`
- `/u/signup`
- `/u/reset-password` (request and complete)
- `/u/device` (enter the user code)
- `/u/consent`
- An error page

**Branding:** a tenant logo and primary color via CSS variables. A configurable override directory lets operators replace templates entirely. All templates and copy are original work.

**Login transaction:** `/authorize` stores a short-lived, signed transaction (state cookie plus server-side record). Login completes it, creates or extends a `LoginSession`, and resumes the authorize response.

**Security:**
- **Session cookie:** HttpOnly, Secure, `SameSite=None` (needed for `web_message`), with separate absolute and idle timeouts.
- **Forms:** CSRF tokens (double-submit, bound to the transaction).
- **Headers:** strict CSP (nonce-based); `frame-ancestors 'none'` everywhere except the `web_message` response.
- **Brute-force protection:** per IP + per user, with exponential backoff and a configurable lockout.
- **Password hashing:** argon2id (tunable). Imported bcrypt hashes are verified and upgraded to argon2id on login.
- **Password policy:** per connection (minimum length, character classes, no reuse of the last N passwords).

### 7.1 UI technology boundary

zeroauthy has two user interfaces, built with different technology on purpose:

| UI | Technology | Sub-project | Why |
|----|-----------|-------------|-----|
| Hosted login (`/u/*`, and later MFA, passwordless, organization pickers) | Server-rendered Go `html/template` | 1 (grows in 2) | It is the most attacked surface, so it stays minimal: strict nonce-based CSP, no JS bundle, almost no supply chain. Silent authentication (`web_message`) must render in a cross-site iframe without client JS. Operators can theme it by overriding templates, with no build toolchain. The screens grow in number, not complexity. |
| Admin console (equivalent of a management dashboard) | Vue 3 + Vite + TypeScript SPA | 3 | It is a large, stateful app (tables, filters, editors for users, applications, APIs, connections, logs), which is where a component framework pays off. |

Admin console rules:
- **API boundary:** the console talks only to the Management API, through a TypeScript client generated from zeroauthy's own management OpenAPI contract (the same spec-first approach as the server). It has no private backend endpoints.
- **Packaging:** the production build is embedded in the Go binary and served under `/admin`, so self-hosting stays a single binary. Node is needed only to build it.
- **Origin:** its own login uses the hosted login pages via authorization code + PKCE like any other SPA client.
- **Clean room:** the dashboard UI is original work; it is never modeled on captures of Auth0's dashboard (see `CLEAN_ROOM.md`).

## 8. Keys and secrets

- Each tenant has its own RS256 key pairs with the lifecycle `next → current → previous → revoked`. JWKS publishes next, current and previous.
- Private keys are encrypted at rest with AES-256-GCM. The data key is wrapped by a master key from `ZEROAUTHY_SECURITY__MASTER_KEY` or a key file. KMS integrations can implement the `KeyWrapper` interface later.
- Client secrets are stored hashed (argon2id). Secret rotation keeps old and new secrets valid during an overlap window.

## 9. Configuration

Configuration comes from a YAML file with `ZEROAUTHY_*` environment overrides (koanf).

```yaml
server:
  listen: ":8080"
  base_domain: auth.example.com     # tenants at {name}.auth.example.com
  trust_proxy_headers: true
storage:
  dsn: sqlite:///var/lib/zeroauthy/zeroauthy.db
  auto_migrate: true
security:
  master_key_file: /etc/zeroauthy/master.key
email:
  driver: smtp                       # or "log" (default; redacts reset links) or "dir"
  # log_links: true                  # log driver only: print reset links in full (local development)
  smtp: { host: …, port: 587, username: …, from: "no-reply@example.com" }
seed: /etc/zeroauthy/seed.yaml       # optional declarative tenants/clients/APIs/connections/users
```

The seed file is idempotent: it upserts by natural keys. Until the Management API exists (sub-project 3), the seed file is how tenants and clients are administered.

## 10. OpenAPI and documentation

- `api/authentication.yaml` (OpenAPI 3.1) is the source of truth. It is written by hand from public docs, and each operation has an `x-source`.
- `oapi-codegen` generates request/response types and a chi `ServerInterface`. The generated code is committed, and `go generate ./...` regenerates it; CI fails if the regenerated output differs.
- `GET /openapi.yaml` serves the spec. `GET /docs` serves an embedded Scalar API reference, which renders markdown in descriptions.
- Redirect- and HTML-producing endpoints (`/authorize`, logout, `/u/*`) are described in the spec but implemented as plain handlers where code generation does not fit.

## 11. Observability and operations

- Structured logging via `log/slog`, JSON by default, with request IDs.
- A tenant log-event stream (login success/failure, signup, token exchange), stored through the store interface so that the future Management API logs endpoint can read it.
- `/healthz` (liveness) and `/readyz` (store reachable).
- Graceful shutdown.

## 12. Testing strategy

| Layer | What | Tooling |
|-------|------|---------|
| Unit | Grants, PKCE, claims, rotation and reuse detection, redirect URI matching, tenant isolation, password hashing | `go test`, TDD |
| Contract | Every integration test request/response validated against `api/authentication.yaml` | kin-openapi |
| Storage | `pkg/storetest` against memory, sqlite, postgres, mysql, and the sample gRPC plugin | testcontainers-go |
| E2E | Sample apps for each SDK in §1.2, driven by Playwright | docker compose |
| Conformance | OIDF Basic OP, Config OP, PKCE plans | OIDF suite container in CI |

## 13. Milestones (input to the implementation plan)

1. Repo skeleton, config, store interfaces, memory driver, `storetest`, CI.
2. JOSE keys, tenant resolution, discovery, JWKS, `/docs`.
3. `client_credentials` and access token issuance. **E2E:** express-oauth2-jwt-bearer.
4. Hosted login, sessions, database connection, `authorization_code` + PKCE, id_token, `/userinfo`. **E2E:** auth0-spa-js.
5. Refresh token rotation, `web_message` / `prompt=none`, `/v2/logout`, `/oidc/logout`. **E2E:** auth0-react, nextjs-auth0.
6. `password` and `password-realm` grants, `/dbconnections/*`, email, reset flow. **E2E:** node-auth0.
7. SQL drivers (sqlite, postgres, mysql) passing `storetest`.
8. gRPC plugin host and sample plugin.
9. `custom-db` bridge with import mode.
10. Device flow, PAR, consent.
11. OIDF conformance in CI; compatibility matrix published.

## 14. Risks

- **Legal:** API compatibility has generally been treated as permissible, but the clean-room discipline and provenance trail are what protect the project. Get a legal review before the public launch. The project name and branding must not imply affiliation with Auth0.
- **Undocumented behavior:** exact parity is impossible where Auth0 behavior isn't documented. Each gap is logged as a decision and appears in the public matrix.
- **SDK drift:** SDK versions are pinned in e2e tests, and a scheduled job runs the latest versions to catch regressions.
- **Plugin boundary:** cross-call transactions aren't available to external drivers. This is mitigated by designing the atomic operations as single methods (§5.1).
