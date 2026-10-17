# zeroauthy — Design: Pushed Authorization Requests (Plan 10)

- **Status:** Implemented (Plan 10)
- **Date:** 2026-10-16
- **Scope:** milestone 10, part 2 of 3 (spec §13). Plan 9 shipped consent; Plan 11 is the device flow. The maintainer chose the PAR core only (scope A): client-secret authentication, no `private_key_jwt`, mTLS, JAR or RAR.

## 1. Goal

A confidential client can push its authorization parameters to `POST /oauth/par` over the back channel, get a one-time `request_uri` that lives 30 seconds, and start the browser at `/authorize?client_id=…&request_uri=…`. A tenant can allow PAR, and a client can require it, the way Auth0 does.

**Success:**
- Unmodified express-openid-connect 3.4 and nextjs-auth0 4.32 apps configured for PAR log in through Chromium against zeroauthy. auth0-auth-js 1.16 builds its authorization URL through PAR and exchanges the code.
- A `request_uri` works once. Reuse, expiry or a client mismatch is refused.
- A client with `require_pushed_authorization_requests` cannot start a plain `/authorize` request.

## 2. Sources (clean room)

Auth0 public documentation:
- Authorization Code Flow with Pushed Authorization Requests (PAR)
- Configure Pushed Authorization Requests (PAR)

Also RFC 9126 (OAuth 2.0 Pushed Authorization Requests), RFC 6749 §5.2 and RFC 8414 (discovery metadata), the Auth0 changelog (reviewed 2026-10-16: no PAR entries; the 2025-10-10 Nuxt SDK beta lists PAR support), the open-source SDKs that send PAR (express-openid-connect, nextjs-auth0, auth0-auth-js), and observations on a tenant the maintainer owns (§6), under `CLEAN_ROOM.md` "Behavior testing against the maintainer's own tenant". PAR needs the Highly Regulated Identity add-on, which the maintainer's original tenant lacks; a new trial tenant offers it.

Documented facts this design follows:
- `POST /oauth/par`, `application/x-www-form-urlencoded`, string values, body at most 10 KB.
- Confidential clients only. Client Secret, Private Key JWT or mTLS authentication; the same method must be used at `/oauth/token`.
- Standard authorization parameters, plus up to 10 custom parameters prefixed `ext-`. Other custom parameters are ignored.
- `201 Created` with `request_uri` (`urn:ietf:params:oauth:request_uri:<opaque>`) and `expires_in`, which is a fixed 30 seconds.
- `/authorize` takes `client_id` and `request_uri`, validates the request again, and accepts each `request_uri` once and only before it expires.
- A tenant setting "Allow Pushed Authorization Requests (PAR)" is off by default. The client field `require_pushed_authorization_requests` can be turned on only after the tenant setting. Non-PAR requests from such a client are refused.

## 3. Data model

Seed YAML uses Auth0 Management API property names.

| Entity | Additions (default) |
|---|---|
| `Tenant` | Allow PAR (false). The property name comes from observation P7; the working name is `pushed_authorization_requests_supported`. |
| `Client` | `require_pushed_authorization_requests` (false). |
| `PushedAuthRequest` (new) | `TenantID`, `IDHash` (`secrets.HashToken` of the opaque part of the URN; the URN is never stored in plaintext), `ClientID`, `Params map[string]string` (the validated parameters, including kept `ext-*` parameters), `ExpiresAt`, `CreatedAt`, `UsedAt`. |

New repository `PushedAuthRequests`, keyed by (`TenantID`, `IDHash`), modelled on `AuthCodes`:
- `Create` returns `ErrConflict` if the hash exists.
- `Consume(tenantID, idHash, at)` atomically sets `UsedAt` and returns the request. A request already used returns `ErrAlreadyUsed`; an unknown one returns `ErrNotFound`. Expiry is checked by the caller against `ExpiresAt`, as for codes.
- `DeleteExpired(before)` removes expired requests in every tenant, used or not; the existing expiry sweeper calls it.

The repository is implemented in the memory, sqlite, postgres and mysql drivers (migration 0004) and in the gRPC plugin protocol (new `PushedAuthRequests` RPCs; tenant and client fields get new proto field numbers).

Seed validation:
- `require_pushed_authorization_requests: true` needs the tenant setting on.
- It is refused on clients whose `token_endpoint_auth_method` is `none`.

The lifetime is a constant, 30 seconds, not configurable.

## 4. Behaviour

### 4.1 `POST /oauth/par` (`internal/oauth`)

1. The body must be form-encoded and at most 10 KB. Repeated parameters are refused. Errors are `400 invalid_request`.
2. With the tenant setting off, the request is refused (P6).
3. The client authenticates with the existing token-endpoint authenticator (`client_secret_basic` or `client_secret_post`). A failure is `401 invalid_client`. A client whose method is `none` is refused (P3).
4. A `request_uri` parameter in the body is `400 invalid_request` (RFC 9126 §2.1).
5. The parameters go through the same validation `/authorize` uses, including Plan 9's strict third-party checks. If that validation is embedded in the handler today, it is split into a pure function shared by both endpoints. Failures are `400` JSON `{error, error_description}` with the `/authorize` error code; nothing is redirected (P2).
6. Known authorization parameters and up to 10 `ext-*` parameters are kept. Other unknown parameters are dropped. More than 10 `ext-*` parameters follow P2.
7. Success: a random 43-character identifier (`secrets.RandomString`, about 256 bits), prefixed `urn:ietf:params:oauth:request_uri:`; `201 {request_uri, expires_in: 30}` with `Cache-Control: no-store`.

Auth0 counts PAR calls against its Authentication API rate limit. zeroauthy has no general rate limiter yet (only per-identity throttles), so this is a follow-up.

### 4.2 `GET /authorize` with `request_uri` (`internal/authz`)

1. `client_id` must be present and name an existing client; otherwise the error page, as today.
2. The `request_uri` is consumed. Unknown, expired or already used: refused (P4). The pushed `client_id` must equal the query `client_id`; otherwise the error page.
3. The pushed parameters become the request. Query parameters other than `client_id` and `request_uri` follow P1 (default: ignored).
4. The request is validated again and the flow continues unchanged: session reuse, login, consent, code. `AuthTransaction.Params` is filled from the pushed parameters, so `/u/login`, `/u/consent` and resume need no change. Kept `ext-*` parameters ride along in the transaction; nothing reads them until Actions exist (sub-project 2).
5. Strict third-party clients keep refusing `request_uri` (Plan 9, D-0025), and a strict client cannot push either, because §4.1 step 5 applies the same checks. Observation P9 checks whether Auth0 lets a strict third-party client push; if it does, this changes.

A client with `require_pushed_authorization_requests` that sends `/authorize` without `request_uri` is refused (P5).

### 4.3 Discovery

When the tenant setting is on, the discovery document lists `pushed_authorization_request_endpoint`. Whether Auth0 also publishes `require_pushed_authorization_requests` and the request-parameter flags follows P8.

### 4.4 Token endpoint

No change. The client already has to authenticate the same way, and RFC 9126 does not bind the code to the pushed request.

## 5. Defaults for undocumented points

Each point has a default from RFC 9126 and the docs. Observation (§6) confirms or replaces it, and every outcome gets a decision (D-0028 onward) and a matrix note.

| # | Point | Default |
|---|---|---|
| P1 | `/authorize` with `request_uri` and extra query parameters | Only pushed parameters count; extras are ignored. |
| P2 | `/oauth/par` validation failures (bad `redirect_uri`, unsupported `response_type`, 11 `ext-*` parameters) | `400` JSON, `/authorize` error code; bad `redirect_uri` is `invalid_request`; too many `ext-*` is `invalid_request`. |
| P3 | Wrong secret; public client | `401 invalid_client`; public client `400 unauthorized_client`. |
| P4 | Reused or expired `request_uri` | Error page, no redirect, `invalid_request`. |
| P5 | Client requires PAR, plain `/authorize` | Error redirect `invalid_request` when `redirect_uri` is valid (subject to `redirection_policy`), else the error page. |
| P6 | `request_uri` in the PAR body; tenant setting off | `400 invalid_request` in both cases. |
| P7 | Management API name of the tenant setting | `pushed_authorization_requests_supported` |
| P8 | Discovery fields before and after enabling | `pushed_authorization_request_endpoint` appears only when enabled. |
| P9 | Strict third-party client calls `/oauth/par` | `400 invalid_request`, as for `request_uri` at `/authorize` (D-0025). |

## 6. Tenant observation (first task)

The first task writes `docs/compat/observations/par.md` with exact steps: a curl script for the back-channel calls and browser steps for `/authorize`. The maintainer runs them on the trial tenant (P6's "setting off" case on the original tenant) and reports only status codes, `error` values, redirect URL shapes and screen types. No messages, credentials, tenant identifiers or personal data are recorded. Later tasks use the observed values.

## 7. Testing

- **Unit:** `/oauth/par` validation table, authentication failures, size limit, `ext-*` cap, discovery fields; `/authorize` resolution: match, client mismatch, reuse, expiry, required PAR, extra query parameters; seed validation.
- **storetest:** `PushedAuthRequests` conformance on memory, sqlite, postgres, mysql and gRPC, including concurrent `Consume` (exactly one caller wins) and `DeleteExpired`.
- **E2E (new m10-par suite):**
  - express-openid-connect 3.4 with `pushedAuthorizationRequests: true`: full login in Chromium.
  - nextjs-auth0 4.32 with PAR enabled: login in Chromium.
  - auth0-auth-js 1.16: authorization URL through PAR, then code exchange.
  - Negative: a client requiring PAR sent to a plain `/authorize` in Chromium sees the P5 outcome. auth0-spa-js cannot drive this case: its clients are public, and only confidential clients can require PAR.

## 8. Documentation

- `docs/par.md` guide: enabling PAR on a tenant, requiring it per client, SDK configuration.
- Matrix rows for PAR, the tenant setting and the client setting; decisions D-0028 onward.
- Core spec §6.1 and §6.2 updated; §13 milestone 10 notes PAR shipped.
- Changelog review log row for this plan.
- Follow-ups: `private_key_jwt` client authentication (with the 2025-10-10 issuer-`aud` changelog item), JAR (`request` objects, `signed_request_object`), RAR (`authorization_details`), mTLS, PAR for public clients, Actions access to `ext-*` parameters.

## 9. Out of scope

`private_key_jwt`, mTLS, JAR, RAR, a configurable lifetime, and Actions access to `ext-*` parameters.
