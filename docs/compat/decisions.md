# Compatibility Decisions

Behaviors not specified by public documentation, and how zeroauthy resolves
them. Each entry: context, sources consulted, decision, rationale.

<!-- Template:
## D-0001: <title>
- **Context:**
- **Sources:**
- **Decision:**
- **Rationale:**
-->

## D-0001: Access tokens carry `jti`

- **Context:** Public Auth0 docs list the standard access token claims but do not say whether a token ID is included.
- **Sources:** RFC 9068 §2.2 (JWT access token profile requires `jti`); RFC 7519 §4.1.7.
- **Decision:** Every access token has a random 24-character `jti`.
- **Rationale:** It follows the JWT access token standard and enables future revocation lists. Clients that ignore unknown claims are unaffected.

## D-0002: client_credentials without an audience

- **Context:** A client_credentials request omits `audience` and the tenant has no default audience.
- **Sources:** RFC 6749 §5.2; Auth0 public docs describe `audience` as the target API and a tenant-level default audience.
- **Decision:** `400 invalid_request` with a description naming the missing audience.
- **Rationale:** The request lacks a required parameter, which is the definition of `invalid_request`.

## D-0003: Requested scopes that are not granted

- **Context:** The `scope` parameter names scopes the client grant does not include.
- **Sources:** RFC 6749 §3.3 (the server may issue a narrower scope and must then return `scope`), §5.2 (`invalid_scope`).
- **Decision:** Ungranted scopes are dropped and the response's `scope` lists what was issued. If none of the requested scopes are granted, respond `400 invalid_scope`.
- **Rationale:** Narrowing is standard; issuing a token with no requested permission is more likely a client bug than intent.

## D-0004: Strict token endpoint client authentication

- **Context:** A client authenticates with a method other than its registered `token_endpoint_auth_method`, or with two methods at once.
- **Sources:** RFC 6749 §2.3 ("MUST NOT use more than one authentication method in each request"); RFC 7591 §2 (`token_endpoint_auth_method`).
- **Decision:** A mismatched method → `401 invalid_client`. Two methods → `400 invalid_request`. The server log records the registered and used methods.
- **Rationale:** It follows the RFCs and avoids ambiguity about which credential was checked.

## D-0005: Session lifetime defaults

- **Context:** The spec requires absolute and idle session timeouts but does not give defaults.
- **Sources:** https://auth0.com/docs/manage-users/sessions/configure-session-lifetime-settings (public docs on tenant session lifetime settings).
- **Decision:** Default absolute lifetime 7 days and idle lifetime 3 days, overridable per tenant (`session_lifetime`, `idle_session_lifetime`, seconds). Every authenticated request slides the idle expiry, never past the absolute expiry.
- **Rationale:** These are conservative defaults for a hosted login session. Making them configurable covers deployments that need other values.

## D-0006: Authorization request validation choices

- **Context:** Several /authorize behaviors are not pinned down by public Auth0 docs.
- **Sources:** RFC 6749 §3.1.2 and §4.1.2.1; RFC 7636; OpenID Connect Core §3.1.2.1; OAuth 2.0 Security BCP (RFC 9700) §4.1 and §2.1.1.
- **Decision:**
  - `redirect_uri` must match a registered callback exactly, except for the single-label wildcard host form `https://*.domain/path` (https only). URIs with a fragment are rejected, as are wildcard URIs with userinfo. Private-use scheme callbacks (RFC 8252, e.g. `com.example.app:/oauth2redirect`) are accepted by exact match only. Seed validation rejects a wildcard whose domain has fewer than two labels (`https://*.com/cb`). A wildcard still matches every site under its domain, so operators must not register wildcards over domains they do not control (for example shared-hosting suffixes).
  - Public clients must use PKCE with `S256`; `plain` is rejected.
  - `prompt=consent` and `prompt=select_account` are accepted and ignored. All clients are first-party until the consent milestone.
  - With no `audience`, the tenant's default audience applies.
  - `organization` and `invitation` are rejected until Organizations are implemented.
- **Rationale:** Exact matching and mandatory S256 PKCE are the security BCP's recommendations. Rejecting organization parameters prevents tokens that silently lack an organization claim.

## D-0007: Hosted login transactions and brute-force protection

- **Context:** The spec requires CSRF-bound login transactions and per-IP/per-user brute-force protection with configurable lockout.
- **Sources:** OWASP Authentication and CSRF Prevention cheat sheets; RFC 6749 §10.12 (CSRF).
- **Decision:**
  - Each login transaction is a server-side record (15 minutes) bound to the browser by an `HttpOnly; Secure; SameSite=Lax` cookie `za_txn_<id>` on path `/u`, and to the form by a CSRF token.
  - After `security.login_max_attempts` (default 10) failures for one (tenant, connection, login) within `security.login_lockout_seconds` (default 900), that login is locked for the same period. Per IP, the limit is 10× higher.
  - Counters are in-process.
  - Failed logins show one message whether the account exists or not.
- **Rationale:** Server-side transactions keep the authorize request out of the browser. The cookie binding defeats login CSRF. The per-account lockout limits guessing without letting one IP lock out every account.

## D-0008: Authorization codes and user-flow tokens

- **Context:** Code lifetime, replay handling, and the audience of user-flow access tokens.
- **Sources:** RFC 6749 §4.1.2 and §10.5; OAuth 2.0 Security BCP (RFC 9700) §4.5; OpenID Connect Core §5.3.1; Auth0 public docs on calling /userinfo with an access token.
- **Decision:**
  - Codes live 60 seconds, are single-use, and are stored hashed. A replayed code is rejected with `invalid_grant` and logged; revoking descendant tokens comes with refresh tokens.
  - User-flow access tokens are JWTs:
    - `aud` holds the API identifier and, when `openid` is granted, `https://{host}/userinfo`.
    - Without an API, `aud` is the userinfo URL only, and clients must treat the token as opaque.
    - Granted scopes are the requested `openid`/`profile`/`email` plus requested scopes the API defines. No `gty` claim is added.
- **Rationale:** A short single-use code limits interception. JWTs for userinfo-only tokens avoid server-side token storage while behaving like opaque tokens to clients.

## D-0009: CORS for browser applications

- **Context:** SPAs call `/oauth/token` and `/userinfo` cross-origin. A preflight does not say which client is calling.
- **Sources:** Fetch Standard (CORS protocol); Auth0 public docs describing "Allowed Web Origins" and "Allowed Origins (CORS)" application settings.
- **Decision:**
  - Discovery and JWKS send `Access-Control-Allow-Origin: *`.
  - `/oauth/token` and `/userinfo` echo the `Origin` back if any client of the tenant lists it in `allowed_origins` or `web_origins`, and preflights reflect the requested headers.
  - Other origins get no CORS headers (403 on preflight).
  - Credentials (cookies) are never allowed cross-origin.
- **Rationale:** Client authentication still happens on the actual request. CORS only decides which browser origins may read responses.

## D-0010: Login pages allow the client's origin as a form-action target

- **Context:** The hosted login form posts to `/u/login`, which redirects (via `/authorize` processing) to the application's `redirect_uri`. Chromium applies the CSP `form-action` directive to the whole redirect chain after a form submission, so `form-action 'self'` blocks the final hop to another origin and the login appears to hang.
- **Sources:** Content Security Policy Level 3 (`form-action` and redirects); observed in Chromium running @auth0/auth0-spa-js against zeroauthy.
- **Decision:** `/u/login` and `/u/signup` pages (including their error re-renders) send `form-action 'self' <origin of the validated redirect_uri>`. For a native app's private-use `redirect_uri` (scheme matching `^[a-z][a-z0-9+.-]*$`, such as `com.example.app:/oauth2redirect`), the page sends `form-action 'self' <scheme>:` so the final hop is not blocked. `http`, `https` and executable or content schemes (`javascript`, `data`, `vbscript`, `file`, `blob`, `about`, `filesystem`) never become a scheme source; any other `redirect_uri` adds nothing.
- **Rationale:** The origin is taken from the already-validated, registered `redirect_uri` of the login transaction, so no attacker-controlled source is added.

## D-0011: Purging expired records

- **Context:** Login transactions, sessions, authorization codes and refresh tokens expire but were never removed. Unauthenticated `/authorize` requests create transactions, so storage grew without bound.
- **Sources:** RFC 6749 §10.5 (codes are short-lived and single-use); OAuth 2.0 Security BCP (RFC 9700) §4.5 (code replay).
- **Decision:** A sweeper runs every 10 minutes in `serve`. It deletes expired transactions, sessions and refresh tokens. Authorization codes are kept for 24 hours after they expire, so a replay within that time is still recognized and revokes the tokens issued from the code.
- **Rationale:** It bounds storage. The code retention keeps replay detection meaningful beyond the 60-second code lifetime.

## D-0012: Refresh token issuance, rotation and lifetimes

- **Context:** Public docs describe refresh token rotation, reuse detection and expiration settings. They do not pin down every condition for issuing a token or every default.
- **Sources:** RFC 6749 §6; OAuth 2.0 Security BCP (RFC 9700) §4.14 (refresh token protection) and §4.5 (code replay); https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation; https://auth0.com/docs/secure/tokens/refresh-tokens/configure-refresh-token-expiration.
- **Decision:**
  - **Issuance:** a refresh token is issued only when all of these hold:
    - `offline_access` is requested;
    - the client's `grant_types` include `refresh_token`;
    - either no API is the audience, or the API allows offline access.
    The response's `scope` then includes `offline_access`.
  - **Policy:**
    - `rotation_type` defaults to `rotating` for SPAs and `non-rotating` otherwise.
    - Rotating tokens must expire.
    - SPAs may not use non-expiring tokens.
    - Expiring tokens default to an absolute lifetime of 31557600 s (the documented maximum, since no default is documented) and an idle lifetime of 2592000 s (the documented default).
  - **Rotation:**
    - Each exchange returns a new token in the same family. It inherits the absolute expiry and starts a new idle period.
    - Presenting a rotated token again after the `leeway` (default 0 s) revokes the whole family and returns `invalid_grant`.
  - **Code replay:** a replayed authorization code revokes the family started from it.
- **Rationale:** These follow the documented settings and the security BCP. Rotation and reuse detection are a single atomic store operation, so concurrent requests cannot fork a family.

## D-0013: Token revocation

- **Context:** `/oauth/revoke` revokes refresh tokens. Public docs do not say what happens for a token issued to another client or for access tokens.
- **Sources:** RFC 7009 §2.1–2.2; RFC 6749 §5.2 (`invalid_grant` covers a grant "issued to another client"); https://auth0.com/docs/secure/tokens/refresh-tokens/revoke-refresh-tokens.
- **Decision:**
  - The client authenticates as at the token endpoint.
  - An unknown token returns `200` with an empty body.
  - A token issued to another client returns `400 invalid_grant` and is left untouched.
  - A known token revokes its whole rotation family.
  - `token_type_hint` is ignored. Access tokens are JWTs and are not revocable, so presenting one is the same as presenting an unknown token.
- **Rationale:** It follows RFC 7009. Family-wide revocation matches what reuse detection does, so a revoked login cannot continue through an earlier successor.

## D-0014: Logout

- **Context:** Public docs describe `/v2/logout` and `/oidc/logout` and their allowed logout URLs. Some edge cases are not covered: a request with no client and no return URL, what an invalid request does to the session, and refresh tokens.
- **Sources:**
  - https://auth0.com/docs/authenticate/login/logout/redirect-users-after-logout
  - https://auth0.com/docs/authenticate/login/logout/log-users-out-of-auth0
  - OpenID Connect RP-Initiated Logout 1.0 §2–§3
  - RFC 9700 §4.11 (open redirection)
- **Decision:**
  - Every logout request is validated before the session ends. An invalid request shows an error page (400), keeps the session, and never redirects.
  - **`/v2/logout`:**
    - `returnTo` is checked against the client's allowed logout URLs when `client_id` is present, otherwise the tenant's.
    - It is compared without its query string and fragment, with scheme and host case-insensitive. The single-label wildcard host form is allowed.
    - With `client_id` and no `returnTo`, the browser goes to the client's first non-wildcard allowed logout URL. With neither, a logged-out page is shown.
    - `federated` is ignored.
  - **`/oidc/logout`:** see D-0015.
  - Logout deletes the server-side session and clears the cookie. Refresh tokens are not revoked; applications revoke them at `/oauth/revoke`.
- **Rationale:** Validating first means a malformed or malicious link can neither redirect elsewhere nor log the user out while claiming failure. Keeping refresh tokens matches the public docs, which describe revocation as a separate step.
