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

## D-0015: RP-Initiated Logout (`/oidc/logout`)

- **Context:** Public docs list the `/oidc/logout` parameters, a confirmation prompt when no hint matches the session, exact matching of `post_logout_redirect_uri`, and errors for inconsistent hints. They do not say how the confirmation is protected or how expired hints are treated.
- **Sources:** OpenID Connect RP-Initiated Logout 1.0 §2–§3; https://auth0.com/docs/authenticate/login/logout/log-users-out-of-auth0; OWASP CSRF Prevention Cheat Sheet.
- **Decision:**
  - **Hints:**
    - `id_token_hint` must be signed by the tenant's published keys and carry the tenant issuer. Expiry is ignored.
    - Its single audience names the client, and must equal `client_id` if both are sent.
    - Its `sid` and `logout_hint` must agree when both are present.
  - **Allowed URLs:**
    - `post_logout_redirect_uri` must match exactly (including the query string) an allowed logout URL. The list is the client's when a client is known, otherwise the tenant's.
    - `state` is added to the redirect's query.
  - **Confirmation:**
    - When the browser has a session and no hint matches it, a confirmation page is shown.
    - The page posts back with a CSRF token. The token is bound to an `HttpOnly; Secure; SameSite=Strict` cookie `za_logout` on path `/oidc/logout` that lives 10 minutes.
    - Without a session there is nothing to confirm, and the request proceeds.
  - `ui_locales` selects the page language (D-0016).
- **Rationale:** It follows the documented behavior. The confirmation stops cross-site requests from silently ending sessions, and the CSRF binding stops them from auto-submitting the confirmation.

## D-0016: Hosted page languages and custom text

- **Context:** Auth0's public docs describe language selection (`enabled_locales`, `ui_locales`, `Accept-Language`) and per-prompt custom text with `${variables}`. They do not say how region tags relate to base languages, or how missing text falls back.
- **Sources:** https://auth0.com/docs/customize/internationalization-and-localization/universal-login-internationalization; https://auth0.com/docs/customize/login-pages/universal-login/customize-text-elements; RFC 5646; RFC 9110 §12.5.4.
- **Decision:**
  - **Language selection:** the language is chosen in this order:
    1. the first `ui_locales` entry, if enabled;
    2. otherwise the first enabled `Accept-Language` entry, by weight;
    3. otherwise the tenant default (the first of `enabled_locales`, else `en`).
    A region tag is matched by an enabled base language (`fr-CA` → `fr`).
  - **Text lookup:** text comes from, in order:
    1. tenant custom text for the language;
    2. the built-in catalog for the language;
    3. the built-in catalog for the base language;
    4. English.
  - **Custom text shape:** prompt → language → screen → key, using Auth0's documented identifiers where a screen matches, and the `zeroauthy` prompt otherwise.
  - **`enabled_locales`:** each entry must be a BCP 47 tag in canonical form (`en_US` and `fr-ca` are rejected with a suggestion of `en-US` and `fr-CA`), naming a language: `und`, private-use (`x-…`) and grandfathered (`i-…`) tags are rejected.
  - **Unrendered Auth0 keys:** custom-text keys under any prompt other than `zeroauthy` that zeroauthy does not render are accepted and ignored. They are documented Auth0 keys for screens zeroauthy does not have yet, so configuration written for Auth0 still loads. They still need a valid, enabled language and non-empty text; variables are checked only on keys zeroauthy knows. Keys under the `zeroauthy` prompt must exist in `en.json`, which catches typos in zeroauthy's own namespace.
  - **Empty custom text** is rejected, and an empty value is ignored at lookup, so a page never shows a blank string.
  - **Logo alt text:** the login and signup pages use `login.login.logoAltText` and `signup.signup.logoAltText` (default `${companyName}`); other pages use `zeroauthy.layout.logoAltText`.
  - **Password policy alias:** if the tenant sets Auth0's `signup.signup.password-policy-not-conformant` for the language, that text replaces all three password policy messages (too short, too long, character classes). It has no built-in text and is not in `en.json`; the catalog test exempts it by name.
  - **Custom-text language keys:** matched against `enabled_locales` case-insensitively (`fr-ca` applies to `fr-CA`); two keys under one prompt that differ only by case are rejected.
  - **`Accept-Language` parsing is tolerant:** entries are ordered by q-value (header order breaks ties). Malformed entries and entries whose tag does not parse are skipped, not fatal to the header. `*`, empty entries, `q=0` and an invalid or out-of-range q-value (outside 0 to 1) are ignored. The `q` parameter name is case-insensitive (`Q=0` means `q=0`). Only the first 1024 comma-separated entries are considered.
  - **English wording:** these are the intended visible English changes:
    - the login and signup subtitle is now a sentence ("Sign in to ${companyName} to continue to ${clientName}."). When the application has no name, it reads "Sign in to ${companyName} to continue." (and "Sign up for …" on signup), so a client ID is never shown to end users;
    - the logout confirmation tab title is "Log out";
    - the `/authorize` error page shows a generic localized message, with the technical detail below it.

    Every other existing string is unchanged.
  - **Variables:** `${companyName}` and `${clientName}` may be used in an override on any key, plus the variables the English string for that key uses. Any other variable is rejected. Unset variables render empty.
  - **Error pages after a verified login transaction:** keep that transaction's language.
  - **`/oidc/logout`:** now honours `ui_locales`, which replaces the D-0015 note.
  - **OAuth `error_description`:** stays English.
- **Rationale:** It follows the documented selection order and custom-text shape, so configuration written for Auth0 keeps working. English fallback guarantees that a page never shows a missing string.

## D-0017: Resource owner password grants

- **Context:** Auth0 documents the `password` grant, the `http://auth0.com/oauth/grant-type/password-realm` extension (realm = connection) and the `auth0-forwarded-for` header, but not error codes beyond success.
- **Sources:** RFC 6749 §4.3 and §5.2; https://auth0.com/docs/api/authentication/resource-owner-password-flow/get-token; OAuth 2.0 Security BCP (RFC 9700) §2.4.
- **Decision:**
  - `password` uses the tenant's `default_directory`; without one it is `invalid_request`.
  - The connection must be a database connection enabled for the client.
  - Wrong credentials and unknown users give the same `invalid_grant`; a blocked user gives `invalid_grant`.
  - Attempts share the hosted login's per-user and per-IP throttles and return `429 too_many_requests` when locked.
  - `auth0-forwarded-for` is honoured only for clients that authenticated with a secret.
  - Access tokens carry `gty: "password"`. ID tokens have `auth_time` = now and no `sid` (no browser session).
  - Refresh tokens follow the `offline_access` rules of D-0012 and start a new family.
- **Rationale:** It follows the documented parameters and RFC 6749 errors. Sharing the throttles prevents the API from being used to bypass hosted-login brute-force protection.

## D-0018: /dbconnections endpoints

- **Context:** Auth0 documents the request and success fields and the status codes of `/dbconnections/signup` (200, 400, 409) and `/dbconnections/change_password` (200 plain text, 400, 404). It does not document error bodies. The two public sources disagree about an unknown user on `change_password`: the Authentication API reference lists a 404 response, while the README of the official `@auth0/auth0-auth-js` SDK says the endpoint never reveals whether the email matches an existing user.
- **Sources:** https://auth0.com/docs/api/authentication/signup/create-a-new-user; https://auth0.com/docs/api/authentication/change-password/change-password (lists 404); the `@auth0/auth0-auth-js` README, `database.changePassword` (never reveals whether a user exists).
- **Decision:**
  - **Error bodies:** they use zeroauthy's JSON error shape `{error, error_description}`:
    - `invalid_request`: missing or malformed parameters, or an unknown client;
    - `invalid_signup`: the connection is not enabled for the client, sign-up is disabled, or the profile is invalid;
    - `invalid_password`: the password policy is not met;
    - `user_exists` (409);
    - `too_many_requests` (429).
  - **`client_id` is required:** zeroauthy has no global client.
  - **Limits of our own choosing:** a request body is capped at 64 KiB; `picture` must be an absolute https URL of at most 2000 characters; `given_name`, `family_name`, `name` and `nickname` are limited to 300 characters; form-encoded bodies cannot carry `user_metadata` (it is an object, so it needs JSON). `user_metadata` follows Auth0's documented limits (10 properties, names up to 100 and string values up to 500 characters).
  - **Signup response:** `_id` is the user ID without the `auth0|` prefix.
  - **`change_password`:** an unknown user gets the same 200 plain-text body as a known one, and no email is sent. The maintainer chose the auth0-auth-js README's behaviour over the API reference's 404 (2026-10-15). `email` matches users' email addresses only, never usernames. The 200 body is a plain-text sentence of our own wording. The remaining 404 is for an unknown tenant. See D-0019 (password reset).
- **Rationale:** It follows every documented field and status. Undocumented error bodies use the shape all other zeroauthy endpoints use.

## D-0019: Password reset tickets

- **Context:** Auth0 documents that `change_password` sends a reset email, and documents the hosted `reset-password` screens. It does not document ticket lifetime or what a reset does to existing sign-ins.
- **Sources:** https://auth0.com/docs/api/authentication/change-password/change-password; https://auth0.com/docs/customize/login-pages/universal-login/customize-text-elements (reset-password prompt); https://auth0.com/docs/secure/attack-protection/brute-force-protection (a password change unblocks a blocked user); OWASP Forgot Password Cheat Sheet (outstanding reset tokens are invalidated once one is used).
- **Decision:**
  - **Tickets:** 43 random characters, stored hashed, single use, valid for 24 hours. The link is `https://{tenant host}/u/reset-password?ticket=…`.
  - **Email:** it is sent in the background, so response time does not depend on mail delivery.
  - **Throttling:**
    - **Send limit:** at most 3 emails per user per hour. Extra requests still return 200 without sending.
    - **Request limit:** requests to `change_password` and to the hosted "Forgot password?" form are limited per IP (429 once the limit is reached; the hosted form is shown again with a "too many attempts" message).
  - **Blocked users:** they get the 200 response but no email.
  - **Completing a reset:**
    - **Checks first:** the user must still exist and not be blocked; otherwise the generic error screen is shown and the ticket is not spent. The new password is hashed before the ticket is used, so a hashing failure does not spend it either.
    - **Other sign-ins:** deletes all of the user's sessions and revokes all of the user's refresh tokens. The maintainer chose this.
    - **Other reset links:** every other unused ticket of the user is deleted, following OWASP's advice to invalidate outstanding tokens. Used tickets stay until they expire, so a replayed link still shows the "already used" screen.
    - **Order:** sessions, refresh tokens and other tickets are revoked before the password is changed, so a storage failure part way leaves the account in the safer state.
    - **Password:** sets a new argon2id hash.
    - **Brute-force lock:** the user's login lock (on their email and, if set, username) is cleared, as Auth0 documents that a password change unblocks a user blocked by brute-force protection.
- **Rationale:** It follows the documented endpoint. Where the docs are silent, the choices follow OWASP guidance, so a reset locks out anyone holding an old session.
