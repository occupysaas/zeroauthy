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

## D-0047: Email provider and template contracts

- **Context:** Public email documentation and the pinned Management SDK define routes, names and some provider credential families, while runtime behavior and some lifecycle details are not observable in this execution.
- **Sources:** Auth0 Management API email/provider and email-template references; Auth0 `auth0` npm SDK 7.4.0; details and evidence classes are in `observations/management-email.md` and `internal/emailrules/inventory.json`.
- **Decision:** Implement the eight documented Management operations and nine executable provider names, while keeping `custom` disabled until Actions exists. Keep credentials write-only and envelope-encrypted. Store all fourteen SDK template names; only `reset_email` drives reset-link delivery, with legacy names separate. Treat absent live evidence as unavailable and use the inventory's explicitly labeled local fallbacks.
- **Rationale:** This follows documented routes and resource shape without claiming that local security and lifecycle choices were observed upstream.

- **D-0047 implementation addendum (2026-10-25):** The nine named providers
  use local protocol adapters; `custom` remains stored-only. The bounded
  renderer is an original restricted evaluator, so no Liquid dependency or
  third-party license notice was added. The enabled tenant provider is read
  for each send and never fails over after an error. Welcome, security and
  operator preview/test sends use durable fixed-window claims; uncertain
  started sends are not retried. Preview/test endpoints are zeroauthy system
  extensions, with test messages addressed only to the verified operator.
  node-auth0 7.4.0, deploy-cli 9.1.0, browser and local conformance lanes were
  exercised as recorded in the Plan 21 acceptance record. The deploy CLI
  inserts `##NAME##` secret placeholders in public exports; same-provider
  imports preserve destination credentials for those placeholders and reject
  them when no private destination credential exists. No live upstream tenant,
  paid provider account or formal OIDF certification was used.

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
- **Sources:** RFC 6749 §4.3 and §5.2; https://auth0.com/docs/api/authentication/resource-owner-password-flow/get-token; OAuth 2.0 Security BCP (RFC 9700) §2.4. The `realm` handling on the plain `password` grant comes from @auth0/auth0-auth-js 1.16.1 (MIT): `AuthClient.getTokenByPassword` in `dist/index.js` sends `grant_type=password` with `realm`, and its type documentation says the realm picks the connection instead of the default directory. The m9 E2E test confirms the behavior on the wire.
- **Decision:**
  - `password` honours `realm` when given (as @auth0/auth0-auth-js sends it) and behaves like the password-realm grant for that connection; otherwise it uses the tenant's `default_directory`, and without one it is `invalid_request`.
  - The connection must be a database connection enabled for the client.
  - Wrong credentials and unknown users give the same `invalid_grant`; a blocked user gives `invalid_grant`.
  - Attempts share the hosted login's per-user and per-IP throttles and return `429 too_many_requests` when locked.
  - `auth0-forwarded-for` is honoured only for clients that authenticated with a secret, and only when its value parses as an IP address; otherwise the request's own address is used.
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
  - **`change_password`:** an unknown user gets the same 200 plain-text body as a known one, and no email is sent. The maintainer chose the auth0-auth-js README's behaviour over the API reference's 404 (2026-10-15). `email` matches users' email addresses only, never usernames. The 200 body is a plain-text sentence of our own wording. The remaining 404 is for an unknown tenant. When `client_id` is given, the client must exist and the connection must be enabled for it (as for signup); otherwise 400 `invalid_request`. See D-0019 (password reset).
  - **Shared IP limit:** `/dbconnections/signup` and `/dbconnections/change_password` count against the same per-IP bucket as the hosted login and the password grants. A server-side backend that calls them for many users from one address should expect to be throttled (429); for password grants it should send the end user's IP in `auth0-forwarded-for`.
  - **Background email:** reset emails are sent after the response. An email still being sent when the server shuts down is lost.
- **Rationale:** It follows every documented field and status. Undocumented error bodies use the shape all other zeroauthy endpoints use.

## D-0019: Password reset tickets

- **Context:** Auth0 documents that `change_password` sends a reset email, and documents the hosted `reset-password` screens. It does not document ticket lifetime or what a reset does to existing sign-ins.
- **Sources:** https://auth0.com/docs/api/authentication/change-password/change-password; https://auth0.com/docs/customize/login-pages/universal-login/customize-text-elements (reset-password prompt); https://auth0.com/docs/secure/attack-protection/brute-force-protection (a password change unblocks a blocked user); OWASP Forgot Password Cheat Sheet (outstanding reset tokens are invalidated once one is used).
- **Decision:**
  - **Tickets:** 43 random characters, stored hashed, single use, valid for 24 hours. The link is `https://{tenant host}/u/reset-password?ticket=…`.
  - **Email:** it is sent in the background, so response time does not depend on mail delivery. Sends still in flight at shutdown are lost; a panic in a send is logged and does not stop the server.
  - **Throttling:**
    - **Send limit:** at most 3 emails per user per hour. Extra requests still return 200 without sending.
    - **Request limit:** requests to `change_password` and to the hosted "Forgot password?" form are limited per IP, in the same bucket as the hosted login, the password grants and signup, so a server-side backend calling `change_password` for many users from one address will be throttled (429 once the limit is reached; the hosted form is shown again with a "too many attempts" message).
  - **Blocked users:** they get the 200 response but no email.
  - **Completing a reset:**
    - **Checks first:** the user must still exist and not be blocked; otherwise the generic error screen is shown and the ticket is not spent. The new password is hashed before the ticket is used, so a hashing failure does not spend it either.
    - **Other sign-ins:** deletes all of the user's sessions and revokes all of the user's refresh tokens. The maintainer chose this.
    - **Other reset links:** every other unused ticket of the user is deleted, following OWASP's advice to invalidate outstanding tokens. Used tickets stay until they expire, so a replayed link still shows the "already used" screen.
    - **Order:** the ticket is used first. Then one transaction locks the user (on a legacy connection by bumping its `Version`, since no local password is written), revokes sessions, refresh tokens and other tickets, and changes the password. A grant that checked the old password and has not minted yet is refused, and one minting at the same moment waits for the lock, so its token is revoked (Plan 17 Task 11). A storage failure in that transaction rolls it back, but the link is spent; the user asks for a new one.
    - **Password:** sets a new argon2id hash.
    - **Brute-force lock:** the user's login lock (on their email and, if set, username) is cleared, as Auth0 documents that a password change unblocks a user blocked by brute-force protection.
- **Rationale:** It follows the documented endpoint. Where the docs are silent, the choices follow OWASP guidance, so a reset locks out anyone holding an old session.

## D-0020: SQL storage encoding and isolation

- **Context:** The spec requires SQLite, PostgreSQL and MySQL drivers that pass the same conformance suite as the memory driver, with atomic single-method operations.
- **Sources:** spec §5.1; the database vendors' documentation for unique-violation codes, row locking, savepoints and collations.
- **Decision:**
  - **Supported versions:** PostgreSQL 14+ (tested on 17), MySQL 8.0.17+ (tested on 8.4), SQLite through `modernc.org/sqlite`. MariaDB is not supported.
  - **Times:** stored as BIGINT microseconds since the Unix epoch (UTC). Zero time is 0 and a nil time is NULL, so every dialect compares and sorts times the same way, with no timezone or precision differences. A session or auth transaction with a zero expiry counts as expired, as in the memory driver.
  - **Values without their own table:** lists and maps are stored as JSON text.
  - **Uniqueness:** enforced by unique indexes; a violation maps to `ErrConflict`. This includes:
    - per-connection user logins, through `user_logins`;
    - tenant domains; a domain repeated within one tenant's `Domains` is also `ErrConflict`, on every driver;
    - one current and one next signing key per tenant, through a partial or generated-column unique index.
  - **Atomic operations:** each runs in one transaction. PostgreSQL and MySQL use `SELECT … FOR UPDATE`. SQLite uses a single connection and immediate transactions.
    - `SigningKeys.Rotate` locks the tenant row, so rotations of one tenant are serialized.
    - Revoking a refresh-token family or all of a user's refresh tokens repeats until nothing more is revoked, so a successor rotated concurrently cannot stay live.
  - **Transactions:**
    - A nested `WithTx`, or a repository call inside a transaction, runs in a SAVEPOINT. An inner error rolls back only the inner work; the memory driver behaves the same way.
    - The public `WithTx` never retries; the caller decides.
    - Single repository writes are attempted up to 3 times (with backoff) when the database aborts them as a deadlock or serialization failure (MySQL 1213; PostgreSQL 40P01 and 40001).
    - If `ROLLBACK TO SAVEPOINT` fails, the transaction is marked broken and is rolled back as a whole.
  - **Isolation:** each dialect's default (PostgreSQL READ COMMITTED, MySQL REPEATABLE READ, SQLite serializable), except that on MySQL the expiry sweepers and set-based deletes run at READ COMMITTED, to avoid gap locks that deadlock with concurrent inserts.
  - **MySQL:**
    - **Collation:** `utf8mb4_0900_bin`, so comparisons are case-sensitive and, being NO PAD, trailing spaces are significant in keys, as on PostgreSQL and SQLite. This collation is why MySQL 8.0.17 is the minimum.
    - **Session settings:** strict SQL mode, a UTC session time zone, and `clientFoundRows`.
  - **Migrations:** embedded and ordered. `serve` refuses to start against an older or newer schema unless `storage.auto_migrate` is true; `zeroauthy migrate` applies pending migrations, and `zeroauthy seed` refuses an unmigrated database.
    - **MySQL recovery:** MySQL commits each DDL statement implicitly, so a migration that fails part-way leaves the statements before the failure applied, with no `schema_migrations` row. Drop or finish those objects by hand before running `zeroauthy migrate` again. PostgreSQL and SQLite run each migration in one transaction.
  - **Email length:** email addresses are capped at 254 bytes (RFC 5321's path limit) at signup, in the seed, and when matching a login or a `change_password` address; a longer one is an invalid email (signup: 400 `invalid_signup`), and a login or reset request naming one matches no user. Auth0 documents no limit. The cap exists because MySQL stores logins in `VARCHAR(255)`, which would otherwise fail where the other drivers succeed.
  - **Seeding races:** `seed.Apply` retries once when its transaction fails with `ErrConflict`, so replicas seeding a fresh shared database at the same time converge instead of failing.
- **Rationale:** One encoding for all dialects keeps the shared SQL simple and the conformance results identical.

## D-0021: Storage plugins: protocol and remote transactions

- **Context:** Milestone 8 lets operators supply a storage driver as a separate process. This is a zeroauthy extension with no Auth0 counterpart.
- **Sources:** spec §5.2; the `hashicorp/go-plugin` and gRPC documentation. User decision, 2026-10-16: transactions cross the plugin boundary. This replaces the earlier rule in spec §5.2 that no transactions are offered across it.
- **Decision:**
  - **Protocol:** `proto/store/v1` has one RPC per store method. Domain errors (not found, conflict and the like) travel in the response message, so they map back to the store sentinels.
  - **Encoding:**
    - Wrapper messages keep nil and empty apart for slices and maps.
    - A plain `time.Time` is always sent as a Timestamp. A `*time.Time` is nil on the wire when absent.
    - User metadata and custom text are JSON bytes; numbers inside them decode as `float64`, as in the SQL drivers.
  - **Remote transactions:**
    - `BeginTx` returns a transaction id; `Commit` and `Rollback` end it. Calls made inside a transaction carry its id.
    - Nesting uses `parent_tx_id` and has savepoint semantics: an inner rollback undoes only the inner work.
    - A transaction tree is a stack. It has at most one open child, and only the innermost transaction accepts calls or `Commit`. Rolling back an ancestor ends the chain below it, innermost first.
    - Each tree has one 60 second idle timer; when it fires, the root is rolled back and the tree released.
    - There is no retry across the boundary; the caller decides, as in D-0020.
    - A failed `Commit` is followed by a best-effort `Rollback`.
    - When the plugin exits, open transactions are abandoned and the database rolls them back as the connection drops.
  - **Errors:** transport errors never match store sentinels. gRPC `Canceled` and `DeadlineExceeded` map to `context.Canceled` and `context.DeadlineExceeded`.
  - **Handshake:** protocol version 1, magic cookie key `ZEROAUTHY_STORE_PLUGIN`, value `5b0f7c1e-store-v1`, plugin name `store`. Only the gRPC protocol is allowed, with AutoMTLS. Starting the plugin is bounded by a 10 second timeout and by the caller's context.
  - **Robustness:** the Go SDK's `Serve` installs a panic-recovery interceptor, so a panic fails one request and the server keeps serving. Plugins written in other languages must handle panics themselves.
  - **Host death:** go-plugin does not notice a dead host, so `Serve` polls its parent pid about once a second and exits when it changes. A SIGKILLed host with a transaction open therefore does not leave a plugin running; the transaction is abandoned and the database rolls it back as the connection drops.
  - **Environment:** the plugin does not inherit zeroauthy's configuration. The host passes the rest of its environment (`PATH`, `HOME`, `PG*` and so on) but removes every `ZEROAUTHY_*` variable, so the master key and the storage DSN never reach the plugin; go-plugin adds only its own handshake variables. A plugin takes its configuration from the `arg` values of its DSN.
  - **Cancellation:** `Commit` and `Rollback` through a plugin are not cancelled by the caller's context, whereas in-process `database/sql` fails a `Commit` whose context is done.
  - **Process handling:** the plugin must `exec` and not fork. `Kill` waits for anything that still holds the plugin's stdio, so a forked child would make shutdown hang.
  - **DSN:** `plugin:///absolute/path/to/binary?arg=…&arg=…`. The host must be empty and the path absolute. Each `arg` value is one argv entry, in order. Any other query key is an error that names the key and never a value. No error quotes the DSN, because arguments may carry secrets. Plugin storage is persistent, so `security.master_key` is required; plugin stores have no schema, so the server does not migrate them.
- **Rationale:** One RPC per method keeps the contract the same as the Go interface, so `storetest` is the single arbiter for in-process, SQL and plugin drivers. Explicit transactions let plugins back the same multi-step operations that SQL drivers do; the stack rule and the idle timer keep a misbehaving or dead host from holding a lock indefinitely.
- **Addendum (Plan 9):** the plugin protocol gained `UserGrants` (find, upsert, list by user, delete) and consent fields on clients, tenants, resource servers, client grants and connections. A plugin must be rebuilt against this version to serve `UserGrants`; an older plugin fails a consent decision with a server error.
- **Addendum (Plan 20):** the protocol adds result-returning signing-key lifecycle calls, certificate compare-and-set, custom public-key storage and nullable signing timestamps. `storetest` covers the new repositories. Plugins must be rebuilt; missing lifecycle RPCs return the actionable plugin-too-old error and never fall back to legacy rotation. Custom sets are not merged into managed verification keys.

## D-0022: Custom database connections: Auth0's shape, scripts run in Node.js

- **Context:** Milestone 9 brings Auth0's custom database connections. Spec §5.3 first designed this as zeroauthy-specific HMAC webhooks under a separate `custom-db` strategy. Auth0's public docs describe a database connection (strategy `auth0`) whose options turn on customization, select import mode, and carry the action scripts written in Node.js and their configuration settings.
- **Sources:** https://auth0.com/docs/authenticate/database-connections/custom-db and its templates, error-handling and best-practice pages; https://auth0.com/docs/manage-users/user-migration/configure-automatic-migration-from-your-database. User decisions, 2026-10-16: follow Auth0's connection shape, and choose any execution model that keeps scripts from reading the system's environment variables.
- **Decision:**
  - **Shape:**
    - The strategy stays `auth0`.
    - The options use Auth0's names: `enabledDatabaseCustomization`, `import_mode`, `customScripts` (keys `login`, `get_user`, `create`, `verify`, `change_password`, `delete`, `change_email`), `configuration` and `set_user_root_attributes`.
    - The user ID is `auth0|<user_id returned by the script>`.
  - **Runtime:**
    - Scripts run unchanged in a real Node.js process (≥ 22.13), so existing Auth0 scripts, including `require()` of pure-JS npm packages, work as written.
    - Each tenant gets its own process, started lazily and stopped when idle. The protocol is newline-delimited JSON over stdin and stdout.
    - Each connection has its own `vm` context with Auth0's globals (`configuration`, `global`, the `WrongUsernameOrPasswordError`, `ValidationError` and `UnauthorizedError` classes, `require`, `fetch`, `console`).
    - One execution may take 20 s, after which the tenant's process is killed. A script may be at most 100 kB.
  - **Isolation:**
    - The process starts with an empty environment.
    - Configuration reaches it only inside requests on stdin.
    - Node's permission model (`--permission`) allows file reads only in the runner and operator-modules directories, and grants no child processes, workers, addons or WASI. Neither the host's environment (including `/proc/<ppid>/environ`) nor its files can be read, even by a script that escapes `vm`.
    - Network access is allowed, because scripts must reach their stores. This is documented as an operator egress concern.
    - Configuration values are encrypted at rest with the master-key envelope, bound to the tenant and connection.
- **Rationale:** Parity is the product. Operators migrating from Auth0 can paste their scripts as they are. A process per tenant contains runaway scripts and keeps one tenant's configuration out of another's memory. The empty environment plus the permission model enforce the user's requirement at the OS-process boundary rather than relying on `vm`, which is not a security boundary. The Actions runtime (sub-project 2) can reuse the runner.
- **Addendum (Plan 8 Task 3):**
  - Node's permission model does not stop a runner from signalling other processes with the same uid. Before any script runs, the runner replaces five methods with locked functions that throw: `process.kill`, `process._kill`, `process._debugProcess` (which sends SIGUSR1 to any pid), `process._debugEnd` and `os.setPriority`. The tests show that scripts cannot call these, reassign them or redefine them, even after escaping `vm`. They also show that `process.binding`, `process.execve`, `inspector`, workers and child processes are denied under `--permission`. That covers every method we found in Node 22 and 26 that acts on another pid. A method added in a later Node release would need to be added to the list.
  - The runner's `require` denylist (child_process, worker_threads, vm and so on) only gives scripts clearer errors. It is not a control, because a script can bypass it with `process.getBuiltinModule`. `--permission` is what enforces the limits.
  - Apart from that, every runner shares the server's uid and kernel. Operators who host untrusted tenants should run zeroauthy under a dedicated uid or in a container, so a runner cannot reach other software on the machine.
  - `--max-old-space-size` limits the JavaScript heap only. Buffers and ArrayBuffers sit outside it, so a script can use more memory than `max_memory_mb`. Use cgroup or container memory limits for a hard cap.
  - Scripts cannot read the environment or files, but they can read basic host facts through `os`, such as the hostname, network interfaces, CPU count and uptime.
  - Network egress is open, including to internal and link-local addresses (for example, cloud metadata endpoints). Operators who need to restrict it should use firewall or egress-proxy rules.

## D-0023: Custom database script errors on the wire

- **Context:** Auth0's custom database docs name the error classes a script may pass to its callback (`WrongUsernameOrPasswordError`, `ValidationError`, `UnauthorizedError`, any other `Error`) and the log events they produce. They do not say which HTTP response each surface returns.
- **Sources:** https://auth0.com/docs/authenticate/database-connections/custom-db/error-handling; RFC 6749 §5.2.
- **Decision:**
  - A login script's `WrongUsernameOrPasswordError` is the same wrong-credentials answer as for a local user.
  - Only `UnauthorizedError` shows the script's message, because Auth0 documents it as the way to send a message to the front end. Every other failure (another error class, a thrown exception, a timeout, an unavailable Node.js, a missing script, an invalid profile) is logged in `identity` with the tenant, connection, script, kind and the script's message, and the user sees a generic error. zeroauthy itself never logs passwords or configuration, and it replaces any configuration value in a script's console output and error messages with `■■■■■■■■` before logging, as Auth0 does. Other secrets your scripts print are logged as they are.
  - Per surface:

    | Surface | `UnauthorizedError` | Other script failure | `change_password` returns false |
    |---|---|---|---|
    | Hosted login `/u/login` | 401; the login form again with the message (HTML-escaped); the attempt counts against the throttles | error page (500); see the throttle rule below | n/a |
    | Password grants | 401 `{"error":"unauthorized","error_description":<message>}`; the attempt counts | 500 `server_error`; see the throttle rule below | n/a |
    | `/dbconnections/signup`, `/u/signup` | 401 `unauthorized` with the message / the form again with the message | 500 `server_error` / error page | n/a |
    | `/dbconnections/change_password`, hosted forgot-password page | the usual answer, no email | the usual answer, no email, logged | n/a |
    | Hosted reset completion | the form again with the message; the link is spent | error page; the link is spent | the form again with `zeroauthy.reset.not-changed`; the link is spent |

  - **Throttles.** Many legacy login scripts report a wrong password with a plain `Error` rather than `WrongUsernameOrPasswordError`. A failure the script raised therefore counts as a failed attempt, as wrong credentials do; otherwise such a script would allow unlimited guessing. Raised failures are an `Error` or `ValidationError` from the script, a thrown exception, an invalid profile, and a profile collision (D-0024). Only failures that kept the script from answering are refunded: a timeout, an unavailable Node.js, a missing script, a configuration that does not open, a cancelled request, and storage errors. `identity` tells the two apart with `ErrScriptUnavailable`; the refund list is an explicit allowlist, and any unrecognised error is counted.
  - **Legacy reset order.** On legacy connections the ticket is spent before `change_password` runs, so two submits of one link run the script at most once; the second gets the "already used" screen. A script that then refuses or fails has spent the link, and the user asks for a new one (changed in Plan 17 Task 11; the link used to stay usable, which let two submits both run the script). Sessions are revoked after the script succeeds. If revocation then fails, the new password is live while old sessions survive; the user should reset again.
  - On sign-up, a `create` script's `UnauthorizedError` is a 401 with its message. So is an `UnauthorizedError` from the login that confirms the new account; any other failure of that login is a script failure.
  - On sign-up, a `create` script's `ValidationError` with code `user_exists` is `user_exists`; any other `ValidationError` is shown like a rejected sign-up field (`invalid_signup` with the script's message).
  - The token endpoint's `unauthorized` is not one of RFC 6749 §5.2's codes. It is used because the client must be able to tell a script's refusal from wrong credentials, and the status (401) matches the meaning.
  - **Addendum (import mode).** In import mode `get_user` is optional, and the local store is authoritative. A connection without a `get_user` script finds nobody: sign-up goes ahead locally, and a reset request for an address with no local user sends no email. A `get_user` failure (other than a missing script) is reported as on a legacy connection. Errors from the `login` script on a user's first login are classified as above, so they count against the throttles in the same way. Once a user is migrated, a wrong password is checked against the local hash and is the usual wrong-credentials answer.
- **Rationale:** The surfaces never reveal more than they do for local users, and the one message Auth0 intends for users reaches them. A reset link no longer survives a legacy store that is down or refuses: it is spent before `change_password` runs, so that two submits of one link cannot both run the script (Plan 17 Task 11); the user asks for a new link.

## D-0024: Custom database profiles: identity, collisions, sync

- **Context:** Auth0 documents the profile a login or `get_user` script returns, prefixes its `user_id` with the connection strategy, and offers `set_user_root_attributes` (`on_each_login`, `on_first_login`). It does not say what happens when a profile clashes with a user that already exists, or which fields follow the legacy store on each login.
- **Sources:** https://auth0.com/docs/authenticate/database-connections/custom-db/templates/login; https://auth0.com/docs/manage-users/user-accounts/user-profiles/configure-connection-sync-with-auth0.
- **Decision:**
  - The user is `auth0|<profile.user_id>`, with the identity `{connection, "auth0", <profile.user_id>}` and no password hash in legacy mode. `user_id` is a non-empty string or an integer, at most 200 bytes, with no control characters and no `|`.
  - A profile is checked before anything is stored: a valid email (lowercased) or username or both, name fields of at most 300 characters, an https picture, and metadata objects. A bad profile is a script failure (D-0023). The error names the field, never its value.
  - Collisions fail closed and are logged. Two cases are collisions: the user ID exists without an identity on this connection, or another user of the connection holds the profile's email or username.
  - Email, username and email_verified always follow the legacy store. The scripts are the source of truth, and a stale local email would send reset links to the wrong address.
  - `set_user_root_attributes` governs name, nickname, given and family name, and picture: they are set on every login by default, or only when the user is created with `on_first_login`. A missing name or nickname takes the same defaults as a sign-up.
  - `user_metadata` and `app_metadata` are set once, when the local user is created, and never overwritten from a profile.
  - A locally blocked user is refused after the script has accepted the password, as for local users.
- **Rationale:** Failing closed on collisions means a legacy store can never take over an account it does not own. Keeping metadata local after creation preserves changes made in zeroauthy.

## D-0025: Third-party applications and API access policies

- **Context:** Auth0 has two third-party modes (`third_party_security_mode`: `strict`, `permissive`) and per-API access policies for user and client flows (`subject_type_authorization`). Client grants carry a `subject_type`. The docs do not give the error codes for refused flows, and they disagree on whether permissive applications need a grant under `allow_all`.
- **Sources:** https://auth0.com/docs/get-started/applications/third-party-applications/security-controls; https://auth0.com/docs/get-started/applications/third-party-applications/permissive-mode; https://auth0.com/docs/get-started/apis/api-access-policies-for-applications; https://auth0.com/docs/get-started/applications/application-access-to-apis-client-grants; observations/consent.md.
- **Decision:**
  - **Defaults:**
    - New third-party clients are `strict`. A stored third-party client with an empty or unknown mode is treated as `strict`.
    - `is_first_party` and `third_party_security_mode` cannot change after creation.
    - Grants created without a `subject_type` are `client`.
    - APIs default to `{user: allow_all, client: require_client_grant}`.
  - **Strict clients:**
    - may use only the `authorization_code`, `refresh_token` and `client_credentials` grants;
    - must use PKCE;
    - get `invalid_request` for `claims`, `id_token_hint`, `login_ticket`, `request`, `request_uri` or `screen_hint`;
    - lose OIDC scopes, so no ID token is issued;
    - always need a `user` client grant;
    - get `invalid_request` at `/authorize` when they send no audience (observed).
  - **Third-party clients in general:** no password grants (the seed refuses them, as Auth0's Management API does). They may not be listed in a connection's `enabled_clients` (observed 400) and log in only through domain connections.
  - **Access policies:** `deny_all` refuses. `require_client_grant` needs a grant of the flow's subject type. `allow_all` admits first-party clients; for permissive clients, see below. Scopes outside the grant are dropped silently (observed).
  - **Refusal codes (observed):**
    - a user flow at `/authorize`: `invalid_request`;
    - a user flow at `/oauth/token` (password, refresh): HTTP 400 `invalid_request`;
    - client credentials: HTTP 403 `access_denied`, as zeroauthy already answers.
  - **Permissive clients follow the API's policy** (no grant needed under `allow_all`), as the permissive-mode page says. This could not be observed, because the maintainer's account cannot create permissive clients.
  - **The refresh grant re-checks the policy and the client grant,** so withdrawing a grant takes effect at the next refresh. This is a zeroauthy choice; Auth0's docs are silent.
- **Rationale:** Observed codes are matched exactly. Unknown stored values fail closed.

## D-0026: Consent and user grants

- **Context:** Auth0 shows consent to third-party clients always, and to first-party clients unless the API skips it. Approvals are remembered as user grants. The docs do not say how later scope changes are handled or what the API default is.
- **Sources:** https://auth0.com/docs/get-started/applications/third-party-applications/user-consent-and-third-party-applications; observations/consent.md.
- **Decision:**
  - **Skipping consent:**
    - `skip_consent_for_verifiable_first_party_clients` defaults to `false` for resource servers that do not set it, as on Auth0 (observed; maintainer's choice of parity, 2026-10-16).
    - Databases migrated to schema 3 keep `true` on existing rows, but a seed apply sets `false` unless the seed names the field. Upgrade notes say so.
  - **What a grant holds:**
    - A grant is keyed by (client, user, audience). The audience is the API identifier, or `https://{domain}/userinfo` when there is none.
    - A request whose scopes are all in the grant skips consent (observed).
    - Accepting consent merges the accepted scopes into the grant (observed). `prompt=consent` forces the screen, except for a first-party client whose API skips consent: there it does not force it. That exception is a zeroauthy assumption, unobserved on Auth0. Declining leaves the grant unchanged (observed).
  - **The consent screen** lists every scope the request will receive, not only the new ones, matching check 7.
  - **Grants with no screen:** Auth0 stored a grant for a first-party client after a login that showed no consent screen (check 1). zeroauthy stores grants only when the user accepts a consent screen. This is a recorded difference until the Management API exposes grants (sub-project 3) and the case is understood.
- **Rationale:** Observed behavior is matched. The one unexplained case is visible only through the grants API, which zeroauthy does not have yet.

## D-0027: Confirmation prompt, prompt=none and redirection policy

- **Context:** Since 2026-04-28, Auth0 asks users to confirm logins that go to non-verifiable callbacks, and `prompt=none` is refused for them. `redirection_policy: open_redirect_protection` keeps errors from being redirected. The docs give neither the error codes nor which errors are kept.
- **Sources:** https://auth0.com/docs/troubleshoot/product-lifecycle/deprecations-and-migrations/migrate-to-non-verifiable-callback-uri-end-user-confirmation; https://auth0.com/docs/secure/security-guidance/measures-against-app-impersonation; observations/consent.md.
- **Decision:**
  - **Non-verifiable** means any scheme other than `http`/`https`, or a host of `localhost`, `127.0.0.1` or `::1`.
  - **When the confirmation appears:** the client's `skip_non_verifiable_callback_uri_confirmation_prompt` overrides the tenant's (default `false`, prompt on). The confirmation appears only when no other screen (login, signup or consent) was shown in the same transaction. That is why a fresh login goes straight back (check 1), while reusing a session shows the prompt (check 5).
  - **`prompt=none`** fails with `consent_required` when consent or confirmation is needed (observed for both), and with `login_required` without a session.
  - **`open_redirect_protection`** shows **every** `/authorize` error on an error page with HTTP 400 once the client and redirect URI are validated. Observed for `consent_required`, `login_required`, `invalid_request` and a declined consent. The decline page's status was not recorded and is 400 as well. With `allow_always`, or when unset on a first-party client, errors redirect.
- **Rationale:** Observed. Showing every error as a page means silent authentication (`prompt=none` in an iframe) cannot work for protected third-party clients, on Auth0 and on zeroauthy alike. Operators who need it set `allow_always`.

## D-0028: The pushed authorization request endpoint

- **Context:** Auth0 documents `POST /oauth/par` (RFC 9126): confidential clients only, a form body of at most 10 KB, up to 10 `ext-` parameters, `201` with a `request_uri` that lives 30 seconds. The docs give no error codes or statuses.
- **Sources:** https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow/authorization-code-flow-with-par; https://auth0.com/docs/get-started/applications/configure-par; RFC 9126; observations/par.md.
- **Decision:**
  - **Who may push:** first-party confidential clients authenticating with `client_secret_basic` or `client_secret_post` (scope A; `private_key_jwt` and mTLS are follow-ups). Public clients get `400 invalid_request` and every third-party client, strict or permissive, gets `400 invalid_request` (observed for strict; the refusal concerns third-party clients in general). A wrong secret is `401 invalid_client`.
  - **Body:** form-encoded only (JSON is `400 invalid_request`), at most 10 KB (`413 payload_too_large`), no repeated parameters, no `request_uri` (`400 invalid_request`), at most 10 `ext-` parameters (an 11th is `400 invalid_request`). Other unknown parameters are dropped.
  - **Validation:** the request goes through the same checks as `/authorize`. Errors keep the `/authorize` code with Auth0's observed status for that code: `invalid_request` 400, `unauthorized_client` 403, `access_denied` 403, `unsupported_response_type` 501. Nothing is redirected.
  - **Differences:**
    - `response_type=token` is `unsupported_response_type` (501). Auth0 answers `403 unauthorized_client` for a client without the implicit grant; zeroauthy has no implicit grant for any client.
    - zeroauthy checks `response_mode` and `prompt` at this endpoint. Auth0 accepts unknown values here and checks them at `/authorize`. RFC 9126 §2.1 asks the server to validate the pushed request as it would at the authorization endpoint, and Auth0's docs list early validation as a benefit of PAR.
  - **Tenant setting off:** `400 invalid_request` (observed).
  - **Success:** `201` with `request_uri` = `urn:ietf:params:oauth:request_uri:` + 64 random characters and `expires_in: 30`, `Cache-Control: no-store`. The 64 characters are stored only as a SHA-256 hash.
- **Rationale:** Observed codes and statuses are matched; the two differences either follow from a grant zeroauthy does not have or follow the RFC and Auth0's own documentation.

## D-0029: request_uri at /authorize and required PAR

- **Context:** Auth0 documents that a `request_uri` works once and expires, and that a client can require PAR. It does not say how other query parameters combine with `request_uri` or how failures are reported.
- **Sources:** the D-0028 docs; RFC 9126 §4; observations/par.md.
- **Decision:**
  - **Only pushed parameters count.** Query parameters other than `client_id` and `request_uri` are ignored, never an error (observed for `state`, `redirect_uri`, `response_type`, `scope` and an unknown parameter).
  - **Failures are error pages** (HTTP 400, no redirect): an unknown, used, expired or wrong-client `request_uri`, or one presented while the tenant setting is off. The request is used up by an attempt from an existing, non-strict client that finds it, including one with the wrong `client_id` (observed); an unknown `client_id` or a strict third-party client never touches it.
  - **Required PAR:** a plain `/authorize` from a client with `require_pushed_authorization_requests` redirects with `error=invalid_request` and the request's `state`, subject to `redirection_policy`. This holds even when the tenant setting is off (observed).
  - **The pushed mark survives the hosted pages:** the login transaction remembers that its request was pushed, so a client that requires PAR is not refused after the login or consent page.
  - Strict third-party clients keep refusing `request_uri` at `/authorize` (D-0025).
- **Rationale:** Observed.

## D-0030: PAR settings and discovery

- **Context:** Auth0 has a tenant toggle and a client field for PAR; the docs name only the client field and say the tenant toggle must be on first.
- **Sources:** https://auth0.com/docs/get-started/applications/configure-par; observations/par.md.
- **Decision:**
  - **Tenant:** `pushed_authorization_requests_supported` (observed name, top level of tenant settings), default `false`.
  - **Client:** `require_pushed_authorization_requests`, default `false`. The seed refuses it when the tenant setting is off (the docs' ordering), on public clients, and on third-party clients (which cannot push, D-0028). Auth0 lets the tenant setting be turned off afterwards; zeroauthy's seed cannot express that state, but stored data from plugins or migrations can, and `/authorize` then refuses every request from that client, as on Auth0.
  - **Discovery:** `pushed_authorization_request_endpoint` only while the tenant setting is on; `request_uri_parameter_supported: false` always (observed in both states). Without it, OpenID Connect clients would assume `request_uri` is accepted outside PAR.
- **Rationale:** Observed names and discovery values are matched.

## D-0031: The device authorization endpoint and the device_code grant

- **Context:** Auth0 documents `POST /oauth/device/code` (RFC 8628), its response, the polling errors `authorization_pending`, `slow_down`, `expired_token` and `access_denied`, and the client prerequisites. Statuses, client identification errors and polling limits are not documented.
- **Sources:** https://auth0.com/docs/get-started/authentication-and-authorization-flow/device-authorization-flow; https://auth0.com/docs/get-started/authentication-and-authorization-flow/device-authorization-flow/call-your-api-using-the-device-authorization-flow; RFC 8628; observations/device-flow.md.
- **Decision:**
  - **Request:** form or JSON body (observed: JSON accepted). An unknown, repeated or unsuitable `client_id` (no grant, not `none`) is `403 unauthorized_client`. `audience=` empty means no audience. An unknown audience, or an API whose access policy refuses the client, is `400 invalid_request` when the code is issued. Access policies are checked again after login.
  - **Response:** `200` with `device_code` (24 random characters, stored as a SHA-256 hash), `user_code`, `verification_uri` = `https://{host}/activate`, `verification_uri_complete` = `…/activate?user_code={formatted code}`, `expires_in: 900`, `interval: 5`, `Cache-Control: no-store`.
  - **Polling:** `403 authorization_pending`; `429 slow_down` only for a poll less than 1 second after the last accepted poll (a slow_down answer does not move that mark, and no `interval` is returned); `403 access_denied` once for a denied code, then `403 invalid_grant`; `200` tokens once for an approved code, then `403 invalid_grant`; an unknown code or another client's code is `403 invalid_grant`. Expiry: the first poll after expiry is `403 expired_token`, later polls `403 invalid_grant` (observed). Auth0 stops answering `expired_token` somewhere between a few seconds and 11 minutes after expiry; zeroauthy answers it on the first poll after expiry at any time while the record is kept (24 hours), which is harmless for clients and simpler than guessing the window.
  - **Tokens:** the access token's audience is the API (plus `/userinfo` with `openid`) and carries no `gty`. The ID token has no `sid` and no `auth_time`: device tokens are not bound to the browser session, so logging out in the browser does not sign the device out. Refresh tokens rotate and revoke like any other; revoking one forces the device to start again.
- **Rationale:** Observed values are matched. The 1-second gap is the narrowest rule consistent with the observation (no `slow_down` at 1 s, alternating `slow_down` in a burst); Auth0's exact algorithm is not observable without load.

## D-0032: The device browser path

- **Context:** Auth0 documents the browser path (enter the code, confirm it, log in, consent if needed) and the custom-text screens `device-code-activation`, `device-code-confirmation`, `device-code-activation-allowed` and `device-code-activation-denied`. Paths and messages are not documented.
- **Sources:** the D-0031 docs; https://auth0.com/docs/customize/login-pages/universal-login/customize-text-elements; observations/device-flow.md.
- **Decision:**
  - **Paths (observed):** `GET /activate` serves the entry form, which posts `state` and `code` to `/activate`; `?user_code=` skips entry. A valid code redirects to `/device/confirmation?state=…`, which posts `state` and `action` (`confirm` or `cancel`). The result pages are `/device/success` and `/device/denied`. Login and consent are the normal `/u/login` and `/u/consent`.
  - **Entry errors:** an unknown, expired or used code all show the `invalid-expired-code` text with status 400; an empty submit shows `no-code`. Codes are matched without case or separators.
  - **Confirmation always shows,** including through `verification_uri_complete` and with a live session.
  - **Session reuse:** a live browser session is reused without a login page (observed).
  - **Consent:** decided as for `/authorize`: an API that skips consent for first-party applications shows none; otherwise consent shows and a remembered user grant skips it later. Declining at confirmation or consent denies the code.
- **Rationale:** Observed. Path parity costs nothing and keeps tenant-hosted links and documentation interchangeable.

## D-0033: Device flow settings, client rules and discovery

- **Context:** Auth0 configures the user code with a tenant character set and mask; the Management API schema names them `device_flow.charset` (`base20` or `digits`) and `device_flow.mask`.
- **Sources:** https://auth0.com/docs/get-started/tenant-settings/configure-device-user-code-settings; the Management API tenant settings schema in the open-source SDKs; observations/device-flow.md.
- **Decision:**
  - **Tenant:** `device_flow: {charset, mask}`, absent by default (observed), meaning `base20` and `****-****`. base20 is `BCDFGHJKLMNPQRSTVWXZ` (observed: exactly these 20 letters). A mask has `*` placeholders and `-` or space separators, at least 8 (base20) or 9 (digits) placeholders, at most 20 characters (documented).
  - **Clients:** the device grant requires `app_type: native`, `token_endpoint_auth_method: none` and a first-party client. The Management API refuses each of the other combinations (observed), so the seed refuses them too.
  - **Discovery:** `device_authorization_endpoint` and the grant in `grant_types_supported` (observed).
- **Rationale:** Observed and documented values are matched.

## D-0034: Device activation limits (deliberate)

- **Context:** Auth0 says it rate-limits the device flow but publishes no numbers, and CLEAN_ROOM.md forbids load testing a tenant to find them.
- **Sources:** the D-0031 docs; RFC 8628 §5.1 (user code brute forcing); design spec §5.
- **Decision:** zeroauthy's own limits on wrong codes at `/activate`, each in-process: 5 per transaction (the transaction is then discarded), 10 per IP per 15 minutes, and 1,000 per tenant per 10 minutes with a 1-minute lockout. The IP limit buckets IPv6 clients by /64 (IPv4 and IPv4-mapped addresses by address). The IP and tenant limits can be turned off (0). Only misses count. Config keys are `security.device_activation_*`.
- **Rationale:** a deliberate deviation in numbers, not in behaviour: Auth0 also throttles, and RFC 8628 requires protection against guessing. The defaults keep a slow or typo-prone user unaffected.

## D-0035: Request objects are refused (deliberate, for now)

- **Context:** OpenID Connect Core §6 lets an OP either process the `request` parameter (a request object) or refuse it with `request_not_supported` (§3.1.2.6). zeroauthy ignored it silently, so the parameters inside it were lost (OIDF `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported`). Auth0 supports signed request objects (JAR) and its discovery lists `request_parameter_supported: true` (observations/par.md).
- **Sources:** OpenID Connect Core §3.1.2.6, §6; OpenID Connect Discovery §3; observations/par.md; the Plan 12 conformance triage rulings (tests/conformance/triage-2026-10.md, row 2).
- **Decision:**
  - `/authorize` answers a `request` parameter with `request_not_supported`, delivered like other authorization errors (to a registered `redirect_uri`, with `state`; on the error page when the client or `redirect_uri` cannot be trusted). When the object is a readable JWS, its `state` and `response_mode` are used for this delivery (they take precedence over the query, §6.1). Its signature is not checked and nothing else in it is read; the `redirect_uri` is always the query's registered one.
  - Strict third-party clients keep D-0025's `invalid_request`.
  - `/oauth/par` refuses a pushed `request` the same way (`400 request_not_supported`).
  - Discovery lists `request_parameter_supported: false`.
  - An empty `request=` is also refused. An unsupported `response_mode` inside the request object yields `invalid_request` (unsupported response_mode) rather than `request_not_supported`.
- **Rationale:** a deliberate, temporary deviation from Auth0's discovery value until request objects (JAR) are implemented, together with `private_key_jwt` (follow-up). Refusing is what the spec requires of an OP that does not process request objects; ignoring them broke clients that put `state`, `nonce` or `response_mode` only in the object.

## D-0036: OpenID conformance accepted warnings and skips

- **Context:** In the OIDF suite (release-v5.3.1) the Basic and Form Post plans finish with no failures, but some modules end with a warning or a skip. OIDF certification accepts warnings and skips; modules must finish without failures (https://openid.net/certification/op_submission/). Each is listed in `tests/conformance/expected-failures.json` or `expected-skips.json`, and the runner fails on any other warning or skip and on a stale entry.
- **Sources:** tests/conformance/triage-2026-10.md (Rulings); https://auth0.com/docs/get-started/apis/scopes/openid-connect-scopes; https://openid.net/certification/op_submission/; D-0013; D-0035.
- **Decision:** accepted, per plan (Basic and Form Post alike):
  - **Warning `oidcc-scope-email`, `oidcc-alternate-happy-flow` (rows 3, 4):** keep Auth0's behaviour of putting the scope's claims (such as `email`) in the ID token, per Auth0's scope documentation (https://auth0.com/docs/get-started/apis/scopes/openid-connect-scopes).
  - **Warning `oidcc-codereuse-30seconds` (row 9):** access tokens issued before a code reuse are not revoked, because JWT access tokens are not revocable (D-0013's reasoning: a JWT access token is self-contained and verified without a server lookup; no Auth0 public doc was found that states this either way).
  - **Warning `oidcc-ensure-request-with-acr-values-succeeds` (row 8):** no `acr` claim, as `acr` is unsupported. `acr` support is a follow-up.
  - **Warning `oidcc-claims-essential` (row 7):** the `claims` request parameter is not supported. Follow-up.
  - **Warning `oidcc-scope-profile` (row 5):** the extra `profile` attributes (`website`, `zoneinfo`, `birthdate`, and so on) are not emitted. Follow-up.
  - **Skipped `oidcc-scope-address`, `oidcc-scope-phone`, `oidcc-scope-all` (rows 11 to 13):** the address and phone scopes and claims are not implemented. Follow-up.
  - **Skipped `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` (row 2):** refusing request objects with `request_not_supported` is permitted behaviour (D-0035).
  - Expected-skip entries cannot pin a reason: the suite's skip format has no condition field, so an entry matches the module whatever caused the skip.
- **Rationale:** each item is either Auth0 parity (rows 3, 4), a choice following D-0013 (row 9), or a feature that does not block certification, so it becomes a follow-up rather than a compatibility switch.

## D-0037: Additive spec behaviours: POST /authorize and form-encoded access token at /userinfo

- **Context:** The spec allows two request shapes that zeroauthy did not accept. The maintainer's rule: support both where Auth0 clients are unaffected.
- **Sources:** OpenID Connect Core §3.1.2.1 (the Authorization Endpoint MUST support GET and MAY support POST with form serialization); RFC 6750 §2.2 (access token in a form-encoded body); OIDF `oidcc-ensure-post-request-succeeds` and `oidcc-userinfo-post-body`.
- **Decision:**
  - **`POST /authorize`:** parameters come from a form-encoded body only (a form content type, at most 64 KB), and then behave as the same parameters in a GET query. GET is unchanged.
  - **`/userinfo`:** the access token may also be sent as `access_token` in a form-encoded POST body. The `Authorization` header is unchanged. Sending both is `400 invalid_request`.
- **Rationale:** purely additive; requests that Auth0 clients already send behave as before.

## D-0038: Client secrets are encrypted, not hashed

- **Context:**
  - Auth0 returns a client's secret to Management API callers holding `read:client_keys` and shows it in its dashboard.
  - Core spec §8 stored secrets only as argon2id hashes.
- **Sources:** observations/management-clients.md (M2); design `docs/superpowers/specs/2026-10-18-zeroauthy-management-design.md` §8; maintainer's decision, 2026-10-18.
- **Decision:**
  - Secrets are sealed with AES-256-GCM under the master key, through the same envelope as signing keys. The AAD binds tenant and client.
  - Secrets are returned only to callers with `read:client_keys`.
  - Existing hash-only secrets keep authenticating. Their plaintext is unknown, so no secret is returned until the client is rotated or its secret is set again.
- **Rationale:** drop-in parity with Auth0. The master key already protects the more sensitive signing keys.

## D-0039: Management API for clients

- **Context:** Auth0 documents `/api/v2/clients`, but not all defaults, statuses and limits.
- **Sources:** the Management API docs for clients; observations/management-clients.md; `auth0-deploy-cli` 9.1.0 source.
- **Decision** (observed values):
  - **Error shape:** `{statusCode, error, message, errorCode}`.
    - Unknown ID: `404 inexistent_client`.
    - Validation failures: `400 invalid_body`. Unknown properties are refused.
    - Missing scope: `403 insufficient_scope`.
    - No token or a bad token: `401`.
  - **Pagination:**
    - a bare array without `include_totals`, or `{clients, start, limit, total}` with it;
    - `per_page` at most 100, otherwise `400 invalid_query_string`;
    - creation order.
  - **Projection:** `fields` plus `include_fields`, with `tenant` always included.
  - **Secrets:**
    - returned only with `read:client_keys`;
    - can be set on `POST`, or on `PATCH` with `update:client_keys`;
    - at least 48 characters; generated secrets are 64;
    - rotation replaces the secret immediately.
  - **Immutable fields:** `is_first_party` and `third_party_security_mode` cannot be changed after creation.
  - **Delete:** `204`, and also `204` for an ID that does not exist.
  - **Create defaults:** the API applies the same defaults to every `app_type`; per-type defaults are the caller's job.
  - **Differences from Auth0:**
    - zeroauthy is always OIDC-conformant. `oidc_conformant` is reported as `true` and cannot be set to `false`.
    - The implicit grant is not offered, so it is not in the defaults.
    - The console applies per-type defaults on create, as Auth0's dashboard does, through the same API.
    - **API create defaults** (Plan 13 Task 5): `app_type` `regular_web` when absent (zeroauthy stores a type for every client); `token_endpoint_auth_method` `none` for `spa` and `native`, `client_secret_post` otherwise; `grant_types` `authorization_code` and `refresh_token`, plus `client_credentials` for confidential clients; refresh tokens rotating and expiring for `spa`, non-rotating and non-expiring otherwise (an SPA must have expiring tokens).
    - **Public clients have no secret:** `client_secret` is refused for `token_endpoint_auth_method` `none`, and `rotate-secret` on a public client is `400 invalid_body`. Switching a client to a confidential method generates a secret.
    - **Grant types:** Auth0's names are accepted and stored, including `implicit` and the MFA grants that `auth0-cli` sends by default; the token endpoint serves only the grants zeroauthy implements. Unknown names are `400 invalid_body`.
    - **Origins:** `web_origins` and `allowed_origins` must be origins (scheme and host, no path).
    - **`update:client_keys`:** needed to set `client_secret` on `PATCH`; a body with only `client_secret` needs no `update:clients`.
    - **Accepted and ignored** (sent by `auth0-cli` or exported by `auth0-deploy-cli`): `description`, `logo_uri`, `client_metadata`, `sso`, `sso_disabled`, `cross_origin_authentication`, `cross_origin_auth`, `cross_origin_loc`, `custom_login_page_on`, `custom_login_page`, `initiate_login_uri`, `native_social_login`, `mobile`, `is_token_endpoint_ip_header_trusted`, `allowed_clients` (`organization_usage` and `organization_require_behavior` were here until Plan 29 made them live, D-0055); also `jwt_configuration.secret_encoded` and `refresh_token.infinite_idle_token_lifetime`. `refresh_token.infinite_token_lifetime` sets the expiration type when `expiration_type` is absent.
    - **Read-only fields** in a body (`tenant`, `global`, `callback_url_template`, `signing_keys`, `created_at`) are unknown properties. `client_id` is `403 operation_not_supported` on `POST` (M10) and allowed on `PATCH` only unchanged.
    - **The console's own client** (`zeroauthy-console` in the system tenant) cannot be changed, rotated or deleted through the API (`403 operation_not_supported`).
    - **Deleting** a client deletes its client grants, user grants and refresh tokens and removes it from every connection's enabled clients; login sessions stay.
- **Rationale:** observed values are matched. The differences follow from features zeroauthy does not have.
- **Open for slice 5:**
  - `auth0-deploy-cli` does not carry `client_secret`, and Auth0 refuses a caller-supplied `client_id`. A migration that keeps client IDs and secrets needs a dedicated step, for example zeroauthy accepting `client_id` on create as an extension.
  - That is a maintainer decision when slice 5 is designed.

## D-0040: The system API for tenants and operators

- **Context:** Auth0 has no API to create, list or delete tenants or dashboard administrators; the console needs one (design §4.3).
- **Sources:** design `docs/superpowers/specs/2026-10-18-zeroauthy-management-design.md` §4.1, §4.3; Auth0's public docs on creating and deleting tenants and on dashboard administrators, for the vocabulary only.
- **Decision:**
  - `/api/system/tenants` (`GET`, `POST`, `PATCH /{name}`, `DELETE /{name}?confirm=<name>`) and `/api/system/operators` (`GET`, `POST`, `DELETE /{id}`), on the system host only, for operator tokens only. It uses the Management API's error shape.
  - **Tenant names** are DNS labels (at most 63 characters); `system` is reserved. **Domains** are hosts with an optional port; the system host is refused. Without a base domain a tenant needs at least one domain, since it would otherwise have no host.
  - **A new tenant** gets signing keys, a database connection `Username-Password-Authentication` (its default directory, enabled for no application yet) and its Management API. `PATCH` changes only the friendly name and domains.
  - **Errors:** `404 inexistent_tenant` and `inexistent_operator`; `409 conflict` for a used name or domain; `409 last_operator`; `403 operation_not_supported` for changing or deleting the system tenant; `400 invalid_query_string` when `confirm` does not repeat the name.
  - **Inviting** an operator returns a one-hour setup link (the password-reset ticket flow); inviting an existing operator issues a new link. **Removing** one deletes the operator record and ends their sessions and refresh tokens at once; their user stays. The last operator cannot be removed.
  - **Seed coexistence:** tenants and clients created through the APIs carry `origin: api`; the seed never touches them, even when it names the same tenant or client ID.
- **Rationale:** the smallest API the console needs, in the shape of the rest of the Management API.

## D-0041: Management API for resource servers and client grants

- **Context:** Auth0 documents `/api/v2/resource-servers` and `/api/v2/client-grants`, but not all defaults, limits, statuses and cascades.
- **Sources:** the Management API docs for both; observations/management-apis.md; `auth0-deploy-cli` 9.1.0, `auth0-cli` v1.37.0 and `go-auth0` v3.6.0 source.
- **Decision** (observed values, matched):
  - **Errors:** the D-0039 shape.
    - Resource servers: `404 inexistent_resource_server`; `409 resource_server_conflict` for a duplicate identifier; `400 reserved_identifier` for the tenant's Management API identifier; `400 delete_system_resource_server`.
    - Client grants: `404 inexistent_client` and `404 inexistent_resource_server` on create; `409 client_grant_conflict`; `404 inexistent_client_grant` on `PATCH`; `400 invalid_uri` for a malformed grant ID.
    - Validation failures: `400 invalid_body`; unknown properties are refused.
  - **Resource server create defaults:** `token_lifetime` 86400, `token_lifetime_for_web` 7200, `signing_alg` `RS256`, `allow_offline_access` and `skip_consent_for_verifiable_first_party_clients` false, `subject_type_authorization` client `require_client_grant` and user `allow_all`. `name` is optional and absent when not given.
  - **Limits:** identifier 1–600 characters, any string, compared case-sensitively; name 1–200 characters without `<` or `>`; scope value 1–280, description at most 500, values unique; `token_lifetime` 1–2592000; `token_lifetime_for_web`, when sent, at most `token_lifetime`.
  - **Immutable:** `identifier` (and `id`, `is_system`) are unknown properties on `PATCH`. A grant's `client_id`, `audience` and `subject_type` likewise.
  - **System APIs:** listed first; `name` cannot be patched; other settings can; `DELETE` is `400 delete_system_resource_server`.
  - **Scopes:** `PATCH` replaces the list. Removing a scope removes it from every client grant that carries it.
  - **Delete:** `204`, also for an unknown ID; an API's client grants are deleted with it. A grant `DELETE` is `204`, also for an unknown ID in the right format.
  - **Reading by identifier:** `GET /resource-servers/{id}` also accepts the URL-encoded identifier (auth0-cli relies on it).
  - **Listing:** resource servers in creation order, client grants in ID order. Offset paging as D-0039 (keys `resource_servers`, `client_grants`). `identifiers` is a repeated parameter. Client grants also support checkpoint paging (`from`/`take`, at most 100, default 50, `{client_grants, next}`, `next` absent on the last page); it wins over `page` and `include_totals`. Filters `client_id`, `audience`, `subject_type`; `subject_type` alone is `400`.
  - **Client grants:** `subject_type` defaults to `client`; one grant per client, audience and subject type; `scope` or `allow_all_scopes` required; scopes the API does not define are refused on `PATCH`.
- **Differences from Auth0:**
  - **Scopes on create:** Auth0 accepts a grant scope the API does not define on `POST` but refuses it on `PATCH`. zeroauthy refuses it on both (`400 invalid_body`), as its seed does, so no grant names a scope its API does not define (Plan 14 review focus 3).
  - **Signing:** zeroauthy signs access tokens with RS256 only. `HS256` and `PS256` are `400 invalid_body`; `signing_secret` is refused.
  - **Grants to a Management API:** only that tenant's own identifier, `subject_type` client, Management API scopes only (Plan 14 review focus 1).
  - **System APIs** (Plan 14 Task 3): `name` is refused as on Auth0, and `scopes` must stay as they are. The settings zeroauthy depends on cannot change either, and naming one with its current value is accepted (`auth0-deploy-cli` sends back what it read). A tenant's Management API keeps its user policy `deny_all` (a tenant user must never get a token for it); its token lifetimes, offline access, skipped consent and client policy can change. The system tenant's `urn:zeroauthy:management` also keeps offline access (the console refreshes with it), skipped consent and both policies (machine clients must never get operator tokens); only its token lifetimes can change. A refused change is `400 invalid_body`. This replaces the plan's "system APIs are read-only".
  - **Resource server fields settled in Plan 14 Task 3:**
    - `token_lifetime_for_web`: accepted, validated, stored and reported (7200 by default); nothing uses it, since zeroauthy has no implicit or hybrid flow. When sent it must not exceed `token_lifetime` (86400 when that is not sent too).
    - `enforce_policies`: only `false` is accepted and reported. zeroauthy has no roles or permissions to enforce, so `true` would promise what it cannot do.
    - `token_dialect`: only `access_token` is accepted and reported; the other dialects change the token format.
    - `consent_policy`, `proof_of_possession` and `token_encryption`: only `null` is accepted, and the fields are not reported; `authorization_details`: `null` or an empty list. Transactional authorization, mTLS and DPoP, token encryption and rich authorization requests are not supported.
    - `signing_secret` is refused with `signing_alg` (above).
    - The ID of an API created through the API is 24 lowercase hexadecimal characters (A1); the seed's keep the `rs_` form. `scopes` is left out of a response when the API has none.
  - **Client grant fields settled in Plan 14 Task 4:**
    - **Organization and rich authorization fields:** zeroauthy has no organizations or rich authorization requests, so `organization_usage` accepts `deny` or null, `allow_any_organization` false or null, `authorization_details_types` an empty list or null, and `default_for` null only; anything else is `400 invalid_body`. Nothing is stored and none of them is reported. A `PATCH` naming only inert values is accepted and changes nothing.
    - **Scopes:** each grant scope is 1 to 280 characters; repeated scopes are dropped. `scope` and `allow_all_scopes: true` do not go together (`invalid_body`). `allow_all_scopes: false` alone on `POST` counts as no scope. On `PATCH`, `scope` replaces the list and turns `allow_all_scopes` off unless the body says otherwise; `allow_all_scopes: true` clears the list.
    - **`allow_all_scopes`:** stored as a flag. The token endpoint (client credentials) and the interactive flows resolve it to every scope the API defines when the token is issued, so scopes added later are covered and scopes removed are not. On the tenant's Management API it means every Management API scope. A response carries `allow_all_scopes: true` and no `scope`.
    - **Management API grants** (Plan 14 review focus 1): the audience must be the caller's own Management API identifier. `urn:zeroauthy:management` is `400 invalid_body` always. A URL of the Management API form (`https://…/api/v2/`) other than the caller's own is `400 invalid_body` too, unless the tenant defines an ordinary API with that identifier (Task 3 allows one), which is granted like any API; the seed makes the same distinction. The check follows the application and API lookups, so the unknown-audience case is the 400, not a 404. A grant to the tenant's own Management API creates it first when no token has yet (the API is made on first use), so an operator can grant it at once.
    - **Order of checks on `POST`:** body shape and the operator audience (`invalid_body`), the application (`404 inexistent_client`), the API (`404 inexistent_resource_server`, or `400 invalid_body` for another tenant's Management API), the scopes against the API (`invalid_body`), then the duplicate (`409`).
    - **`client_id` filter:** an ID is malformed (`400 invalid_query_string`) when it is empty, longer than 255 characters, or holds whitespace or control characters. zeroauthy client IDs are whatever the seed names (32 letters and digits through the API), so nothing stricter is safe.
    - **Grant IDs:** `cgr_` and 16 letters and digits (the seed's too since Plan 14); `GET`, `PATCH` and `DELETE` accept `cgr_` and 1 to 64 letters and digits, since older seeded grants have 24. Anything else is `400 invalid_uri`, checked before the body. `GET /client-grants/{id}` for an unknown ID is `404 inexistent_client_grant`.
    - **Checkpoint cursor:** `next` is the URL-safe base64 of a version tag and the ID of the last grant returned, and `from` lists the grants whose ID sorts after it (store filter `AfterID`), so grants added or deleted between pages neither repeat nor skip another. The cursor names no tenant: a listing is always of the caller's tenant, so a cursor cannot reach another tenant's data. A `from` that does not decode to the tag and a grant ID is `400` without an `errorCode`. `take` outside 1 to 100 is `400 invalid_query_string`. With `take` or `from`, `page`, `per_page` and `include_totals` are not read.
    - **Not supported:** the `allow_any_organization` and `default_for` list filters.
- **Addendum (follow-ups to Plans 13 and 14):**
  - **Deleting the tenant's default audience:** deleting the API whose identifier is the tenant's `default_audience` clears `default_audience` in the same operation (the store's delete cascade, so every store does it) and the delete is still `204`. Requests that leave the audience out then behave as for a tenant with no default: client credentials are `400 invalid_request`, and `/authorize` carries on without an audience. Observed on Auth0 (observations/management-apis.md): the field is absent from the tenant settings afterwards and the delete is `204`.
  - **Stale scopes in consents:** removing a scope from an API with `PATCH` also removes it from every user grant (stored consent) for that audience, as it does from client grants. The grants stay, even with no scope left. Auth0's behaviour here was not observed.
  - **Create-only seed mode:** `seed_mode: create_only` (config key `seed_mode`, not a nested `seed.mode`, because `seed` is already the file path) makes the seed create what is missing and change nothing that exists. In that mode a tenant is not marked `seeded` (an existing seeded tenant loses the marker), so the console shows no banner. The default is `apply`.
- **Open for the maintainer:** Auth0 names the system API "Auth0 Management API", and `auth0-deploy-cli` leaves it out of exports by that name. zeroauthy's is "zeroauthy Management API", so deploy-cli exports it as an ordinary API (its `is_system` flag still limits what deploy-cli updates). Matching the name would use Auth0's trademark beyond a nominative statement (CLEAN_ROOM.md).

## D-0042: Management API for database connections

- **Context:** Auth0 documents `/api/v2/connections`, but not every default, limit, cascade or the current password model in full.
- **Sources:** the Management API docs for connections and their clients; observations/management-connections.md; `auth0-cli` v1.37.0, `auth0-deploy-cli` 9.1.0 and `go-auth0` v3 source.
- **Decision** (observed values, matched):
  - **Errors:** the D-0039 shape. `409 connection_conflict` for a used name; `404 inexistent_connection` for a well-formed unknown ID; `400 invalid_uri` for a malformed ID (zeroauthy also accepts its existing seeded IDs: `con_` followed by 1–64 letters and digits); `400 inexistent_client` on the clients endpoint; validation failures `400 invalid_body`.
  - **Names:** `^[a-zA-Z0-9](-[a-zA-Z0-9]|[a-zA-Z0-9])*$`, at most 128 characters. New IDs: `con_` and 16 letters and digits.
  - **Create defaults** (API-created connections; seeded ones keep the seed's values): `password_options` as observed (`min_length` 15, no character types, rule `all`, identical and sequential characters allowed, overlong passwords refused, history off with size 3, dictionary off with `en_100k`, personal data off with the observed blocked fields), `brute_force_protection: true`, `realms: [name]`, `is_domain_connection: false`, password authentication enabled and passkeys disabled.
  - **`options` is replaced whole on `PATCH`;** keys inside `password_options` that are not sent take their defaults. Unknown keys in `options` are stored and returned as sent (`Extra`).
  - **Password models:** `password_options` is the model zeroauthy stores. The legacy fields (`passwordPolicy`, `password_complexity_options`, `password_history`, `password_dictionary`, `password_no_personal_info`) are accepted and mapped onto it; both together are `400 invalid_body`. Responses carry `password_options`.
  - **Configuration:** values are strings or `null`, sealed at rest, and returned as opaque blobs (zeroauthy's sealed envelope, base64), never plaintext. A blob sent back unchanged keeps the stored value; anything else is new plaintext.
  - **Enabled clients:** `GET/PATCH /connections/{id}/clients` (`{clients:[{client_id}]}` with checkpoint paging; `PATCH` a non-empty `[{client_id, status}]` → `204`). `enabled_clients` accepted on `POST`, refused on `PATCH`, absent from `GET /connections/{id}`.
  - **Listing:** case-insensitive name order; D-0039 paging (`per_page` default 100) and checkpoint paging (`take`/`from`, `{connections, next}`); filters `name` and `strategy`; `fields` always adds `id` and `is_domain_connection`.
  - **Delete:** `202 {deleted_at}`, then `204` for an ID already deleted; the connection's users (with their sessions, refresh tokens, grants and password history) go with it; the tenant's `default_directory` is cleared when it names the connection.
  - **Other options:** `validation.username` 1–128 with `min` < `max`; `precedence` at least 3 of `email`, `username`, `phone_number`; `import_mode` needs `enabledDatabaseCustomization`; `set_user_root_attributes` only on a custom database using the external store; `customScripts` keys limited to the seven script names.
- **Enforced by zeroauthy:** complexity (`min_length`, `character_types` with rule `all` or `three_of_four`, `identical_characters`, `sequential_characters`, `max_length_exceeded`), history, dictionary (`en_10k`, `en_100k` and custom words), personal data (`profile_data.blocked_fields`, the fields zeroauthy holds), `validation.username`, `disable_signup`, `requires_username`, `is_domain_connection`, the custom database options, `brute_force_protection` (switches zeroauthy's existing login throttle for the connection; the thresholds stay zeroauthy's until tenant attack protection, slice 5).
- **Stored, not enforced** (accepted, returned, shown as such in the console; Plan 15 follow-ups): `authentication_methods` and `passkey_options`, `attributes` and `precedence`, `mfa`, `disable_self_service_change_password`, `non_persistent_attrs`, `display_name`, `show_as_button`, `metadata`, `realms` beyond the default, `connected_accounts`, `authentication`, and any unknown option key.
- **Differences from Auth0:**
  - **Script size:** Auth0 accepted scripts of 1.1 MB; zeroauthy keeps its limit (D-0022).
  - **Strategies:** only `auth0` (database); others are `400 invalid_body` until their slice.
  - **Not observed** (entitlement missing on the dev tenant): the runtime behaviour of history, dictionary and personal data. zeroauthy's: history compares the candidate with the newest `size` stored hashes; the dictionary compares case-insensitively with the list and the custom words; personal data refuses a password containing any blocked field's value (case-insensitive, values shorter than 3 characters ignored).
- **Extension:** `POST /api/system/tenants/{tenant}/connections/{id}/scripts/{name}/try` (operators only) runs a custom-database script with test arguments (design §5.4). Auth0 has no such API.
- **Rationale:** observed values are matched; the differences follow from features zeroauthy does not have yet.
- **Addendum (Plan 15 review findings and behaviour that is zeroauthy's own):**
  - **Seed mode and API mode differ.** The name pattern, the 72-character cap on `min_length` and the rule that `set_user_root_attributes` needs a custom database with the external store apply to the API only. Seeded connections keep zeroauthy's defaults (minimum length 8) and the seed's own checks; tightening the seed to match is a follow-up.
  - **Legacy `min_length` 73 to 128 is refused.** Auth0 accepts up to 128 in `password_complexity_options.min_length`; zeroauthy passwords are at most 72 characters, so a longer minimum could never be met (`400 invalid_body`).
  - **`passwordPolicy` levels** map onto complexity as: `none` at least 1 character; `low` at least 6; `fair` at least 8 with lower case, upper case and numbers; `good` at least 8 with three of the four character types; `excellent` at least 10, three or more identical characters in a row refused, all four character types. This table comes from Auth0's public description of the levels and is **not verified against Auth0's runtime**. An explicit `password_complexity_options.min_length` overrides the level's length.
  - **`set_user_root_attributes`:** `never_on_login` is stored and returned but behaves as `on_each_login` (stored, not enforced): only `on_first_login` changes behaviour.
  - **`max_length_exceeded`:** with `truncate`, the stored hash is of the password cut to 72 characters. Switching a connection to `error` locks out users who still type an over-long password, since the full text no longer matches. They need a reset.
  - **Deleting an unknown ID:** `DELETE` of a well-formed ID that never existed is `204`, as for APIs and client grants. This is inferred, not observed for connections.
  - **Reserved prefix:** a configuration value that starts with `zcv1.` is refused (`400 invalid_body`), because that prefix marks the opaque blobs zeroauthy returns; accepting it could be mistaken for a blob sent back.
  - **Configuration masking** (applies to custom-database scripts; the `try` endpoint and the server log):
    - *What is masked:* in a `try` response, the result, the console lines and the error message; in the server log, script console lines and script error messages. The mask is `■■■■■■■■`, whatever the value's length. That Auth0 masks secrets a script logs this way was reported by the maintainer (2026-10-18); it was not observed through the Management API. Keys are not masked. Real logins and signups return script output to the user **unmasked**; masking exists so an operator trying a script does not see secrets, not as a defence against a script that returns them.
    - *Matching* is exact, case-sensitive substring matching, longest value first. A script that encodes, splits, transforms or reformats a secret (base64, one character per line, reversed) defeats it.
    - *Rotation:* a process masks every value it has seen for the connection since it started, so a value that was replaced is still masked until a restart.
    - *Truncation:* the runner keeps 2048 characters of a console line and 1024 of an error message. A value cut at those limits is still masked; a long line ending in the first characters of a value may be masked more than strictly needed.
  - **Console output is lost on a timeout:** when a script times out (or the runner dies) the try response has `logs: []`, because the runner returns console lines only with a finished run.
  - **`en_100k` source:** the large list is SecLists' `xato-net-10-million-passwords-100000.txt` (the 100,000 most common passwords of Mark Burnett's 10-million release; MIT through SecLists), not the NCSC list. SecLists states only its repository-wide MIT licence and nothing on the NCSC file's origin, so that file is not clearly permissive. `en_10k` is SecLists' `10k-most-common.txt`. Both are in `NOTICE`; this differs from Auth0's list contents, which are not public.

## D-0043: Management API for users

- **Context:** Auth0 documents the user endpoints, the v3 search syntax, tickets, sessions, refresh tokens, grants and jobs, but not every default, error code, merge rule or search edge case.
- **Sources:** the Management API docs for users, users-by-email, sessions, refresh tokens, grants, tickets and jobs; the user search query syntax docs; observations/management-users.md.
- **Decision** (observed values, matched):
  - **User shape:** as U1. `name` defaults to the email, `nickname` to its local part; `blocked`, names and metadata are absent until set; login fields appear after the first login. New user IDs are `auth0|` and 24 lowercase hex characters. A supplied `user_id` (`^\S*$`, at most 255) is always prefixed with `auth0|`.
  - **Errors:** duplicate user `409 auth0_idp_error`; weak password `400` without `errorCode` (`PasswordStrengthError: …`); username or phone on a connection without them, and email with password in one `PATCH`, `400 operation_not_supported`; malformed user ID (not `provider|id`) `400 invalid_uri`; unknown user `404 inexistent_user`; unknown session or refresh token `404` without `errorCode`.
  - **Update:** top-level metadata merge, `null` deletes a key, nested objects replaced, `{}` empties; an email change clears `email_verified` unless the body sets it. Neither a password change nor `blocked: true` revokes sessions or refresh tokens; a blocked user's refresh and password grants answer `invalid_grant` "user is blocked".
  - **Delete:** `204`, also for an unknown well-formed ID; the cascade of users design §4.
  - **Search:** the U4 semantics, including: case-insensitive exact match on root fields, case-sensitive on metadata; bare terms over `name`, `given_name`, `family_name`, `nickname` and the email's local part and domain; juxtaposition is `OR`; `NOT` on a root string field excludes users without the field, elsewhere absent counts as not matching; leading, trailing and bare wildcards on root fields, none on metadata; ranges on `logins_count` and the dates only; `search_engine` absent, `v2` or `v3` all mean v3, `v1` is `400 operation_not_supported`; search errors `400` without `errorCode` and with Auth0's `invalid query: …` messages; sort pattern `field:1|-1`, unknown sort fields ignored; default order `last_login` descending, never-logged-in last; the 1000-record paging limit (`400 invalid_paging`).
  - **users-by-email:** case-sensitive match on the stored (lowercase) email.
  - **Linking:** the secondary record is removed and its identity moves to the primary with `profileData` `{email, email_verified}`; logins through it resolve to the primary. **Unlink recreates the secondary from `profileData` only**, with a new `created_at` and no names, picture or metadata, as Auth0 does. Unlinking an identity that is not linked is `200`. `link_with` needs `aud` = the calling client's ID.
  - **Sessions and refresh tokens:** the U8 objects; newest first; checkpoint paging only (`take` 1–100, default 50; `next` on every non-empty page); every delete is `202 {}`; deleting sessions leaves refresh tokens alone.
  - **Grants:** objects with `clientID` (sic) and a sorted `scope` array.
  - **Tickets:** `/u/reset-verify?ticket=…#` and `/u/email-verification?ticket=…#`; `result_url` with `client_id` is `400 invalid_body`; default TTL 432000 s. Verification consumes on open and redirects with the U6 parameters (`success`, `code`, `message`, `email` only with `includeEmailInRedirect`, `supportSignUp`, `supportForgotPassword`). The password-change success page does not redirect to `result_url` (as observed on Auth0's current hosted pages); the value is stored.
  - **Ticket choices not observed:** an expired verification ticket shows the error page (no redirect); `result_url` with `client_id` is refused on both ticket kinds; an unknown `client_id` is `404 inexistent_client` and an unknown `connection_id` `400 inexistent_connection`; `ttl_sec` above 2^31−1 is clamped; `organization_id` is an unknown property (zeroauthy has no organizations). On a custom database connection not in import mode a missing or failing `verify` script leaves `email_verified` false. A verification ticket is bound to the email it was issued for: once the user's email changes (Management API, custom database profile sync), opening it shows the error page and verifies nothing. Changing a user's email through the Management API also deletes their open verification and unused password reset tickets. Signup sends the verification email whenever the new user has an unverified email (zeroauthy has no email template switches yet).
  - **Search choices not observed:** `identities.*` matching is case-insensitive; a `YYYY-MM-DD` date term means the whole UTC day; metadata paths do not step through arrays. `_exists_` on a root boolean, number or date field (`blocked`, `email_verified`, `logins_count`, `created_at`, …) is always true. A bare term containing an unescaped `*` is a wildcard in all six bare-term alternatives. A dangling `AND` anywhere gives "'AND' requires at least one operand on each side", other dangling operators "undefined"; a range on a root field that has none gives "operator 'greater or equal' is not supported". Guide: `docs/user-search.md`.
  - **Create and update choices not observed:** `POST /users` with an unknown connection is `400 inexistent_connection`; `create:users_app_metadata` is accepted on create. Custom database script failures are `400 auth0_idp_error`, `409 user_exists` and `503 script_runtime_unavailable`. A legacy (custom database) create ignores a caller-supplied `user_id`. Password reset by a linked secondary's email finds no user.
  - **Linking choices not observed:** `profileData` also keeps `username` (restored on unlink). The wordings for a missing `provider`, `link_with` mixed with `provider`/`user_id`/`connection_id`, and linking a user that already has linked accounts were not observed; a bad signature, `iss` or `exp` on `link_with` reuses "Invalid token (link_with).". Deleting a connection that holds only a linked identity of a user removes that identity (the user's `Version` is bumped) and keeps the user.
  - **Refresh tokens:** zeroauthy's own ID formats (no `dcr_` prefix; 24-character session IDs); deleting one refresh token revokes its rotation family; a token with only the userinfo audience lists `resource_servers` `[{audience: https://{host}/userinfo}]`; `device` comes from the token's session and is omitted for password-grant tokens; the messages for `take` below 1 or not a number are zeroauthy's.
  - **Races:** the user version closes only the window between loading the user and minting; the authorization-code and device-code grants check only that the user exists and is not blocked, and the hosted login does not check the version (plan-1-followups). A password grant that loses that race to a block answers `invalid_grant` "user is blocked"; one that loses it to a reset, a session revocation or a deletion answers `invalid_grant` "the user is not allowed to sign in", as the refresh grant does. A legacy (custom database) reset link is spent when `change_password` fails (the D-0023 reversal, recorded there).
  - **Last operator (zeroauthy only):** on the reserved `system` tenant the Users API reaches operators too, so `DELETE /users/{id}`, `PATCH` with `blocked: true` and linking the user as a secondary account are `409 last_operator` when the user is the last operator, as the system API's operator removal is.
  - **Unstorable input:** a query parameter that is not valid UTF-8 or contains NUL (`connection`, `email`, the grants filters) is `400 invalid_query_string`; such a session, refresh token or grant ID is unknown (`404` without `errorCode` on read, the endpoint's success on delete). A password-change ticket never targets a linked identity: a user whose only database identity is linked is `400 operation_not_supported`, as a user without one. Sessions' IPs and a user's `last_ip` are stored only when the client IP is an IP address (canonical form, no zone), and are empty otherwise.
  - **Hosted pages:** the password-change success page does not redirect; the generic reset error screen (forged CSRF token, blocked or deleted user) shows "Link Expired". Link scanners in email clients consume verification tickets on `GET`, as on Auth0.
- **Differences from Auth0:**
  - **Immediate consistency:** zeroauthy's search reads the store directly; Auth0's index lags writes. zeroauthy only returns newer results.
  - **Default picture:** the same Gravatar URL shape (`s=480&r=pg`), but `d=mp` (Gravatar's built-in placeholder) instead of an initials image on Auth0's CDN, so no zeroauthy page depends on Auth0's hosts.
  - **`blocked: false`:** never returned, because the store cannot tell "set to false" from "never set"; Auth0 shows `blocked: false` once it was set.
  - **PostgreSQL locale:** Unicode case folding in user search needs a UTF-8 `LC_CTYPE`; with another one zeroauthy folds ASCII letters only and logs a warning at startup.
  - **`device.*_asn`:** not returned (zeroauthy has no ASN database); IPs and user agents are.
  - **`app_metadata` scope split:** not observed (the observer could not narrow its token); zeroauthy follows the reference: writing `app_metadata` needs `update:users_app_metadata` and reading it needs `read:users` or `read:users_app_metadata`.
- **Rationale:** observed values are matched; the differences avoid depending on Auth0's infrastructure or data zeroauthy does not have.

## D-0044: Management API jobs (user import, export, verification email)

- **Context:** Auth0 documents the jobs endpoints, the import schema, the custom hash formats and the export options, but its sources disagree in places and leave error codes, upsert rules and file details unstated.
- **Sources:** the Management API reference for the jobs endpoints; the bulk import, import schema and bulk export docs; observations/management-users.md (U10, U11) and observations/management-jobs.md (J1–J10).
- **Decision** (observed values, matched):
  - **Create checks:** the J1 errors; the 512000-byte limit applies to the whole request body (`413` without `errorCode`); a third active import in a tenant is `429` without `errorCode` (J3); a non-boolean `upsert` and unknown form fields are accepted.
  - **Files:** malformed files are accepted at create and the job fails with J2's `status_details`; non-object entries are `INVALID_TYPE` record errors.
  - **Jobs:** a running job reads `pending`, without `percentage_done` or `time_left_seconds`; `send_completion_email` defaults to `true`; `external_id` is echoed; job data is deleted 24 hours after creation, then `404 inexistent_job`.
  - **Errors endpoint:** `200 []` for a completed import without errors, `204` for an export, and the job object (`200`) for a failed job.
  - **Upsert:** matches by email; replaces names, `email_verified` and whole metadata objects; ignores `blocked`, `user_id` and `password_hash` on an existing user; replaces `custom_password_hash` only while the user has never signed in (else `CONFLICT`). `upsert: false` reports `DUPLICATED_USER` (U10), where the docs say existing users are skipped: observation wins.
  - **Records:** J5's codes, messages and paths, with hash values masked; a duplicate within one file fails only the later record.
  - **Unusable hashes:** an imported argon2 or PBKDF2 value that cannot be parsed is accepted, and signing in answers `invalid_grant` "Password change required." (J6).
  - **Export:** no `limit` exports every user; an empty body is CSV over every connection; unknown field names give empty columns (CSV) or no key (JSON); `password_hash` as a field exports nothing; CSV object and array subfields are empty; strings are quoted with a leading `'`; no `connection_id` exports every connection (U11), where the reference names a default connection: observation wins.
  - **Verification email:** `201` with a `pending` job; J10's errors.
- **Differences from Auth0:**
  - **Rehash:** the first sign-in with an imported hash stores zeroauthy's argon2id hash (Auth0 rehashes to bcrypt).
  - **No cleartext:** an ldap `{CLEARTEXT}` value is refused with `ONE_OF_MISSING` (path `custom_password_hash`), so no password is ever stored in clear. Auth0 stores it and asks for a password change at sign-in.
  - **Masked PATTERN message:** the `PATTERN` message for `password_hash` ends in `*****`, not the hash. Auth0 repeats the hash there.
  - **Hash cost limits:** a scrypt or argon2 cost whose memory exceeds 1 GiB is refused at import with `MAXIMUM` (path `custom_password_hash`). The implementation raised the planned 256 MiB cap to admit libsodium sensitive settings; scrypt also accounts for its parallelization buffers. Work budgets additionally cap PBKDF2 rounds × output blocks at 50,000,000, argon2 time × memory in KiB at 2^32, and scrypt N × r × p at 2^30. These are zeroauthy limits, not observed Auth0 limits.
  - **`mfa_factors`:** accepted and ignored (zeroauthy has no MFA yet); Auth0 stores the enrollments.
  - **Completion email recipients:** the operators whose tenant list covers the tenant (zeroauthy has no tenant owners).
  - **Download URL:** `https://<tenant host>/export/<job id>/<tenant>.<json|csv>.gz?expires=…&sig=…`, signed with a key derived from the master key, valid 60 seconds, a new one on every job read; Auth0's points at its object storage. An expired or wrong link is `403`.
  - **Export order:** rows are written in `user_id` order; Auth0's order is unspecified.
  - **Verification email without a mailer:** zeroauthy always has one (the log mailer at least), so the job completes; Auth0's fails on a tenant without an email provider.
  - **Hash algorithms Go lacks:** argon2d comes from a vendored copy of `golang.org/x/crypto/argon2` (BSD-3, NOTICE); Whirlpool and MDC-2 are written from their published specifications.
- **Rationale:** observed values are matched; the differences keep passwords and hashes from being stored or shown in clear, bound the work a file can cause, and avoid depending on Auth0's infrastructure.


## D-0045: Tenant settings and protection evidence boundaries (Plan 19)

- **Context:** Public schemas specify fields/scopes but leave reset/merge details and several runtime behaviors unstated. The authorized firewalled observer obtained tenant/attack reads, paced same-value patches and safe unknown-ID block checks; threshold, linked-account, breach and provider runtime behavior was not observed. GET omits provider credentials, preventing exact credential restoration, so no credential writes were attempted.
- **Sources:** observations/management-tenant-settings.md (T1–T3), observations/management-attack-protection.md (A1–A6), their dated operation/behavior/vendor URLs, pinned node-auth0 7.4.0 and auth0-cli v1.37.0 public APIs. No hosted-page/dashboard assets or proprietary implementation were used.
- **Decision:** Match documented nested schemas and observed statuses; distinguish explicit local fallbacks from observations. PATCH session hours/minutes are integers >=1 with mutually exclusive aliases; GET hours may be fractional. Cookie mode lives at session_cookie.mode. Reject unknown/root-empty/invalid-null fields atomically; recursively merge unobserved object cases, replace arrays and reset only documented nullable fields. Store every inventoried inert field with its named future owner. Do not add the seed-only consent-description property to the public contract.
- **Protection policy:** Suspicious-IP rate is milliseconds per replenished attempt; separate token buckets use reference defaults rather than this tenant's overrides. Brute blocks expire 30 days after last failed attempt. Connection-scoped alias resolution, success refunds/reset and generation handling are local choices described in A2–A4. User-ID unknown read/delete is 404; identifier unknown delete is 204. Administrative User.Blocked remains separate from automatic state.
- **Legacy configuration:** Explicitly supplied legacy login_max_attempts/login_lockout_seconds initialize only absent tenant policy once in a transaction, with internal compatibility marker and warning. Unsupplied config uses documented new defaults. Subsequent seed/API settings win and restart never overwrites them; a relevant policy edit exits legacy semantics. Never expose compatibility markers as invented API fields.
- **Breach availability:** Default server checker is off and default local tenant breach policy disabled. Imported enabled policy remains enabled. Unavailable is not clean: blocking stages fail temporarily before mutation; monitoring-only may continue with a redacted event. Range lookup needs explicit server opt-in and only a SHA-1 prefix; local corpus and error fixtures do not claim Credential Guard/upstream corpus parity. Plaintext Management create/change checks use their corresponding local stage; exact upstream behavior is unobserved. Task 8 local error fixtures select `401 password_leaked` for password grants, `400 password_leaked` for direct signup, `400 invalid_body` for Management writes, and `503 temporarily_unavailable` when an enforcing checker is unavailable. Hosted forms use localized messages with the corresponding status. Reset refusal preserves the ticket, password, history and sessions. Legacy custom-login profile synchronization and first-time custom imports wait until the verified-password breach check succeeds. An existing imported hash still upgrades after successful verification before the check, preserving Plan 18/19 upgrade semantics; refusal nevertheless issues no session or token. `/dbconnections/change_password` only requests email; the password check occurs on hosted completion.
- **Bot risk:** Local shared 15-minute tenant/IP failure history, low/medium/high thresholds 10/5/1, is an explicit substitute for proprietary intelligence; no ML parity claim. Monitoring/allowlist handling is independent from other protections.
- **CAPTCHA:** Keep all documented provider settings, encrypt credentials and omit them from reads. Provider omission preserves; a supplied object needs all documented required children, including replacement credential. Explicit empty credential clears locally; an active external provider without usable required credentials is rejected. Required challenges with unavailable Arkose/Auth Challenge/Simple CAPTCHA verifiers fail closed; do not build a pretend solver or add Turnstile. Their fail_open flag is stored-only. This deliberately differs from vendor recommendations/failure behavior.
- **Direct API:** ROPG has no inline CAPTCHA completion protocol. Return requires_verification and require interactive web login. Signup/reset also refuse required challenges where no documented proof transport was established; no invented public required parameter. Local hosted forms bind proof acceptance to existing transaction/reset context and globally consume proof hashes at most once.
- **Provider versions:** Enterprise uses an API key for projects.assessments.create, not bearer API-key auth or legacy siteverify. Friendly v1 widget + solution/secret/sitekey verification is the frozen local choice; Auth0's public configuration page does not explicitly guarantee its version. v2 response/X-API-Key verification is incompatible and is not silently substituted.
- **Differences and limits:** Sparse/forced tenant projection fields, reset/merge defaults, existing-session lifetime changes, automatic connection/identity rules, local breach errors, local risk and verifier availability must be recorded in the compatibility matrix when implemented. Tests of these choices are local fixtures, not fabricated observations. No unresolved source ambiguity is permission to claim upstream parity.


### D-0045 implementation addendum (2026-10-24)

The runtime and console now implement Plan 19. Operator guides are
[tenant settings](../tenant-settings.md) and [attack protection](../attack-protection.md).
Seed top-level durations retain seconds and old validators; nested settings use
API units and reject duplicates. Empty device masks retain runtime fallback;
unusable nonempty masks refuse issuance. Huge session lifetimes saturate at
year 9999. Required provider service/credential failures are unavailable and
do not count as user risk. Plan 21 adds user blocked-account and breach
notifications; administrator notices and email unblock links remain deferred.
Device/general/Try limits remain open. No new module or adapted licensed code
was introduced, so NOTICE is unchanged.

## D-0046: Plan 20 signing-key and deploy-cli local contract

- **Context:** Public documentation and the pinned deploy-cli package leave runtime history, exact errors, registry support and several migration edge cases unresolved. The implementation session had no separate observer report or disposable-tenant authorization, so it made no live Management API calls.
- **Sources:** `observations/management-signing-keys.md`, `observations/management-deploy-cli.md`; Auth0 public Management API signing-key docs; Auth0 `auth0-deploy-cli` v9.1.0, MIT, tag `v9.1.0`, commit `b8178b4bf48f31d05e61f55918bba75d4c846c37`; RFC 7517 and RFC 5652.
- **Decision:** Until sanitized observer evidence supersedes it, follow documented scopes and success statuses; retain every unrevoked previous key; allow revoke only for previous keys; retain the first revocation timestamp on repeated calls. Backfill stable self-signed RSA/SHA-256 certificates without changing key identity and do not invent historical lifecycle timestamps. Custom public JWKS is limited to 1–10 validated public RSA/EC keys, stored separately, never published or trusted internally, and cannot reuse a managed key ID. The exact local field, validation and error contracts are tested, but are not represented as observed Auth0 behavior.
- **Migration contract:** Pin deploy-cli 9.1.0 and inventory all handler keys in `tests/e2e/deploy-cli/manifest.json`. Include nonempty clients, resource servers, client grants and tenant settings in the real CLI lane. Keep inert database/connection fixtures; mark the pinned databases/connections/attackProtection handlers tool-unsupported with exact dependency reasons and roadmap owners. Secret preservation requires the protected create-only bootstrap. The observer-only upstream export lane is unavailable until separately supplied.
- **Retired resources:** Only the finite collection GET paths for `/api/v2/rules`, `/api/v2/rules-configs` and `/api/v2/hooks` are in scope; writes are rejected and no wildcard success shim is allowed.
- **Management API local choices:** Rotation returns the key promoted from next to current in that operation's committed snapshot. All seven signing-key operations return `operation_not_supported` for the reserved system tenant, while internal Ensure/backfill still runs. These choices preserve the operation result identity and the existing boundary that tenant APIs do not mutate operator-tenant settings.
- **Retired-resource local fallback:** Collection reads return empty arrays (`rules`/`hooks` optionally use the standard totals wrapper); `rules-configs` returns an empty array. `read:rules` protects rules and rules-configs, and `read:hooks` protects hooks. The rules-config scope and exact error response are local choices pending observer evidence. No write or per-resource route is implemented.
- **Rationale:** These defaults preserve token verification and migration data unless an operation explicitly and irreversibly revokes a key. Local tests can establish zeroauthy's behavior; public docs and package source do not justify claiming unobserved server parity.

- **D-0046 execution addendum (2026-10-25):** Installed SDK evidence corrects the
  revoke path to `/api/v2/keys/signing/{kid}/revoke`. The strict migration
  comparator now rejects dangling references on each side independently and
  permits only approved field/rule normalizations. Local CLI 9.1.0 passes four
  isolated format/credential-mode combinations. `databases` requires the
  unimplemented Actions API; generic `connections` excludes `auth0`;
  `attackProtection` requires phone-provider protection. These are explicit
  versioned tool limitations, not successful migrations or new empty shims.
  D-0039's credential-preservation recipe and D-0041's built-in API name are
  resolved for supported local migrations; upstream parity remains unobserved.

## D-0048: Branding and Universal Login local contract (Plan 22)

- **Evidence:** Public API documentation and the pinned MIT Node SDK 7.4.0,
  Auth0 CLI 1.37.0 and Deploy CLI 9.1.0. The frozen operation/field inventory is
  `internal/brandingrules/inventory.json`; `observations/branding-prompts.md`
  records unavailable live upstream evidence. Local tests establish zeroauthy's
  behavior, not unobserved server parity.
- **Storage and ownership:** A tenant aggregate with CAS owns branding,
  templates, themes/default pointer, prompt settings, text and partials. Legacy
  branding/text projects once. Omitted seed sections preserve API configuration.
  Older plugins fail visibly rather than returning empty records. Theme creation
  activates it; updating an inactive theme does not; deleting the default clears
  the pointer without selecting another theme.
- **Rendering:** Share the bounded email Liquid evaluator while preserving email
  behavior and limits. Hosted HTML/CSS is a restricted subset, public context
  is projected and escaped, and branch-sensitive trusted markers preserve the
  head/widget. Invalid presentation falls back without altering authentication
  fields/status/CSRF/CAPTCHA. Protocol pages and reserved-system login retain
  their existing CSP. Full Liquid/Auth0-template parity is not promised.
- **Preview:** Synthetic server fixtures, no state/config writes, strict no-network
  CSP and a sandbox granting no capabilities. Because `srcdoc` inherits the
  console CSP, validated styles rebind to a per-document console style nonce;
  scripts remain disabled. External image placeholders are intentional.
- **State:** Identifier-first is captured at transaction creation. CAS precedes
  password authentication; uncertain infrastructure failures require a fresh
  transaction. Accessible `ulp-` fields bind exact rendered declarations,
  configuration revision, state revision, screen and locale. They live only in
  the expiring transaction, never metadata/claims/logs/mail/custom-DB arguments.
  Future Actions validation and custom-DB prompt context need separate designs.
- **Compatibility limits:** Classic/WebAuthn-first settings, unsupported theme
  controls, recognized future text/partials are stored only. ACUL, tenant
  JavaScript, custom domains, social controls and organizations remain deferred.
  Public template APIs supersede the old filesystem-template-directory follow-up.
- **Tool boundary:** Deploy CLI exports branding settings, the default theme,
  prompts, custom text and partials. Template export requires custom-domain
  discovery and is explicitly unavailable; no empty success shim or fabricated
  domain is added. Missing templates are not normalized away. ACUL discovery
  remains unavailable and is reported by the pinned tool.

## Plan 23 — frozen custom-domain contracts (2026-10-26)

Public API schemas and the local design govern the nine-operation inventory in
`internal/customdomain/inventory.json`; the pending creation description wins over
ready sample values, string-only metadata wins over SDK nullable values, and the
diagnostic operation requires update scope locally. Upstream errorCode details
remain unobserved. See observations/custom-domains.md for licensed client provenance,
strict query limits, stored-only RP IDs and Deploy CLI header/default constraints.
Universal Login template GET adds documented `body` while preserving the
existing `template` alias; PUT retains `template`. No ACUL claim is implied.


### Plan 23 implementation choices

- One global normalized hostname owner; pinned canonical API audience; existing
  privileged aliases preserve upgrade identity. Roll out a stopped/drained fleet,
  not mixed old/new resolver nodes. Legacy empty-origin grants mean canonical.
- Background ownership checks run independently of ACME. Managed notification
  origins recheck certificate validity at selection/execution even if workers
  are stopped; implicit fallback retains the configured default pointer.
- DNS cleanup requires the current resource lease before the bounded provider
  call; stale workers leave shared challenge records to their successor.
- Certificate/account material uses shared wrapper keys and versioned AAD.
  Hosted wildcard retry backoff remains per-worker memory, a documented limit.
- Template GET supplies body+template. Strict Deploy CLI migration uses explicit
  destination preparation, staged proof/default import and API-only-header
  rejection; target-specific identity/proof/origin fields are not portable.
- Custom public signing JWKS publication, WebAuthn RP enforcement, ACUL, prompt
  partial domain context and additional DNS providers remain follow-ups. No
  unavailable observer/provider lane is labeled as live passing evidence.


## Plan 24 — frozen federation contract (2026-10-26)

Connection-list checkpoint mode preserves the existing take/from presence
selection ahead of page/per_page, default take=50 (1–100),
`{connections:[...],next?}` envelope, previous-next-to-from continuation and
next omission at the terminal/empty page. include_totals does not add summary
fields in checkpoint mode, even when true.

The [source inventory](observations/social-connections.md) and
`internal/federation/inventory.json` govern subsequent implementation tasks.
Only google-oauth2, oauth2 and back-channel oidc are active. Public PKCE examples
confirm OIDC `scopes` string; node-auth0 7.4.0 types use `scope`, which remains an
unconfirmed alias and is rejected. Google supports email/profile flags, default
openid profile email. Purpose uses the source-confirmed `authentication.active`
object, already persisted by connrules, rather than a scalar false or enabled key.

Supplied options replaces nonsecret settings; omitted sealed client_secret alone
preserves credentials. All ordinary reads/exports omit provider secrets; explicit
reinjection is required. Existing local connection scopes/public-options behavior
is retained, a difference from the documented options-specific scope gate.
Individual GetUser with read:users AND read:user_idp_tokens projects string
identities[].access_token/refresh_token and no-store; all other projections omit
these fields, even though upstream unlink schemas also declare scoped tokens.

Google IDs retain provider|subject. OAuth/OIDC use provider|connection-name|subject
as an explicit local format, with fixed-prefix parsing so subject separators are
preserved. Connection names reject the separator. Immutable connection ID plus
raw subject is authoritative; public-ID collision or ambiguous import fails closed
without email matching or silent remapping. Generic upstream ID serialization,
script context details and provider-specific error identifiers remain unobserved.

Mandatory S256, immutable issuer/client binding, bounded script/network behavior,
first provisioning under never_on_login, and the explicit context/metadata
allowlists are local policies. Unsupported configured Google domain restrictions
fail validation; hd is only a hint. Parameter maps may round-trip inertly with
diagnostics, but protocol/domain/authentication overrides are rejected. In particular,
acr_values, max_age, claims and prompt are rejected for every value and for
aliases naming those keys, before any inert-map storage.

Pinned MIT sources inspected: node-auth0 v7.4.0 management connections/types/users;
auth0-cli v1.37.0 commit a6239f907a81238e081a4abb1882c028558b2655
internal/cli/connections.go; auth0-deploy-cli v9.1.0 commit
b8178b4bf48f31d05e61f55918bba75d4c846c37 connection/YAML/directory/default handlers.
No source was copied. Social script files need explicit source materialization
(directory JSON) or a YAML scalar include; no implicit .js path expansion exists.
The tool also needs directory-provisioning discovery and skips empty desired
client lists in one helper; Tasks 11–12 must resolve/report these actual dependencies.
All real tool-runtime/provider/tenant comparisons remain deferred or unavailable.

## D-0049: Social and OIDC federation runtime (Plan 24)

Local runtime decisions on top of the frozen contract above; none is an
observed upstream behaviour.

- **Identity ownership:** the store maintains a `(tenant, connection ID,
  subject)` index inside every user create/update/delete and connection
  delete; an identity naming an unknown connection, or one of another
  strategy, is refused. Federated identities never enter the email/username
  login index. Upstream tokens are keyed by identity, not user, so linking
  moves ownership without decrypting them.
- **Identity epoch:** every user deletion and identity removal/transfer
  increments a tenant epoch in the same transaction; attempts started before it
  cannot complete. No tombstones or clock comparisons.
- **Attempts:** single-use, superseded per login transaction, bound to a
  per-attempt `za_fed_*` cookie, the transaction origin and the connection
  revision; claim is one conditional write. The final transaction rechecks
  attempt, epoch, revision, enablement and the callback host binding, resolves
  the identity, writes tokens and creates the session; the login transaction is
  ended by the existing resume path right after commit.
- **Buttons:** a connection whose `show_as_button` was never named shows a
  button; only an explicit `false` hides it (explicit `connection=` still
  works). A posted social choice is handed to the provider by an auto-submitted
  GET page whose CSP `form-action` admits only the provider origin, because
  browsers apply the login page's `form-action` to redirects after a POST.
- **Protection:** `social-login` spends the suspicious-IP pre-login budget at
  the provider redirect; `social-signup` applies the registration budget to a
  first provisioning; the callback checks current IP blocks without charging.
- **Scope:** `read:user_idp_tokens` is excluded from `allow_all_scopes` and never
  shown to operators.
- **Profile scripts:** one short-lived Node 25+ process per execution with a
  startup probe proving socket and fetch denial; OAuth2 is refused before the
  provider redirect when the runtime is unavailable.
- **MySQL:** every user-ID column becomes `VARBINARY(1280)` (subjects
  `VARBINARY(1024)`) so 1024-byte subjects never truncate.

## D-0051 — Plan 25 email-account contract (2026-10-26)

Freeze Microsoft personal `windowslive` and enterprise `waad` as a documented
local v2 sign-in subset; preserve Google. See
[public evidence and limitations](observations/email-account-connections.md)
and `internal/federation/email_accounts_inventory.json`. Fixed sign-in scopes,
ID-token-only profiles, conservative Microsoft email verification and
organizations-only multitenancy are deliberate choices. Multitenant `tid:oid`
identities differ from the pinned SDK's common-endpoint `sub` hint. Public
userid option confirmation is unavailable; neither SDK types nor our chosen
IDs establish Auth0 defaults or legacy-ID migration parity. No live observation
or provider login result is claimed. Unknown harmless metadata stays inert;
unsupported security requirements fail validation. Capability and existing-data
preflight must precede Microsoft activation; migration 0021 remains unchanged.

Implemented 2026-10-27 as frozen, with no contract change. Deploy CLI
migration requires explicit per-connection provider-secret reinjection; see
`docs/email-account-connections.md` and the Plan 25 implementation record.

## D-0052 — Plan 26 tenant roles and permissions contract (2026-10-27)

Freeze the [public review and limits](observations/roles-permissions.md) and
`internal/rbacrules/inventory.json`. Membership operation scopes are all-of;
creation/mutation success statuses follow each public operation rather than a
uniform REST convention. Group/organization-role/effective-role APIs remain
deferred. Runtime/profile behavior follows public RBAC/profile docs and RFC 9068.

Explicit local decisions where public material leaves the contract open:

- Role names: 1–128 Unicode code points, no controls or whitespace-only names;
  exact tenant-local case-sensitive uniqueness. Descriptions: 0–255 code points,
  no controls; omitted patch preserves, empty clears, null rejects.
- Assignment batches: 1–100 items before deduplication; atomic validation,
  idempotent valid additions/removals. Unknown references fail rather than
  partially changing assignments. Invalid input 400, missing parent 404,
  conflicting role name 409.
- Permission source projection: DIRECT omits source ID/name; ROLE carries
  source_id/source_name. Current public schema says any; this is no observation.
- Stable ID ordering and tenant/role-bound exclusive checkpoint cursors;
  offset/checkpoint mixtures are rejected. Cursor expiry is not promised.
- Scope deletion atomically removes both direct and role edges; recreation
  restores no rights. API/user/role/tenant deletion removes only owned edges.
  Account linking keeps primary privileges and never unions secondary rights.
- Reserved system APIs and protocol scopes cannot receive user assignments.
  RBAC-off `_authz` omits user permissions. M2M authorization remains client-
  grant-based, while its requested access-token profile still applies.
- Refresh scope ceiling is the original client/consent-authorized set before
  RBAC; later assignments may activate a requested scope but cannot introduce
  an unrequested scope. Current assignments are read at each issuance snapshot.
  Revocation affects the next snapshot; already-started issuance/issued JWTs
  are not retroactively cancelled.
- Old plugins fail capability admission before serving new code; operators
  upgrade all writers before enabling RBAC. No downgrade to permissive tokens.

These are implementation contracts, not proof of completion or live parity.

## D-0053 — Plan 27 Actions contract (2026-10-27)

Freeze the [public review](observations/actions.md) and
`internal/actionsrules/inventory.json` (14 operations, `post-login` and
`credentials-exchange`). Success statuses follow the public reference (create
201, delete 204, deploy and version deploy 202, test 200). No live tenant was
observed; unavailable items are listed in the review and never invented.

Local choices where public material is silent or open:

- Names 1–128 code points, unique per tenant, case-sensitive; runtime `node22`
  only; <= 64 secrets; <= 50 dependencies; <= 20 bindings per trigger;
  continue state 15 minutes, single-use; <= 5 redirects per login; artifact
  <= 50 MB. Code, secret and cache limits are Auth0's published values.
- `modules` and `registry_url` and binding `secrets` are refused with 400;
  only the two triggers are advertised and creating an Action for any other
  trigger is 400 until Plan 28. Build status emits pending, building, built,
  failed only. Unknown properties 400. Binding an undeployed Action 400.
- Secrets are snapshotted into a version at deploy; a secret change takes
  effect at the next deploy (public docs silent).
- Errors: `actions.ErrDraftNotBuilt` maps to 400 and a missing Action or
  version to 404 at the test endpoint. Test runs record rather than apply
  metadata, redirects and denials, uses a throwaway cache and writes no
  execution record.
- Delivery: `access.deny(reason)` on authorize redirects with
  `error=access_denied`; at the token endpoint it is 403 `access_denied`;
  uncaught error or timeout redirects `server_error` with a generic
  description and shows a hosted error page with the execution reference
  when the client shows error pages; the reference never appears in OAuth
  `error_description`. Credentials-exchange deny codes are `invalid_scope`,
  `invalid_request`, `server_error` (documented); other codes fail closed.
  Their HTTP statuses are 400, 400 and 500 respectively (local).
- Metadata commits once at flow end on success, deny or validation.error and
  is discarded on error, timeout or unsupported call; across a redirect it is
  held in continue state. Post-login runs before the consent screen (public
  scope docs show consent lists Action-edited target scopes); effects of a flow
  whose consent is later declined are not rolled back beyond the metadata
  rule above. `event` reflects earlier Actions for `transaction.target_scopes`
  and `transaction.metadata` (documented) and `user.app_metadata`/`user_metadata`
  after a commit-free in-memory overlay (local).
- `/userinfo` does not return Action ID-token custom claims in Plan 27; this
  supersedes the original local default and remains deferred (Ruling 10).
  Non-namespaced access-token claims are dropped for the tenant's Management
  API audience. `request.geoip`, `asn`, organization, MFA, prompt, agent and
  Enterprise members are omitted; `groups.*` return empty; `rules.wasExecuted`
  is false; session, refresh_token, authentication, multifactor, prompt and
  samlResponse members throw "not supported by zeroauthy" and fail closed.
- Execution IDs appear in the operator log line for every failed or denied
  flow (tenant, trigger, Action name, secrets masked), in test-endpoint
  responses, and as a "reference" on the hosted error page; they are never put
  in OAuth `error_description`. Record retention 10 days (documented).
- Lists (actions, versions, bindings): `page` from 0, `per_page` default 20
  (documented) and local maximum 100; larger is 400.
- Secret names match `[A-Za-z0-9_]{1,128}`. Dependency `version` is an exact
  semver or empty/`latest` (resolved at build); ranges, git/file/URL/tarball
  specs and `registry_url` are refused with 400.
- At most 20 bindings per trigger, 400 above that. DELETE of an Action still
  bound to a trigger without `force=true` is 400 (local; the public page states
  only that it must be unbound).
- Byte units: Auth0's "kB" limits are taken as decimal (code and custom claims
  100,000 bytes; cache values 4,096 and total 8,192 as binary-exact values the
  public page writes as 4 kB/8 kB; secret value 4096 bytes); the artifact
  limit is 50,000,000 bytes. The inventory stores these exact integers.
- `event.transaction.id` is a random 24-character ID generated per post-login
  flow and kept across redirects (local format; credentials-exchange has
  none). Action code cannot connect to unix-domain socket paths (local
  hardening; Node's permission model does not cover them); TCP is open.
- Unsupported `api` members throw at call time and fail the flow; none is
  silently omitted. "Metadata commits at flow end" means user and app
  metadata; transaction metadata lives only for the transaction.
- Consent order source:
  https://auth0.com/docs/customize/actions/handling-scopes-in-actions.

- Token-endpoint post-login `validation.error` is 403 with its supplied code.
  Codes are 1–128 bytes in the RFC 6749 error charset; reasons/messages replace
  disallowed bytes with `?` and truncate at 512 bytes. Device approval cannot
  redirect. Password/realm protocols are `oauth2-password` /
  `oauth2-resource-owner`; `device_code` joins stripped request credentials.
- User scope order is request → target edits → API/application policy/RBAC →
  consent → final access-token edits. `addScope` bypasses the former checks;
  add/removeScope do not change ID-token issuance, and adding offline_access
  cannot create a refresh token. Refresh ceilings are issued/consented scopes
  intersected with pre-Action authorized scopes; Action additions never enter
  them. Refresh reruns Actions; consent-requiring clients' target additions
  also need stored audience grants. Target edits can restore family scopes
  omitted by a downscoped refresh request. Removing final offline_access
  suppresses rotation, while target-only removal can still rotate a family.
- Bound post-login flows on RBAC-enabled APIs snapshot assignments before
  execution. They survive consent/code/device/continue; role assignment via
  Management API affects the next issuance. Current API definitions/settings
  and application policy still apply at mint; captured permissions intersect
  current declared non-protocol API permissions. Without a captured flow,
  ordinary issuance-time RBAC reads apply. RBAC-disabled APIs omit permissions.
- Redirect/resume phases each have their own execution record; an execution
  ID does not span the browser gap. Test IDs are ephemeral with no lookup row.
  Execution purge runs hourly and expired continue-state purge every minute.
- Synchronous latest resolution is limited to 15 seconds per resolver process,
  with a separate bounded semaphore; slot wait follows caller context.
  Interrupted pending/building drafts recover on Queue/GET/deploy/test,
  rather than a startup scan. Artifacts are store-backed and hash-verified on
  extraction; existing extracted roots are trusted. npm runs with private HOME,
  empty user/global configs and ignored scripts; its built-in npmrc remains
  readable. Registry authentication via operator .npmrc is unsupported.
- Action seed application uses ApplyWithActions: ordinary seed transaction,
  then external builds, then atomic ready Action create/deploy. Existing names
  and initialized trigger sets are create-only in both modes. Durable atomic
  tenant/trigger initialization preserves management [] across restarts and
  remains retryable after rollback. This supersedes the empty-trigger heuristic.
  Actions plugin capability is 2; older plugins refuse startup.
- Runtime console capture currently keeps 100 messages of up to 2048
  characters each (plus level prefix). Inventory's 256-character per-Action
  declaration is not enforced; this is a deferred minor contract drift.

Local implementation and verification are recorded in the
[Plan 27 record](../superpowers/2026-10-27-plan-27-implementation-record.md).
The final whole-branch review and its fixes are in the implementation record; no live upstream parity is claimed.

These are implementation contracts, not proof of completion or live parity.

## D-0054 — Plan 28 Actions II contracts (2026-10-28)

Sources: the [Actions II source review](observations/actions.md#actions-ii-contract-review-2026-10-28)
links every public reference and the pinned open-source client files. These
are implementation contracts; Task 1 does not claim runtime completion.
Plan 27 isolation, sandbox, build, fail-closed and dry-run rules still apply.

Scope and catalogue (author's call): add only triggers whose calling flow
already exists: pre-/post-user-registration, post-change-password,
password-reset-post-challenge and custom-email-provider. With Plan 27's two,
the catalogue has seven `trigger-bound` triggers; all others remain 400 on
Action creation. Phone triggers belong to Plan 34, custom-token-exchange to
35, event-stream to 32. Password-hash-migration, login-post-identifier,
signup-post-identifier and post-credential-validation have no assigned plan
(`DeferredTrigger.Plan = "deferred"`). Custom user ID assignment, Akamai risk
signals and JA3/JA4/security_context remain deferred. The inventory lists
fields zeroauthy will supply; it does not imply every upstream optional
field is implemented. GeoIP, security_context and authentication risk data
are omitted. Reset authentication challenge methods (Plan 33) and prompt
render (Plan 38) throw "not supported by zeroauthy" and fail closed.
Reset handler exports are `onExecutePostChallenge` and
`onContinuePostChallenge`, confirmed in the public reset overview. The reset
API reference lists three redirect methods, without `canRedirect`; exposing
`redirect.canRedirect` there is a local reuse of the Plan 27 helper, not a
claim that the reset reference documents it.

The separate observer's documented trigger catalogue read found `v2` current
and `v1` deprecated for pre-/post-user-registration and post-change-password,
with `node22` available. Inventory `Version` records `v2` for those three;
this metadata does not prove trigger execution or alter runtime behavior in
Task 1. Versions not confirmed in this review remain unspecified.

The six evidence gaps in spec §2 are frozen as follows; unavailable live
checks leave these defaults in force (see the observation availability
record for the actual extent of upstream evidence):

1. Management API user creation and bulk import do not fire registration
   triggers. Database-connection signups do, including hosted and custom-DB
   signup; passwordless is deferred until its caller exists.
2. Post-change-password fires after hosted reset/change-password-ticket
   submission and Management API PATCH of a database user's `password`.
   Bulk import, password-hash migration and custom-DB-only changes do not
   fire it; a custom-DB script reporting no change does not fire it.
3. Pre-registration deny at `/dbconnections/signup` returns HTTP 400 with
   `name: ExtensibilityError`, `code: extensibility_error`, `description`
   equal to the supplied user message and `statusCode: 400`.
   `validation.error` uses the Action's code instead. Hosted signup shows
   the user message on its signup page. An uncaught error, timeout or
   unsupported call returns a generic 400 extensibility error; the hosted
   generic view includes the execution reference. No user, custom-DB create
   call or post-registration job is allowed after a failed blocking flow.
4. Custom-email-provider uncaught errors and timeouts are treated as retry.
5. At most 100 versions per module, 100 modules per tenant and 10 module
   references per Action. Module code is at most 65,536 characters and name
   at most 255; secret values retain the 4096 limit. The code/name bounds
   are public schema constraints; the counts are local defaults.
6. Rollback replaces the module draft's code, dependencies and secrets; it
   does not publish or change existing Action versions. This agrees with
   the public rollback reference.

Registration metadata is validated and merged into the insert. For a legacy
custom-DB connection (author's call), merged `user_metadata` is passed to the
existing create-script contract and `app_metadata` is applied only to the
local record after that script succeeds. A later duplicate-user/insert
failure uses the ordinary signup error and discards metadata. Pre-registration
has no user ID or password. Every request body removes password-like fields.
Hosted-only transaction fields and custom-domain fields are conditional.

Reset challenge outcome is stored on the bearer reset ticket (author's
call), with pass time and optional result URL. A passed ticket skips the
challenge on later opens; deny/error records no pass and does not spend the
ticket. POST checks current bindings and refuses an unpassed ticket without
spending it, including bindings added after GET. With no bindings the existing
POST behavior applies. Redirect/continue binds state to the ticket hash and
`za_reset` cookie; a resumed success records the pass. `setResultUrl` uses the
ticket URL rules: absolute HTTPS, or HTTP for localhost, with optional query.
Invalid URLs fail the flow. Reset deny displays the supplied reason.

Non-blocking work uses a durable, shared per-tenant job queue (author's call).
Enqueue pins bindings, Action versions and module versions and seals the event
snapshot with the master-key envelope. Enqueue occurs in the same store
transaction as the user/password/email write; without a surrounding
transaction it follows the local write. A worker holds a 60-second lease,
longer than the 20-second flow budget. A run is delivered again only after
lease expiry or an explicit email retry; lease expiry gives at-least-once
delivery. Registration/password jobs run once, even on failure. Every run
leaves an execution record and failure logs include its ID. Per-tenant
process limits and timeout effects are shared with blocking Actions.

Custom-email retries use the local schedule 30 s, 1 m, 2 m, 4 m and 8 m
(five retries after the initial attempt). The final retry/drop call wins;
reasons truncate to 1024 characters. Drop is terminal; exhaustion is failed.
The pending cap is 10,000 per tenant. At that cap signup/password changes
still succeed and log the dropped job; email enqueue reports provider failure.
Jobs and execution records are purged after 10 days. Custom email with no
binding is a provider configuration error; no fallback transport. Send returns
on enqueue; console test send waits for the first attempt up to 20 s and
reports its outcome. The test message type is
`try_provider_configuration_email`; other types are emitted only for existing
email flows. Database users start tracking `last_password_reset`.

Module create with `publish:true` waits for a ready build and publishes in
the request; failure/timeout leaves no module. Publishing an unbuilt draft is
400, an unchanged draft 409, version exhaustion 412. Module delete in use is
412; "in use" means any Action draft or currently deployed Action version
(author's call). Older versions and queued jobs instead retain hidden module
version tombstones until no Action version or job pins them. List/usage counts
use this same local definition. Module names are immutable, PATCH secrets
replace the whole list, values remain write-only and sealed per tenant/module.
Public create schema permits names without NUL up to 255 characters; the
pinned CLI's stricter lowercase name validation is a client rule, not adopted
as an undocumented server requirement. Module pagination follows the public
page/per_page schema (page 0, default 20 where paging applies) and Plan 27's
local maximum 100; module list with both paging parameters absent is unpaged.

Action drafts accept module IDs/version IDs or name/version-number pairs;
responses include all four fields. Missing modules/versions are 400. Deploy
pins exact versions, never auto-upgrades. Each module is evaluated once per
Action-version/module-version pair in a private context with its own npm tree
and `actions.secrets`, with log masking. It cannot import `actions:*` or read
another Action/module/tenant's secrets or build tree. Plan 27's `registry_url`
and binding-secret refusals continue; its Action `modules` refusal is
superseded. Test execution records effects without applying them, sending
email or enqueueing jobs. Seed ownership remains create-only.

Pinned open-source support is available: Deploy CLI 9.1.0 imports/exports
`actionModules` in YAML and directory formats and resolves Action module
name/number references; auth0-cli 1.37.0 exposes native module and version
commands and `--module` on Action create/update; node-auth0 7.4.0 exposes all
ten module operations. The public tutorial's claim that auth0-cli lacks a
module flag is stale relative to that pinned source. This is source support,
not a completed local round-trip; Task 13 must exercise all four Deploy CLI
format/credential cells with modules. Implementation is original; no upstream
code was copied or adapted.

Final-review addendum (2026-10-28). Auth0 documents "You can have at most one
Action bound to the `custom-email-provider` trigger"
(https://auth0.com/docs/customize/email/configure-a-custom-email-provider/configure-a-custom-email-provider-with-terraform).
zeroauthy enforces that limit in `PATCH /actions/triggers/custom-email-provider/bindings`,
the seed, the console and every store's `ReplaceBindings`. Auth0 documents no error body for a second binding;
the refusal uses the existing local binding-validation 400 (`invalid_body`),
a local choice. Independently of the limit (jobs queued earlier, or bindings
written outside the API), a recorded `drop` is terminal even when a later
Action fails, and an attempt in which any Action completed without asking to
retry is failed instead of retried, so a completed Action never runs again; a
job envelope that cannot open fails at once. Without an Actions engine, a
signup whose tenant has pre-user-registration bound fails closed, as the reset
page does. Restoring an old Action version into the draft (`update_draft`)
keeps that version's pins to deleted-module tombstones; only the Action whose
versions pin a tombstone may keep it in its draft.

Isolation addendum (2026-10-28). Review Focus 5 asked that module code be unable
to read the importing Action's secrets or another module's secrets. The final
review showed this does not hold. Per-version and per-module VM contexts share
host-realm objects (`console`, `process`, `Buffer`, `require`, Node built-ins),
and npm dependencies load through Node's own loader in the host realm. So code
in a tenant's Actions process can read every Action and module secret of that
tenant. The maintainer ruled on 2026-10-28 that the tenant is the trust domain.
Separating secrets inside a tenant is documented as a convention, not a
guarantee, and no follow-up plan is scheduled. The boundaries that still hold
are enforced outside the VM. Each tenant has its own Node process with an empty
environment (no server environment variables), Node `--permission` limits reads
to the runner and the tenant's build root with no writes, child processes,
workers, addons or WASI, signalling is locked, and unix-socket path connections
are refused (D-0053). Whether Auth0 separates secrets between Actions and
modules of one tenant was not observed.

## D-0055 — Plan 29 Organizations I contracts (2026-10-28)

Sources: the public Management API reference (each operation page under
`https://auth0.com/docs/api/management/v2/organizations/`, the public
OpenAPI document `https://auth0.com/docs/oas/management/v2/management-api-oas.json`
and `users/get-user-organizations`), the Organizations guides listed in spec
§2, the pinned clients below, and the separate observer's
[notes](observations/organizations.md) (2026-10-28, maintainer's tenant,
documented endpoints only). The frozen inventory is
`internal/orgrules/inventory.json` (`orgrules.Inventory`, `Deferred`,
`InventoryMetadata`). These are implementation contracts; Task 1 claims no
runtime behavior. Where an observation contradicts a spec default or the
public schema, the observation wins (strict parity) and the spec was
corrected.

**Operations (20; 26 with the Task 5 addition at the end of this section).** Organizations CRUD and lookup by name; members; member
roles; effective roles; role members; enabled connections;
`GET /users/{id}/organizations`. Scopes follow the public reference:

- the member list accepts either `read:organization_members` or
  `read:organization_member_roles`, and `fields=roles` needs
  `read:organization_member_roles`;
- effective roles need `read:organization_member_effective_roles`, not
  `read:organization_member_roles`;
- role members need both `read:organization_members` and `read:roles`
  (all-of, as D-0052 does for membership listings; the public reference lists
  both and gives no 403 text). This operation is Early Access upstream and is
  kept in Plan 29 as the spec chose;
- user organizations accept either `read:users` or `read:organizations`;
- `POST /organizations` also needs `create:organization_connections` when it
  carries `enabled_connections`.

**Spec §2 items.** Status is from the observer notes. Unavailable or
unobserved parts keep the spec default as a local decision.

1. `/authorize` errors: **partly observed.** Before authentication, these
   redirect to the callback with `invalid_request`: an unknown or malformed
   ID; a name while names are off; `organization` sent to a `deny` client;
   `require` + `no_prompt` without an organization; and any `invitation`
   (Plan 30). `organization=` with an empty value counts as absent. **A
   `connection=` that is unknown, or not enabled for the organization, gives
   no pre-authentication error** (correction). The hosted login offers only
   the client/organization intersection and refuses authentication through
   any other connection (local). Local decisions for the parts after
   authentication: a non-member without auto-membership gets
   `access_denied`; a third-party client facing `block` gets `access_denied`;
   a picker with no eligible organization gives `access_denied`. Errors that
   cannot be redirected use the D-0026 error page. Error descriptions are our
   own wording, one per cause.
2. `prompt=none`: **partly observed.** Without a session the result is
   `login_required` for a valid organization. `require` + `no_prompt` without
   an organization is `invalid_request`, because the organization check runs
   before the login check. The session-user cases keep the spec default
   (local): silent for a member or an auto-membership user, otherwise
   `login_required`; `require` + `post_login_prompt` is silent with exactly
   one eligible organization, otherwise `interaction_required`.
3. Tenant roles and direct permissions in an organization login:
   **unavailable.** Local: the union of tenant roles, direct permissions and
   the active organization's member roles, filtered by API.
4. Refresh: **unavailable.** Local: the refresh token keeps its organization.
   Every refresh re-checks that the organization exists and that the user is
   a member, with `invalid_grant` on failure and no revocation. Permissions
   are recomputed.
5. `allow` + `post_login_prompt` without an organization: **unavailable.**
   Local: no picker; the user logs in as an individual.
6. `is_signup_enabled` without `assign_membership_on_login`: **observed.**
   400 on create, and on enabled-connection PATCH in both directions.
7. Password and device grants for a `require` client: **observed
   (correction).** Auth0 refuses this at configuration time, not at the token
   endpoint. `POST`/`PATCH /clients` setting `organization_usage: require`
   while `grant_types` contains `password`,
   `http://auth0.com/oauth/grant-type/password-realm` or
   `urn:ietf:params:oauth:grant-type:device_code` is 400. Adding those grants
   to a `require` client is also 400. For `deny`/`allow` clients the grants
   work, ignore `organization` and never carry `org_id`/`org_name`. A
   token-time `unauthorized_client` remains only as defense in depth for
   stored legacy data.
8. Name format: **observed.** `^[a-z0-9][a-z0-9_-]{0,49}$`, the same on create
   and PATCH. Invalid names are 400 `invalid_body`. Rename is allowed;
   duplicates are 409.
9. Limits: **partly observed.** Observed: metadata at most 25 keys, keys 1–50
   characters matching `^[a-zA-Z0-9]\w*$`, values 1–255 characters;
   `display_name` 1–255; `per_page`/`take` 1–100; page window 1000 (400
   `invalid_paging` beyond it). Documented: at most 10 enabled connections on
   create. Local: 10,000 organizations per tenant; 50 enabled connections per
   organization; 50 roles per member; unlimited members; 1–10 IDs per
   member/role POST or DELETE.
10. Membership removal versus sessions: **unavailable.** Local: removal
    affects only the next authorization or refresh. Observed separately:
    **member role assignments survive membership removal** and reappear when
    the user is re-added (correction to spec §3). Tokens still require current
    membership. Deleting the organization, user or role removes the
    assignments.

**Frozen schema details** (observed unless marked otherwise):

- ID `org_` plus 16 ASCII alphanumerics. A malformed path ID is 400
  `invalid_uri`; a well-formed unknown ID is 404. The by-name route validates
  the name format before lookup.
- `display_name` defaults to `name`.
- `third_party_client_access` is always present and defaults to `block`.
- `is_app_entitlement_active` is always present and `false`. Writes of `true`
  are refused until Plan 30 (local).
- `branding`/`metadata` are omitted when unset.
- GET, by-name and list responses never carry `enabled_connections`; only the
  create response echoes them.
- **Metadata values are strings only**: null, empty and non-string values are
  400 on create and PATCH. The public schema allows null; the observation
  wins.
- `logo_url` must be https. A `colors` object needs both colors as HTML hex.
- **PATCH replaces `branding` and `metadata` whole, and `{}` or null clears
  them.** Omitted properties are untouched. An empty PATCH body is 400.
- DELETE of an unknown organization is 404, so it is not idempotent.
- Lists: a bare array; with `include_totals`,
  `{organizations,start,limit,total}`; checkpoint mode returns
  `{organizations,next?}` (no totals), and `from` wins over `page`. An invalid
  cursor is 400. Without `sort`, offset mode orders by ascending name and
  checkpoint mode by creation order.
- Members:
  - Items are `{user_id,email,picture,name}`.
  - `fields` takes `user_id,email,picture,name,roles`. With
    `include_fields` true or absent, only the named fields come back;
    `include_fields=false` excludes them; another name is 400. Roles appear
    only when requested, as `[{id,name}]` and `[]` when there are none.
  - POST with any nonexistent user is 404 `inexistent_user` and adds
    nothing. Adds and deletes are idempotent.
- Member roles:
  - offset pagination only (`take` is 400);
  - 404 for a non-member and for an unknown role;
  - DELETE for a nonexistent user is 404 `inexistent_user`;
  - otherwise idempotent.
- Effective roles return `{roles:[{id,name,description,sources:["direct"]}],next?}`,
  with checkpoint pagination and direct roles only until groups.
- Role members return `{members:[...],next?}`, checkpoint only.
  `include_totals`, `page` and `per_page` are ignored.
- Enabled connections:
  - Defaults are `assign_membership_on_login` false, `is_signup_enabled`
    false and `show_as_button` true.
  - `show_as_button:false` on a database connection is 400.
  - An unknown connection is 404 `inexistent_connection`; a duplicate is 409.
  - Unknown or camelCase properties are 400.
  - PATCH `{}` returns the entry unchanged.
  - DELETE of an existing connection that is not enabled is 204; DELETE of
    an unknown connection is 404.
  - The list with totals is `{enabled_connections,start,limit,total}`.
- Client fields:
  - `organization_usage` and `organization_require_behavior` accept null,
    which unsets them.
  - `post_login_prompt` requires `oidc_conformant` (documented and observed).
  - **`pre_login_prompt` is accepted with `deny`, `allow` and `require`**
    (correction: the spec refused it without `require`). With `allow` and no
    organization, `/authorize` shows the organization prompt.
  - `organization_discovery_methods` (EA upstream) needs at least one entry
    and is **allowed only while the behavior is `pre_login_prompt`**. Plan 29
    stores it and always asks for the name.
- Tenant flag: `allow_organization_name_in_authentication_api`, default
  false (documented). It was not toggled during observation, so name
  acceptance is a documented default.
- Client credentials with `organization` stay `invalid_request` (400) until
  Plan 30, **for every audience** (local), after the client-grant check, so
  a missing grant is still 403 `access_denied`. This matches the observed
  result for the reserved Management API audience. Client
  `organization_usage` does not affect client credentials.
- `/authorize` and PAR bind the resolved organization in the request under
  the internal `za_org_id`/`za_org_mode` keys, which no request parameter
  can set. With `request_uri`, an `organization` in the query is ignored
  like every other extra parameter (Plan 10 rule P1), so it can neither add
  nor override the pushed one (local).

**`/organizations/{id}/connections` ruling.** It is not a documented GA alias.
The public OpenAPI document marks all five operations
`x-release-lifecycle: EA`. The organization-connections guide says that
managing organization connections through the new endpoints and attributes
is Early Access. The reference page does not call it an alias. The observer
found it shares state with `enabled_connections` and adds `is_enabled`,
`organization_access_level` and `organization_member_access_level`. It is
deferred to Plan 30 (`organization_connections_ea`). Superseded by the Task 5
addition at the end of this section.

**Deferred** (with target plan in the inventory):

- Plan 30: invitations and the `invitation` parameter; organization client
  grants and grant organization fields; discovery domains and email
  discovery; client credentials `organization`; `/organizations/{id}/clients`;
  `/organizations/search`; `is_app_entitlement_active`; `/connections`;
  organization-scoped roles; `include_client_association_for`; the
  `read:organizations_summary` scope; client `default_organization`;
  change-password `organization`.
- Plan 35: `token_quota`.
- Plan 37: SAML/WS-Fed organization login.
- Plan 38: groups and group-sourced effective roles.
- Plan 42: My Organization API, client `my_organization_configuration`, and
  Universal Portals.

**Pinned clients** (source read, not run):

- auth0-cli 1.37.0, `internal/cli/organizations.go`, through go-auth0 1.50.0:
  `orgs list/show/create/update/delete/open`, `members list`, `roles list`,
  `roles members list` and invitations. It pages with
  `include_totals=true`, uses `enabled_connections`, and its update re-sends
  the whole branding and metadata it builds on the client, which is
  consistent with PATCH replace.
- node-auth0 7.4.0 organizations resources: every Plan 29 operation, plus
  EA/Plan 30/38 resources.
- Deploy CLI 9.1.0, `src/tools/auth0/handlers/organizations.ts` and the YAML
  and directory handlers: `name`, `display_name`, `branding`, `metadata`,
  `connections`, `client_grants`, `token_quota`, `discovery_domains` and
  `clients`. It **reads and writes connections through the EA
  `/organizations/{id}/connections`**. Its export lists organization client
  grants unconditionally, and a 404 or 501 empties the whole organizations
  export. It has no members or member roles. With `/connections` and client
  grants deferred, Task 13's organization Deploy matrix is unavailable unless
  the maintainer moves those reads into Plan 29.

**Author's calls carried from spec §5–§12** remain as written there:

- PAR binds `organization`;
- codes record the organization;
- the picker shows at most 20 organizations, sorted by display name;
- member listings are ordered by `user_id`;
- the plugin capability is v1 with 501 fallbacks;
- operators can never leave the system tenant unmanageable (409).

**Addition (Task 5, maintainer ruling): `/connections` and organization
client grants for the Deploy CLI.** The pinned Deploy CLI 9.1.0 organization
handler exports nothing without these two reads, so Plan 29 serves them.
This supersedes the `/connections` deferral above; the POST and DELETE of
organization client grants stay deferred to Plan 30.

- `/organizations/{id}/connections` (list, POST, get, PATCH, DELETE) is
  Early Access upstream and is marked so in the inventory and the OpenAPI
  document. It uses the `*:organization_connections` scopes and is served
  from the same links as `enabled_connections`, so a link made through one
  resource is visible, and conflicts (409), through the other (observed).
  - Entries are the enabled-connection entry plus `is_enabled` (`true`),
    `organization_access_level` (`none`) and
    `organization_member_access_level` (`limited`). These are the values the
    observer saw. The observation does not pin the other values or what they
    mean, so they are **not stored** (local).
  - Writes may send `is_enabled: true`, the two default access levels (or
    null), and `organization_connection_name: null`. Any other value is 400
    `invalid_body`, citing D-0055 (local). Unknown properties are 400.
  - Lists accept `page`, `per_page`, `include_totals` and `is_enabled`
    (`false` gives an empty list). With totals the shape is
    `{connections,start,limit,total}`.
  - Flag rules, 404s and DELETE behave as on `enabled_connections`
    (local where unobserved).
- `GET /organizations/{id}/client-grants` needs
  `read:organization_client_grants` (public reference). It accepts `page`,
  `per_page`, `include_totals`, `audience`, `client_id` and up to 10
  `grant_ids`. It always returns an empty list (`[]`, or
  `{client_grants:[],start,limit:0,total:0}`), because organization client
  grants cannot exist until Plan 30 (local). Unknown and malformed
  organizations are 404 and 400 `invalid_uri`.
- Connection lists with totals report `limit` as the number of entries
  returned. This matches the observed `limit: 0` for an empty list; other
  pages were not observed (local).
- A storage plugin without the capability makes every organization route
  `501 organizations_unavailable` (local error code).

**Addition (Task 11, local operator grants).**

- `PATCH /api/system/operators/{id}` replaces `tenants` with existing tenant
  names, an empty array, or exactly `["*"]`; missing/null/non-array values,
  unknown names and mixed wildcard/name lists are 400. The response is the
  operator object. This follows the existing local system API prefix (D-0040).
- Both signed token grants and the current stored grants constrain every
  Management request. Shrinks take effect on the next request without reissuing
  a token; expanding storage does not expand an old token's narrower grant.
- Only system-capable operators can manage the system API. A separate local
  `GET /api/console/tenants`, on the system host, allows operator tenant discovery
  without a system grant. It returns the existing tenant DTO filtered by the
  intersection of signed and stored grants. It grants no system API access;
  M2M callers cannot use it. This dedicated discovery route is the maintainer's
  Task 11 ruling to preserve the no-system-access requirement for tenant-only
  operators while allowing their console to load.
- Operator PATCH/delete and system user delete/block/link-as-secondary serialize
  on the system tenant row before locking users. Removing the last usable
  system-capable operator is 409 `last_operator`. Tenant-only grants, orphaned
  operator rows and blocked users cannot serve as fallback administrators.
- The console refreshes discovery after a Management API 403, clears stale
  tenants if discovery fails, and offers tenant creation only with system
  tenant access.

These are local zeroauthy behaviors, without Auth0 API counterparts. The public
[dashboard operator guide](https://auth0.com/docs/get-started/manage-dashboard-access/add-dashboard-users)
provides context only, not these wire contracts.

### D-0056 — Organizations II wire contract and supported policy subset

Date: 2026-10-29. Status: accepted local implementation contract for Plan 30;
not a statement that these endpoints are operational. D-0055 remains authoritative
for its observed surface. No live Auth0 request or hosted-page capture informed
this decision. The per-operation public sources, scopes, request/response shapes,
null/omission policy, paging and errors are frozen separately in
`internal/orgrules/inventory.json` (`organizations_ii_operations`); Plan 29's
inventory and historical deferral entries are retained unchanged.

Evidence audit: the public documentation's `.md` representation embeds the
operation's OpenAPI contract, including OAuth security scopes (unlike the
rendered bearer-only authorization display). Each operation was checked
individually. Client associations use organization_clients scopes; domains use
organization_discovery_domains scopes; reverse grant organizations uses
read:organization_client_grants, not read:client_grants. Search's OAuth scope
array contains both read:organizations and read:organizations_summary. We require
both as listed; choosing an any-scope summary projection would need separate
proof and is outside this supported contract. This conservative interpretation
may reject a summary-only caller upstream accepts; it grants no extra access.

Documented corrections to the initial draft: invitation creation is 200; TTL
omitted/zero=604800 and max=2592000. Invitation list supports fields/include_fields
and sort (default created_at:-1); include_totals has start/limit/invitations,
**no total**. Client association POST is 201 with an array and requires explicit
use_for_member_access for every item. Domain list is `{domains,next?}`. Organization list annotation is `client:{use_for_member_access}`, omitted without an association; it is not a client summary or filter. Correct
public source paths are post-organization-connection,
delete-client-grants-by-grant-id, get-name-by-discovery-domain and
get-client-grant-organizations. Public domain POST permits status; this subset
accepts pending, defaults pending, and requires PATCH to attest verified (local).
Public source links are attached to every operation in the API YAML and inventory.

Omission/null rules: new org entitlement defaults false; grant organization_usage
and allow_any_organization default deny/false. PATCH omission preserves values;
explicit null is rejected for these policy fields. Client-subject grants alone
may activate organization policy; user-subject grants retain deny/false. Omitted
EA connection values preserve observed D-0055 defaults: enabled true, organization
access none, member access limited. This also governs migration, preserving the
observed member default rather than spec draft's proposed none. Explicit null
resets enabled to true, local connection name to the underlying name and either
access level to none (local). PATCH omission preserves. Access levels are stored
metadata only; delegated execution belongs to Plan 42 and never grants scopes
or login rights. Disabling retains the association; legacy enabled_connections
lists enabled associations only; legacy add can re-enable, delete removes it.

Internal Task 2 representation ruling (not an observed wire behavior): retain
`OrganizationConnection.IsEnabled bool` and add `IsEnabledSet bool`. A bare old
Go literal omits both; creation defaults enabled, while replacement omission
preserves the stored value. Explicit disable requires the marker true; persisted
reads and future SQL/plugin decoders restore it true. This marker never appears
in public DTOs. Empty access strings default none/limited on creation and preserve
stored values on replacement. API null clears are explicit none/underlying-name/
enabled-true values before storage. The alternative of interpreting every bare
false as disable would silently break existing Go callers.

Local validation/error rulings: reject unknown body keys, explicit null except
the EA clears above, and unsupported query combinations. IDs/references are
scoped to tenant; missing/cross-tenant parent or item returns 404 not_found for
Management. Malformed URI/body/paging returns 400 invalid_uri/invalid_body/
invalid_paging; token absence/invalidity is 401 invalid_token; insufficient route
scope or live operator grant is 403 insufficient_scope. Duplicate associations
or domains and failed write preconditions are 409 conflict; store ErrInvalid,
ErrNotFound, ErrConflict and ErrPrecondition map to 400/404/409/409 respectively.
These mappings are local where the public operation omits them (for example
some connection operations omit a 404). They do not claim observed upstream
messages. Invitation DELETE is 204 for missing/expired/consumed invite inside an
existing org; missing org is 404. Expired/consumed invitation GET is 404. Empty
roles are omitted in invitation output; optional absent metadata/connection is
omitted. Metadata objects use existing user metadata limits. Invitation roles
are deduplicated under the existing per-member cap. Duplicate invites remain
independent; wrong-account attempts retain their ticket. Acceptance is durable
before Actions; same transaction receipt replay is idempotent, other replay fails.

Local policy rulings: M2M malformed parameters yield OAuth invalid_request;
valid but forbidden organization yields access_denied (including absent required
org, missing org, or revoked association). Revoked code/refresh eligibility uses
normal invalid_grant. No live observation claims these exact error choices.
Explicit M2M org issuance moves from Plan 35 to Plan 30; quota controls/headers
stay in Plan 35, no default-M2M-org inference. Third-party clients cannot use
allow-any and require explicit grant association plus the existing org opt-in.
Member app entitlement never grants M2M permissions. Invitations bind original
tenant/org/client/primary connection across PAR/resume and cannot be accepted
at token exchange/refresh. prompt=none returns interaction_required.

Search documents q<=1000, max five predicates, take default50/max100 and
checkpoint-only paging. Local depth<=16, created_at then ID default ordering,
case-sensitive name/display/metadata comparison, >=3-character contains/suffix
literals and authenticated tenant/query/parser/sort cursor binding bound the
supported parser. Empty q matches all; next is omitted at end. Reads are locally
immediately consistent rather than upstream's eventual consistency. Unsupported
changelog-only boolean filters remain excluded.

Password change uses Authentication `organization`, Management ticket
`organization_id`, both IDs only. Omission adds no org context; null is invalid.
Tickets reject result_url together with organization_id as documented. Invalid
context is invalid_request in Authentication, 404 not_found for a missing
Management reference, 400 invalid_body for malformed input (local). Resolve
context before email lookup, preserve unknown-email anti-enumeration, carry the
bound ID through reset/email/branding, recheck org/connection at completion;
never add membership or silently fall back. Existing redirect restrictions apply.

Old plugins keep Organizations v1 and Plan 29 defaults/read behavior. Independently
negotiate OrganizationsII v1; new II Management reads/writes without it return
501 organizations_ii_unavailable (ErrOrganizationsIIUnavailable). Active II
authentication policy fails closed, never silently drops fields; transient
negotiation failures must be retried, not cached permanently. Public docs do
not define our plugin protocol, invitation URL validation, receipt semantics,
DNS attestation, metadata merge or failure ordering: the spec explicitly owns
these local choices. Domain verified status is administrative attestation, not
an assertion that DNS was queried. Quotas, groups, SAML, My Organization API and
self-service connection execution remain excluded.


D-0056 Task 5 prerequisite clarification (2026-10-29): application login URI is
required for application-first invitation URL construction. `initiate_login_uri`
now persists on Client through memory, SQL migration 0027 and additive protobuf
field 24; Management create/PATCH accept a validated HTTPS URI (local 2048-byte
bound), PATCH omission preserves and null rejects. This narrowly supersedes the
historical D-0039 ignored-field entry. The tenant `default_redirection_uri` is
used only when the application setting is absent. URI query values are preserved
except invitation/organization/organization_name, which are replaced. No live
Auth0 observation informed this prerequisite.


D-0056 Task 7 acceptance rulings (2026-10-29): the existing AuthTransaction.Params
is the sole invitation binding authority (invitation/org/client/forced connection),
with no additional InvitationID model field. External authorize/PAR parameters
cannot supply the reserved binding keys. Raw invitation bearers are replaced by
internal invitation IDs before transaction/PAR persistence and are absent from
Actions request query snapshots.

Acceptance checks the server-bound, persisted authenticated session, normalized
invited email and stored verified ownership. The current platform has no enforced
MFA subsystem (connection MFA remains stored-only under D-0041); Task 7 uses the
strongest established authentication completion point and introduces no client
MFA/verification assertion. Future enforced MFA must complete before this point.
Existing verification tickets/scripts remain authoritative; verification failure
retains the invitation and pending transaction for a verified retry.

Same-transaction receipt idempotence applies only to a live, pending transaction,
with its authenticated user/session binding. The normal completed hosted
transaction is claimed/deleted before Actions, preventing repeated Actions or
code issuance from completed POST replay. Actions denial or later issuance
failure leaves membership/receipt durable, but a denied completed flow needs a
new authorization request. A new transaction cannot reuse the consumed ticket.
Actions role snapshots now union tenant roles and the active organization's
member roles, deduplicated by role ID; other organizations and removed membership
contribute no roles. This is additive to the existing tenant role event/API
contract and does not assign organization roles at tenant scope. API permission
snapshot semantics remain the Plan 29 union.
