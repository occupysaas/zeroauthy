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
    - **Order:** sessions, refresh tokens and other tickets are revoked before the password is changed, so a storage failure part way leaves the account in the safer state.
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
  - Only `UnauthorizedError` shows the script's message, because Auth0 documents it as the way to send a message to the front end. Every other failure (another error class, a thrown exception, a timeout, an unavailable Node.js, a missing script, an invalid profile) is logged in `identity` with the tenant, connection, script, kind and the script's message, and the user sees a generic error. zeroauthy itself never logs passwords or configuration; messages your scripts produce (error messages, console output) are logged as they are, so don't put secrets in them.
  - Per surface:

    | Surface | `UnauthorizedError` | Other script failure | `change_password` returns false |
    |---|---|---|---|
    | Hosted login `/u/login` | 401; the login form again with the message (HTML-escaped); the attempt counts against the throttles | error page (500); see the throttle rule below | n/a |
    | Password grants | 401 `{"error":"unauthorized","error_description":<message>}`; the attempt counts | 500 `server_error`; see the throttle rule below | n/a |
    | `/dbconnections/signup`, `/u/signup` | 401 `unauthorized` with the message / the form again with the message | 500 `server_error` / error page | n/a |
    | `/dbconnections/change_password`, hosted forgot-password page | the usual answer, no email | the usual answer, no email, logged | n/a |
    | Hosted reset completion | the form again with the message; the link stays usable | error page; the link stays usable | the form again with `zeroauthy.reset.not-changed`; the link stays usable |

  - **Throttles.** Many legacy login scripts report a wrong password with a plain `Error` rather than `WrongUsernameOrPasswordError`. A failure the script raised therefore counts as a failed attempt, as wrong credentials do; otherwise such a script would allow unlimited guessing. Raised failures are an `Error` or `ValidationError` from the script, a thrown exception, an invalid profile, and a profile collision (D-0024). Only failures that kept the script from answering are refunded: a timeout, an unavailable Node.js, a missing script, a configuration that does not open, a cancelled request, and storage errors. `identity` tells the two apart with `ErrScriptUnavailable`; the refund list is an explicit allowlist, and any unrecognised error is counted.
  - **Legacy reset order.** On legacy connections the password changes in the legacy store (`change_password`) before the ticket is spent and sessions are revoked, so a failing script leaves the link usable. If revocation then fails, the new password is live while old sessions survive; the user should reset again.
  - On sign-up, a `create` script's `UnauthorizedError` is a 401 with its message. So is an `UnauthorizedError` from the login that confirms the new account; any other failure of that login is a script failure.
  - On sign-up, a `create` script's `ValidationError` with code `user_exists` is `user_exists`; any other `ValidationError` is shown like a rejected sign-up field (`invalid_signup` with the script's message).
  - The token endpoint's `unauthorized` is not one of RFC 6749 §5.2's codes. It is used because the client must be able to tell a script's refusal from wrong credentials, and the status (401) matches the meaning.
  - **Addendum (import mode).** In import mode `get_user` is optional, and the local store is authoritative. A connection without a `get_user` script finds nobody: sign-up goes ahead locally, and a reset request for an address with no local user sends no email. A `get_user` failure (other than a missing script) is reported as on a legacy connection. Errors from the `login` script on a user's first login are classified as above, so they count against the throttles in the same way. Once a user is migrated, a wrong password is checked against the local hash and is the usual wrong-credentials answer.
- **Rationale:** The surfaces never reveal more than they do for local users, the reset link survives a legacy store that is down, and the one message Auth0 intends for users reaches them.

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
    - Accepting consent merges the accepted scopes into the grant (observed). `prompt=consent` forces the screen. Declining leaves the grant unchanged (observed).
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
