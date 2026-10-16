# zeroauthy — Design: Consent, Third-Party Applications, API Access Policies (Plan 9)

- **Status:** Draft, awaiting review
- **Date:** 2026-10-16
- **Scope:** milestone 10, part 1 of 3 (spec §13). The maintainer split milestone 10 into Plan 9 (consent, this document), Plan 10 (PAR) and Plan 11 (device flow). Consent comes first because the device flow's `/activate` page reuses the consent screen.

## 1. Goal

zeroauthy decides who may get tokens for which API, and when the user must approve, the way Auth0 does today. Since the core spec was written, Auth0's model has grown:

- Third-party applications come in two modes, `strict` and `permissive` (`third_party_security_mode`, fixed at creation). New applications default to `strict` from 2026-10-23.
- `redirection_policy` keeps third-party applications from receiving error redirects.
- API access policies (`subject_type_authorization`) govern user flows as well as client credentials. Client grants carry a `subject_type` of `user` or `client`.
- Since 2026-04-28, a login confirmation prompt protects non-verifiable callback URIs by default.

The maintainer chose full parity: both third-party modes and the access policies.

**Success:**
- An unmodified auth0-spa-js app registered as a strict third-party client shows the consent page on first login. If the user accepts, the app gets tokens, and later silent authentication succeeds without a prompt because the grant is remembered. If the user declines, the app gets `access_denied`, or an error page under `open_redirect_protection`.
- A first-party app with a localhost callback sees the confirmation prompt unless `skip_non_verifiable_callback_uri_confirmation_prompt` is set.

## 2. Sources (clean room)

Auth0 public documentation:
- User consent and third-party applications
- Third-party applications: security controls, permissive mode, troubleshooting
- Migrate to enhanced security for third-party applications
- API access policies for applications
- Application access to APIs (client grants)
- Migrate to non-verifiable callback URI end-user confirmation
- Measures against application impersonation

Also OIDC Core §3.1.2.6 for the error codes, the Auth0 changelog (2025-10-28 entry), and observations on the maintainer's own tenant (§6), recorded under `CLEAN_ROOM.md` "Behavior testing against the maintainer's own tenant".

## 3. Data model

Seed YAML uses Auth0 Management API property names.

| Entity | Additions (default) |
|---|---|
| `Client` | `is_first_party` (true). `third_party_security_mode`: `strict` or `permissive`, third-party only, default `strict`, immutable after creation. `redirection_policy`: `open_redirect_protection` or `allow_always`, default protection for third-party clients and `allow_always` for first-party. `skip_non_verifiable_callback_uri_confirmation_prompt`: optional; when unset, the tenant's value applies. |
| `Tenant` | `skip_non_verifiable_callback_uri_confirmation_prompt` (false, so the prompt is on). `use_scope_descriptions_for_consent` (false). |
| `ResourceServer` | `skip_consent_for_verifiable_first_party_clients` (default from observation O1). `subject_type_authorization.user.policy`: `allow_all`, `require_client_grant` or `deny_all`, default `allow_all`. `subject_type_authorization.client.policy`: `require_client_grant` or `deny_all`, default `require_client_grant` (today's behaviour). |
| `ClientGrant` | `subject_type`: `client` or `user`. Uniqueness becomes (client, audience, subject type). Existing grants migrate to `client`, and `ClientGrants.Find` takes the subject type. |
| `Connection` | `is_domain_connection` (false). Third-party applications may log in only through domain connections. |
| `UserGrant` (new) | ID, client ID, user ID, audience, scopes, created and updated times. Unique per (tenant, client, user, audience). The repository offers `Find`, `Upsert` (merges scopes), `ListByUser` and `Delete`, and a user's grants are removed with the user. |

Plumbing:
- Migration 0003 for SQLite, PostgreSQL and MySQL, plus the memory driver.
- New `store/v1` proto fields, `UserGrants` RPCs and the `grpcstore` codec.
- `pkg/storetest` conformance for all new fields and `UserGrant`.
- Seed parsing, validation and apply. Strict clients must have expiring refresh tokens and RS256.

**Out of scope** (each gets a backlog row):
- Organizations and `third_party_client_access`
- `default_for: third_party_clients` default permissions, which arrive with dynamic client registration
- `allow_all_scopes` and `authorization_details_types` on client grants
- RBAC
- The `/api/v2/grants` and client-grant Management API endpoints (sub-project 3)
- The `tpc_` client ID prefix, which applies to generated IDs (sub-project 3)

## 4. The access decision

A new package, `internal/access`, holds one pure function, `Decide(Input) Decision`. It does no I/O; callers load the records it needs.

**Input:**
- The client and the resource server (nil when there is no audience)
- The client grant for the flow's subject type, and the user's existing grant
- The requested scopes, the redirect URI and the prompts
- The flow kind: interactive, password, refresh or client credentials

**Decision:**
- The granted scopes
- The scopes that need consent
- Whether confirmation is needed
- An error, as a code and description

Rules, in order:

1. **Third-party limits.** The password grants are refused in both modes. Strict clients also:
   - must use PKCE;
   - get `invalid_request` if they send `screen_hint`, `request`, `request_uri`, `invitation`, `login_ticket`, `id_token_hint` or `claims`;
   - have OIDC scopes dropped: no ID token is issued, and `/userinfo` refuses their tokens.
2. **Access policy for the flow's subject type** (`user` for interactive, password and refresh; `client` for client credentials):
   - `deny_all` refuses.
   - `require_client_grant` needs a grant of that subject type.
   - `allow_all` admits first-party clients. Strict third-party clients always need a grant. Permissive third-party clients follow observation O8.
3. **Scopes.** The granted scopes are the requested scopes, intersected with the API's scopes and, when a grant applies, with the grant's scopes. Scopes outside the intersection are dropped silently.
4. **Consent.** A third-party client always needs consent unless the user's grant already covers the scopes. A first-party client needs consent unless the API's skip flag is on; with a non-verifiable callback, observation O4 decides. `prompt=consent` forces consent.
5. **Confirmation.** It is needed when all of these hold:
   - the callback is non-verifiable (a custom scheme, `localhost`, `127.0.0.1` or `[::1]`);
   - the effective skip flag is false (the client's setting overrides the tenant's);
   - no consent screen has been shown in this transaction.
6. **`prompt=none`.** If consent or confirmation is needed, the request fails. The codes come from observation O5; `consent_required` and `interaction_required` are expected.

**Callers:**
- **`/authorize` and `Resume`** (`internal/authz`): after the session or login step, `/authorize` calls `Decide`. If a screen is needed, the `AuthTransaction` is kept, records which screens have been shown, and sends the browser to `/u/consent?state=…`. Otherwise the code is issued. Request validation adds the strict parameter list and the PKCE requirement.
- **Hosted pages** (`internal/login`):
  - `/u/consent` renders and handles accept or decline, using the transaction's CSRF token. Accept stores the user grant (for consent, not for confirmation) and issues the code.
  - Decline returns `access_denied` by redirect, or shows the error page under `open_redirect_protection`. Which other errors that policy turns into an error page comes from observation O6.
  - For third-party clients, the login page and session reuse accept only domain connections.
- **`/oauth/token`** (`internal/oauth`): the password, client credentials and refresh grants call `Decide`. The refresh grant re-checks the access policy and the client grant, so withdrawing a grant takes effect at the next refresh. Error codes come from observation O7; `unauthorized_client` for a missing grant at the token endpoint follows the troubleshooting page.

## 5. Hosted page

`consent.html` has two variants:
- **Consent:** lists the requested scopes for each API, showing names or descriptions according to `use_scope_descriptions_for_consent`. Third-party clients also show an external-application notice naming the callback domain.
- **Confirmation:** asks the user to confirm the application that will receive the login.

All text comes from new keys in the English catalog. The copy, layout and styles are original.

## 6. Tenant observation (first task)

Auth0's documentation does not settle several of the points above. Before any code is written, they are observed on the maintainer's own tenant:
- **Management API calls:** made with auth0-cli.
- **Browser steps:** the maintainer opens `/authorize` URLs that Claude provides and reports only the final redirect URL or the kind of screen reached (consent, confirmation, error page). No hosted-page content is captured or copied.
- **Results:** recorded as facts only in `docs/compat/observations/`, then turned into decisions D-0025 onward.

| ID | Question |
|---|---|
| O1 | Defaults: a new API's `skip_consent_for_verifiable_first_party_clients` and `subject_type_authorization`; a new third-party client's `third_party_security_mode` and `redirection_policy`; the `subject_type` of a grant created without one. |
| O2 | With no `audience` (only `openid profile`): is consent shown, and which audience does the stored grant carry? |
| O3 | When a later request asks for a subset or a superset of the granted scopes: is consent shown again, and are the scopes merged (read back through `/api/v2/grants`)? |
| O4 | First-party client, skip flag on, localhost callback: consent, confirmation or both? |
| O5 | `prompt=none` error codes when consent is needed and when confirmation is needed. |
| O6 | Under `open_redirect_protection`, is `login_required` redirected or shown as an error page? |
| O7 | Under user `deny_all`: does the error come from `/authorize` or from `/oauth/token`, and with which code? |
| O8 | Permissive client, `allow_all`, no grant. If the account cannot create permissive clients, this is decided from the permissive-mode page ("follows the API's access policy"). |

All test APIs, clients and users are deleted afterwards.

## 7. Testing

- `internal/access`: table tests for every rule.
- Store: `storetest` conformance for `UserGrant` and the new fields on memory, SQLite, PostgreSQL and MySQL (`./scripts/test-sql.sh`), and through a plugin (`grpcstore`).
- Handlers: authz, login and oauth handler tests. The OpenAPI contract gains the new `/authorize` error codes.
- E2E:
  - Existing seeds set `skip_non_verifiable_callback_uri_confirmation_prompt: true` because their apps use localhost callbacks.
  - A new m10-consent suite drives auth0-spa-js in Chromium with a strict third-party client: accept, decline, and silent re-authentication with the remembered grant. A first-party client with a localhost callback reaches the confirmation prompt.
  - The m4, m5, m6 and m9 suites are re-run.

## 8. Documentation

- Matrix rows for consent, third-party clients, access policies and the confirmation prompt.
- Decisions D-0025 onward.
- Backlog rows for the out-of-scope items in §3.
- Core spec §6.2: the consent line points to this design.
- A new operator guide, `docs/consent.md`.
