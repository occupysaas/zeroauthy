# Consent, third-party applications and access policies

- **Observed:** 2026-10-16
- **Docs:**
  - https://auth0.com/docs/get-started/applications/third-party-applications/user-consent-and-third-party-applications
  - https://auth0.com/docs/get-started/applications/third-party-applications/security-controls
  - https://auth0.com/docs/get-started/applications/third-party-applications/permissive-mode
  - https://auth0.com/docs/get-started/apis/api-access-policies-for-applications
  - https://auth0.com/docs/get-started/applications/application-access-to-apis-client-grants
  - https://auth0.com/docs/troubleshoot/product-lifecycle/deprecations-and-migrations/migrate-to-non-verifiable-callback-uri-end-user-confirmation
- **Method** (CLEAN_ROOM.md "Behavior testing against the maintainer's own tenant"):
  - **Management API calls:** made with auth0-cli 1.37.0 logged in as a user (device login), not as a machine client.
  - **Token requests:** password and client credentials, made with curl against `/oauth/token`.
  - **/authorize:** the maintainer opened URLs in a private browser window and reported only the final address-bar URL (parameter names and the `error` code) or the kind of screen reached. No page text or images were captured.
  - **Tenant state:** the tenant had neither `skip_non_verifiable_callback_uri_confirmation_prompt` nor `use_scope_descriptions_for_consent` set.
  - **Clean-up:** all test objects were deleted afterwards.

## Defaults (Management API, user login)

- `POST /resource-servers` without the fields:
  - `skip_consent_for_verifiable_first_party_clients` = `false`
  - `subject_type_authorization` = `{user: {policy: allow_all}, client: {policy: require_client_grant}}`
- `POST /clients` with `is_first_party: false`:
  - `third_party_security_mode` = `strict`
  - `redirection_policy` = `open_redirect_protection`
  - the client ID has the `tpc_` prefix
- `POST /clients`, first-party: `redirection_policy` absent from the response.
- `POST /client-grants` without `subject_type`: `subject_type` = `client`.
- `POST /clients` with `third_party_security_mode: permissive`: 400 (`invalid_body`). The account is not eligible for permissive applications, so no permissive behavior was observed.
- `PATCH /clients/{id}` adding `password` to a third-party client's `grant_types`: 400.
- `PATCH /connections/{id}/clients` enabling a third-party client: 400. The whole request was refused, including the first-party client in the same body. Third-party clients reach a database connection only through `is_domain_connection: true`.

## /authorize

The test API had scopes `read:things`, `write:things`, `admin:things`. Clients: a first-party regular web app, and a strict third-party regular web app with a `user` client grant for all three scopes. The test API's `skip_consent_for_verifiable_first_party_clients` was set to `true` for these checks.

| # | Request | Result |
|---|---|---|
| 1 | First-party, callback `http://localhost:…`, fresh login | No screen after the login form; redirect with `code`. A user grant was stored for the first-party client with scopes `openid read:things` |
| 2 | Same, `prompt=none`, session exists | Redirect, `error=consent_required` |
| 5 | Same as 1, session exists, no `prompt` | A screen asking the user to authorize or confirm the application; after accepting, redirect with `code`. The stored grant was unchanged |
| 3 / 15 | Strict third-party, no `audience`, `scope=openid profile` | `open_redirect_protection`: error page. `allow_always`: redirect, `error=invalid_request` |
| 4 | Strict third-party, `scope=read:things`, after login | Consent screen; accept → `code`. Grant stored: audience = the API identifier, scopes `read:things` |
| 6 | Same, `scope=read:things` again | No screen; redirect with `code` (a covered request skips consent) |
| 7 | Same, `scope=read:things write:things` | Consent screen listing both scopes; accept → `code`. Grant scopes: `read:things write:things` |
| 8 | Same, `scope=write:things`, `prompt=consent` | Consent screen; accept → `code`. Grant scopes still `read:things write:things`, so accepting merges rather than replaces |
| 9 / 16 | `prompt=consent`, user declines | `open_redirect_protection`: error page (status not recorded), served under `/authorize/resume`. `allow_always`: redirect, `error=access_denied`. The existing grant was unchanged |
| 10 / 17 | `scope=admin:things` (not yet consented), `prompt=none` | `open_redirect_protection`: error page, HTTP 400. `allow_always`: redirect, `error=consent_required` |
| 11 | First-party, an API whose user policy is `deny_all` | Redirect, `error=invalid_request` |
| 12 / 18 | Strict third-party, the same `deny_all` API | `open_redirect_protection`: error page, HTTP 400. `allow_always`: redirect, `error=invalid_request` |
| 13 / 19 | Strict third-party, no session, `prompt=none` | `open_redirect_protection`: error page, HTTP 400. `allow_always`: redirect, `error=login_required` |
| 14 | First-party (redirection policy unset), no session, `prompt=none` | Redirect, `error=login_required` |

## /oauth/token

| Request | Result |
|---|---|
| `client_credentials`, no client grant | 403, `access_denied` |
| `client_credentials`, API client policy `deny_all`, without and with a `client` grant | 403, `access_denied` |
| password-realm, first-party client, API user policy `allow_all`, no grant | 200 |
| password-realm, API user policy `deny_all` | 400, `invalid_request` |
| password-realm, API user policy `require_client_grant`, no `user` grant | 400, `invalid_request` |
| password-realm, `require_client_grant`, `user` grant `[read:things]`, requested `read:things write:things` | 200, `scope=read:things` (scopes outside the grant dropped silently) |

## Not observed

- **Permissive third-party applications:** the account can't create them.
- **The HTTP status of the decline error page.**
- **Whether a first-party grant is stored on every login** or only in the case of check 1 (non-verifiable callback, API that skips consent).
- **The machine-login (client credentials) view of the Management API defaults.**
