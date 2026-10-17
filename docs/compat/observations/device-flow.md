# Device authorization flow

- **Observed:** 2026-10-17 (late morning, US Eastern)
- **Docs:**
  - https://auth0.com/docs/get-started/authentication-and-authorization-flow/device-authorization-flow
  - https://auth0.com/docs/get-started/authentication-and-authorization-flow/device-authorization-flow/call-your-api-using-the-device-authorization-flow
  - https://auth0.com/docs/get-started/tenant-settings/configure-device-user-code-settings
- **Method** (CLEAN_ROOM.md "Behavior testing against the maintainer's own tenant"):
  - **Tenant:** the maintainer's original tenant. The device flow needs no add-on.
  - **Management API calls:** auth0-cli logged in as a user.
  - **`/oauth/device/code` and `/oauth/token`:** called directly over HTTPS. Only the HTTP status, the `error` value and the JSON key names are recorded. Error descriptions were read only to interpret a result.
  - **Browser:** the maintainer opened URLs (a normal window first, then a private window) and reported paths without the host, parameter names, screen types, and the gist of messages. Some redirects were read from the browser's network tab.
  - **Load:** at most one burst of 8 polls and three wrong or stale codes.
  - **Clean-up:** all test clients, APIs and the test user were deleted.

## Settings and discovery (D2, D6)

- `GET /api/v2/tenants/settings` has no `device_flow` key on a tenant that never changed it.
- Codes issued with those defaults are four characters, a hyphen, and four characters, for example `ABCD-EFGH`. Across eleven codes, the characters were exactly the 20 letters `BCDFGHJKLMNPQRSTVWXZ`: no vowels, no `Y`, no digits.
- Discovery lists `device_authorization_endpoint` (`https://{domain}/oauth/device/code`). `grant_types_supported` includes `urn:ietf:params:oauth:grant-type:device_code`.

## Management API rules for device clients (D3, D11)

- `POST /api/v2/clients` refuses the device grant with `400` when:
  - `app_type` is not `native`
  - `token_endpoint_auth_method` is not `none` on a native client
  - the client is third party: the allowed grants are only `authorization_code`, `refresh_token` and `client_credentials`
- `third_party_security_mode: permissive` cannot be set on this tenant (`400`), so a permissive device client could not be tried.

## /oauth/device/code (D3)

Native first-party client with the device grant, form body, unless stated.

- **Success:** `200`. Keys: `device_code`, `user_code`, `verification_uri`, `verification_uri_complete`, `expires_in`, `interval`.
  - `device_code` is 24 characters.
  - `verification_uri` is `https://{domain}/activate`.
  - `verification_uri_complete` is `https://{domain}/activate?user_code=ABCD-EFGH` (the formatted code).
  - `expires_in: 900`, `interval: 5`.
- **No `scope`:** `200`.
- **`audience=` (empty):** `200`, treated as absent.
- **Unknown `audience`:** `400 invalid_request`.
- **API with `subject_type_authorization.user.policy: deny_all`:** `400 invalid_request`. The access policy is checked when the code is issued, before any user is known.
- **Client without the device grant:** `403 unauthorized_client`.
- **Unknown `client_id`:** `403 unauthorized_client` (not `invalid_client`).
- **Repeated `client_id`:** `403 unauthorized_client`.
- **JSON body:** `200`. JSON is accepted here.

## Polling /oauth/token (D5, D9)

- **Pending:** `403 authorization_pending`. The body has no keys other than `error` and `error_description`.
- **Polls 1 second apart** (six polls): `authorization_pending` every time, never `slow_down`.
- **A burst of 8 back-to-back polls:** `authorization_pending` and `429 slow_down` alternated (pending, pending, slow_down, pending, slow_down, …). No `interval` key in any response.
- **Approved:** `200` with `access_token`, `id_token`, `refresh_token`, `scope`, `expires_in`, `token_type`.
  - The ID token claims were exactly `aud`, `exp`, `iat`, `iss`, `sub`: no `sid` and no `auth_time`.
  - The access token's `aud` was the API plus `/userinfo`, with no `gty` claim.
- **The same code polled again after success:** `403 invalid_grant`.
- **Denied** (cancel at confirmation, or decline at consent): `403 access_denied` once, then `403 invalid_grant` on later polls.
- **Unknown `device_code`:** `403 invalid_grant`.
- **Another client polling a valid pending code** (a native client without the grant): `403 unauthorized_client`.
- **Expired code, first polled 11 minutes after expiry:** `403 invalid_grant` on three polls, not `expired_token`.
- **Polled around the moment of expiry** (one fresh code, polls at expiry −3 s, +1 s, +4 s, +8 s, +20 s): `403 authorization_pending`; `429 slow_down`; `403 expired_token`; `403 invalid_grant`; `403 invalid_grant`.
  - `expired_token` appears once, a few seconds after expiry, then `invalid_grant`. A code first polled 11 minutes after expiry never got `expired_token`.
  - The `slow_down` at +1 s came 4 seconds after the previous poll. It is unexplained by the 1-second pattern above (perhaps a transition state at expiry) and is not modelled.

## Browser path (D1, D4, D7, D8, D10)

- **`/activate`:** a code-entry page served at `/activate` itself, with no redirect. The form posts to `/activate` with form fields `state` and `code`.
- **Wrong, expired, or already used code:** `400`, the same page, one "invalid or expired code" message for all three cases.
- **Empty submit:** the same page, a different "enter your device code" message.
- **Code typed in lower case without the hyphen:** accepted.
- **Valid code:** `302` to `/device/confirmation?state=…`. The page shows the code and the application's name, with confirm and cancel buttons. The form posts `state` and `action` (`confirm` or `cancel`).
- **`verification_uri_complete`** (`/activate?user_code=…`): `302` straight to `/device/confirmation?state=…`. Code entry is skipped and confirmation still shows.
- **Cancel at confirmation:** `302` to `/device/denied`, which is a `200` "activation denied" page.
- **Confirm without a session:** `/u/login?state=…` (the normal login page), then after login `/device/success`.
- **Confirm with a live session in the browser:** no login page, straight to `/device/success` (session reused).
- **Consent with an API that skips consent for verifiable first-party clients** (first-party native client): no consent screen.
- **Consent with an API that does not skip consent:** confirm `302`s to `/authorize/resume?state=…`, which `302`s to `/u/consent?state=…`. The consent screen named the application and listed the requested permissions, with accept and decline buttons.
  - **Decline:** the POST `302`s to `/authorize/resume`, which `302`s to `/device/denied`.
- **Success page:** `/device/success`, a "you're all set" page.
