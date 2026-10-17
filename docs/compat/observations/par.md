# Pushed authorization requests

- **Observed:** 2026-10-16 (evening, US Eastern)
- **Docs:**
  - https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow/authorization-code-flow-with-par
  - https://auth0.com/docs/get-started/applications/configure-par
- **Method** (CLEAN_ROOM.md "Behavior testing against the maintainer's own tenant"):
  - **Tenant:** a trial tenant owned by the maintainer, with the Highly Regulated Identity features available. PAR was already on when the session started.
  - **Management API calls:** auth0-cli 1.37.0 logged in as a user.
  - **`/oauth/par`:** called directly over HTTPS, recording the HTTP status and the `error` value. Error descriptions were read to interpret a result and are not recorded.
  - **`/authorize`:** the maintainer opened URLs in a private browser window and reported only the final address-bar URL (parameter names, and the values of `error` and `state`) or that an error page appeared. Each URL was created at most a few seconds before it was opened. Where a result was ambiguous, the tenant log's event type settled it.
  - **Clean-up:** all test clients and the test user were deleted. The PAR setting was turned off for one check and turned back on.

## Settings and discovery (P7, P8)

- The tenant setting is `pushed_authorization_requests_supported`, a boolean at the top level of `GET /api/v2/tenants/settings` (not under `flags`).
- The client setting `require_pushed_authorization_requests: true` was accepted on `POST /api/v2/clients` while the tenant setting was on. It is absent from clients created without it.
- Turning the tenant setting off was accepted while a client still had `require_pushed_authorization_requests: true`.
- Discovery with PAR on: `pushed_authorization_request_endpoint` (`https://{domain}/oauth/par`); `request_uri_parameter_supported: false`.
- Discovery with PAR off: no `pushed_authorization_request_endpoint`; `request_uri_parameter_supported: false` still present.
- In both states, discovery also listed `request_parameter_supported: true` and `request_object_signing_alg_values_supported`. These belong to signed request objects (JAR), not PAR.
- Successful `/authorize` responses carried an `iss` parameter (RFC 9207); the tenant settings include `authorization_response_iss_parameter_supported`.

## /oauth/par (P2, P3, P6a, P9)

Confidential client, `client_secret_post`, form body with `response_type=code`, a registered `redirect_uri`, `scope=openid` and `state`, unless stated.

- **Success:** `201`, JSON with `request_uri` and `expires_in: 30`. The `request_uri` is `urn:ietf:params:oauth:request_uri:` followed by 64 characters from the base64url alphabet.
- **Unknown parameter** (`foo=bar`): `201`.
- **10 `ext-` parameters:** `201`. **11:** `400 invalid_request`.
- **Unregistered `redirect_uri`:** `400 invalid_request`.
- **`response_type=token`:** `403 unauthorized_client`; the client did not have the implicit grant.
- **`response_type=bogus`:** `501 unsupported_response_type`.
- **No `response_type`:** `400 invalid_request`.
- **Unknown `audience`:** `403 access_denied`.
- **`response_mode=bogus`, `prompt=bogus`:** `201` (not checked at this endpoint).
- **Body over 10 KB** (one 11000-character `ext-` value): `413` with `error` `payload_too_large`.
- **JSON body:** `400 invalid_request`.
- **Wrong client secret:** `401 invalid_client`.
- **Public client** (SPA, `token_endpoint_auth_method: none`): `400 invalid_request`.
- **`request_uri` in the body:** `400 invalid_request`.
- **Strict third-party client** (with or without PKCE): `400 invalid_request`. The error description concerns third-party clients in general, not the strict mode. The log event type for refusals at this endpoint is `fpar`.
- **Client requiring PAR:** `201`.
- **Tenant setting off:** `400 invalid_request`, also for the client that requires PAR.

## /authorize with request_uri (P1, P4, P5, P6b)

The browser had a session, so successful requests returned straight to the callback.

- **`client_id` and `request_uri` only:** redirect with `code`, the pushed `state` and `iss`.
- **P1a, query `state=s2` (pushed `s1`):** redirect with `state=s1`.
- **P1b, query `redirect_uri` = a second registered callback:** the browser ended on the pushed callback.
- **P1c, query `response_type=token`, a different `scope` and `foo=bar`:** redirect with `code` and `state=s1`. The extra query parameters were ignored and did not cause an error.
- **P4a, the same URL again a few seconds after a success:** error page, no redirect. Log event: failure, request_uri not found.
- **P4b, a URL opened after more than 30 seconds:** error page, no redirect. Same log event.
- **P4c, the `request_uri` with another confidential client's `client_id`:** error page, no redirect. Same log event.
- **Wrong client first, then the right client within the lifetime:** both error pages. The wrong-client attempt used up the request.
- **P5, plain `/authorize` for the client requiring PAR:** redirect with `error=invalid_request` and the original `state`.
- **P5 with the tenant setting off:** the same redirect with `error=invalid_request`.
- **P6b, a `request_uri` pushed just before the tenant setting was turned off:** error page, no redirect. Log event: failure, the PAR feature is not enabled.
