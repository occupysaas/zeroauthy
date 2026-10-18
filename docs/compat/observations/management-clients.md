# Management API: clients

- **Observed:** 2026-10-18
- **Docs:**
  - https://auth0.com/docs/api/management/v2/clients/get-clients
  - https://auth0.com/docs/api/management/v2/clients/post-clients
  - https://auth0.com/docs/api/management/v2/clients/patch-clients-by-id
  - https://auth0.com/docs/api/management/v2/clients/post-rotate-secret
- **Method** (CLEAN_ROOM.md "Behavior testing against the maintainer's own tenant"):
  - **Tenant:** the maintainer's non-live development tenant.
  - **Callers:** `auth0-cli` logged in as a user, and an M2M client using the `client_credentials` grant with Management API scopes.
  - **Recorded:** statuses, `error` and `errorCode` values, and field names. Messages were read only to interpret a result.
  - **Clean-up:** every test client and grant was deleted.
- **Also used:** `auth0-deploy-cli` 9.1.0 source (MIT, github.com/auth0/auth0-deploy-cli, commit b8178b4), `src/readonly.ts` and `src/tools/auth0/handlers/clients.ts`, for which fields it exports and sends.

## Create defaults (M1)

A `POST /api/v2/clients` with only `name` and `app_type` gives the **same defaults for every `app_type`** (`native`, `spa`, `regular_web`, `non_interactive`):
- `grant_types`: `authorization_code`, `implicit`, `refresh_token`, `client_credentials`
- `token_endpoint_auth_method`: absent from the response
- `is_first_party: true`
- `oidc_conformant: false`
- `jwt_configuration`: `lifetime_in_seconds` 36000
- `refresh_token`: non-rotating, non-expiring
- `cross_origin_authentication: false`, `sso_disabled: false`, `custom_login_page_on: true`
- one signing key
- no `callbacks`, `allowed_logout_urls`, `web_origins` or `allowed_origins`

So per-type defaults are not applied by the API; they must come from the caller.

The response also carries `client_id`, `client_secret` (64 characters), `created_at`, `updated_at`, `tenant`, `global`, `callback_url_template`, `encrypted`, `cross_origin_auth` and `enforce_anon_session_transfer_network_binding`.

## Secrets (M2, M3, M4)

- **Reading:** `GET /api/v2/clients/{id}` returns `client_secret` only to callers holding `read:client_keys`. With `read:clients` alone, the field is absent.
- **Setting:**
  - `POST` with a caller-supplied `client_secret` succeeds.
  - `PATCH` with `client_secret` needs `update:client_keys`.
  - A secret shorter than 48 characters gives `400 invalid_body` (minimum length 48).
- **Rotating:** `POST /api/v2/clients/{id}/rotate-secret` gives `200` with the client, including a new 64-character secret. The old secret is refused at once (`401` at `/oauth/token`); there is no overlap.

## Errors (M5)

All error bodies have the shape `{statusCode, error, message, errorCode}`.

- **Unknown client ID:** `404 Not Found`, `errorCode` `inexistent_client`.
- **Bad `app_type`, unknown property, missing `name`, a callback that is not a URL:** `400 Bad Request`, `errorCode` `invalid_body`. These are payload validation errors; unknown properties are refused, not ignored.
- **Missing scope:** `403 Forbidden`, `errorCode` `insufficient_scope`.
- **No token, or an invalid token:** `401 Unauthorized`.

## Pagination and projection (M6, M7)

- **Without `include_totals`:** the response is a bare JSON array.
- **With `include_totals=true`:** `{clients, start, limit, total}`.
- **`per_page`:** the maximum is 100; 101 gives `400 Bad Request` `invalid_query_string`.
- **Order:** with no paging parameters, every client of this small tenant came back, in creation order, not sorted by name.
- **`fields=name`:** returns `name` and `tenant`. With `include_fields=false`, the listed fields are left out and the rest returned.

## Immutable fields (M8)

- **`is_first_party: false` on a first-party client:** refused with `400`, because a third-party client cannot have `oidc_conformant: false`.
- **`third_party_security_mode` on a first-party client:** `400 invalid_body` (it can only be set on third-party clients).
- `auth0-deploy-cli` strips `third_party_security_mode` from updates as "immutable after creation".

## Delete (M9)

`DELETE` gives `204`, and a second `DELETE` of the same ID also gives `204`.

## auth0-deploy-cli (M10)

- **Export:** `client_secret` is treated as read-only and left out of the export, along with `callback_url_template`, `signing_keys`, `global`, `tenant`, `custom_login_page_preview`, `config_route` and `owners`.
- **Matching:** clients are matched by `client_id`, then `name`.
- **Create:** strips `external_metadata_type`, `external_metadata_created_by` and `jwks_uri`.
- **Update:** strips `callback_url_template`, `signing_keys`, `global`, `tenant`, `jwt_configuration.secret_encoded`, `resource_server_identifier`, the external metadata fields, `jwks_uri`, `third_party_security_mode`, `created_at` and `updated_at`.
- **Supplied `client_id`:** `POST` with a caller-supplied `client_id` is refused by Auth0 with `403` `operation_not_supported`.

Consequence: moving a tenant with `auth0-deploy-cli` alone gives every application a new `client_id` and `client_secret`. Keeping them needs a dedicated migration step (slice 5).

## Audience (M11)

The Management API resource server's identifier is `https://<tenant>.<region>.auth0.com/api/v2/`, on the tenant's own domain, and is marked as a system API.
