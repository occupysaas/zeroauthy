# Management API: resource servers and client grants

- **Observed:** 2026-10-18
- **Docs:**
  - https://auth0.com/docs/api/management/v2/resource-servers/get-resource-servers
  - https://auth0.com/docs/api/management/v2/resource-servers/post-resource-servers
  - https://auth0.com/docs/api/management/v2/resource-servers/patch-resource-servers-by-id
  - https://auth0.com/docs/api/management/v2/resource-servers/delete-resource-servers-by-id
  - https://auth0.com/docs/api/management/v2/client-grants/get-client-grants
  - https://auth0.com/docs/api/management/v2/client-grants/post-client-grants
  - https://auth0.com/docs/api/management/v2/client-grants/patch-client-grants-by-id
  - https://auth0.com/docs/api/management/v2/client-grants/delete-client-grants-by-id
- **Method** (CLEAN_ROOM.md "Behavior testing against the maintainer's own tenant"):
  - **Tenant:** the maintainer's non-live development tenant.
  - **Caller:** an M2M client using the `client_credentials` grant, with `read/create/update/delete` scopes for `resource_servers` and `client_grants` (plan 14 Task 1, option A), and `auth0-cli` v1.37.0 with `AUTH0_CLI_AUTH_MODE=env`.
  - **Recorded:** statuses, `error` and `errorCode` values, field names, defaults and limits. Messages were read only to interpret a result.
  - **Clean-up:** every test API was deleted, which also removed its grants. One `PATCH` of `token_lifetime` on the system Management API (A4) was reverted to 86400.
  - **Pacing:** a burst of about 30 requests in a few seconds gave `429 too_many_requests`; later runs were paced at about one request per second.
- **Also read:**
  - `auth0-deploy-cli` 9.1.0 (MIT, github.com/auth0/auth0-deploy-cli, commit b8178b4): `src/tools/auth0/handlers/resourceServers.ts` and `clientGrants.ts`.
  - `auth0-cli` v1.37.0 (MIT): `internal/cli/apis.go` and `client_grants.go`.
  - `go-auth0` v3.6.0 (MIT): `management/clientgrants/client/client.go`.

## Resource server create defaults (A1)

`POST /api/v2/resource-servers` with only `identifier` returns `201` with:
- `token_lifetime` 86400, `token_lifetime_for_web` 7200
- `signing_alg` `RS256`
- `allow_offline_access: false`
- `skip_consent_for_verifiable_first_party_clients: false`
- `subject_type_authorization`: `client.policy` `require_client_grant`, `user.policy` `allow_all`
- no `name` (the field is absent, not set to the identifier), no `scopes`, no `is_system`
- `id`: 24 lowercase hex characters

With `signing_alg` `HS256`, the response also carries a generated `signing_secret` of 32 characters. An RS256 API has no `signing_secret` field.

## Resource server validation (A2)

All failures below are `400 invalid_body` unless noted.

- **`identifier`:** required, 1 to 600 characters. It need not be a URL: `urn:…`, a bare word and a string with a space are all accepted.
- **Duplicate `identifier`:** `409 resource_server_conflict`. The comparison is case-sensitive: the same URL with an upper-case scheme and host is a different identifier.
- **The tenant's own Management API identifier:** `400 reserved_identifier`.
- **`name`:** optional; 1 to 200 characters; must not contain `<` or `>`. Names need not be unique.
- **Unknown properties:** refused.
- **`scopes`:** an array of `{value, description}`. `value` is 1 to 280 characters (spaces and `<` are accepted); `description` is at most 500. Duplicate values are refused. Unknown properties in a scope are refused.
- **`token_lifetime`:** an integer, greater than 0 and at most 2592000 (30 days). A string is refused.
- **`token_lifetime_for_web`:** when it is in the body, it must not exceed `token_lifetime` (the one in the body, or the stored one). A `PATCH` of `token_lifetime` alone below the stored web lifetime is accepted.
- **`signing_alg`:** `HS256`, `RS256` or `PS256` are valid; `ES256` and `none` are `invalid_body`. `RS512` gave `403 operation_not_supported` on this tenant.
- **`signing_secret`:** at least 16 characters.
- **`token_dialect`:** `access_token`, `access_token_authz`, `rfc9068_profile`, `rfc9068_profile_authz`.
- **`subject_type_authorization`:** `client.policy` is `require_client_grant` or `deny_all` (`allow_all` is refused); `user.policy` is `allow_all`, `require_client_grant` or `deny_all`. On `PATCH` the two subject types merge: sending only `user` keeps `client`.
- **Also accepted:** `enforce_policies`, `allow_offline_access`, `skip_consent_for_verifiable_first_party_clients`, `consent_policy` (a string or `null`).

## Immutable fields (A3)

`PATCH` is a different schema from `POST`: `identifier`, `id` and `is_system` are unknown properties there (`400 invalid_body`), even when unchanged. An empty `PATCH` body is `200`.

## The system Management API (A4)

- It is listed first, with `is_system: true` and the name "Auth0 Management API".
- **`PATCH` with `name`:** `400 invalid_body` (an unknown property for a system API).
- **`PATCH` of the other settings** (such as `token_lifetime`) is accepted.
- **`DELETE`:** `400 delete_system_resource_server`.
- **Creating** another API with its identifier: `400 reserved_identifier` (A2).

`auth0-deploy-cli` sends only `token_lifetime`, `proof_of_possession`, `skip_consent_for_verifiable_first_party_clients`, `subject_type_authorization`, `authorization_policy` and `require_consent_non_repudiation` when it updates a system API.

## Scopes under client grants (A5)

- `scopes` on `PATCH` replaces the whole list.
- Removing a scope that a client grant carries is accepted, and the scope is removed from that grant.

## Deleting a resource server (A6)

- `DELETE` gives `204` with an empty body. The API's client grants are deleted with it.
- A second `DELETE`, an unknown ID and a malformed ID also give `204`.
- `GET /resource-servers/{id}` for an unknown or malformed ID gives `404 inexistent_resource_server`.
- `GET /resource-servers/{id}` also accepts the URL-encoded identifier in place of the ID. `auth0-cli` relies on this (it reads an API by audience).

## Listing resource servers (A7)

- **Order:** creation order, system API first.
- **Paging:** as for clients (D-0039): a bare array without `include_totals`; `{total, start, limit, resource_servers}` with it. `start` is `page × per_page`; a page past the end has an empty array. `per_page` must be 1 to 100, otherwise `400 invalid_query_string`.
- **Checkpoint paging** (`from`, `take`): `400 invalid_query_string`.
- **`identifiers`:** a repeated query parameter (`identifiers=a&identifiers=b`) filters by identifier. A comma-separated value is one identifier, not a list.
- **`fields=name`:** returns only `name`; an API without a name comes back as `{}`. No field is always added (clients always add `tenant`).

## Creating client grants (A8)

- **Response:** `201` with `id`, `client_id`, `audience`, `scope`, `subject_type`. Grant IDs are `cgr_` followed by 16 letters and digits.
- **`subject_type`:** defaults to `client`; `user` is accepted. One grant per (`client_id`, `audience`, `subject_type`); a duplicate is `409 client_grant_conflict`. A `client` and a `user` grant for the same pair can coexist.
- **Required:** `client_id` (or `default_for`), and `scope` (or `allow_all_scopes`). `scope: []` is valid. Missing either is `400 invalid_body`.
- **`allow_all_scopes: true`:** stored without a `scope` field.
- **Unknown client:** `404 inexistent_client`.
- **Unknown audience:** `404 inexistent_resource_server`. The audience is compared case-sensitively.
- **A scope the API does not define:** accepted on create, even when the API defines other scopes. `PATCH` does check it (A10).
- **Unknown properties:** refused.

## Listing client grants (A9)

- **Order:** by grant ID in byte order, not by creation time.
- **Offset paging:** as for resource servers, with the key `client_grants`.
- **Checkpoint paging:** supported. `take` (1 to 100, default 50) returns `{client_grants, next}`; `next` is an opaque cursor passed back as `from`. The last page has no `next`. When `take` or `from` is present, checkpoint paging wins over `page` and `include_totals`. A bad `from` is `400` with no `errorCode`.
- **Filters:** `client_id`, `audience`, `subject_type`, combinable.
  - `client_id` must look like a client ID; otherwise `400 invalid_query_string`.
  - `subject_type` must be `client` or `user`; otherwise `400 invalid_query_string`.
  - `subject_type` alone, without `client_id`, `audience` or `default_for`, is `400` with no `errorCode`.
- **`go-auth0` v3, which `auth0-cli` v1.37.0 uses for grants,** sends `include_totals=true&take=50` and follows `next`. So zeroauthy must implement checkpoint paging for `auth0 client-grants list`.

## Changing and deleting client grants (A10)

- **`GET /client-grants/{id}`:** supported (`auth0 client-grants show` uses it).
- **`PATCH` may change:** `scope`, `allow_all_scopes`, `organization_usage`, `allow_any_organization`, `authorization_details_types`. `client_id`, `audience` and `subject_type` are unknown properties. An empty body is `400 invalid_body` (at least one property).
- **`PATCH` with a scope the API does not define:** `400 invalid_body`, including on an API with no scopes.
- **`PATCH` or `DELETE` of an ID in the right format that does not exist:** `PATCH` gives `404 inexistent_client_grant`; `DELETE` gives `204`.
- **A malformed ID** (not `cgr_…`): `400 invalid_uri` on `PATCH` and `DELETE`.
- **`DELETE`:** `204`; a second `DELETE` also gives `204`.

## auth0-deploy-cli (A11)

- **Resource servers:**
  - matched by `id`, then `identifier`;
  - `client_id` and `is_system` are stripped on create; `identifier`, `client_id` and `is_system` are stripped on update;
  - the Management API (by name) is left out of the export;
  - its schema names `name`, `identifier`, `scopes`, `allow_online_access`, `allow_online_access_with_ephemeral_sessions`, `enforce_policies`, `token_dialect`, `proof_of_possession`, `subject_type_authorization`, `token_lifetime_for_anonymous_access_tokens`, `access_token`, `client_id` and `require_consent_non_repudiation`, but does not close the object: whatever a `GET` returns (less the stripped fields) is sent back.
- **Client grants:**
  - matched by `id`, then (`client_id`, `audience`, `subject_type`), then (`client_id`, `audience`);
  - `audience`, `client_id`, `subject_type`, `is_system` and `default_for` are stripped on update;
  - read with checkpoint paging;
  - the grants of the client deploy-cli itself uses, and grants with `is_system: true`, are left out;
  - its schema names `client_id`, `audience`, `scope`, `subject_type`, `authorization_details_types`, `allow_all_scopes` and `default_for`; other fields a `GET` returns (such as `organization_usage` and `allow_any_organization`) are sent back as read.
