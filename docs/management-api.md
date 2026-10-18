# Management API

Every zeroauthy tenant serves Auth0's Management API v2 at
`https://<tenant host>/api/v2/`, on each of its hosts. Slices 1 and 2 cover
**applications** (`/api/v2/clients`), **APIs** (`/api/v2/resource-servers`)
and **client grants** (`/api/v2/client-grants`); later slices add
connections, users and tenant settings (design
`docs/superpowers/specs/2026-10-18-zeroauthy-management-design.md`).

The contract is [api/management.yaml](../api/management.yaml). Behaviour
that Auth0 does not document comes from observation of Auth0's API
([observations/management-clients.md](compat/observations/management-clients.md),
[observations/management-apis.md](compat/observations/management-apis.md))
and is recorded in decisions D-0038 to D-0041 of
[compat/decisions.md](compat/decisions.md).

## Tokens

Two kinds of bearer token are accepted.

**Machine-to-machine clients of the tenant** (as on Auth0). A client
credentials token whose audience is the tenant's **Management API
identifier**:

- `https://<name>.<server.base_domain>/api/v2/`, or
- without a base domain, `https://<first of the tenant's domains>/api/v2/`.

The identifier stays the same whichever of the tenant's hosts receives the
request. Each tenant has a system API, "zeroauthy Management API", for that
identifier with Auth0's scope names. The client needs a client grant for it.
In a seed file:

```yaml
tenants:
  - name: acme
    domains: [login.acme.example]
    clients:
      - client_id: deploy-bot
        app_type: non_interactive
        client_secret: <at least a long random string>
        grant_types: [client_credentials]
    client_grants:
      - client_id: deploy-bot
        audience: "https://login.acme.example/api/v2/"
        scopes: [read:clients, create:clients, update:clients, delete:clients, read:client_keys, update:client_keys]
```

```bash
curl https://login.acme.example/oauth/token \
  -d grant_type=client_credentials -d client_id=deploy-bot -d client_secret=… \
  -d audience=https://login.acme.example/api/v2/
```

**Console operators.** An access token from the `system` tenant for the
audience `urn:zeroauthy:management`, issued to the console. Operators hold
every scope on every tenant they manage (all tenants for now). This is the
only token one tenant accepts from another. See [console.md](console.md).

The `system` tenant has no machine-to-machine Management API: only
operators manage it.

## Scopes

| Operation | Scope |
|---|---|
| `GET /api/v2/clients`, `GET /api/v2/clients/{id}` | `read:clients`; `client_secret` is included only with `read:client_keys` |
| `POST /api/v2/clients` | `create:clients` |
| `PATCH /api/v2/clients/{id}` | `update:clients`; setting `client_secret` needs `update:client_keys` |
| `DELETE /api/v2/clients/{id}` | `delete:clients` |
| `POST /api/v2/clients/{id}/rotate-secret` | `update:client_keys` |
| `GET /api/v2/resource-servers`, `GET /api/v2/resource-servers/{id}` | `read:resource_servers` |
| `POST /api/v2/resource-servers` | `create:resource_servers` |
| `PATCH /api/v2/resource-servers/{id}` | `update:resource_servers` |
| `DELETE /api/v2/resource-servers/{id}` | `delete:resource_servers` |
| `GET /api/v2/client-grants`, `GET /api/v2/client-grants/{id}` | `read:client_grants` |
| `POST /api/v2/client-grants` | `create:client_grants` |
| `PATCH /api/v2/client-grants/{id}` | `update:client_grants` |
| `DELETE /api/v2/client-grants/{id}` | `delete:client_grants` |

## Shared behaviour

- **Errors** have Auth0's shape: `{"statusCode": 400, "error": "Bad Request", "message": "…", "errorCode": "invalid_body"}`. `401` (`invalid_token`) for a missing, invalid, expired or foreign token; `403` (`insufficient_scope`) for a missing scope; `404` (`inexistent_client`) for an unknown application.
- **Pagination:** `page` (from 0), `per_page` (1 to 100, default 50) and `include_totals`. Without totals the response is a bare array; with them `{"clients": […], "start": …, "limit": …, "total": …}`. Applications are listed in creation order.
- **Projection:** `fields` (comma-separated) with `include_fields` (`true` to keep only those, `false` to leave them out). `tenant` is always returned.
- **CORS** allows only the console's origin (the system host).
- Every write is logged with its actor (client ID or operator user ID).

## Applications

Fields: `client_id`, `tenant`, `name`, `app_type`, `is_first_party`,
`third_party_security_mode`, `oidc_conformant` (always `true`),
`callbacks`, `allowed_logout_urls`, `web_origins`, `allowed_origins`,
`grant_types`, `token_endpoint_auth_method`, `client_secret`,
`jwt_configuration` (`alg` RS256, `lifetime_in_seconds`), `refresh_token`
(`rotation_type`, `expiration_type`, `leeway`, `token_lifetime`,
`idle_token_lifetime`, `infinite_*`), `redirection_policy`,
`skip_non_verifiable_callback_uri_confirmation_prompt`,
`require_pushed_authorization_requests`, `created_at`.

- **Create defaults:** `app_type` `regular_web`; `token_endpoint_auth_method` `none` for `spa` and `native`, `client_secret_post` otherwise; `grant_types` `authorization_code` and `refresh_token`, plus `client_credentials` for confidential clients; rotating, expiring refresh tokens for `spa`. The console sends defaults per type instead.
- **Secrets** are generated with 64 characters, or supplied (at least 48). They are encrypted under the master key (D-0038) and returned only with `read:client_keys`. Secrets stored before D-0038 keep working but cannot be shown: rotate them to get one you can see. Public clients (`none`) have no secret.
- **Rotation** replaces the secret at once; the old one stops working immediately.
- **Fixed after creation:** `is_first_party` and `third_party_security_mode`.
- **Unknown fields** are refused (`invalid_body`), except those Auth0's tools always send, which are accepted and ignored (`description`, `client_metadata`, `logo_uri` and others; D-0039).
- **Deleting** an application deletes its client grants, user consents and refresh tokens and removes it from every connection; sign-in sessions stay. Deleting an unknown ID answers `204`, as on Auth0.
- **The seed** never touches applications created through the API, even if it names the same client ID.

`auth0-cli` works unchanged: `auth0 apps create/list/show --reveal-secrets/update/delete` and `auth0 api get clients`, logged in with client credentials (`AUTH0_CLI_AUTH_MODE=env`, `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`) against a tenant served on port 443.

## APIs (resource servers)

An API is a service whose access tokens zeroauthy issues. Its `identifier`
becomes the `aud` of those tokens and is the `audience` clients ask for.

Fields: `id`, `name`, `identifier`, `scopes` (`value`, `description`),
`signing_alg` (`RS256`), `token_lifetime` (seconds, 1 to 2592000, default
86400), `token_lifetime_for_web` (default 7200, at most `token_lifetime`),
`allow_offline_access`, `skip_consent_for_verifiable_first_party_clients`,
`subject_type_authorization` (`client` and `user` policies, defaults
`require_client_grant` and `allow_all`), `enforce_policies` (`false`),
`token_dialect` (`access_token`), `is_system`. `GET /api/v2/resource-servers/{id}`
also accepts the URL-encoded identifier in place of the ID, which is what
auth0-cli sends. Listing takes `identifiers` (repeated), `page`, `per_page`
and `include_totals` (key `resource_servers`), in creation order, system APIs
first.

- **The identifier is fixed** after creation, and compared case-sensitively
  (1 to 600 characters). A duplicate is `409 resource_server_conflict`.
- **Scopes:** `PATCH` replaces the whole list; values are unique, 1 to 280
  characters, descriptions at most 500. Removing a scope removes it from every
  client grant that carries it. Users' consents that name it are left as they
  are (see the follow-ups).
- **Deleting** an API deletes its client grants, the users' consents for it and
  the refresh tokens issued for it. Access tokens already issued stay valid
  until they expire. `204`, also for an unknown ID.
- **System APIs** (`is_system: true`): each tenant's "zeroauthy Management
  API", and `urn:zeroauthy:management` on the system tenant. They can be read
  and granted, never deleted (`400 delete_system_resource_server`), and their
  name, scopes and the settings zeroauthy relies on cannot change; naming a
  setting with its current value is accepted, since `auth0-deploy-cli` sends
  back what it read. The tenant's Management API identifier cannot be used
  for a new API (`400 reserved_identifier`).
- **Seed:** the seed never touches APIs created through the API.

Differences from Auth0 (D-0041):

- **Signing is RS256 only.** `HS256`, `PS256` and `signing_secret` are
  `400 invalid_body`.
- **Inert-only fields.** `token_lifetime_for_web` is stored and reported but
  used by nothing (no implicit or hybrid flow). `enforce_policies` accepts only
  `false` and `token_dialect` only `access_token`, since there are no roles or
  permissions to enforce and no other token formats. `consent_policy`,
  `proof_of_possession` and `token_encryption` accept only `null`, and
  `authorization_details` only `null` or an empty list; none of them is
  reported.
- **IDs** of APIs created through the API are 24 hexadecimal characters.

## Client grants

A client grant authorizes an application to request tokens for an API with a
set of scopes. Fields: `id` (`cgr_` and 16 letters and digits), `client_id`,
`audience`, `scope`, `allow_all_scopes`, `subject_type` (`client` by default,
or `user`).

- **One grant** per application, audience and subject type
  (`409 client_grant_conflict`). `client_id`, `audience` and `subject_type`
  cannot be changed; `scope` can.
- **Scopes are checked on create as well as on update.** A scope the API does
  not define is `400 invalid_body`. Auth0 accepts it on create and refuses it on
  update; zeroauthy refuses both, so no grant names a scope its API lacks.
- **`allow_all_scopes: true`** grants every scope the API defines at the time a
  token is issued, so scopes added later are covered and removed ones are not.
  It does not go with `scope`. A response then has the flag and no `scope`.
- **Management API grants.** The audience may only be the caller's own
  Management API identifier (`subject_type` client, Management API scopes only).
  `urn:zeroauthy:management` and another tenant's identifier are
  `400 invalid_body`. An ordinary API that happens to have an identifier of that
  form is granted like any other.
- **Organizations and rich authorization** do not exist: `organization_usage`
  accepts `deny` or null, `allow_any_organization` false or null,
  `authorization_details_types` an empty list or null and `default_for` null.
- **Listing** filters on `client_id`, `audience` and `subject_type` (the last
  needs another filter). Offset paging as for applications (key
  `client_grants`), or **checkpoint paging**: `take` (1 to 100, default 50) and
  `from` give `{"client_grants": […], "next": "…"}`, with `next` absent on the
  last page. Pass `next` back as `from`. The cursor names the last grant ID, so
  grants added or removed between pages neither repeat nor skip others. With
  `take` or `from`, `page`, `per_page` and `include_totals` are ignored. Grants
  are listed in ID order.
- **Deleting** a grant is `204`, also for an unknown ID of the right form.
  Deleting an application or an API deletes its grants.
- **The seed** never touches grants created through the API.

## A machine-to-machine application without the seed

Everything below runs against a tenant with a Management API token that holds
the scopes `create:resource_servers`, `create:clients`, `create:client_grants`
and `read:client_keys` (an operator token has them all). Set `MGMT` to the
token and `HOST` to the tenant host.

```bash
# 1. The API.
curl -sS -X POST https://$HOST/api/v2/resource-servers \
  -H "Authorization: Bearer $MGMT" -H 'Content-Type: application/json' \
  -d '{"name":"Orders","identifier":"https://orders.example/api",
       "scopes":[{"value":"read:orders","description":"Read orders"}]}'

# 2. The machine-to-machine application; the response has client_id and client_secret.
curl -sS -X POST https://$HOST/api/v2/clients \
  -H "Authorization: Bearer $MGMT" -H 'Content-Type: application/json' \
  -d '{"name":"Orders worker","app_type":"non_interactive"}'

# 3. The grant.
curl -sS -X POST https://$HOST/api/v2/client-grants \
  -H "Authorization: Bearer $MGMT" -H 'Content-Type: application/json' \
  -d '{"client_id":"CLIENT_ID","audience":"https://orders.example/api","scope":["read:orders"]}'

# 4. A token.
curl -sS https://$HOST/oauth/token \
  -d grant_type=client_credentials -d client_id=CLIENT_ID -d client_secret=CLIENT_SECRET \
  -d audience=https://orders.example/api
```

With auth0-cli, logged in as a machine-to-machine client of the tenant
(`AUTH0_CLI_AUTH_MODE=env`, `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`,
`AUTH0_CLIENT_SECRET`; the tenant on port 443):

```bash
auth0 apis create --name Orders --identifier https://orders.example/api \
  --scopes read:orders --json
auth0 apps create --name "Orders worker" --type m2m --reveal-secrets --json
auth0 api post client-grants --data \
  '{"client_id":"CLIENT_ID","audience":"https://orders.example/api","scope":["read:orders"]}'
curl -sS https://$HOST/oauth/token -d grant_type=client_credentials \
  -d client_id=CLIENT_ID -d client_secret=CLIENT_SECRET -d audience=https://orders.example/api
```

Also working: `auth0 apis list/show/update/delete`, `auth0 apis scopes list`,
and `auth0 api get/patch/delete client-grants[/{id}]`. The console does all
of this too: see [console.md](console.md).

## The system API

zeroauthy's own API for the console, at `/api/system/` on the system host,
for operator tokens only (D-0040). Auth0 has no equivalent.

| Operation | What it does |
|---|---|
| `GET /api/system/tenants` | Every tenant, with its canonical `host`, `management_api_identifier`, `domains`, `seeded` and `reserved` (the system tenant) |
| `POST /api/system/tenants` | `{"name", "friendly_name", "domains"}`. Names are DNS labels (63 characters at most); `system` is reserved. A new tenant gets signing keys, the database connection `Username-Password-Authentication` and its Management API. Without a base domain it needs a domain |
| `PATCH /api/system/tenants/{name}` | Friendly name and domains |
| `DELETE /api/system/tenants/{name}?confirm={name}` | Deletes the tenant and all of its data |
| `GET /api/system/operators` | The operators |
| `POST /api/system/operators` | `{"email"}`: invites an operator; the response's `setup_url` is a one-hour link to choose a password |
| `DELETE /api/system/operators/{user_id}` | Removes an operator and ends their sessions; never the last one |

The system tenant cannot be changed or deleted here. Tenants created through
this API are never touched by the seed.
