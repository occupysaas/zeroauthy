# Management API

Every zeroauthy tenant serves Auth0's Management API v2 at
`https://<tenant host>/api/v2/`, on each of its hosts. Slice 1 covers
**applications** (`/api/v2/clients`); later slices add APIs, client grants,
connections, users and tenant settings (design
`docs/superpowers/specs/2026-10-18-zeroauthy-management-design.md`).

The contract is [api/management.yaml](../api/management.yaml). Behaviour
that Auth0 does not document comes from observation of Auth0's API
([observations/management-clients.md](compat/observations/management-clients.md))
and is recorded in decisions D-0038 to D-0040 of
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
