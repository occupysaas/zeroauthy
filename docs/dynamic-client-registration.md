# Dynamic Client Registration and Client ID Metadata Documents

zeroauthy lets applications register themselves the way Auth0 does, in two
ways:

- **Dynamic Client Registration (DCR):** anyone can `POST /oidc/register`
  (RFC 7591, open registration) and receive a third-party application.
- **Client ID Metadata Documents (CIMD):** an application uses the HTTPS URL
  of a JSON document that describes it as its `client_id`. An administrator
  can register such an application in advance, or the tenant can create it
  the first time the URL is used.

Every application created either way is a **third-party application** with
the rules of D-0025: it logs in only through domain-level connections and
reaches APIs only through client grants. Before you turn either feature on,
create [default permissions for third-party applications](#default-permissions-for-third-party-applications),
or these applications cannot get tokens for any API.

The decisions are D-0090 (with amendments to D-0025 and D-0063) in
[compat/decisions.md](compat/decisions.md); the open questions about Auth0's
behaviour are R41-1…8 in the [plan 1 follow-ups](superpowers/plan-1-followups.md#plan-41b-observation-points).

## Tenant settings

| Setting | Default | Effect |
|---|---|---|
| `flags.enable_dynamic_client_registration` | `false` | Opens `/oidc/register`. Off, the endpoint answers `404`. |
| `dynamic_client_registration_security_mode` | `strict` | `third_party_security_mode` of registered applications. |
| `client_id_metadata_document_supported` | `false` | Accept a metadata document URL as `client_id` at `/authorize`, `/oauth/par`, `/oauth/token` and `/oauth/revoke`. |
| `client_id_metadata_document_dynamic_registration_supported` | `false` | Create an application the first time an unknown document URL is used. Has an effect only with the setting above. |

Set them with `PATCH /api/v2/tenants/settings`, in the console under
**Settings → Advanced**, or in the seed:

```yaml
tenants:
  - name: acme
    domains: [auth.example.com]
    settings:
      flags: {enable_dynamic_client_registration: true}
      dynamic_client_registration_security_mode: strict
      client_id_metadata_document_supported: true
    cimd_clients: ["https://agent.example.com/client.json"]
```

Discovery advertises `registration_endpoint` when DCR is on and
`client_id_metadata_document_supported: true` when CIMD is on.

## Registering an application (DCR)

```sh
curl -sS https://auth.example.com/oidc/register \
  -H 'content-type: application/json' \
  -d '{"client_name":"My Dynamic Application","redirect_uris":["https://app.example.com/callback"],"token_endpoint_auth_method":"none"}'
```

```json
{
  "client_id": "tpc_8SXWY6j3afl2CP5ntwEOpM",
  "client_name": "My Dynamic Application",
  "redirect_uris": ["https://app.example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "client_secret_expires_at": 0
}
```

| Member | Rule |
|---|---|
| `redirect_uris` | Required, 1 to 20. HTTPS, `http` on a loopback host, or a private-use scheme (`com.example.app:/cb`). No wildcards, fragments or credentials. Otherwise `400 invalid_redirect_uri`. |
| `client_name` | 1 to 255 characters; `My App` when absent. |
| `token_endpoint_auth_method` | `none` (a single-page application) or `client_secret_post` (the default, a regular web application). Anything else is `400 invalid_client_metadata`. |
| `grant_types` | Only `authorization_code` and `refresh_token` are granted; others are dropped from the answer. |
| `response_types` | Only `code`. |
| Other members | `logo_uri`, `client_uri`, `policy_uri`, `tos_uri`, `contacts` and the rest are accepted and ignored. |

The secret of a confidential application is returned once and stored
sealed; it never expires. The origins of the `http` and `https` redirect URIs
become the application's `allowed_origins`, so a browser application can
call `/oauth/token`. Registered applications cannot change themselves
afterwards (no RFC 7592); the tenant's administrators manage them through
the Management API like any other application.

The endpoint takes at most **5 requests per second per tenant** (`429`
afterwards, counted per process). Network ACL rules with the
`dynamic_client_registration` scope arrive with Plan 38c.

## Client ID Metadata Documents

A document is JSON served with `200` and `application/json` at an HTTPS URL
with a path, at most 200 characters:

```json
{
  "client_id": "https://agent.example.com/client.json",
  "client_name": "Example agent",
  "redirect_uris": ["https://agent.example.com/callback"],
  "token_endpoint_auth_method": "private_key_jwt",
  "jwks_uri": "https://agent.example.com/jwks.json"
}
```

- `client_id` must equal the document's URL exactly.
- `token_endpoint_auth_method` is `none` (the default) or `private_key_jwt`;
  there are no shared secrets, so `client_secret` is refused.
- `private_key_jwt` needs keys in `jwks` or `jwks_uri` (not both): RSA, 2048
  to 4096 bits, at most 10. They become the application's credentials and
  are replaced whenever the document is fetched again.
- `redirect_uris` follow the DCR rules above.

zeroauthy fetches documents and JWKS only over HTTPS to public addresses,
checked at every connection, without a proxy, within 10 seconds, at most 64
KiB, and refuses redirects. A document is cached for its `Cache-Control:
max-age`, bounded to 5 minutes to 24 hours. When a refresh fails the
application keeps working on the cached document, marked
`external_metadata_status: unavailable`, until 24 hours after the last good
fetch; then its requests are `invalid_client`.

Creating applications from unknown URLs is limited like `/oidc/register`, to
5 per second per tenant.

At `/oauth/token`, a `private_key_jwt` assertion carries the document URL as
`iss` and `sub`. Applications created from documents are always `strict`
third-party applications, so they get no ID token (D-0025).

### Management API

| Route | Scope | What it does |
|---|---|---|
| `POST /api/v2/clients/cimd/preview` | `read:clients` | Fetches and validates the document and shows how it maps to application fields. Creates nothing. A document that cannot be fetched answers `200` with `errors`. |
| `POST /api/v2/clients/cimd/register` | `create:clients` to create (`201`), `update:clients` to update (`200`) | Creates or updates the application of that URL. `409` when a user's authorization request already created it; `400` for an unreachable or invalid document. |

The console's applications list has a **Register from a client metadata
document** form that calls both, and marks DCR and CIMD applications.
Applications carry `external_client_id`, `external_metadata_type` (`dcr` or
`cimd`), `external_metadata_created_by` (`admin` or `client`) and
`external_metadata_status`.

The seed's `cimd_clients` are registered when the server starts; a document
that cannot be fetched only logs a warning.

## Default permissions for third-party applications

A client grant with `default_for: third_party_clients` instead of a
`client_id` applies to every third-party application that has no grant of
its own for that API and subject type:

```sh
curl -sS https://auth.example.com/api/v2/client-grants \
  -H "authorization: Bearer $MGMT_TOKEN" -H 'content-type: application/json' \
  -d '{"default_for":"third_party_clients","audience":"https://api.example.com","subject_type":"user","scope":["read:things"]}'
```

- A grant for the application itself takes precedence.
- First-party applications never use default grants.
- There is one default per API and subject type (`409` for a second).
- System APIs (the Management, My Account and My Organization APIs) refuse
  default grants, and default grants take no organization policy.
- `GET /api/v2/client-grants?default_for=third_party_clients` lists them.

## Conformance

The OpenID Foundation's Dynamic OP profile registers every client with
`private_key_jwt`, `request_uri` and sector identifiers, which Auth0's open
registration does not offer. zeroauthy follows Auth0, so that profile is not
part of `tests/conformance/run.sh` (see [conformance](conformance.md)).
