# Plan 41b — Dynamic Client Registration and Client ID Metadata Documents

**Date:** 2026-11-16. **Status:** design; not implemented.

**Roadmap entry:** [management roadmap, Plan 41](2026-10-19-zeroauthy-management-roadmap-design.md)
(Dynamic Client Registration; Plan 35 moved "CIMD client registration"
here); [parallel paths](2026-11-13-zeroauthy-parallel-paths-design.md)
item **P4** (track P, after P1; independent code from P2/P3, so it may be
built in parallel once its track turn comes). Read the
[clean-room policy](../../../CLEAN_ROOM.md), `AGENTS.md`, D-0025
(third-party clients, strict/permissive), D-0063 (client credentials),
and the [Plan 38c network ACLs spec](2026-11-16-zeroauthy-network-acls-design.md)
(`dynamic_client_registration` scope).

## 1. Outcome and scope

- **DCR (RFC 7591, open registration):** with the tenant flag
  `enable_dynamic_client_registration`, anyone can `POST /oidc/register`
  and get a third-party client (`tpc_` prefix), strict or permissive per
  `dynamic_client_registration_security_mode`; protection comes from
  network ACLs and the endpoint's rate limit, as Auth0 documents.
- **CIMD (Client ID Metadata Documents, OAuth draft):** a client whose
  `client_id` at `/authorize` is an HTTPS URL is resolved by fetching that
  metadata document (tenant flags, Early Access on Auth0), and operators
  pre-register or preview such clients with `POST /api/v2/clients/cimd/register`
  and `/preview` (GA).
- Discovery advertises `registration_endpoint` when DCR is on, and the
  CIMD support flag when on.
- The OIDF **Dynamic OP** certification profile becomes runnable locally
  (Plan 41a's conformance plan list gains it).

**Rule:** strict 1:1 with Auth0's documented behaviour (memory: Auth0 parity
first); RFC 7591 and the CIMD draft where Auth0 is silent. Local rulings
**LR41b-n**, observation points **R41-1…n** in **D-0090** (P4 block
D-0090–0099).

### In scope

1. `POST /oidc/register` (§3).
2. Tenant settings `flags.enable_dynamic_client_registration` (stored since
   Plan 19 → enforced), `dynamic_client_registration_security_mode`
   (`strict` | `permissive`), `client_id_metadata_document_supported`,
   `client_id_metadata_document_dynamic_registration_supported`.
3. Client fields `external_client_id`, `external_metadata_type` (`cimd` |
   `dcr`), `external_metadata_created_by` (`admin` | `client`),
   `external_metadata_status` (EA; returned, LR41b-1).
4. `POST /api/v2/clients/cimd/preview`, `POST /api/v2/clients/cimd/register`
   (§4).
5. CIMD resolution at `/authorize`, `/oauth/par` and `/oauth/token` (§5).
6. Default third-party API permissions (§6) — the prerequisite Auth0 names.

### Not in scope

- RFC 7592 client configuration endpoints (Auth0: third-party developers
  cannot modify registered clients).
- Initial access tokens / software statements (Auth0 supports open
  registration only, LR41b-2).
- Federation with OpenID Federation entity statements.

### Anti-goals

- **Registration as privilege.** A DCR client is always third party, can
  never request `client_credentials` through DCR, uses only domain-level
  connections, and gets API access only through explicit client grants
  (strict) or the API's policy (permissive), as D-0025 already enforces.
- **SSRF through CIMD.** Metadata fetches use the federation outbound
  policy (HTTPS, public addresses, 10 s, 64 KiB, no redirects except same
  origin, LR41b-3), are cached with `Cache-Control` bounds (min 5 min, max
  24 h), and never forward user data.
- **Identity confusion.** A CIMD `client_id` URL must equal the document's
  `client_id` member exactly; the document's `redirect_uris` are the only
  allowed callbacks; a document change takes effect only after a refetch
  and never reuses another client's credentials.
- **Secrets in logs.** Registered client secrets are returned once and then
  sealed like every client secret; never logged.

## 2. Evidence

- Auth0 DCR guide `/docs/get-started/applications/dynamic-client-registration`
  (read 2026-11-16): enable with `flags.enable_dynamic_client_registration`;
  `POST /oidc/register` with `client_name`, `redirect_uris` (required),
  `token_endpoint_auth_method` (`none` | `client_secret_post` default),
  `grant_types` (filtered), `response_types`; response `client_name`,
  `client_id` (`tpc_`), `client_secret` (absent for `none`),
  `redirect_uris`, `client_secret_expires_at: 0`, `grant_types`,
  `token_endpoint_auth_method`; created clients are third party with
  enhanced controls, PKCE required, only `authorization_code` and
  `refresh_token`, explicit client grants, domain-level connections; no
  token needed; restrict with a tenant ACL `dynamic_client_registration`
  rule; 5 requests per second per tenant; no later modification by the
  developer.
- Permissive mode page (DCR security mode setting independent of
  `POST /api/v2/clients` defaults; configure default API permissions first).
- Management OpenAPI: `post_cimd_preview` (`read:clients`… response
  `client_id`, `external_metadata_created_by`, `errors`, `validation`,
  `mapped_fields`), `post_cimd_register` (idempotent upsert by
  `external_client_id` ≤ 120, `201` create / `200` update, scopes
  `create:clients`/`update:clients`, fetch + validate + map + credentials
  from the JWKS, "HTTPS-only, no shared secrets", `409` when a DCR client
  already has that `external_client_id`), client fields above, tenant
  settings above.
- RFC 7591; `draft-ietf-oauth-client-id-metadata-document` (version read
  at build time, R41-1).

## 3. `/oidc/register`

- Off → `404` (R41-2: Auth0's answer when disabled; local: `404` like an
  unknown route).
- Request JSON (RFC 7591): `client_name` (1–255, default "My App",
  R41-3), `redirect_uris` (required, 1–20 absolute URLs, HTTPS except
  loopback and private-use schemes per D-0025 native rules), `grant_types`
  (∩ `authorization_code`, `refresh_token`; others silently filtered —
  documented), `response_types` (`code` only; others `400
  invalid_client_metadata`), `token_endpoint_auth_method` (`none` |
  `client_secret_post` default; others `400`), `logo_uri`, `client_uri`,
  `policy_uri`, `tos_uri`, `contacts` (stored as client metadata where the
  client has fields: `logo_uri`; others ignored, R41-4).
- Creates: `client_id` `tpc_` + 22 base62, `is_first_party: false`,
  `third_party_security_mode` from the tenant setting, `app_type`
  `regular_web` (secret) or `spa` (none) (R41-5), `oidc_conformant: true`,
  `external_metadata_type: dcr`, `external_metadata_created_by: client`,
  callbacks = `redirect_uris`, the PKCE requirement (strict).
- Response `201` with the documented fields (`client_secret_expires_at: 0`).
- Errors RFC 7591 §3.2.2: `400 {"error":"invalid_redirect_uri"|"invalid_client_metadata","error_description":...}`.
- Rate limit 5 requests/second per tenant (token bucket, store-backed via
  the Plan 45 general limiter group), `429`.
- Logs: the Auth0 log type for DCR from the logs schema (`sapi`-style
  types read at build time, R41-6); network ACL scope
  `dynamic_client_registration` applies (O1).

## 4. CIMD Management routes

- `preview`: fetch `external_client_id`, validate (§5 rules) and return
  the OpenAPI response members `client_id`, `external_metadata_created_by`,
  `errors`, `validation` and `mapped_fields`; create nothing.
- `register`: idempotent upsert keyed by `external_client_id`: create
  (`201`, needs `create:clients`) or update (`200`, needs
  `update:clients`); maps `client_name`, `redirect_uris`, `logo_uri`,
  `grant_types`, `token_endpoint_auth_method` (`none` or `private_key_jwt`
  only — "no shared secrets"); `jwks` / `jwks_uri` → Plan 35 client
  credentials (`public_key`), rotated to match the document;
  `external_metadata_type: cimd`, `external_metadata_created_by: admin`.
  `409` if a DCR client already has that `external_client_id`.

## 5. CIMD at the authorization server

- Enabled by `client_id_metadata_document_supported`.
- A `client_id` parameter that is an absolute HTTPS URL with a path
  (draft rules) is resolved: an existing client with that
  `external_client_id` is used (refetching when the cache expired);
  otherwise, if `client_id_metadata_document_dynamic_registration_supported`,
  a client is created as `register` would, with
  `external_metadata_created_by: client`; otherwise `invalid_client`.
- Validation: document `client_id` equals the URL; `redirect_uris` present;
  `token_endpoint_auth_method` `none` or `private_key_jwt`; no
  `client_secret`; size and content-type limits; `jwks_uri` same-origin or
  HTTPS public.
- `external_metadata_status`: `available` after a good fetch,
  `unavailable` after a failed refresh (the cached document is used until
  its hard expiry, then `invalid_client`, R41-7).
- Discovery: `client_id_metadata_document_supported: true` when on.

## 6. Default third-party permissions

Auth0: "configure default permissions for third-party applications" before
enabling DCR. zeroauthy maps this to the per-API `subject_type_authorization`
(Plan 30) plus an optional tenant-level default client grant template
applied to every DCR/CIMD client at creation (`default_third_party_grants:
[{audience, scope}]` in tenant settings — R41-8 for Auth0's actual
setting name; read at build time). If Auth0's setting is not public, this
is a local extension and documented as such.

## 7. Storage, console, seed, tests

- **Storage:** client columns `external_client_id` (unique per tenant),
  `external_metadata_*`; `cimd_documents(tenant_id, url, etag,
  fetched_at, expires_at, body)`; one migration numbered at merge;
  gRPC fields on the client message (capability `cimd.v1` gates writes).
- **Console:** Settings → Advanced (DCR switch, security mode, CIMD
  switches); applications list marks DCR/CIMD clients; CIMD preview form.
- **Seed:** tenant flags; `cimd_clients: [url]` registers at seed time
  only if the fetch succeeds (else warning).
- **Tests:** `/oidc/register` table (fields, filtering, errors,
  `tpc_` format, strict vs permissive), rate limit, ACL scope, CIMD fetch
  policy (SSRF table), cache, `register` idempotency and `409`, `/authorize`
  resolution with and without dynamic registration, credential rotation
  from `jwks`.
- **Conformance:** OIDF Dynamic OP plan (`oidcc-dynamic-certification-test-plan`)
  added to `tests/conformance/run.sh` with expected files triaged.
- **E2E:** `make e2e-dcr` (new lane): raw RFC 7591 registration requests,
  then `@auth0/auth0-spa-js` 2.28.3 logging in with the returned `tpc_`
  client; a local HTTPS server hosting a CIMD
  document for the CIMD path.

## 8. Local rulings and observation points

| ID | Ruling |
|---|---|
| LR41b-1 | `external_metadata_status` (EA) is returned read-only. |
| LR41b-2 | Open registration only; no initial access tokens. |
| LR41b-3 | CIMD fetches follow the federation outbound policy. |

Observe later (`docs/superpowers/plan-1-followups.md`):

- **R41-1** CIMD draft version Auth0 follows.
- **R41-2** `/oidc/register` answer when DCR is off.
- **R41-3** Default `client_name`.
- **R41-4** Which RFC 7591 metadata Auth0 keeps.
- **R41-5** `app_type` of DCR clients.
- **R41-6** DCR log types.
- **R41-7** Behaviour when a CIMD document becomes unreachable.
- **R41-8** Auth0's default third-party permissions setting.
