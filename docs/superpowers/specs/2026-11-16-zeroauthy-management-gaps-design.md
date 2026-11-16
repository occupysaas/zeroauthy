# Plan 38d — Management API gaps (remaining GA routes, legacy resources, list parameters)

**Date:** 2026-11-16. **Status:** design; not implemented.

**Roadmap entry:** [management roadmap, Plan 38](2026-10-19-zeroauthy-management-roadmap-design.md)
("remaining resources" and the pre-1.0 OAS gap list); [parallel paths](2026-11-13-zeroauthy-parallel-paths-design.md)
item **M1** (track M, only item, independent of the other tracks). Read
the [clean-room policy](../../../CLEAN_ROOM.md), `AGENTS.md`, D-0043
(users), D-0041/D-0042, roadmap §5 (not planned) and the
[Management API guide](../../management-api.md).

## 1. Outcome and scope

Every **GA** route of Auth0's Management API either exists in zeroauthy or
is owned by a named paths item, and the routes zeroauthy already serves
stop ignoring documented list parameters.

**Inventory (2026-11-16).** Auth0's Management OpenAPI lists 490
operations; `api/management.yaml` has 299. The 195 missing operations,
grouped by owner:

| Owner | Operations |
|---|---|
| F1 (Plan 36, designed) | connection keys, `/connections/{id}/status`, `/connections/{id}/users` |
| P2 (Plan 48, designed) | `/refresh-tokens` list/revoke/patch, `/sessions/{id}` patch and revoke |
| P4 (Plan 41b) | `/clients/cimd/preview`, `/clients/cimd/register` |
| P6 (Plan 43) | `/users/{id}/connected-accounts` |
| H1 (Plan 44, designed) | `/prompts/rendering`, `/prompts/{p}/screen/{s}/rendering` |
| A2 (Plan 38b) | `/forms`, `/flows`, `/flows/{id}/executions`, `/flows/vault/connections` |
| F4 (Plan 37c) | SCIM configuration and tokens, directory provisioning, `/connections-scim-configurations`, `/connections-directory-provisionings`, `/self-service-profiles`, `/connection-profiles`, `/groups`, `/roles/{id}/groups`, `/organizations/{id}/groups*`, `/users/{id}/groups`, `.../sources/groups` |
| O1 (Plan 38c) | `/network-acls` |
| O2 (Plan 45a) | `/keys/encryption*` (customer-managed keys sit on the master-key rotation work; LR38d-1) |
| **M1 (this plan)** | the rows of §1 "In scope" |
| Tracked, not built (Early Access) | `/agents`, `/client-profiles`, `/experimentation/*`, `/portals`, `/rate-limit-policies`, `/supplemental-signals`, `/user-attribute-profiles`, `/keys/network-acls`, `/clients/search`, `/client-grants/search`, `/resource-servers/search`, `/users/{id}/consent-signing-keys`, `/organizations/{id}/roles/{id}/groups` |
| Decision §8 | `/verifiable-credentials/verification/templates` |

**Rule:** strict 1:1 with Auth0's documented behaviour (memory: Auth0 parity
first). Local rulings **LR38d-n** and observation points **G1–Gn** go in
**D-0240** (M1 block D-0240–0249).

### In scope

1. **Effective roles and permissions** (GA):
   `GET /users/{id}/effective-roles`, `GET /users/{id}/effective-permissions`,
   `GET /users/{id}/effective-permissions/sources/effective-roles`. Without
   groups (F4), the sources are the direct roles; F4 adds group sources
   and `GET /users/{id}/effective-roles/sources/groups` (LR38d-2).
2. **`POST /users/{id}/revoke-access`** (`session_id`?,
   `preserve_refresh_tokens`?): revoke one session or all, with or without
   their refresh tokens; `202`.
3. **`GET /clients/{id}/connections`**: enabled connections for a client,
   checkpoint pagination, `strategy` filter, `fields`.
4. **Device credentials** (`GET`, `POST`, `DELETE /device-credentials`):
   listing `refresh_token` and `rotating_refresh_token` entries from the
   refresh-token store (Plan 17/48), `public_key` credentials stored (§3).
5. **Risk assessment settings** (`GET`/`PATCH /risk-assessments/settings`,
   `.../settings/new-device` with `remember_for` 1–365 days) and
   `POST /users/{id}/risk-assessments/clear` (`connection`, `assessors`),
   feeding Plan 33's known-device check and A1's `riskAssessment`.
6. **Rules, hooks and rules-configs completeness** (roadmap §5): the routes
   that do not exist yet answer as Auth0 does for a tenant without these
   legacy features (§4).
7. **List parameters** zeroauthy ignores today (pre-1.0 review):
   `/clients` `q`, `is_global`, `from`, `take`, `app_type`, `is_first_party`;
   `/roles` `from`, `take`, `name_filter`; `GET /logs` `sort` on every
   documented field (not only `date`); and any other documented parameter
   found ignored by the Task 1 audit (§5).

### Not in scope

Everything assigned to another owner in the inventory table, and the Early
Access rows (roadmap §6 rule).

### Anti-goals

- **Scope widening.** Every new route enforces its documented scope set
  exactly (several need two scopes, e.g. `revoke-access` needs
  `delete:sessions` and `delete:refresh_tokens`).
- **Public-key credentials as a bypass.** A stored `public_key` device
  credential grants nothing at `/oauth/token` (no legacy delegation
  grant exists); it is data only (LR38d-3).
- **Silent parameter drops.** After this plan, an unknown query parameter
  on an audited route is either honoured or rejected as Auth0 rejects it —
  never silently ignored (Task 1 audit pins each route).

## 2. Evidence

Management OpenAPI (read 2026-11-16): operations `get_effective-roles`,
`get_effective-permissions`, `get_effective-permissions-sources-effective-roles`
(scopes `read:user_effective_roles`, `read:user_effective_permissions`,
`read:user_permission_source_roles`; checkpoint `from`/`take`;
`resource_server_identifier`, `permission_name`), `post_revoke-access`
(scopes `delete:sessions` + `delete:refresh_tokens`; body `session_id` ≤ 50,
`preserve_refresh_tokens`; `202`), `get_client_connections` (scopes
`read:connections` + one of `read:clients` / `read:client_summary`;
`strategy`, `from`, `take`, `fields`, `include_fields`; `404` unknown
client), `get_device-credentials` (`user_id`, `client_id`, `type`; paging;
`403` "User to be acted on does not match subject in bearer token" for
user-scoped tokens), `post_device-credentials`
(`create:current_user_device_credentials`; `device_name`, `type`
`public_key`, `value`, `device_id`, `client_id`; `409` "A public key
already exists for the device"), `delete_device-credentials_by_id`,
`get/patch risk-assessments settings` (`update:attack_protection`; `403`
"Please upgrade your subscription to use adaptive MFA"),
`post_risk-assessments_clear` (`update:users`), the rules/hooks/rules-configs
operations, and the list parameters of `get_clients`, `get_roles`,
`get_logs`.

## 3. Behaviour

### 3.1 Effective roles and permissions

- Roles: direct tenant roles (Plan 26), ordered by role ID, checkpoint
  pagination (`from` = last ID, `take` ≤ 100, default 50). Each entry is the
  role object plus `sources: [{type: "direct"}]` (G1: Auth0's source
  shape; read the OpenAPI items at build time).
- Permissions: direct permissions ∪ permissions of direct roles, de-duplicated
  by (resource server, name), optional `resource_server_identifier` filter,
  ordered by (identifier, name); `sources` listing `direct` and/or the
  granting roles' IDs (G1).
- `sources/effective-roles?resource_server_identifier=&permission_name=`:
  the roles granting that permission (direct only until F4).
- Organization roles (Plan 29) are not tenant effective roles (G2).

### 3.2 `revoke-access`

- With `session_id`: that session (must belong to the user; else `404`,
  G3) is deleted; its refresh tokens revoked unless
  `preserve_refresh_tokens: true`.
- Without: every session of the user; refresh tokens likewise.
- Back-channel logout initiator `session-revoked` (Plan 41a) when present.
- `202`, synchronous (LR38d-4).

### 3.3 Client connections

Connections whose enabled clients include the client, ordered by
connection ID, `strategy` filter (repeatable, G4), full connection objects
with the usual secret projection.

### 3.4 Device credentials

- `GET` requires `user_id` with a `read:device_credentials` token (or a
  user-scoped token for the caller's own ID); `type` filters
  `public_key` | `refresh_token` | `rotating_refresh_token`; entries
  `id`, `device_name` (from the refresh token's user agent or the stored
  name), `device_id`, `type`, `user_id`, `client_id`.
- `refresh_token` / `rotating_refresh_token` entries are the user's live
  refresh tokens (IDs equal to `/refresh-tokens/{id}`).
- `POST` stores a `public_key` credential (PEM or JWK `value`, ≤ 4 KiB),
  one per (user, client, device_id) (`409` otherwise).
- `DELETE /device-credentials/{id}`: a refresh-token entry revokes that token
  (grant kept, as unlinking a device is documented to keep it); a public
  key is deleted.

### 3.5 Risk assessments

- `settings.enabled` (default `false`, G5) and `new-device.remember_for`
  (default 30, G5) per tenant. When `enabled` is false, A1's
  `riskAssessment` is absent and Plan 33's `confidence-score` policy treats
  every device as known (G6). zeroauthy has no subscription tiers, so the
  `403` upgrade answer never occurs (LR38d-5).
- `remember_for` sets how long Plan 33's known-device record lasts.
- `risk-assessments/clear` with `assessors: ["new-device"]` clears the
  user's known devices on that connection; other assessor names `400` (G7).

## 4. Rules, hooks, rules-configs

Auth0 has ended these features; zeroauthy never implements them
(roadmap §5). Today the list routes return empty lists for Deploy CLI.
The remaining routes:

- `GET /rules/{id}`, `GET /hooks/{id}`, `GET /hooks/{id}/secrets` → `404`
  (nothing can exist).
- `POST`, `PATCH`, `DELETE`, `PUT` on rules, hooks, hook secrets and
  rules-configs → refused with the answer Auth0 gives a tenant that cannot
  use them (G8; local answer until observed: `403` with an explanatory
  message naming Actions).
- `DELETE` on an id that does not exist → local `404`; Auth0 answers `204`
  for missing ids on some resources, so G8 records the real answer.

## 5. List-parameter audit

Task 1 walks every list route in `api/management.yaml` against the
OpenAPI's parameters and produces a table: honoured, rejected like Auth0,
or ignored. Every "ignored" row becomes a test and a fix in this plan unless
its feature belongs to another owner (then it stays rejected with `400` and
is listed for that owner). Known rows: `/clients` `q` (Lucene subset over
`name`, `client_id`, `app_type`, `is_first_party`; G9),
`is_global`, `app_type`, `is_first_party`, `from`/`take` (checkpoint);
`/roles` `name_filter`, `from`/`take`; `/logs` `sort` (`date`, `type`,
`client_name`, `user_name`, … per the OpenAPI) with `:1`/`:-1`.

## 6. Storage, console, seed, tests

- **Storage:** `device_credentials` table (public keys); tenant settings gain
  `risk_assessments` JSON; known-device records gain an expiry derived from
  `remember_for`. One migration numbered at merge.
- **Console:** user detail → "Effective permissions" panel and "Revoke
  access" button; application → Connections tab uses the new route;
  Security → Risk assessment settings.
- **Seed:** `risk_assessments` settings.
- **Tests:** handler tests per route (scopes, paging, filters, errors),
  the audit table as a table-driven test, node-auth0 7.4.0 calls for every
  route it has (`users.getEffectiveRoles` etc. — whichever exist in 7.4.0),
  auth0-cli `api` for the rest, Deploy CLI unchanged (rules/hooks still
  export empty).

## 7. Local rulings and observation points

| ID | Ruling |
|---|---|
| LR38d-1 | `/keys/encryption*` moves to O2 (master-key rotation). |
| LR38d-2 | Effective roles without groups until F4. |
| LR38d-3 | `public_key` device credentials are data only. |
| LR38d-4 | `revoke-access` runs synchronously, answers `202`. |
| LR38d-5 | No subscription `403` for risk assessments. |

Observe later (`docs/superpowers/plan-1-followups.md`):

- **G1** `sources` shapes on effective roles and permissions.
- **G2** Organization roles in effective roles.
- **G3** `revoke-access` with another user's session ID.
- **G4** `strategy` filter repetition on client connections.
- **G5** Risk assessment defaults.
- **G6** Known-device behaviour when risk assessment is disabled.
- **G7** Accepted assessor names for `clear`.
- **G8** Rules/hooks write and delete answers on a tenant without them.
- **G9** `/clients` `q` syntax supported by Auth0.

## 8. Decisions needed from the maintainer

1. **Verifiable credentials verification templates** (`/verifiable-credentials/verification/templates`,
   GA: verifying mobile driver's licences in Universal Login). Not on the
   roadmap; it needs a wallet-presentation runtime. Proposed: add to
   roadmap §5 "not planned" until a user asks.
2. Confirm `/keys/encryption*` belongs to O2 (LR38d-1); the roadmap listed
   it both under §5 (not planned) and under Plan 38's pre-1.0 additions.
