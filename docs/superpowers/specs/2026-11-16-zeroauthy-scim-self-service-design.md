# Plan 37c — Inbound SCIM, directory groups, self-service SSO, connection profiles and directory provisioning

**Date:** 2026-11-16. **Status:** design; not implemented.

**Roadmap entry:** [management roadmap, Plan 37](2026-10-19-zeroauthy-management-roadmap-design.md)
("SCIM configuration and tokens with an inbound SCIM 2.0 server;
self-service profiles and SSO tickets; directory groups … if Auth0
documents a groups resource at build time"); [parallel paths](2026-11-13-zeroauthy-parallel-paths-design.md)
item **F4** (track F, after F3). The brief's open question "whether
directory groups ship" is answered by the evidence: Auth0's `/api/v2/groups`
family is GA (2026-11-16), so groups ship here. Plan 38d (M1) handed this
plan the group sources of effective roles. Read the
[clean-room policy](../../../CLEAN_ROOM.md), `AGENTS.md`, D-0026 (RBAC),
D-0055 (organizations), the Plan 36/37a/37b specs.

## 1. Outcome and scope

Phased (each phase merges on its own):

- **Phase A — Inbound SCIM and groups.** An enterprise connection (`samlp`,
  `oidc`, `okta`, `waad`; documented list) gets a SCIM configuration and up
  to two SCIM tokens; the customer's IdP provisions users and groups into
  zeroauthy at the connection's SCIM 2.0 endpoint. Groups are first-class:
  `/api/v2/groups` (read, delete), members, group roles, role→groups,
  user→groups, organization groups and their roles, and effective roles and
  permissions gain group sources (closing Plan 38d's LR38d-2).
- **Phase B — Self-service SSO and connection profiles.** Operators define
  self-service profiles; an SSO ticket lets a customer administrator open a
  hosted assistant that configures their own enterprise connection (SAML,
  OIDC, Okta, Entra, ADFS) within the profile's limits, optionally with
  domains, organizations, provisioning (SCIM) and client access. Connection
  profiles template the created connections.
- **Phase C — Directory provisioning** (Google Workspace directory sync on
  `google-apps` connections): configuration, mapping, on-demand and
  automatic synchronization, synchronized-group selection.

**Rule:** strict 1:1 with Auth0's documented behaviour; RFC 7643/7644 for
SCIM where Auth0 is silent. Local rulings **LR37c-n**, observation points
**Q1–Qn** in **D-0150** (F4 block D-0150–0159).

### In scope (by Management operation, from the OpenAPI)

**Phase A:** `/connections/{id}/scim-configuration` (GET, POST, PATCH,
DELETE), `.../default-mapping`, `.../tokens` (GET, POST, DELETE),
`/connections-scim-configurations` (list); `/groups` (GET list, GET, DELETE),
`/groups/{id}/members`, `/groups/{id}/roles` (GET, POST, DELETE),
`/roles/{id}/groups` (GET, POST, DELETE), `/users/{id}/groups`,
`/users/{id}/effective-roles/sources/groups`, `/organizations/{id}/groups`,
`/organizations/{id}/groups/{group_id}/roles` (GET, POST, DELETE),
`/organizations/{id}/members/{user_id}/effective-roles/sources/groups`;
the SCIM 2.0 server (§3).

**Phase B:** `/self-service-profiles` (CRUD), `.../custom-text/{language}/{page}`,
`.../sso-ticket` (POST), `.../sso-ticket/{id}/revoke`; `/connection-profiles`
(CRUD), `/connection-profiles/templates` (+ by ID); the hosted
self-service assistant (§5).

**Phase C:** `/connections/{id}/directory-provisioning` (GET, POST, PATCH,
DELETE), `.../default-mapping`, `.../synchronizations` (POST),
`.../synchronized-groups` (GET, POST, PUT, DELETE),
`/connections-directory-provisionings` (list), the `google-apps` strategy
if not yet present (Q1).

### Not in scope

- Outbound SCIM (zeroauthy provisioning into other apps): Auth0 does not
  offer it.
- `/organizations/{id}/roles/{role_id}/groups` (Early Access): tracked.
- Okta Express Configuration (`express_configuration` clients): Early
  Access-like partner flow; tracked (F1 deferral).
- `user_attribute_profile_id` behaviour (user attribute profiles are Early
  Access): stored only (LR37c-1).

### Anti-goals

- **Cross-connection writes.** A SCIM token acts only on users and groups
  of its own connection; it can never read or modify users of another
  connection or tenant.
- **Privilege by group name.** Groups grant roles only through explicit
  group-role assignments made by an operator; SCIM cannot assign roles.
- **Self-service escalation.** An SSO ticket can only create or edit the
  one connection it names, within the profile's `allowed_strategies`, and
  cannot enable clients or organizations beyond the ticket's lists.
- **Token leakage.** SCIM tokens are shown once, stored hashed; SSO
  tickets single use until expiry; neither logged.
- **Deprovisioning gaps.** `active: false` blocks the user, ends sessions,
  revokes refresh tokens and triggers back-channel logout (documented).

## 2. Evidence

- Management OpenAPI (read 2026-11-16): the operations above with their
  scopes (`read:scim_config`, `create:scim_token`, `read:groups`,
  `create:group_roles`, `read:self_service_profiles`,
  `create:sso_access_tickets`, `read:connection_profiles`,
  `read:directory_provisionings`, …), request/response members (SCIM
  config `user_id_attribute`, `mapping`; token `scopes`, `token_lifetime`
  > 900; group `id` `grp_` + 14–22 base58, `name` unique per connection,
  1–128 printable ASCII, `external_id`, `connection_id`; self-service
  profile `name`, `description`, `branding`, `allowed_strategies`,
  `user_attributes`; SSO ticket `connection_id`, `connection_config`,
  `enabled_clients`, `enabled_organizations`, `ttl_sec`,
  `domain_aliases_config`, `provisioning_config`,
  `use_for_organization_discovery`, `third_party_client_access_config`,
  `enabled_features`; connection profile members; directory provisioning
  `mapping`, `synchronize_automatically`, `synchronize_groups`, status
  fields).
- Inbound SCIM guide `/docs/authenticate/protocols/scim/configure-inbound-scim`
  (strategies SAML, OIDC, Okta, Entra; Google Workspace uses Directory
  Sync; Users and Groups; Users POST/GET/PUT/PATCH/SEARCH/DELETE with
  `eq`/`and`/`or`, Groups with `eq`; token scopes `get|post|put|patch|delete:users|groups`;
  default mapping from RFC 7643 core attributes, `id` = Auth0 `user_id`,
  no `password`; `active=false` blocks and ends sessions/tokens/back-channel
  logout; two active tokens; minimum lifetime 900 s; group `displayName`
  unique per connection; only `user` members).
- Self-service SSO guides (read at build time for the assistant steps and
  the ticket URL form, Q2).
- RFC 7643 / RFC 7644.

## 3. SCIM 2.0 server (Phase A)

- Base: `https://<tenant host>/scim/v2/connections/<connection_id>/`
  (Q3: Auth0's base path) with `Users`, `Groups`, `ServiceProviderConfig`,
  `ResourceTypes`, `Schemas`.
- Auth: `Authorization: Bearer <scim token>`; scopes per method/resource.
- Users: create (provisions a user on that connection before first login;
  `user_id` = the connection's federated format with the SCIM `externalId`
  or the mapped `user_id_attribute`, Q4), read, list with `filter`
  (`eq`, `and`, `or` on mapped searchable attributes), `startIndex`/`count`
  paging, replace (PUT), PATCH (RFC 7644 §3.5.2 ops `add`/`replace`/`remove`
  on mapped paths), delete (as `DELETE /api/v2/users/{id}`).
- Login matching: a later federated login whose upstream subject equals the
  provisioned identity attaches to that user (identity index, Plan 24),
  never by email.
- Groups: create/read/list (`filter` `displayName eq`)/PUT/PATCH (members
  add/remove)/delete; members only users of the same connection.
- Errors per RFC 7644 §3.12 (`schemas: [urn:ietf:params:scim:api:messages:2.0:Error]`,
  `status`, `scimType`, `detail`).
- Limits: bulk not supported (Q5); 1000 members per PUT logged without the
  list (documented).

## 4. Groups and roles (Phase A)

- Groups belong to one connection; created by SCIM (and Phase C sync);
  `DELETE /api/v2/groups/{id}` removes the group and its role assignments.
- Group roles: tenant roles assigned to a group → every member's
  effective roles (token-time RBAC and Plan 38d effective endpoints).
- Organization groups: groups of connections enabled on an organization;
  organization group roles flow into organization-scoped roles for members.
- `api.groups.getUserGroups` / `hasGroupMembership` in Actions (empty since
  Plan 27) return real data (closes the A1 note).
- Event streams: group events if the events catalog lists them (Q6).

## 5. Self-service SSO (Phase B)

- Profile: branding (logo, colours), `allowed_strategies` (subset of
  `oidc`, `samlp`, `waad`, `google-apps`, `adfs`, `okta`, `keycloak-samlp`,
  `pingfederate` — those zeroauthy has; others refused, Q7),
  `user_attributes` (attributes the created connection must map),
  custom text per language/page.
- Ticket: `POST .../sso-ticket` → `{ticket: "https://<host>/self-service/<token>"}`
  (Q2) valid `ttl_sec` (default 432000 s = 5 days, Q8); revocable; single
  connection: creates a new one (name from `connection_config.name` or a
  connection-profile prefix template) or edits `connection_id`.
- Assistant (hosted, branded): pick the strategy, enter IdP metadata or
  OIDC discovery, verify with a test login, map attributes, optionally
  add domains (unverified unless `domain_aliases_config` allows, Q9),
  optionally set up SCIM (Phase A token shown once), enable the ticket's
  clients/organizations, done. Writes go through the same rules packages as
  the Management API.
- Connection profiles: templates (`connection_config`, `strategy_overrides`,
  `enabled_features`, `provisioning`, name prefix) applied by tickets that
  reference them; `templates` endpoints list built-in templates (Q10).

## 6. Directory provisioning (Phase C)

- `google-apps` connections (Google Workspace): with
  `directory-provisioning`, zeroauthy reads users (and selected groups) from
  the Google Admin SDK Directory API with the connection's delegated
  credentials, creates/updates/blocks users per `mapping`, on demand
  (`synchronizations`) and every 40 minutes when `synchronize_automatically`
  (Q11), recording `last_synchronization_*`.
- Requires the `google-apps` strategy; if F-track work has not added it,
  Phase C adds it as a federated strategy on Plan 24/25 code (Q1).

## 7. Storage

- Phase A: `scim_configurations`, `scim_tokens` (hashed), `groups`,
  `group_members`, `group_roles`, `organization_group_roles`.
- Phase B: `self_service_profiles`, `self_service_custom_text`,
  `sso_tickets` (hashed), `connection_profiles`.
- Phase C: `directory_provisionings`, `synchronized_groups`,
  `directory_sync_runs`.
- One migration per phase, numbered at merge; gRPC capabilities
  `scim.v1`, `self_service.v1`, `directory_sync.v1`.

## 8. Console, seed, Deploy CLI, tests

- Console: connection → Provisioning tab (SCIM config, tokens, mapping),
  Groups pages, role → groups, user → groups; Self-service profiles and
  ticket creation; connection profiles; Directory sync status.
- Seed and Deploy CLI: which handlers 9.1.0 has for these (`selfServiceProfiles`,
  `connectionProfiles` exist in its handler list; groups/SCIM checked in
  Task 1); round trips where available.
- Tests: SCIM conformance-style suite (RFC 7644 examples), token isolation
  across connections, filter parser fuzzing, deprovisioning effects, group
  role propagation into tokens, ticket scope enforcement in the assistant,
  directory sync against a fixture Directory API.
- E2E: `make e2e-scim` with a SCIM client (Microsoft's/Okta's are SaaS;
  local: a Node script following RFC 7644, plus the `scim2-tester`-style
  checks written in-house), Playwright through the self-service assistant.

## 9. Local rulings and observation points

| ID | Ruling |
|---|---|
| LR37c-1 | `user_attribute_profile_id` stored only (EA dependency). |

Observe later: **Q1** `google-apps` availability; **Q2** ticket URL form
and assistant steps; **Q3** SCIM base path; **Q4** user ID for
SCIM-provisioned users; **Q5** SCIM bulk; **Q6** group events; **Q7**
strategies in `allowed_strategies`; **Q8** default ticket TTL; **Q9**
domain verification in the assistant; **Q10** built-in connection profile
templates; **Q11** automatic sync interval.

## 10. Decisions needed from the maintainer

1. Phase order: A → B → C as proposed, or B first (self-service is the
   B2B-facing feature; SCIM is what enterprise customers ask about first).
2. Phase C needs Google Workspace admin credentials for real testing
   (fixture only in CI); acceptable to ship with fixture coverage only?
