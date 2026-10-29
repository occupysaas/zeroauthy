# Organizations

One tenant can serve several organizations, each with members, assignments of
tenant roles, enabled connections and branding. Manage them under **User
Management → Organizations**, through `/api/v2/organizations`, or in seed
configuration. Organization data is isolated by tenant.

The wire inventory is [internal/orgrules/inventory.json](../internal/orgrules/inventory.json).
[D-0055](compat/decisions.md#d-0055--plan-29-organizations-i-contracts-2026-10-28)
and the [observation notes](compat/observations/organizations.md) distinguish
observed behavior from documented contracts and local decisions. The
[implementation record](superpowers/2026-10-28-plan-29-implementation-record.md)
records verification and remaining limitations.

## Resources and limits

Organizations have `id`, `name`, `display_name`, `branding`, `metadata` and
`third_party_client_access` (`block` by default, or `allow`). IDs are `org_`
plus 16 random alphanumeric characters. Names are unique within a tenant and
match `^[a-z0-9][a-z0-9_-]{0,49}$`; display names contain 1–255 characters.
Duplicate names return 409. Unknown or cross-tenant resources return 404.
Unknown body properties and unsupported query parameters return 400.

Branding accepts an HTTPS `logo_url` or null. If `colors` is present, both
`primary` and `page_background` must be hex colors. Metadata has at most 25
keys matching `^[a-zA-Z0-9]\w*$`, each 1–50 characters, with nonempty string
values of at most 255 characters. Null metadata values are rejected. PATCH
replaces the entire `branding` or `metadata` object; `{}` or null clears it.
GET and list responses omit `enabled_connections`; use its subresource.

| Limit | Value |
|---|---|
| Organizations per tenant | 10,000 (local) |
| Enabled connections on organization create | 10 |
| Enabled connections per organization | 50 |
| Roles per member | 50 (local) |
| User IDs or role IDs per assignment/removal request | 10 (local) |
| Members | No organization-specific count cap |
| User organization listing | Up to 1,000 organizations, paginated |
| Offset page / page size | `page` 0–1000; `per_page` 1–100, default 50 |
| Checkpoint page size | `take` 1–100 |
| Picker entries | 20, ordered by display name |

Organization `sort` accepts `name`, `display_name` or `created_at`, followed
by `:1` or `:-1`. Lists support offset (`page`, `per_page`, `include_totals`)
or checkpoint (`from`, `take`,
`next`) paging. Member lists are ordered by user ID. Member-role lists use
offset paging only. Effective roles and role members use checkpoint only;
effective roles return `{roles: [{id, name, description, sources}], next?}`.
Effective roles are direct organization assignments until groups exist.

Use `/organizations/{id}/members` to add/remove existing users and
`/organizations/{id}/members/{user_id}/roles` for role assignments. Unknown
users return 404 `inexistent_user`; member-role operations require current
membership and existing roles, otherwise 404. Batches validate atomically.
Removing a member preserves their role assignments, which apply again upon
rejoining. Deleting the organization, user or role removes its assignments;
deleting a connection removes its organization links.

The enabled-connections resource supports list/create/get/PATCH/delete.
`assign_membership_on_login` defaults to false. Enterprise-only
`show_as_button` defaults to true; false hides a button but still permits an
explicit `connection=` selection. Database-only `is_signup_enabled` defaults
to false and requires auto-membership. Connection creation checks existence
and strategy-specific flags; it does not add an extra strategy allowlist.

The Early Access `/organizations/{id}/connections` resource also manages
these same links for pinned Deploy CLI compatibility. Its access-level fields
are unstored defaults. `GET /organizations/{id}/client-grants` is truthfully
empty; organization grants are not yet enabled. Responses keep
`is_app_entitlement_active` false.

## Management routes

Routes below use the `/api/v2` prefix. M2M callers require the listed scopes;
operators still require target tenant grants.

| Resource | Methods and scopes |
|---|---|
| `/organizations` | GET `read:organizations`; POST `create:organizations`, plus `create:organization_connections` when `enabled_connections` is supplied |
| `/organizations/{id}`, `/organizations/name/{name}` | GET `read:organizations` |
| `/organizations/{id}` | PATCH `update:organizations`; DELETE `delete:organizations` |
| `/organizations/{id}/members` | GET either `read:organization_members` or `read:organization_member_roles`; POST `create:organization_members`; DELETE `delete:organization_members` |
| `/organizations/{id}/members/{user_id}/roles` | GET/POST/DELETE `read/create/delete:organization_member_roles` respectively |
| `/organizations/{id}/members/{user_id}/effective-roles` | GET `read:organization_member_effective_roles` |
| `/organizations/{id}/roles/{role_id}/members` | GET both `read:organization_members` and `read:roles` |
| `/organizations/{id}/enabled_connections` (or `/connections`) | GET `read:organization_connections`; POST `create:organization_connections` |
| `/organizations/{id}/enabled_connections/{connection_id}` (or `/connections/{connection_id}`) | GET/PATCH/DELETE `read/update/delete:organization_connections` respectively |
| `/organizations/{id}/client-grants` | GET `read:organization_client_grants`, empty until Plan 30 |
| `/users/{id}/organizations` | GET either `read:users` or `read:organizations` |

`fields=roles` on member listing additionally needs
`read:organization_member_roles`. Organization creation returns 201; successful
assignment/removal and deletion return 204. Empty organization PATCH is 400.

## Application settings and login

`organization_usage` is `deny` (default), `allow`, or `require`.
`organization_require_behavior` is `no_prompt` (default), `pre_login_prompt`,
or `post_login_prompt`. Pre-login behavior is accepted with every usage.
`organization_discovery_methods` accepts `email` and/or `organization_name`
only with `pre_login_prompt`. Email discovery is stored and validated;
the hosted screen always asks for a name until Plan 30. Post-login behavior
requires `oidc_conformant`.

A `require` application cannot hold password, password-realm or device-code
grants. Creating or changing either side of that combination returns 400.
Token-time `unauthorized_client` remains a guard for legacy data. Password
and device flows for other applications never carry organization claims.
Client credentials refuses the `organization` parameter with `invalid_request`.

| Authorization request | Result |
|---|---|
| Organization supplied to `deny` | `invalid_request` |
| Valid organization supplied to `allow`/`require` | Bind it to this authorization transaction |
| Missing organization, `require` + `no_prompt` | `invalid_request` |
| Missing organization, `allow`/`require` + `pre_login_prompt` | Name screen before authentication |
| Missing organization, `require` + `post_login_prompt` | Authenticate, then choose an eligible organization |
| Missing organization, `allow` + `post_login_prompt` | Individual login |
| Missing organization, `deny` | Individual login |

An empty `organization=` is absent. Unknown organization IDs/names return
`invalid_request`. IDs always work; request names work only while the tenant
setting `allow_organization_name_in_authentication_api` is true. The hosted
name prompt resolves a name internally to an ID even when request names are
disabled. PAR binds the pushed organization; an authorize query cannot
override it. A session never silently carries its previous organization into
a new authorization request.

The login screen offers the intersection of application-enabled and
organization-enabled connections, including identifier-first routing.
An explicitly selected application-enabled connection outside the organization
is refused in the hosted step with `invalid_request` through the validated
callback. The existing earlier `/authorize` refusal of an unknown or
application-disabled `connection=` remains a compatibility follow-up. An
empty intersection retains the existing no-connection behavior.

After authentication, a member may continue. A non-member may continue only
when this organization's selected connection enables auto-membership; adding
the membership and the login user write are atomic. Otherwise login returns
`access_denied`. The authenticated session can still serve an individual login.
A third-party application requires `third_party_client_access: allow`.

Post-login selection considers memberships reachable through the authenticated
connection. Exactly one eligible choice is selected automatically; several
show the picker and none return `access_denied`. A single matching
organization with auto-membership may enroll the user; several auto-membership
candidates do not arbitrarily choose an organization. The displayed list is
bounded to 20 and sorted by display name.

Database signup additionally requires the selected organization's
`is_signup_enabled` and existing application/connection signup rules. User
creation and membership commit together. Social and enterprise first-login
membership shares the create/link transaction.

With `prompt=none`, an eligible session member (or eligible auto-membership)
can continue silently. A missing session or ineligible fixed organization
returns `login_required`. A required post-login choice succeeds silently only
with one eligible organization; otherwise it returns `interaction_required`.
Consent keeps its existing rules. Unsafe redirect destinations use the hosted
error page.

## Claims, permissions and refresh

Organization ID/access tokens carry reserved `org_id`. While the tenant names
setting is on, `org_name` contains the current canonical name, never its display
name. Turning the setting off omits names from newly issued tokens and rejects
request names. `/userinfo` echoes organization claims from its access token.
Actions cannot replace either reserved claim. Third-party applications keep
the existing no-ID-token policy.

API permissions combine direct assignments, tenant roles and roles assigned
in the active organization. Roles from other organizations never contribute.
Existing API RBAC, scope ceilings and all four access-token dialects apply.
An Actions login flow sees the same frozen authorization snapshot as issuance.

Authorization codes and refresh tokens persist both `OrganizationID` and the
original `OrganizationConnectionID`. Rotation carries these unchanged; no
later session or linked primary identity substitutes a different connection.
This binding survives session deletion/expiry. Legacy organization grants
missing the original connection fail closed.

Code redemption and refresh re-check the organization, enabled original
connection, membership, application organization usage and third-party access.
An organization grant becomes `invalid_grant` if any is no longer eligible;
an individual refresh is refused after the application becomes `require`.
Failed organization checks do not revoke the family. Successful refresh
recomputes permissions and reads the current organization name and names
setting. Existing JWTs keep their claims until expiry.

## Branding, templates and Actions

Organization logo and primary/background colors override tenant-theme values
on organization login, signup, consent and error pages. Other theme settings
stay tenant-level. The `organizations` custom-text prompt contains
`organization-selection` and `organization-picker` screens.

Full hosted Liquid templates receive `organization.id`, `name`, `display_name`,
`metadata`, `branding.logo_url` and `branding.colors.primary/page_background`;
there is no organization object for an individual transaction. Existing template
escaping, bounds and CSP apply. Post-login, pre-user-registration and
post-user-registration Actions receive `event.organization` with `id`, `name`,
`display_name`, and `metadata`. Registration jobs seal that snapshot. No new
organization Action commands are exposed.

## Per-tenant operators

Local system-host `/api/system/operators/{id}` PATCH replaces `tenants` with
existing tenant names, an empty list, or `["*"]` alone. System-API callers
must themselves manage the system tenant. Every tenant request checks the
intersection of signed token grants and current persisted grants: shrinking
access applies to old tokens immediately; expansion requires a new token.

Local `GET /api/console/tenants` lets a signed, live operator discover only
that intersection for the console switcher, without a system-tenant grant.
M2M callers are refused. It does not grant access to the system API.

Removing or shrinking the last usable system administrator returns 409.
System-tenant user deletion, blocking and linking as a secondary identity
share the same serialization/guard. Blocked or missing identities and
tenant-only operators do not count as viable fallback administrators.

## Storage, seed and deferred work

Apply additive migration 0025 and upgrade storage-plugin writers before using
organizations. Memory, SQLite, PostgreSQL, MySQL and gRPC share the contract.
An old plugin starts with a warning; organization routes and non-`deny`
application writes return 501, and an organization authorize parameter is
`invalid_request`. Old plugins can lose inert behavior/discovery values on a
`deny` application after echoing the write; upgrade before configuring them.
Mixed old/new writers are unsupported.

Seed `organizations` are create-only, with connection names and role names.
Members identify a user by `user_id` or by email plus connection; unresolved
references fail startup. Pinned Deploy CLI 9.1.0 round trips organizations and
connections in YAML/directory with generated or preserved credentials. It does
not migrate members or member-role assignments.

Plan 30 owns invitations/acceptance and invitation email, organization-grant
writes/enforcement, discovery domains/email discovery, organization search,
app entitlement and change-password organization context. The existing EA
connections routes need parity expansion there; their Plan 29 compatibility
subset is already active. Plan 35 owns organization token quotas with
client-credentials organization work. Plan 38 owns groups and inherited roles;
Plan 37 owns SAML/WS-Fed organization login; Plan 42 owns the My Organization
API. Classic Login/Lock, per-organization custom domains and unsupported
organization token flows remain outside this release.
