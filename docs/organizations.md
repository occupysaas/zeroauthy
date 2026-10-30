# Organizations

One tenant can serve several organizations, each with members, assignments of
tenant roles, enabled connections and branding. Manage them under **User
Management → Organizations**, through `/api/v2/organizations`, or in seed
configuration. Organization data is isolated by tenant.

The wire inventory is [internal/orgrules/inventory.json](../internal/orgrules/inventory.json).
[D-0055](compat/decisions.md#d-0055--plan-29-organizations-i-contracts-2026-10-28)
and the [observation notes](compat/observations/organizations.md) distinguish
observed behavior from documented contracts and local decisions. The
[Organizations II implementation record](superpowers/2026-10-29-plan-30-implementation-record.md)
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
these same links, including disabled links, local connection names and stored
access-level metadata. These delegation metadata fields grant no self-service
permissions. Legacy enabled-connections calls preserve them when re-enabling a link.

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
| `/organizations/{id}/invitations` | GET/POST `read/create:organization_invitations`; item GET/DELETE `read/delete:organization_invitations` |
| `/organizations/{id}/clients` | GET/POST/DELETE `read/create/delete:organization_clients`; item GET/PATCH `read/update:organization_clients` |
| `/organizations/{id}/client-grants` | GET/POST `read/create:organization_client_grants`; item DELETE `delete:organization_client_grants` |
| `/client-grants/{id}/organizations` | GET `read:organization_client_grants` |
| `/organizations/{id}/discovery-domains` | GET/POST `read/create:organization_discovery_domains`; item GET/PATCH/DELETE `read/update/delete:organization_discovery_domains` |
| `/organizations/search` | GET both `read:organizations` and `read:organizations_summary` |
| `/users/{id}/organizations` | GET either `read:users` or `read:organizations` |

`fields=roles` on member listing additionally needs
`read:organization_member_roles`. Organization creation returns 201; successful
assignment/removal and deletion return 204. Empty organization PATCH is 400.

## Application settings and login

`organization_usage` is `deny` (default), `allow`, or `require`.
`organization_require_behavior` is `no_prompt` (default), `pre_login_prompt`,
or `post_login_prompt`. Pre-login behavior is accepted with every usage.
`organization_discovery_methods` accepts `email` and/or `organization_name`
only with `pre_login_prompt`. Email discovery considers verified domains enabled
for discovery and current application/connection eligibility; routing does not
verify an email address or enroll a member. Post-login behavior
requires `oidc_conformant`.

A `require` application cannot hold password, password-realm or device-code
grants. Creating or changing either side of that combination returns 400.
Token-time `unauthorized_client` remains a guard for legacy data. Password
and device flows for other applications never carry organization claims.
Client credentials accepts an explicit organization subject to grant policy below.

| Authorization request | Result |
|---|---|
| Organization supplied to `deny` | `invalid_request` |
| Valid organization supplied to `allow`/`require` | Bind it to this authorization transaction |
| Missing organization, `require` + `no_prompt` | `invalid_request` |
| Missing organization, `allow`/`require` + `pre_login_prompt` | Configured name/email screen before authentication |
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

Apply additive migrations 0025–0027 and upgrade storage-plugin writers before using
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

Organizations II seed fields include `is_app_entitlement_active`,
`third_party_client_access`, `clients`, `client_grants`, `discovery_domains` and
connection enabled/access metadata. All organization configuration is create-only
in either seed mode: reseeding never restores a removed association/domain or
overwrites API-managed policy. Client references accept an existing ID or unique
application name. Organization grant references use `client_id` plus `audience`
and resolve an existing client-subject grant in the same tenant. Connection and
organization names use the existing seed mapping. An unresolved reference rolls
back the entire seed transaction, including earlier grant scope changes.

```yaml
organizations:
  - name: example
    is_app_entitlement_active: true
    third_party_client_access: block
    clients:
      - client_id: Browser # existing ID or unique name
        use_for_member_access: true
    client_grants:
      - client_id: Service
        audience: https://api.example.test
    connections:
      - name: Enterprise
        is_enabled: false
        organization_connection_name: Enterprise login
        organization_access_level: none
        organization_member_access_level: limited
    discovery_domains:
      - domain: example.test
        use_for_organization_discovery: true
```

Tenant-level `client_grants` accept `organization_usage` and
`allow_any_organization` only as initial policy. Existing grants keep those
values across reseeding; API-created grants retain their ownership protections.
User-subject grants cannot activate organization policy, and third-party
applications cannot use allow-any. Discovery domains default pending; seed
rejects verified status, requiring a deliberate Management API attestation.
Invitations, receipts and bearer ticket fields are rejected by the seed parser.
See [Deploy CLI limitations](deploy-cli.md) for the pinned tool's smaller
portable policy subset.

## Invitations and application entitlement

Set an application `initiate_login_uri` before creating invitations. The emailed
URL opens that application route with `invitation` and `organization`; the
application forwards both into its normal authorization request. Invitation
create/get return a bearer URL; avoid logging or sharing it. Sending uses the
normal durable email engine and `user_invitation` template. Template/provider
policy controls delivery; creating an invitation does not prove email was sent.

Acceptance requires the invited verified email and original primary connection.
Signup uses the normal email-verification flow; an invitation alone does not
verify an existing account. Wrong-account attempts retain the ticket for a new
login. Acceptance atomically consumes the ticket, adds membership and roles,
and merges metadata; existing metadata keys win. Actions then see the accepted
organization. Action denial does not undo membership. A second authorization
transaction cannot replay the ticket. The platform currently has no MFA engine;
no MFA completion or enforcement is claimed. First-time federated invitation
provisioning fails closed; pre-provisioned federated users are supported.

When `is_app_entitlement_active` is true, member access additionally requires
an organization application association with `use_for_member_access: true`.
Authorization, invitation acceptance, code exchange and refresh all enforce
current entitlement and connection policy.

## Machine access, domains and search

Client-subject grants use `organization_usage: deny|allow|require` (default
`deny`). `require` rejects requests without an explicit organization. An
organization request needs either `allow_any_organization` or an explicit grant
association. Third-party clients require an explicit association and organization
`third_party_client_access: allow`; configuring allow-any for them returns 400.
Member entitlement and member roles do not authorize machine access. Quotas and
default organization selection remain outside this release.

Discovery domains start pending. An administrator PATCH to `verified` attests
that ownership was independently checked; the server does not resolve DNS to
prove ownership. Only verified, discovery-enabled domains route email discovery.
The challenge is destination-local and cannot be ported as verified seed data.
Self-service domain verification is excluded.

Search accepts bounded Lucene or SCIM expressions with ascending `name`,
`display_name` or `created_at` sorting. Opaque checkpoint cursors bind tenant,
parser, query and sort; changing them or tampering with a cursor returns 400.
Search paging is independent of legacy list sort syntax.

OrganizationsII plugin capability is negotiated separately from Organizations I.
An older plugin retains Plan 29 support but active II operations fail closed;
upgrade every writer before enabling II configuration. Mixed writers are unsupported.

Plan 35 owns token quotas, Plan 38 groups/inherited roles, Plan 37 SAML/WS-Fed
organization login, and Plan 42 the My Organization API. Classic Login/Lock,
per-organization custom domains and unsupported organization token flows remain
outside this release. Exact tested versions and remaining verification limits
are recorded in the Organizations II implementation record.
