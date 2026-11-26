# My Organization API

The My Organization API lets an organization's administrators manage their
own organization from your application: its details and branding, its
members and their roles, and invitations (Plan 42b Phase A, D-0220); its
domains, its own enterprise identity providers and their SCIM
provisioning (Phase B, D-0221). It
follows Auth0's My Organization API (OpenAPI 1.0.0, Early Access at Auth0)
at `https://{host}/my-org/v1`; zeroauthy's contract is
[`api/myorg.yaml`](../api/myorg.yaml). This fits the self-service use case:
each customer organization manages its own users and access.

Served: `GET /config`, `GET|PATCH /details`, `GET /members`,
`GET /members/{user_id}`, `POST /delete-memberships`,
`GET|POST /members/{user_id}/roles`, `POST /members/{user_id}/unassign-roles`,
`GET /roles`, `GET|POST /member-invitations`,
`GET /member-invitations/{id}`, `GET /member-invitations/{id}/roles`,
`POST /delete-member-invitations`, `GET /user-stores`; Phase B:
`GET /config/identity-providers`, `/domains` (list, claim, get, delete,
`verify`, `identity-providers`), `/identity-providers` (list, create, get,
update, delete, `update-attributes`, `detach`, domains) and their
`provisioning` with SCIM tokens: every operation of the OpenAPI 1.0.0.

## Set it up

1. **Activate the API.** Console: APIs → **My Organization API** →
   **Activate**. Management API: `POST /api/v2/resource-servers` with
   `{"identifier": "https://{canonical host}/my-org/"}`. Seed:
   `my_organization_api: {active: true}`. It becomes the system API
   `My Organization API` with user access `require_client_grant`,
   machine-to-machine access `deny_all`, RBAC on and 600-second tokens
   (fixed). Deleting it deactivates; `/my-org/v1` then answers `404`.
2. **Give administrators permissions.** Add permissions of the My
   Organization API (`read:my_org:members`, `create:my_org:member_roles`
   and so on) to a role, and assign the role to members in their
   organization (organization member roles). A user's `my_org` permissions
   in an organization are those of their roles there.
3. **Mark the roles administrators may hand out.** `PATCH
   /api/v2/roles/{id}` with `{"my_organization_visible": true}` (a
   zeroauthy extension; the console's role editor has a checkbox; seed:
   `my_organization_visible: true`). `GET /my-org/v1/roles` lists these
   roles and only these can be assigned or put on invitations.
4. **Configure the application.** It needs a user client grant for the
   API (console: the application's **APIs** tab → **My Organization API**
   → **Allow user access**) and a `my_organization_configuration`
   (same tab, or `PATCH /api/v2/clients/{id}`, or the seed); without one
   the API refuses its tokens (`403`).

```json
{
  "my_organization_configuration": {
    "allowed_strategies": ["oidc", "samlp"],
    "connection_deletion_behavior": "allow_if_empty",
    "invitation_landing_client_id": "{client that invitees land on}",
    "enforce_permission_ceiling": true,
    "enforce_self_assignment_restriction": true
  }
}
```

| Member | Effect |
|---|---|
| `invitation_landing_client_id` | Where invitees accept; required for invitations. |
| `enforce_permission_ceiling` | Administrators may assign only roles whose `my_org` permissions they hold themselves. Off by default, as at Auth0. |
| `enforce_self_assignment_restriction` | Administrators may not assign roles to themselves. Off by default. |
| `allowed_strategies`, `connection_deletion_behavior`, `third_party_client_access`, profile IDs | Returned by `GET /config`; `third_party_client_access.allowed_values` limits what `PATCH /details` may set. The rest is for Phase B. |

## Get a token

Sign the administrator in **in their organization** (the `organization`
parameter) with the audience `https://{host}/my-org/`, using the
authorization code flow. Tokens without an organization and client
credentials are refused. The access token carries `org_id` and the
`my_org` scopes the user's roles grant within the client grant; the ID
token lists them in `urn:auth0:my_org_current_user_permissions` for your
UI. Use one host throughout, as with the My Account API.

```js
const client = new auth0.Auth0Client({
  domain: 'login.example.com', clientId: 'portal',
  authorizationParams: {redirect_uri: location.origin, audience: 'https://login.example.com/my-org/',
    organization: 'org_…', scope: 'openid profile read:my_org:members create:my_org:member_invitations'},
});
```

Every operation acts on the token's organization; no path or body names an
organization. The user must still be a member when calling.

## Operations

- **Members:** checkpoint paging (`from`, `take` ≤ 100), `include_totals`
  (counted up to 1000, `total_is_capped`), `fields`/`include_fields`.
  `roles` (first ten) appears only when the token also has
  `read:my_org:member_roles`. Profile fields only; no metadata.
- **Remove a member:** `POST /delete-memberships` with one user ID removes
  the membership; the user and their role assignments stay, as with the
  Management API.
- **Roles:** assign and unassign visible roles; the configuration's
  ceiling and self-assignment rules apply. The organization's last member
  holding a role with `my_org` permissions cannot lose it, through
  unassignment or removal (`409`).
- **Invitations:** up to ten invitees, each with an `email` and up to ten
  visible roles, through a `user_store_id` (from `GET /user-stores`: the
  organization's database connections) or `identity_provider_id`;
  `ttl_sec` defaults to seven days, at most 30. A new invitation for an
  email revokes its earlier ones. Invitations are emailed with the
  `user_invitation` template, as from the Management API.
- **Details:** `name`, `display_name`, `branding` (logo URL, colors) and
  `third_party_client_access`.

## Domains (Phase B)

An organization's domains are its discovery domains (the Management API's
`/organizations/{id}/discovery-domains` shows the same list).

1. `POST /domains` `{"domain": "acme.example"}` claims a domain:
   `status: pending`, with `verification_host`
   (`_zeroauthy-org.acme.example`) and `verification_txt`. A domain another
   organization of the tenant has verified cannot be claimed (`409`).
2. The administrator publishes a TXT record with `verification_txt` at
   `verification_host`.
3. `POST /domains/{id}/verify` looks the record up and answers `202` with
   `verified` or `failed`. A DNS failure leaves the status and answers
   `503`.

Unverified domains claimed here are deleted 7 days after the claim.
Domains created here do not take part in organization discovery; enable
that with the Management API if wanted.

The lookup uses the deployment's resolver:
`server.custom_domains.dns_resolver` (`host:port`), else the system
resolver. Without one, verification answers `503`.

## Identity providers (Phase B)

Administrators create enterprise connections for their organization:
`oidc`, `okta`, `waad`, `google-apps`, `adfs` and `samlp`, as the
application's `allowed_strategies` permit (`pingfederate` is listed but
cannot be created). `options` take the OpenAPI's per-strategy members, for
example:

```json
{"name": "acme-sso", "strategy": "oidc", "display_name": "Acme",
 "options": {"type": "back_channel", "client_id": "…", "client_secret": "…",
             "discovery_url": "https://idp.acme.example/.well-known/openid-configuration"}}
```

- A created provider is a connection enabled only on the organization, at
  access level `full`, for the calling application and the invitation
  landing application. Responses never contain `client_secret`; updates
  that omit it keep it.
- `GET /identity-providers` lists the organization's providers at access
  levels `readonly`, `limited` and `full`; connections you enabled at
  `none` (the default) stay hidden. Set the organization connection's
  `organization_access_level` to share one of yours.
- Updates: `display_name` and `options` need `full`; `show_as_button`,
  `assign_membership_on_login` and `is_enabled` need `full` or `limited`
  and, for the first two, a connection profile that marks them `optional`.
  `DELETE` (`full`) deletes the connection (`allow_if_empty` refuses one
  with users); `detach` only removes it from the organization.
- A connection you share with several organizations stays yours: its
  deletion, display name, options, domains and provisioning cannot be
  changed through this API (`403`), whatever the access level; each
  organization still controls its own `is_enabled`, `show_as_button` and
  `assign_membership_on_login`, and can detach it.
- Domains: `POST …/domains` links a verified organization domain for home
  realm discovery (the connection's `domain_aliases`); a domain belongs to
  one provider of the organization. Deleting the organization domain
  unlinks it.
- `GET /config/identity-providers` describes what administrators may do,
  from the application's `connection_profile_id` (console: the
  application's My Organization configuration).

## Provisioning (Phase B)

`POST /identity-providers/{id}/provisioning` enables SCIM for an `oidc`,
`okta`, `waad` or `samlp` provider whose strategy the connection profile
provisions (any of these without a profile). `POST …/scim-tokens` returns a
token once; the profile's scopes, default and maximum lifetime apply; two
tokens may be active. SCIM clients call
`https://{host}/scim/v2/connections/{id}`. Provisioning writes need access
level `full`.

zeroauthy has no User Attribute Profiles: `attributes` of a provider is
empty, provisioning `attributes` is the SCIM mapping, and both
`update-attributes` operations return them unchanged.

## Errors and logs

Errors carry `type`, `status`, `title`, `detail` and, for invalid fields,
`validation_errors`, with the `x-correlation-id` header. Operations record
the `my_organization_api_*` log events (member, invitation, details, role,
domain and `idp` events). Invitation tickets, client secrets and SCIM
tokens are never logged; the Management API writes behind identity
providers log as client `my-organization-api`.
