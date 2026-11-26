# My Organization API

The My Organization API lets an organization's administrators manage their
own organization from your application: its details and branding, its
members and their roles, and invitations (Plan 42b Phase A, D-0220). It
follows Auth0's My Organization API (OpenAPI 1.0.0, Early Access at Auth0)
at `https://{host}/my-org/v1`; zeroauthy's contract is
[`api/myorg.yaml`](../api/myorg.yaml). This fits the self-service use case:
each customer organization manages its own users and access.

Served: `GET /config`, `GET|PATCH /details`, `GET /members`,
`GET /members/{user_id}`, `POST /delete-memberships`,
`GET|POST /members/{user_id}/roles`, `POST /members/{user_id}/unassign-roles`,
`GET /roles`, `GET|POST /member-invitations`,
`GET /member-invitations/{id}`, `GET /member-invitations/{id}/roles`,
`POST /delete-member-invitations`, `GET /user-stores`. Not yet served
(Phase B): domains, the organization's own identity providers, their
provisioning and SCIM tokens.

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

## Errors and logs

Errors carry `type`, `status`, `title`, `detail` and, for invalid fields,
`validation_errors`, with the `x-correlation-id` header. Operations record
the `my_organization_api_*` log events (member, invitation, details, role
failures). Invitation tickets are never logged.
