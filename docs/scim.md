# SCIM provisioning and directory groups

zeroauthy is a SCIM 2.0 service provider (RFC 7643 and RFC 7644) for
enterprise connections, as Auth0 is: the customer's identity provider, such
as Microsoft Entra ID or Okta, creates, updates, deactivates and deletes the
connection's users and groups. Operators then assign roles to those groups,
and every member gets the roles in newly issued tokens.

SCIM is available for `samlp`, `oidc`, `okta` and `waad` connections
(D-0150). Storage plugins need the `scim.v1` capability; without it the
routes answer 501.

## Enable SCIM on a connection

In the console, open the connection under **Authentication → Enterprise**
and choose the **Provisioning** tab. **Enable SCIM** creates the
configuration with the default mapping. With the Management API:

```sh
# Configuration: an empty body takes the default mapping and externalId.
curl -X POST https://$TENANT/api/v2/connections/$CONNECTION_ID/scim-configuration \
  -H "authorization: Bearer $MGMT_TOKEN" -H 'content-type: application/json' -d '{}'

# A token for the identity provider; shown once, stored as a hash.
curl -X POST https://$TENANT/api/v2/connections/$CONNECTION_ID/scim-configuration/tokens \
  -H "authorization: Bearer $MGMT_TOKEN" -H 'content-type: application/json' \
  -d '{"scopes":["get:users","post:users","put:users","patch:users","delete:users","get:groups","post:groups","put:groups","patch:groups","delete:groups"]}'
```

Give the identity provider:

- **Tenant URL:** `https://{tenant host}/scim/v2/connections/{connection_id}`
  (the console shows it).
- **Secret token:** the `token` of the response. It is shown only once.

| Route | Scope |
|---|---|
| `GET`, `POST`, `PATCH`, `DELETE /api/v2/connections/{id}/scim-configuration` | `read:`, `create:`, `update:`, `delete:scim_config` |
| `GET /api/v2/connections/{id}/scim-configuration/default-mapping` | `read:scim_config` |
| `GET`, `POST /api/v2/connections/{id}/scim-configuration/tokens`, `DELETE .../tokens/{token_id}` | `read:`, `create:`, `delete:scim_token` |
| `GET /api/v2/connections-scim-configurations` | `read:scim_config` |

Rules (from Auth0's documentation unless marked):

- One configuration per connection. A second `POST` answers 400 with a
  message that the configuration already exists (the Deploy CLI relies on
  that message).
- Tokens: scopes from `get|post|put|patch|delete:users|groups` (all of them
  when `scopes` is absent); `token_lifetime` in seconds must be greater than
  900, and absent or `null` means no expiry; at most two unexpired tokens per
  connection (409). The token list never includes the secret, and
  `last_used_at` records the latest SCIM request.
- `DELETE .../scim-configuration` deletes the configuration and every token
  of the connection. Provisioned users and groups stay.

## Mapping

The mapping pairs an Auth0 profile field with a SCIM attribute path. The
default:

| Auth0 | SCIM |
|---|---|
| `email` | `emails[primary eq true].value` |
| `name` | `displayName` |
| `given_name` | `name.givenName` |
| `family_name` | `name.familyName` |
| `nickname` | `userName` |
| `app_metadata.department` | `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department` |

Root profile fields and `app_metadata.*` or `user_metadata.*` keys can be
mapped; `id`, `meta`, `schemas`, `active`, `groups` and `password` cannot.
`user_id_attribute` (default `externalId`) names the SCIM attribute that
becomes the user's identity: the SCIM `id` and the Auth0 `user_id` are
`{strategy}|{connection name}|{value}`, the same user a later login through
the connection finds.

## The SCIM endpoint

Under `https://{tenant host}/scim/v2/connections/{connection_id}`, with
`Authorization: Bearer {scim token}` and `application/scim+json`:

| Resource | Operations | Token scope |
|---|---|---|
| `/Users` | `POST`, `GET` (list and filter), `GET /{id}`, `PUT`, `PATCH`, `DELETE` | `{method}:users` |
| `/Groups` | `POST`, `GET` (list and filter), `GET /{id}`, `PUT`, `PATCH`, `DELETE` | `{method}:groups` |
| `/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas` | `GET` | any valid token of the connection |

- **Filters:** `eq`, `and` and `or`, with parentheses. Users can be found by
  `id`, the user ID attribute, `active` and the mapped root attributes;
  groups by `displayName`, `externalId` and `id`. Other operators answer 400
  `invalidFilter`. `startIndex` and `count` (at most 100) page lists.
- **PATCH:** `add`, `replace` and `remove`, case-insensitive (Entra ID sends
  `Replace`), with or without `path`. A path-less value may use attribute
  paths as keys (`name.givenName`, URN-qualified extension attributes).
  Group members are added and removed by value, including
  `members[value eq "…"]`.
- **Deactivation:** `active: false` blocks the user, ends their sessions with
  back-channel logout and revokes their refresh tokens. `active: true`
  unblocks.
- **Delete:** as `DELETE /api/v2/users/{id}`.
- **Isolation:** a token acts only on its own connection. Users and groups
  of another connection are not found (404), and a token presented at
  another connection's endpoint is refused (401).
- **Errors:** the RFC 7644 error schema with `status` and, where it applies,
  `scimType` (`uniqueness`, `invalidFilter`, `invalidValue`, …).
- **Not supported:** bulk operations, sorting, ETags and password changes
  (`ServiceProviderConfig` says so).

## Groups

Groups belong to one connection and are created by SCIM. A group's
`displayName` is unique within its connection (1–128 printable ASCII
characters), and only users of the same connection can be members. Group
IDs are `grp_` followed by base58 characters.

The console lists them under **User Management → Groups**, with members,
group roles and deletion; roles and users show their groups on a
**Groups** tab.

| Route | Scope |
|---|---|
| `GET /api/v2/groups` (`connection_id`, `name`, `external_id`, `search` prefix), `GET /api/v2/groups/{id}`, `GET /api/v2/users/{id}/groups` | `read:groups` |
| `DELETE /api/v2/groups/{id}` | `delete:groups` |
| `GET /api/v2/groups/{id}/members` | `read:group_members` |
| `GET`, `POST`, `DELETE /api/v2/groups/{id}/roles`; `GET`, `POST`, `DELETE /api/v2/roles/{id}/groups` | `read:`, `create:`, `delete:group_roles` |
| `GET /api/v2/users/{id}/effective-roles/sources/groups?role_id=` | `read:user_role_source_groups` |
| `GET /api/v2/organizations/{id}/groups` | `read:organization_groups` |
| `GET`, `POST`, `DELETE /api/v2/organizations/{id}/groups/{group_id}/roles` | `read:`, `create:`, `delete:organization_group_roles` |
| `GET /api/v2/organizations/{id}/members/{user_id}/effective-roles/sources/groups?role_id=` | `read:organization_member_role_source_groups` |

### Roles through groups

- **Tenant group roles** apply to every member in every token: the
  permissions of the role are in access tokens for APIs with RBAC, and the
  role is in `event.authorization.roles` and `api.roles` in Actions.
- **Organization group roles** apply only when the member logs in to that
  organization, and only to groups of connections enabled on it (400
  otherwise). An organization member's effective roles list them with the
  source `group`; tenant group roles are not organization roles.
- SCIM cannot assign roles: only an operator's group-role assignment does.
- Assignment changes reach newly issued tokens; existing access tokens stay
  valid until they expire.

In Actions, `api.groups.getUserGroups({take, from})` pages the user's
groups and `api.groups.hasGroupMembership(groups)` is true when the user
belongs to any group listed by name or ID.

## Deploy CLI

The Deploy CLI exports a connection's configuration as `scim_configuration`
(`user_id_attribute` and `mapping`) and creates or updates it on import.
Tokens are never exported.

## Testing

`make e2e-scim` runs the production server with throwaway secrets: the
pinned node-auth0 SDK configures SCIM, issues and revokes tokens and manages
groups and group roles; an RFC 7644 client provisions users and groups with
the payload shapes Entra ID and Okta send; the server log is checked for
every issued token; then the pinned Deploy CLI round-trips
`scim_configuration` in four cells.
