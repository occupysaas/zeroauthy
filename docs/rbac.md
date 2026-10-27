# Roles and permissions

Roles collect API permissions and can be assigned to users. Users may also
receive permissions directly. Enable RBAC on a custom API to make new user
access tokens reflect those assignments.

In the console, define the API's permissions first, then create a role under
User Management → Roles and assign its permissions and users. User detail has
Roles and Permissions tabs. A permission inherited from a role is removed by
changing the role or membership; deleting a direct assignment leaves inherited
sources in place.

## Scope and permissions claims

For an API with RBAC enabled, the access token's `scope` contains requested API
permissions that the user owns, subject to application access and consent.
Protocol scopes such as `openid` and `offline_access` keep their existing rules.
With RBAC disabled, requested defined API scopes follow the existing application
policy without user-role filtering.

The optional `permissions` array contains all the user's currently assigned
permissions for that audience, including permissions the application did not
request. APIs must deliberately choose which claim to use. Middleware checking
`scope` does not treat entries in `permissions` as granted scopes.

| API token dialect | Protected type | Client ID claim | Permissions |
|---|---|---|---|
| `access_token` | `JWT` | `azp` | omitted |
| `access_token_authz` | `JWT` | `azp` | included when RBAC enabled |
| `rfc9068_profile` | `at+jwt` | `client_id` | omitted |
| `rfc9068_profile_authz` | `at+jwt` | `client_id` | included when RBAC enabled |

RFC profiles omit `gty`. All profiles retain a unique `jti` and use the existing
RS256 managed keys. ID tokens and `/userinfo` do not gain permissions or role
claims. Machine-to-machine scope authorization continues to use client grants;
it never consults user assignments. System and Management APIs retain their
existing authorization boundaries and settings restrictions.

## Assignment changes and refresh

New token issuance reads one consistent snapshot of API configuration and
assignments. Permission changes made before that snapshot affect issuance;
an issuance already using an earlier snapshot may finish. Existing JWTs remain
valid until expiry.

Refresh families retain the original scope ceiling after client/consent checks
and before RBAC filtering. If an application originally requested `read:x write:x`
but the user owned only `read:x`, assigning `write:x` later can make it available
on refresh. A permission outside the original ceiling never expands refresh
scope. Revoking and restoring an original permission removes and restores it
on subsequent refreshes. The optional permissions array still represents current
assignments, including those outside the scope ceiling.

Deleting a role removes its memberships and grants. Deleting an API permission
removes both role and direct assignments; recreating the permission does not
restore them. API, user, connection and tenant deletion clean up affected
assignments. Linking accounts retains primary-account privileges and discards
the deleted secondary account's assignments. Unlinking does not copy privileges.

## API and tools

Use `/api/v2/roles`, role detail, role permissions and role users to manage
roles. Use `/api/v2/users/{id}/roles` to add/remove memberships and
`/api/v2/users/{id}/permissions` to read effective permissions or change direct
assignments. Permission keys contain `resource_server_identifier` and
`permission_name`. Assignment batches validate and commit together; failed
batches do not partially apply.

Membership endpoints require all documented scopes together. For example,
listing role members requires `read:users`, `read:roles` and `read:role_members`.
An existing restricted client grant does not automatically receive new scopes
when the server's Management API inventory is upgraded.

Deploy CLI supports role definitions and role permissions with API RBAC fields.
User assignments remain separate management operations. Seed role definitions follow the existing create-only policy. For example:

```yaml
tenants:
  - name: example
    roles:
      - name: Reader
        description: Reads reports
        permissions:
          - resource_server_identifier: https://reports.example.test
            permission_name: read:reports
```

Define that custom API and scope under the same tenant before applying roles.
Restarting with a seed does not overwrite later management edits. User
assignments are managed separately through the API or console.

## Storage upgrades and compatibility

Apply the additive Plan 26 SQL migration before serving with the new binary.
Legacy API settings retain RBAC disabled and the default token format. Upgrade
all server and storage-plugin writers before enabling RBAC. Old plugins fail
the versioned capability check at startup; mixed old/new writers are unsupported.
Lookup, transport and capability failures do not fall back to permissive tokens.

Tenant roles and direct user assignments are supported. Group inheritance,
organization roles, the Authorization Extension, Actions-provided custom claims
and new signing algorithms are outside this release. Local compatibility
choices and public-source evidence are recorded in
[roles-permissions observations](compat/observations/roles-permissions.md).
