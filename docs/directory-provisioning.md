# Google Workspace connections and directory provisioning

A `google-apps` connection signs in the accounts of one Google Workspace and
can synchronize that Workspace's users and groups into zeroauthy, as Auth0's
Google Workspace connection with directory provisioning does (D-0150
LR37c-14…16). Storage plugins need `scim.v1` version 3; without it the
directory provisioning routes answer 501.

## The connection

Create an OAuth client of type *Web application* in the Google Cloud
console of the Workspace and register both redirect URIs:

- `https://{host}/login/callback` (sign-in)
- `https://{host}/directory-provisioning/callback` (the administrator
  consent below)

for every host of the tenant (canonical host and custom domains). Then:

```sh
curl -X POST https://$TENANT/api/v2/connections \
  -H "authorization: Bearer $MGMT_TOKEN" -H 'content-type: application/json' \
  -d '{"name":"workspace","strategy":"google-apps","enabled_clients":["'$CLIENT_ID'"],
       "options":{"client_id":"…apps.googleusercontent.com","client_secret":"…",
                  "domain":"example.com","api_enable_groups":true}}'
```

- `domain` is the Workspace's primary domain. A login succeeds only when the
  verified ID token's `hd` claim equals it and the email is verified;
  personal Google accounts and accounts of other Workspaces are refused,
  whatever their email address. `tenant_domain`, when sent, must equal
  `domain`. `domain_aliases` feed home realm discovery.
- `user_id` is `google-apps|{email}` (lowercase), Auth0's default, or
  `google-apps|{Google user ID}` with `map_user_id_to_id: true`, which
  survives email changes. `domain` and `map_user_id_to_id` cannot change.
- `client_secret` is write-only and stored sealed.
- `api_enable_users` (default true) and `api_enable_groups` (default false)
  allow directory provisioning of users and groups.
- `ext_*` flags are stored and returned but not applied at login.
  `allow_setting_login_scopes` and `handle_login_from_social` must be false.
  Auth0's `admin_access_token`, `admin_refresh_token` and
  `admin_access_token_expiresin` are refused: remove them from Deploy CLI
  exports; zeroauthy obtains its own grant (below).

In the console: **Authentication → Enterprise → Create → Google Workspace**.

## Directory provisioning

1. Create the configuration:

   ```sh
   curl -X POST https://$TENANT/api/v2/connections/$CONN/directory-provisioning \
     -H "authorization: Bearer $MGMT_TOKEN" -H 'content-type: application/json' \
     -d '{"synchronize_automatically":true,"synchronize_groups":"selected"}'
   ```

   `mapping` defaults to `GET …/directory-provisioning/default-mapping`:
   `email`←`primaryEmail`, `name`←`name.fullName`, `given_name`←`name.givenName`,
   `family_name`←`name.familyName`, `picture`←`thumbnailPhotoUrl`. `idp`
   paths address the [Directory API user resource](https://developers.google.com/admin-sdk/directory/reference/rest/v1/users)
   with the SCIM path syntax (`organizations[primary eq true].department`);
   `auth0` names a root profile field or `app_metadata.*`/`user_metadata.*`.
   Group synchronization (`all` or `selected`) needs `api_enable_groups`.

2. Authorize directory access. In the console's **Provisioning** tab choose
   **Authorize directory access**, or call the system API as an operator of
   the tenant:

   ```sh
   curl -X POST https://$SYSTEM_HOST/api/system/tenants/$TENANT_NAME/connections/$CONN/directory-provisioning/consent \
     -H "authorization: Bearer $OPERATOR_TOKEN"
   # {"url":"https://login.example.com/directory-provisioning/consent?ticket=…", …}
   ```

   Send the link (valid 15 minutes; treat it as a secret) to a Google
   Workspace administrator. Google asks them to allow read-only access to
   users (and groups). zeroauthy keeps the refresh token, sealed to the
   tenant and connection, only after a Directory API call shows the account
   can read the directory, then schedules a synchronization. Consent again
   whenever a synchronization reports that the grant was revoked.

3. Synchronizations run on demand (`POST …/synchronizations`, 409 while one
   is pending or running) and about every 40 minutes with
   `synchronize_automatically`. Each run:

   - lists the domain's users and creates or updates them with the mapping
     (`email_verified` is true for Workspace addresses);
   - blocks suspended, archived and removed users, ends their sessions,
     revokes their refresh tokens and sends back-channel logout; a user
     blocked by synchronization is unblocked when active again, but a block
     an administrator set in zeroauthy stays;
   - with `synchronize_groups`, mirrors all or the selected groups (by
     Google group ID, `…/synchronized-groups`) as directory groups of the
     connection with their user members, and deletes the connection's
     groups that are no longer selected or present. Group roles
     ([SCIM](scim.md#groups)) then flow into tokens;
   - records `last_synchronization_at`, `_status` (`success` or `failed`)
     and `_error`, which never contains a token.

   A later login through the connection signs the synchronized user in.

Deleting the configuration deletes the grant and the group selection;
synchronized users and groups stay.

## Scopes

| Routes | Scope |
|---|---|
| `GET` configuration, default mapping, synchronized groups, `/connections-directory-provisionings` | `read:directory_provisionings` |
| `POST` configuration, synchronizations | `create:directory_provisionings` |
| `PATCH` configuration, synchronized groups (`POST`, `PUT`, `DELETE`) | `update:directory_provisionings` |
| `DELETE` configuration | `delete:directory_provisionings` |

## Testing

Coverage uses a fixture Google (token endpoint, JWKS and Directory API;
maintainer ruling 2026-11-22): `go test ./internal/dirsync ./internal/federation ./internal/login`
and the Management contract tests in `internal/server`. A live Workspace
check is an observation point (Q18).

## Not supported

Login-time extended attributes (`ext_*`), Google Workspace in the
self-service assistant (Q19), push notifications from Google (zeroauthy
polls), and service-account (domain-wide delegation) credentials.
