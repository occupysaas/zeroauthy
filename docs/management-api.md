# Management API

Every zeroauthy tenant serves Auth0's Management API v2 at
`https://<tenant host>/api/v2/`, on each of its hosts. Slices 1 to 3 cover
**applications** (`/api/v2/clients`), **APIs** (`/api/v2/resource-servers`),
**client grants** (`/api/v2/client-grants`) and **database connections**
(`/api/v2/connections`). Slice 4 adds **users**, sessions, refresh tokens,
grants and tickets. Plan 19 adds tenant settings and attack protection (design
`docs/superpowers/specs/2026-10-18-zeroauthy-management-design.md`).

The contract is [api/management.yaml](../api/management.yaml). Behaviour
that Auth0 does not document comes from observation of Auth0's API
([observations/management-clients.md](compat/observations/management-clients.md),
[observations/management-apis.md](compat/observations/management-apis.md),
[observations/management-connections.md](compat/observations/management-connections.md),
[observations/management-users.md](compat/observations/management-users.md))
and is recorded in decisions D-0038 to D-0043 of
[compat/decisions.md](compat/decisions.md).

## Tokens

Two kinds of bearer token are accepted.

**Machine-to-machine clients of the tenant** (as on Auth0). A client
credentials token whose audience is the tenant's **Management API
identifier**:

- `https://<name>.<server.base_domain>/api/v2/`, or
- without a base domain, `https://<first of the tenant's domains>/api/v2/`.

The identifier stays the same whichever of the tenant's hosts receives the
request. Each tenant has a system API, "zeroauthy Management API", for that
identifier with Auth0's scope names. The client needs a client grant for it.
In a seed file:

```yaml
tenants:
  - name: acme
    domains: [login.acme.example]
    clients:
      - client_id: deploy-bot
        app_type: non_interactive
        client_secret: <at least a long random string>
        grant_types: [client_credentials]
    client_grants:
      - client_id: deploy-bot
        audience: "https://login.acme.example/api/v2/"
        scopes: [read:clients, create:clients, update:clients, delete:clients, read:client_keys, update:client_keys]
```

```bash
curl https://login.acme.example/oauth/token \
  -d grant_type=client_credentials -d client_id=deploy-bot -d client_secret=… \
  -d audience=https://login.acme.example/api/v2/
```

**Console operators.** An access token from the `system` tenant for the
audience `urn:zeroauthy:management`, issued to the console. Operators hold
every scope on every tenant they manage (all tenants for now). This is the
only token one tenant accepts from another. See [console.md](console.md).

The `system` tenant has no machine-to-machine Management API: only
operators manage it.

## Scopes

| Operation | Scope |
|---|---|
| `GET /api/v2/clients`, `GET /api/v2/clients/{id}` | `read:clients`; `client_secret` is included only with `read:client_keys` |
| `POST /api/v2/clients` | `create:clients` |
| `PATCH /api/v2/clients/{id}` | `update:clients`; setting `client_secret` needs `update:client_keys` |
| `DELETE /api/v2/clients/{id}` | `delete:clients` |
| `POST /api/v2/clients/{id}/rotate-secret` | `update:client_keys` |
| `GET /api/v2/resource-servers`, `GET /api/v2/resource-servers/{id}` | `read:resource_servers` |
| `POST /api/v2/resource-servers` | `create:resource_servers` |
| `PATCH /api/v2/resource-servers/{id}` | `update:resource_servers` |
| `DELETE /api/v2/resource-servers/{id}` | `delete:resource_servers` |
| `GET /api/v2/client-grants`, `GET /api/v2/client-grants/{id}` | `read:client_grants` |
| `POST /api/v2/client-grants` | `create:client_grants` |
| `PATCH /api/v2/client-grants/{id}` | `update:client_grants` |
| `DELETE /api/v2/client-grants/{id}` | `delete:client_grants` |
| `GET /api/v2/connections`, `GET /api/v2/connections/{id}`, `GET /api/v2/connections/{id}/clients` | `read:connections` |
| `POST /api/v2/connections` | `create:connections` |
| `PATCH /api/v2/connections/{id}`, `PATCH /api/v2/connections/{id}/clients` | `update:connections` |
| `DELETE /api/v2/connections/{id}` | `delete:connections` |
| `GET /api/v2/users`, `GET /api/v2/users-by-email`, `GET /api/v2/users/{id}` | `read:users`; `app_metadata` is included with `read:users` or `read:users_app_metadata` |
| `POST /api/v2/users` | `create:users`; `app_metadata` in the body also needs `create:users_app_metadata` or `update:users_app_metadata` |
| `PATCH /api/v2/users/{id}` | `update:users` or `update:users_app_metadata`; changing anything but `app_metadata` needs `update:users`, and writing `app_metadata` needs `update:users_app_metadata` |
| `DELETE /api/v2/users/{id}` | `delete:users` |
| `POST /api/v2/users/{id}/identities`, `DELETE /api/v2/users/{id}/identities/{provider}/{user_id}` | `update:users` |
| `GET /api/v2/users/{id}/sessions`, `GET /api/v2/sessions/{id}` | `read:sessions` |
| `DELETE /api/v2/users/{id}/sessions`, `DELETE /api/v2/sessions/{id}` | `delete:sessions` |
| `GET /api/v2/users/{id}/refresh-tokens`, `GET /api/v2/refresh-tokens/{id}` | `read:refresh_tokens` |
| `DELETE /api/v2/users/{id}/refresh-tokens`, `DELETE /api/v2/refresh-tokens/{id}` | `delete:refresh_tokens` |
| `GET /api/v2/grants` | `read:grants` |
| `DELETE /api/v2/grants`, `DELETE /api/v2/grants/{id}` | `delete:grants` |
| `POST /api/v2/tickets/password-change`, `POST /api/v2/tickets/email-verification` | `create:user_tickets` |
| `POST /api/v2/jobs/users-imports` | `create:users` |
| `POST /api/v2/jobs/users-exports` | `read:users` |
| `POST /api/v2/jobs/verification-email` | `update:users` |
| `GET /api/v2/jobs/{id}`, `GET /api/v2/jobs/{id}/errors` | `create:users` or `read:users` |

## Shared behaviour

- **Errors** have Auth0's shape: `{"statusCode": 400, "error": "Bad Request", "message": "…", "errorCode": "invalid_body"}`. `401` (`invalid_token`) for a missing, invalid, expired or foreign token; `403` (`insufficient_scope`) for a missing scope; `404` (`inexistent_client`) for an unknown application.
- **Pagination:** `page` (from 0), `per_page` (1 to 100, default 50) and `include_totals`. Without totals the response is a bare array; with them `{"clients": […], "start": …, "limit": …, "total": …}`. Applications are listed in creation order.
- **Projection:** `fields` (comma-separated) with `include_fields` (`true` to keep only those, `false` to leave them out). `tenant` is always returned.
- **CORS** allows only the console's origin (the system host).
- Every write is logged with its actor (client ID or operator user ID).

## Applications

Fields: `client_id`, `tenant`, `name`, `app_type`, `is_first_party`,
`third_party_security_mode`, `oidc_conformant` (always `true`),
`callbacks`, `allowed_logout_urls`, `web_origins`, `allowed_origins`,
`grant_types`, `token_endpoint_auth_method`, `client_secret`,
`jwt_configuration` (`alg` RS256, `lifetime_in_seconds`), `refresh_token`
(`rotation_type`, `expiration_type`, `leeway`, `token_lifetime`,
`idle_token_lifetime`, `infinite_*`), `redirection_policy`,
`skip_non_verifiable_callback_uri_confirmation_prompt`,
`require_pushed_authorization_requests`, `created_at`.

- **Create defaults:** `app_type` `regular_web`; `token_endpoint_auth_method` `none` for `spa` and `native`, `client_secret_post` otherwise; `grant_types` `authorization_code` and `refresh_token`, plus `client_credentials` for confidential clients; rotating, expiring refresh tokens for `spa`. The console sends defaults per type instead.
- **Secrets** are generated with 64 characters, or supplied (at least 48). They are encrypted under the master key (D-0038) and returned only with `read:client_keys`. Secrets stored before D-0038 keep working but cannot be shown: rotate them to get one you can see. Public clients (`none`) have no secret.
- **Rotation** replaces the secret at once; the old one stops working immediately.
- **Fixed after creation:** `is_first_party` and `third_party_security_mode`.
- **Organizations** (D-0055): `organization_usage` (`deny`, `allow`, `require`), `organization_require_behavior` (`no_prompt`, `pre_login_prompt`, `post_login_prompt`) and `organization_discovery_methods` (`email`, `organization_name`; only with `pre_login_prompt`) are stored and reported once set; null unsets them. A `require` application cannot hold the `password`, password-realm or device grants, whichever is set first (`400`). A storage plugin without Organizations refuses a usage other than `deny` (`501 organizations_unavailable`).
- **Unknown fields** are refused (`invalid_body`), except those Auth0's tools always send, which are accepted and ignored (`description`, `client_metadata`, `logo_uri` and others; D-0039).
- **Deleting** an application deletes its client grants, user consents and refresh tokens and removes it from every connection; sign-in sessions stay. Deleting an unknown ID answers `204`, as on Auth0.
- **The seed** never touches applications created through the API, even if it names the same client ID.

`auth0-cli` works unchanged: `auth0 apps create/list/show --reveal-secrets/update/delete` and `auth0 api get clients`, logged in with client credentials (`AUTH0_CLI_AUTH_MODE=env`, `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`) against a tenant served on port 443.

## APIs (resource servers)

An API is a service whose access tokens zeroauthy issues. Its `identifier`
becomes the `aud` of those tokens and is the `audience` clients ask for.

Fields: `id`, `name`, `identifier`, `scopes` (`value`, `description`),
`signing_alg` (`RS256`), `token_lifetime` (seconds, 1 to 2592000, default
86400), `token_lifetime_for_web` (default 7200, at most `token_lifetime`),
`allow_offline_access`, `skip_consent_for_verifiable_first_party_clients`,
`subject_type_authorization` (`client` and `user` policies, defaults
`require_client_grant` and `allow_all`), `enforce_policies` (`false`),
`token_dialect` (`access_token`), `is_system`. `GET /api/v2/resource-servers/{id}`
also accepts the URL-encoded identifier in place of the ID, which is what
auth0-cli sends. Listing takes `identifiers` (repeated), `page`, `per_page`
and `include_totals` (key `resource_servers`), in creation order, system APIs
first.

- **The identifier is fixed** after creation, and compared case-sensitively
  (1 to 600 characters). A duplicate is `409 resource_server_conflict`.
- **Scopes:** `PATCH` replaces the whole list; values are unique, 1 to 280
  characters, descriptions at most 500. Removing a scope removes it from every
  client grant that carries it. Users' consents that name it are left as they
  are (see the follow-ups).
- **Deleting** an API deletes its client grants, the users' consents for it and
  the refresh tokens issued for it. Access tokens already issued stay valid
  until they expire. `204`, also for an unknown ID.
- **System APIs** (`is_system: true`): each tenant's "zeroauthy Management
  API", and `urn:zeroauthy:management` on the system tenant. They can be read
  and granted, never deleted (`400 delete_system_resource_server`), and their
  name, scopes and the settings zeroauthy relies on cannot change; naming a
  setting with its current value is accepted, since `auth0-deploy-cli` sends
  back what it read. The tenant's Management API identifier cannot be used
  for a new API (`400 reserved_identifier`).
- **Seed:** the seed never touches APIs created through the API.

Differences from Auth0 (D-0041):

- **Signing is RS256 only.** `HS256`, `PS256` and `signing_secret` are
  `400 invalid_body`.
- **Inert-only fields.** `token_lifetime_for_web` is stored and reported but
  used by nothing (no implicit or hybrid flow). `enforce_policies` accepts only
  `false` and `token_dialect` only `access_token`, since there are no roles or
  permissions to enforce and no other token formats. `consent_policy`,
  `proof_of_possession` and `token_encryption` accept only `null`, and
  `authorization_details` only `null` or an empty list; none of them is
  reported.
- **IDs** of APIs created through the API are 24 hexadecimal characters.

## Client grants

A client grant authorizes an application to request tokens for an API with a
set of scopes. Fields: `id` (`cgr_` and 16 letters and digits), `client_id`,
`audience`, `scope`, `allow_all_scopes`, `subject_type` (`client` by default,
or `user`).

- **One grant** per application, audience and subject type
  (`409 client_grant_conflict`). `client_id`, `audience` and `subject_type`
  cannot be changed; `scope` can.
- **Scopes are checked on create as well as on update.** A scope the API does
  not define is `400 invalid_body`. Auth0 accepts it on create and refuses it on
  update; zeroauthy refuses both, so no grant names a scope its API lacks.
- **`allow_all_scopes: true`** grants every scope the API defines at the time a
  token is issued, so scopes added later are covered and removed ones are not.
  It does not go with `scope`. A response then has the flag and no `scope`.
- **Management API grants.** The audience may only be the caller's own
  Management API identifier (`subject_type` client, Management API scopes only).
  `urn:zeroauthy:management` and another tenant's identifier are
  `400 invalid_body`. An ordinary API that happens to have an identifier of that
  form is granted like any other.
- **Organizations and rich authorization** do not exist: `organization_usage`
  accepts `deny` or null, `allow_any_organization` false or null,
  `authorization_details_types` an empty list or null and `default_for` null.
- **Listing** filters on `client_id`, `audience` and `subject_type` (the last
  needs another filter). Offset paging as for applications (key
  `client_grants`), or **checkpoint paging**: `take` (1 to 100, default 50) and
  `from` give `{"client_grants": […], "next": "…"}`, with `next` absent on the
  last page. Pass `next` back as `from`. The cursor names the last grant ID, so
  grants added or removed between pages neither repeat nor skip others. With
  `take` or `from`, `page`, `per_page` and `include_totals` are ignored. Grants
  are listed in ID order.
- **Deleting** a grant is `204`, also for an unknown ID of the right form.
  Deleting an application or an API deletes its grants.
- **The seed** never touches grants created through the API.

## Database connections

A connection is a way for users to sign in. zeroauthy has one kind, the
database connection (strategy `auth0`): users with passwords stored by
zeroauthy, or users checked by a custom database script. Other strategies are
`400 invalid_body` until a later slice. Decision D-0042. The scopes `read:connections_options` and `update:connections_options` are accepted in tokens but no operation requires them; the connection routes use `read:connections` and `update:connections`.

Fields: `id` (`con_` and 16 letters and digits), `name`, `strategy`, `options`,
`realms`, `is_domain_connection`, `display_name`, `metadata`. `enabled_clients`
is accepted on create and is not part of a `GET`; use the clients endpoint.

- **Names** are letters, digits and hyphens (no leading or trailing hyphen,
  at most 128 characters); a used name is `409 connection_conflict`. A
  well-formed unknown ID is `404 inexistent_connection`, a malformed one
  `400 invalid_uri`.
- **Listing** is ordered by name, ignoring case. Filters: `name`, `strategy`
  (repeatable). `fields` and `include_fields` work as elsewhere, and always
  keep `id` and `is_domain_connection`. Offset paging (key `connections`,
  `per_page` default 100) or checkpoint paging with `take` and `from`.
- **`options` is replaced whole on `PATCH`.** Keys inside `password_options`
  that you leave out take their defaults. Option keys zeroauthy does not know
  are stored and returned as sent.
- **Enabled applications:** `GET /api/v2/connections/{id}/clients` lists
  `{"clients": [{"client_id": …}], "next": …}` (checkpoint paging);
  `PATCH` takes a non-empty `[{"client_id", "status"}]` and answers `204`.
  Only enabled applications can sign in with the connection.
- **Deleting** answers `202` with `{"deleted_at": …}`, and `204` once it is
  gone, also for an ID that never existed (inferred from APIs and client
  grants; not observed for connections). The connection's users go with it,
  with their sessions, refresh tokens, grants and password history, and the
  tenant's `default_directory` is cleared when it names the connection.

### Password rules

Stored as `options.password_options`. Defaults for a connection created
through the API: minimum length 15, no required character types, identical
and sequential characters allowed, passwords over the maximum refused, history
off (size 3), dictionary off (`en_100k`), personal data off, and
`brute_force_protection` on.

| Rule | Behaviour |
|---|---|
| `complexity` | `min_length`; `character_types` (lower case, upper case, numbers, special characters) with `character_type_rule` `all` or `three_of_four`; `identical_characters` and `sequential_characters` `allow` or `block`; `max_length_exceeded` `truncate` or `error` (passwords are at most 72 characters) |
| `history` | Refuses a password equal to one of the user's newest 1 to 24 (`size`) |
| `dictionary` | Refuses (ignoring case) a word of the list (`en_10k` or `en_100k`, embedded) or of your own `custom` words |
| `profile_data` | Refuses a password that contains the user's own email, name or similar fields (`blocked_fields`; values under 3 characters are ignored) |

The legacy fields (`passwordPolicy`, `password_complexity_options`,
`password_history`, `password_dictionary`, `password_no_personal_info`) are
accepted and mapped onto `password_options`; sending both is `400 invalid_body`.
Responses carry `password_options`. The `passwordPolicy` levels map as `none`
(1 character), `low` (6), `fair` (8 with lower, upper and numbers), `good` (8,
three of four types) and `excellent` (10, no three identical in a row, all
four types); this table is not verified against Auth0's runtime. Legacy
`min_length` above 72 is refused, since passwords are at most 72 characters.

- **Where the rules apply:** sign-up and password reset (and the console's
  password checker, which mirrors them except for the embedded lists). The dictionary and history rules were not
  observable on Auth0's side (D-0042); zeroauthy's behaviour is the one
  described above.
- **`max_length_exceeded`:** with `truncate` the password is cut to 72
  characters before hashing. Switching to `error` later locks out users who
  still type a longer password; they need a reset.
- **`brute_force_protection`** switches zeroauthy's login throttle for this
  connection only; thresholds follow the tenant attack-protection policy
  ([guide](attack-protection.md)). Other protections remain independent.
- **Usernames:** `validation.username` `min` and `max` (1 to 128, `min` below
  `max`), with `requires_username`.
- **Seeded connections** keep the seed's own rules (minimum length 8), not the
  API defaults and not the API-only checks (name pattern, 72-character cap).

### Custom databases

`options.enabledDatabaseCustomization`, `customScripts` (keys: the seven
script names), `import_mode` (needs customization), `configuration` and
`set_user_root_attributes` (only for a custom database that is not imported).
Scripts are limited as in D-0022 (Auth0 accepts larger ones).

- **Configuration** values are strings or `null`. They are sealed at rest and
  returned as opaque `zcv1.` blobs, never as plaintext; send a blob back
  unchanged to keep the value, anything else is a new value. A plaintext value
  that itself starts with `zcv1.` is refused.
- **`set_user_root_attributes`:** `never_on_login` is stored and returned but
  behaves as `on_each_login`; only `on_first_login` changes behaviour.

### Trying a script (zeroauthy extension)

`POST /api/system/tenants/{tenant}/connections/{id}/scripts/{name}/try`, for
operator tokens on the system host (not the Management API; Auth0 has no
equivalent). Body `{"args": […]}` with the script's arguments; the answer is
`{"result", "error": {"name", "message"}, "logs", "duration_ms"}`. Ten tries
per minute per operator (`429`). Arguments and results are not written to the
log.

- **Masking:** configuration values are replaced with `■■■■■■■■` in the
  response's result, console lines and error message, and in the server log's
  script console lines and script error messages. A process masks every value
  it has seen for the connection, so a rotated value stays masked until a
  restart. Masking is exact, case-sensitive substring matching: a script that
  encodes, splits or reformats a secret is not covered. A value cut at the
  runner's limits (2048 characters of a console line, 1024 of an error message)
  is still masked, and a long line may be masked more than needed. Real logins
  and sign-ups return script output to the user unmasked.
- **Timeouts:** the console output is lost when a script times out (`logs` is
  empty).

### Stored, not enforced

Accepted, returned and marked "saved, not enforced yet" in the console, but
without effect: `authentication_methods`, `passkey_options`, `attributes`,
`precedence`, `mfa`, `disable_self_service_change_password`,
`non_persistent_attrs`, `display_name`, `show_as_button`, `metadata`, `realms`
beyond the default, `connected_accounts`, `authentication`, unknown option
keys, and `never_on_login`.

### With auth0-cli

Verified with 1.37.0 (m15-mgmt-cli): `auth0 connections create --name staff
--strategy auth0`, `list`, `show`, `update --data …`, `delete`, and
`auth0 connections enabled-clients show|update`. Then users sign up through
`/dbconnections/signup` on the new connection, with the rules applied.

## Users

Users of the tenant's database connections. Decision D-0043; the search
language has its own guide, [user-search.md](user-search.md). The
`GET /api/v2/users/{id}` shape is the one the hosted login and `/userinfo`
agree on: `user_id` (`auth0|` and 24 hex characters), `email`,
`email_verified`, `name`, `nickname`, `picture` (a Gravatar URL), `identities`,
`user_metadata`, `app_metadata`, `created_at`, `updated_at`, and after the
first login `last_login`, `last_ip` and `logins_count`. `blocked`, names and
metadata are absent until set; `blocked: false` is never shown (D-0043).

- **List and search:** `GET /api/v2/users` takes `q` (v3 syntax), `sort`
  (`field:1` or `field:-1`), `connection`, `fields`/`include_fields` and
  offset paging (`page`, `per_page` 1 to 100, default 50, `include_totals` for
  `{start, limit, length, total, users}`). Only the first 1000 results can be
  reached; beyond that is `400 invalid_paging`. Without `sort`, users are
  ordered by `last_login` descending, never-logged-in users last. Search sees
  every write at once (Auth0's index lags).
- **By email:** `GET /api/v2/users-by-email?email=` matches the stored
  (lowercase) address exactly; `fields` and `include_fields` work.
- **Create:** `connection` is required and the connection's rules apply as
  for sign-up: a duplicate is `409 auth0_idp_error`,
  a password the policy refuses is `400` without an `errorCode`, an unknown
  connection `400 inexistent_connection`. A supplied `user_id` is always
  prefixed `auth0|`. An unverified email gets the verification email unless
  `verify_email` is `false`. On a custom database connection that is not in
  import mode the `create` script runs first (script failures: `400
  auth0_idp_error`, `409` for `user_exists`, `503 script_runtime_unavailable`).
- **Update:** `PATCH` merges `user_metadata` and `app_metadata` at the top
  level (`null` removes a key, nested objects are replaced, `{}` empties). An
  email change clears `email_verified` unless the body sets it, and deletes
  the user's open verification and unused password-change tickets. Email
  together with `password` in one request, and username or phone on a
  connection without them, are `400 operation_not_supported`. Neither a
  password change nor `blocked: true` ends sessions or refresh tokens (a
  blocked user's refresh and password grants are refused).
- **Delete:** `204`, also for an unknown well-formed ID. It deletes the
  user's sessions, refresh tokens, grants, tickets and password history.
- **Errors:** an ID that is not `provider|id` is `400 invalid_uri`, an unknown
  user `404 inexistent_user`.

### Linking identities

`POST /api/v2/users/{id}/identities` links a secondary account to the primary
`{id}`, named by `provider` and `user_id` (with an optional `connection_id`)
or by `link_with`, an ID token this tenant issued to the calling client. The
secondary stops existing as a user; its identity (with its password) moves to
the primary and logging in with it yields the primary. Its sessions, refresh
tokens and grants are deleted. The answer is `201` with the primary's
identities. `DELETE …/identities/{provider}/{user_id}` unlinks: the secondary is
recreated from the identity's `profileData` only (email, verification and
username), with a new `created_at` and no names, picture or metadata.
Unlinking an identity that is not linked is `200`.

### Sessions, refresh tokens and grants

- `GET /api/v2/users/{id}/sessions` and `…/refresh-tokens` list newest first by
  **checkpoint paging only** (`take` 1 to 100, default 50; `from` the previous
  page's `next`, which is present on every non-empty page). `page`, `per_page`
  and `include_totals` are ignored. `GET /api/v2/sessions/{id}` and
  `/api/v2/refresh-tokens/{id}` read one (`404` without an `errorCode` when
  unknown).
- Every delete answers `202 {}`. Deleting a user's sessions leaves their
  refresh tokens alone, and deleting one refresh token revokes its whole
  rotation family.
- `GET /api/v2/grants` lists the consents users gave (`user_id`, `client_id`,
  `audience` filters; offset paging, `include_totals` answers
  `{grants, start, limit, total}`). Each has `clientID` (sic, as on Auth0) and a
  sorted `scope` array. `DELETE /api/v2/grants?user_id=` deletes a user's
  grants and `DELETE /api/v2/grants/{id}` one grant; both answer `204`.

### Tickets

`POST /api/v2/tickets/password-change` and `…/email-verification` answer `201`
with `{"ticket": "https://<tenant host>/u/reset-verify?ticket=…#"}` (and
`/u/email-verification?ticket=…#`), valid for `ttl_sec` seconds (432000 by
default). A verification ticket is consumed when the link is opened and then
redirects with `success`, `code`, `message` and the other parameters of the
documented redirect; it is bound to the email it was issued for. The
password-change success page does not redirect to `result_url`, as on Auth0's
current pages. See D-0043 for the choices Auth0 does not document.

### Jobs

`POST /api/v2/jobs/users-imports` (`create:users`) takes a multipart JSON file
and connection ID and returns `202`. `POST /api/v2/jobs/users-exports`
(`read:users`) takes format, optional connection, fields and limit and returns
`200`. See [the import/export guide](user-import.md) for hash examples,
upsert rules, limits, errors and download links. Completed imports report a
summary and masked per-record errors; completed exports supply a signed
`location` valid for 60 seconds. Read the job again for a fresh link.


`POST /api/v2/jobs/verification-email` checks the request at once (unknown
user, identity or application, no email address) and answers `201` with a
`pending` job; a worker sends the email. `GET /api/v2/jobs/{id}` reads the
job: a running job still reads `pending`, with no progress, as on Auth0.
`GET /api/v2/jobs/{id}/errors` answers `204` for a verification job and the
job itself when it failed. Jobs are kept for 24 hours. `jobs.workers`
(default 2; 0 turns the workers off on that process) and `jobs.lease`
(default 60s) configure the workers; several processes may share a database.

## A machine-to-machine application without the seed

Everything below runs against a tenant with a Management API token that holds
the scopes `create:resource_servers`, `create:clients`, `create:client_grants`
and `read:client_keys` (an operator token has them all). Set `MGMT` to the
token and `HOST` to the tenant host.

```bash
# 1. The API.
curl -sS -X POST https://$HOST/api/v2/resource-servers \
  -H "Authorization: Bearer $MGMT" -H 'Content-Type: application/json' \
  -d '{"name":"Orders","identifier":"https://orders.example/api",
       "scopes":[{"value":"read:orders","description":"Read orders"}]}'

# 2. The machine-to-machine application; the response has client_id and client_secret.
curl -sS -X POST https://$HOST/api/v2/clients \
  -H "Authorization: Bearer $MGMT" -H 'Content-Type: application/json' \
  -d '{"name":"Orders worker","app_type":"non_interactive"}'

# 3. The grant.
curl -sS -X POST https://$HOST/api/v2/client-grants \
  -H "Authorization: Bearer $MGMT" -H 'Content-Type: application/json' \
  -d '{"client_id":"CLIENT_ID","audience":"https://orders.example/api","scope":["read:orders"]}'

# 4. A token.
curl -sS https://$HOST/oauth/token \
  -d grant_type=client_credentials -d client_id=CLIENT_ID -d client_secret=CLIENT_SECRET \
  -d audience=https://orders.example/api
```

With auth0-cli, logged in as a machine-to-machine client of the tenant
(`AUTH0_CLI_AUTH_MODE=env`, `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`,
`AUTH0_CLIENT_SECRET`; the tenant on port 443):

```bash
auth0 apis create --name Orders --identifier https://orders.example/api \
  --scopes read:orders --json
auth0 apps create --name "Orders worker" --type m2m --reveal-secrets --json
auth0 api post client-grants --data \
  '{"client_id":"CLIENT_ID","audience":"https://orders.example/api","scope":["read:orders"]}'
curl -sS https://$HOST/oauth/token -d grant_type=client_credentials \
  -d client_id=CLIENT_ID -d client_secret=CLIENT_SECRET -d audience=https://orders.example/api
```

Also working: `auth0 apis list/show/update/delete`, `auth0 apis scopes list`,
and `auth0 api get/patch/delete client-grants[/{id}]`. The console does all
of this too: see [console.md](console.md).

## The system API

zeroauthy's own API for the console, at `/api/system/` on the system host,
for operator tokens only (D-0040). Auth0 has no equivalent.

| Operation | What it does |
|---|---|
| `GET /api/system/tenants` | Every tenant, with its canonical `host`, `management_api_identifier`, `domains`, `seeded` and `reserved` (the system tenant) |
| `POST /api/system/tenants` | `{"name", "friendly_name", "domains"}`. Names are DNS labels (63 characters at most); `system` is reserved. A new tenant gets signing keys, the database connection `Username-Password-Authentication` and its Management API. Without a base domain it needs a domain |
| `PATCH /api/system/tenants/{name}` | Friendly name and domains |
| `DELETE /api/system/tenants/{name}?confirm={name}` | Deletes the tenant and all of its data |
| `GET /api/system/tenants/{name}/jobs` | Tenant job list, newest first, with `page`, `per_page` and `include_totals`; operators only |
| `GET /api/system/operators` | The operators |
| `POST /api/system/operators` | `{"email"}`: invites an operator; the response's `setup_url` is a one-hour link to choose a password |
| `DELETE /api/system/operators/{user_id}` | Removes an operator and ends their sessions; never the last one |

The system tenant cannot be changed or deleted here. Tenants created through
this API are never touched by the seed.

## Signing keys and deploy migration (Plan 20)

Signing-key endpoints use `read:signing_keys`, `create:signing_keys`, and
`update:signing_keys`. Rotation retains eligible previous keys; custom public
JWKS remain stored-only and are not trusted by zeroauthy's token verifiers.
See [signing-keys.md](signing-keys.md) for the lifecycle and cache limits.

Offline credential-preserving bootstrap and Deploy CLI comparison commands are
in [deploy-cli.md](deploy-cli.md). The pinned CLI passes local YAML/directory round trips for clients, APIs,
grants and tenant settings in generated-ID and preserved-credential modes.
Three handlers have explicit tool-support limitations; upstream observations
remain unavailable.


## Tenant settings and attack protection (Plan 19)

[Tenant settings](tenant-settings.md) covers GET/PATCH settings, API hours and
minutes versus legacy seed seconds, runtime consumers and stored-only fields.
[Attack protection](attack-protection.md) covers all five GET/PATCH policy
resources, user-block and IP-anomaly reads/deletes, exact scopes, shared-store
requirements, encrypted credentials, unavailable-checker behavior and recovery.
Automatic blocks are separate from the user's administrative `blocked` flag.
The public responses contain neither internal receipts nor provider secrets.

## Custom domains

Nine scoped operations under `/api/v2/custom-domains` manage list/create,
read/PATCH/delete by ID, POST verify/test and GET/PATCH `default`. The literal
`default` route takes precedence over IDs. Pending creation does not activate
a host. First successful explicit self-managed Verify returns a one-time proxy
key; subsequent reads/verification never recover it. API fields are projected
from internal state; private certificate/account/proof-token data is omitted.
`origin_domain_name` is a proxy routing instruction, never the public issuer.

See the [operator guide](custom-domains.md), [wire inventory](../internal/customdomain/inventory.json)
and [compatibility evidence](compat/observations/custom-domains.md) for request
limits, supported queries, scopes, errors and local/unobserved differences.
Canonical API audiences remain stable across aliases; local Management API
tokens must carry the origin serving the request as issuer.

## Organizations and scoped operators (Plan 29)

[Organizations](organizations.md) covers CRUD/name lookup, enabled connections,
members, member-role/effective-role lists, role members and user organizations.
Scopes follow the inventory, including `read:organization_member_effective_roles`;
member listing accepts either members-read or member-roles-read, user organizations
accepts either users-read or organizations-read, and role members requires both
members-read and roles-read. Organization creation with `enabled_connections`
also requires connection-create scope, including an empty supplied array.

D-0055 observed corrections govern validation and replacement PATCH behavior.
The Early Access `connections` alias manages the same links for Deploy CLI;
organization-client-grants GET is empty until Plan 30 enables grants. Invitation,
discovery-domain, search and grant-write workflows remain deferred.

Local system-host `/api/system/operators/{id}` PATCH sets tenant grants.
`/api/console/tenants` discovers their signed/persisted intersection without
opening the system API to tenant-only operators. Last-system-admin protection
also covers deleting, blocking and linking the administrator's user identity.
These local endpoints have no Auth0 counterpart.
