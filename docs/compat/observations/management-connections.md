# Management API: database connections

- **Observed:** 2026-10-18
- **Docs:**
  - https://auth0.com/docs/api/management/v2/connections/get-connections
  - https://auth0.com/docs/api/management/v2/connections/post-connections
  - https://auth0.com/docs/api/management/v2/connections/patch-connections-by-id
  - https://auth0.com/docs/api/management/v2/connections/delete-connections-by-id
  - https://auth0.com/docs/api/management/v2/connections/get-connection-clients
  - https://auth0.com/docs/api/management/v2/connections/patch-clients
- **Method** (CLEAN_ROOM.md "Behavior testing against the maintainer's own tenant"):
  - **Tenant:** the maintainer's non-live development tenant.
  - **Caller:** an M2M client with the connection, user and tenant-settings scopes (`client_credentials`).
  - **Recorded:** statuses, `errorCode` values, field names, defaults and limits. Messages were read only to interpret a result.
  - **Clean-up:** every test connection was deleted (its test user went with it); the tenant's `default_directory`, absent before, is absent again.
  - **Entitlement:** this tenant's plan lacks the `password-advanced-options` entitlement, so enabling password history, the dictionary and the personal-data check was refused (`403 feature_not_entitled`). Their schema limits were still visible; their runtime behaviour was not observed.
- **Also read:** `auth0-cli` v1.37.0 (`internal/cli/connections.go`), `auth0-deploy-cli` 9.1.0 (`src/tools/auth0/handlers/databases.ts`, `connections.ts`), all MIT.

## Create defaults (C1)

`POST /api/v2/connections` with `name` and `strategy: auth0` returns `201` with:
- `id`: `con_` followed by 16 letters and digits.
- `is_domain_connection: false`, `enabled_clients: []`, `realms: [<name>]`, `authentication.active: true`, `connected_accounts.active: false`; no `display_name`.
- `options`:
  - `strategy_version: 2`, `brute_force_protection: true`, `mfa: {active: true, return_enroll_settings: true}`;
  - `authentication_methods`: `password` enabled (`api_behavior: required`, `signup_behavior: allow`), `passkey` disabled; `passkey_options`: `challenge_ui: both`, progressive and local enrollment enabled;
  - `password_options` (the current password model, below) with `complexity.min_length` **15**, `character_types: []`, `character_type_rule: all`, `identical_characters: allow`, `sequential_characters: allow`, `max_length_exceeded: error`; `history` inactive, size 3; `dictionary` inactive, `default: en_100k`, `custom: []`; `profile_data` inactive with blocked fields `name`, `username`, `nickname`, `email`, `phone_number`, `user_metadata.name`, `user_metadata.first`, `user_metadata.last`.

## Names and strategies (C2)

- **Name:** pattern `^[a-zA-Z0-9](-[a-zA-Z0-9]|[a-zA-Z0-9])*$` (letters and digits, single hyphens between them; no `_`, `.`, spaces, leading, trailing or double hyphens), at most 128 characters, case kept. Duplicate: `409 connection_conflict`.
- **Strategy:** an unknown value is `400 invalid_body`; `sms` without a phone provider is `400` (no `errorCode`).
- **Unknown top-level properties:** `400 invalid_body`. **Unknown keys inside `options`:** accepted, stored and returned as sent (objects and arrays included).

## Updates (C3)

- **`options` is replaced whole** by `PATCH`: keys not sent are dropped (a `PATCH` with one option removed the configuration, the scripts and `password_options`). Within `password_options`, parts not sent are filled with the defaults.
- `name`, `strategy` and `enabled_clients` are unknown properties on `PATCH` (`400 invalid_body`). An empty body is `400 invalid_body`.
- **`configuration`:** values are strings or `null`; the response returns each value as an opaque encrypted blob, never the plaintext. Sending a returned blob back keeps the stored secret unchanged; sending plaintext (even the same plaintext) stores a new blob. No key or value length limit was hit (a 300-character key, a 6000-character value).

## Password settings (C4)

- **Two models; never both:** the current `password_options` object (`complexity`, `history`, `dictionary`, `profile_data`) and the legacy fields (`passwordPolicy`, `password_complexity_options`, `password_history`, `password_dictionary`, `password_no_personal_info`). Sending both is `400 invalid_body`.
- **`password_options.complexity`:** `min_length` 1–72; `character_types` any of `uppercase`, `lowercase`, `number`, `special`; `character_type_rule` `all` or `three_of_four` (the latter only with all four types listed); `identical_characters` and `sequential_characters` `allow` or `block`; `max_length_exceeded` `error` or `truncate`.
- **`history.size`:** 1–24. **`dictionary.default`:** `en_10k` or `en_100k`. **`profile_data.blocked_fields`:** free strings.
- **Legacy:** `passwordPolicy` `none`, `low`, `fair`, `good` or `excellent`; `password_complexity_options.min_length` 1–128; `password_history.size` at most 24.

## Custom database and other options (C5, C6)

- **`customScripts`:** keys limited to the script names (`login`, `get_user`, `create`, `verify`, `change_password`, `delete`, `change_email`); others are `400 invalid_body`. No size limit was hit up to 1.1 MB.
- **`import_mode: true`** needs `enabledDatabaseCustomization: true` (`400`, no `errorCode`).
- **`set_user_root_attributes`:** allowed only on a custom database that uses the external store; otherwise `400 invalid_body`. Values are an enum (`on_each_login`, `on_first_login`, `never_on_login` per the docs).
- **`validation.username`:** `min` ≥ 1, `max` ≤ 128, `min` < `max`.
- **`precedence`:** at least 3 items from `email`, `username`, `phone_number`.
- **`attributes`:** accepted; the response fills `unique`, `profile_required`, `verification_method` and signup verification defaults. `auth0-deploy-cli` refuses `attributes` together with `requires_username` or `validation`, and an active email identifier with non-unique emails.
- **`brute_force_protection`:** a boolean on the connection (default `true`; a string was stored as `true`). Its thresholds are tenant-level attack protection.
- **Also accepted:** `disable_signup`, `disable_self_service_change_password`, `non_persistent_attrs`, `requires_username`.

## Enabled clients (C7)

- `GET /connections/{id}/clients` returns `{clients: [{client_id}]}`; it supports checkpoint paging (`take`, `from`; a bad `from` is `400 invalid_query_string`).
- `PATCH /connections/{id}/clients` takes a non-empty array of `{client_id, status}` (`status: true` enables, `false` disables) and returns `204`. An unknown client is `400 inexistent_client`; a malformed client ID `400 invalid_body`; an empty array `400 invalid_body`.
- `enabled_clients` is accepted on `POST` (and returned there), refused on `PATCH`, and absent from `GET /connections/{id}`. `auth0-deploy-cli` deletes it before create and sets clients through the endpoint above in chunks of 100.

## Listing (C8)

- **Order:** by name, case-insensitive.
- **Paging:** as D-0039 (`{total, start, limit, connections}` with totals; `per_page` 1–100, default 100), plus checkpoint paging (`take` returns `{connections, next}`).
- **Filters:** `name` (exact) and `strategy` (repeatable).
- **`fields=name`** also returns `id` and `is_domain_connection`.

## Deleting (C9, C10)

- `DELETE` returns `202` with `{deleted_at}`; the connection is gone at once (`GET` is `404`). A second `DELETE` is `204`.
- **The connection's users are deleted with it** (a user created on it was `404` right after).
- **The tenant's `default_directory`**, when it names the connection, is cleared.
- **IDs:** a malformed ID (not `con_` and 16 letters and digits) is `400 invalid_uri` on `GET` and `DELETE`; a well-formed unknown ID is `404 inexistent_connection` on `GET`.
- **`POST /users`** on a connection with no enabled client is `400 connection_is_disabled`.

## Tools (C11)

- **`auth0-cli` v1.37.0:** `connections create` sends `name` and `strategy` plus an optional raw `--data` body; `enabled-clients show/update` use the `/clients` endpoint (go-auth0 v3).
- **`auth0-deploy-cli` 9.1.0:** databases are matched by `name`, then `id`; `strategy` and `name` are stripped on update; an update first reads the current connection and merges the options it sends into it (consistent with `PATCH` replacing `options`); `enabled_clients` goes through the `/clients` endpoint.

## Dictionary sources (C12)

Permissively licensed lists for the two dictionary sizes: SecLists (MIT, github.com/danielmiessler/SecLists, commit 60e43f4) `Passwords/Common-Credentials/10k-most-common.txt` for `en_10k`, and `Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt` for `en_100k` (the UK NCSC list, under its own licence, to be recorded in NOTICE when it is vendored).
