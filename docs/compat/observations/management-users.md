# Management API: users, sessions, refresh tokens, grants, tickets, jobs

- **Observed:** 2026-10-19
- **Docs:**
  - https://auth0.com/docs/api/management/v2/users/get-users, `post-users`, `get-users-by-id`, `patch-users-by-id`, `delete-users-by-id`
  - https://auth0.com/docs/api/management/v2/users-by-email/get-users-by-email
  - https://auth0.com/docs/api/management/v2/users/post-identities, `delete-user-identity-by-user-id`
  - https://auth0.com/docs/api/management/v2/users/get-sessions-for-user, `delete-sessions-for-user`, `get-refresh-tokens-for-user`, `delete-refresh-tokens-for-user`
  - https://auth0.com/docs/api/management/v2/sessions/get-session, `delete-session`; `refresh-tokens/get-refresh-token`, `delete-refresh-token`
  - https://auth0.com/docs/api/management/v2/grants/get-grants, `delete-grants-by-id`, `delete-grants-by-user-id`
  - https://auth0.com/docs/api/management/v2/tickets/post-password-change, `post-email-verification`
  - https://auth0.com/docs/api/management/v2/jobs/post-users-imports, `post-users-exports`, `post-verification-email`, `get-jobs-by-id`, `get-errors`
  - https://auth0.com/docs/manage-users/user-search/user-search-query-syntax
- **Method** (CLEAN_ROOM.md "Behavior testing against the maintainer's own tenant"):
  - **Tenant:** one of the maintainer's non-live tenants.
  - **Caller:** the observer M2M client (`client_credentials`) for the Management API. Logins used a temporary first-party regular web application and a temporary API with offline access: the password-realm grant for refresh tokens, and a scripted Chromium through hosted login for sessions and grants.
  - **Recorded:** statuses, `errorCode` values, field names, defaults, limits and page outcomes. Messages were read only to interpret a result, except where a message is the observable behaviour (search errors, ticket redirect parameters).
  - **Clean-up:** every test user, the temporary application and the temporary API were deleted; no grant for the API remains.
  - **Not observable here:** the client-credentials grant ignored a narrowed `scope` parameter, so the `read/update:users_app_metadata` split was not observed (see "Scopes").

## User shape (U1)

A database user created with only `connection`, `email` and `password` returns `201` with: `user_id` (`auth0|` and 24 lowercase hex characters), `created_at`, `updated_at` (ISO 8601 with milliseconds), `email` (stored lowercase), `email_verified: false`, `identities: [{connection, user_id, provider: "auth0", isSocial: false}]`, `name` (= the email), `nickname` (= the email's local part), `picture`.
- **`picture` default:** `https://s.gravatar.com/avatar/<md5 of the lowercased email>?s=480&r=pg&d=` and the URL-encoded `https://cdn.auth0.com/avatars/<xx>.png`, where `<xx>` is two lowercase letters: the initials of `name` when it has two words ("Bea Obs" → `bo`), otherwise its first two letters (an email-like name `obs-…@…` → `ob`).
- **`name`** stays the email even when `given_name` and `family_name` are given.
- **Absent until set:** `blocked` (present only once set, `true` or `false`), `given_name`, `family_name`, `user_metadata`, `app_metadata`, `username`. `last_login`, `last_ip` and `logins_count` appear after the first login.
- `user_metadata: {}` is returned as `{}` once it has been emptied.
- **`last_password_reset`** appears in the primary identity's `profileData` in the link/unlink responses after a password change.

## Create (U2)

- `connection` missing: `400 invalid_body` ("Missing required property: connection").
- Bad email: `400 invalid_body`. Unknown top-level property: `400 invalid_body` (the message suggests the metadata fields).
- Duplicate email in the connection: **`409`, `errorCode: auth0_idp_error`**, message "The user already exists."
- Weak password: `400` with **no `errorCode`**, message `PasswordStrengthError: Password is too weak`.
- `username` on a connection without `requires_username`: `400 operation_not_supported`.
- `phone_number` on a connection without flexible identifiers: `400 invalid_body` ("not allowed").
- **Supplied `user_id`:** pattern `^\S*$`, at most 255 characters (`400 invalid_body` otherwise). It is always prefixed with `auth0|`, even when it already starts with `auth0|` (`auth0|x` becomes `auth0|auth0|x`, identity `user_id` `auth0|x`).
- `email_verified: true` with `verify_email: true` is accepted; the user is created verified. `blocked`, `nickname`, `picture`, `given_name`, `family_name`, `name` are taken as sent.
- Mixed-case email input is stored lowercase.

## Update (U3)

- **Metadata merge:** top-level keys merge; a key set to `null` is deleted; a nested object is **replaced whole** (`{new:{a:1}}` then `{new:{b:2}}` gives `{new:{b:2}}`). **Sending `{}` empties the object.** The same rules hold for `app_metadata`.
- **Email change** sets `email_verified: false` unless the body sets it. No `connection` was needed for a single-identity database user.
- `email` and `password` together: `400 operation_not_supported` ("Cannot update password and email simultaneously"), even with `connection`.
- `username` on a connection without usernames: `400 operation_not_supported`. Unknown property: `400 invalid_body`.
- **Password change through `PATCH` revokes nothing:** an existing refresh token kept working and stayed listed.
- **`blocked: true` revokes nothing**, but the refresh grant and the password grant answer `invalid_grant` "user is blocked" while blocked. The refresh token stays listed and works again after unblocking.

## Search (U4)

`GET /users?q=…&search_engine=v3`. Omitting `search_engine` behaves as `v3`; `v2` is accepted and behaves the same; `v1` is `400 operation_not_supported`; any other value is `400 invalid_query_string`.

- **Case:** matching on root profile fields is case-insensitive (`email:OBS-…` matches). Metadata string values match **case-sensitively** (`app_metadata.plan:PRO` does not match `pro`).
- **Exact by default:** a term matches the whole value (`name:bea` does not match "Bea Obs"; `name:"bea obs"` does).
- **Bare terms** (no field) match the whole value, case-insensitively, of `name`, `given_name`, `family_name` or `nickname`, or the email's local part or domain (`example.com` matched every user at that domain; `p17` matched nothing; a `user_id` part matched nothing).
- **Juxtaposition** (`a:x b:y`) is `OR`. `AND`, `OR`, `NOT`, a leading `-` (as `NOT`) and parentheses work. A group value `email:(x OR y)` works.
- **`NOT` and missing fields:** `NOT family_name:X` (and `NOT given_name:X`) excludes users who have no `family_name`. `NOT app_metadata.k:X`, `NOT blocked:true` and `NOT logins_count:N` include users without the field (absent `blocked` counts as `false`, absent `logins_count` as `0`).
- **Wildcards:** `*` works as a trailing (`email:o*`, one character before it was enough), a leading (`email:*p17-a@example.com`, `name:*obs`) or a bare (`*`, `email:*`) wildcard. Inside quotes it is literal (`email:"obs*"` matches nothing). On metadata fields a wildcard is `400`: "invalid query: operator 'wildcard' is not supported on field 'user_metadata.color'".
- **Ranges:** `[a TO b]`, `{a TO b]`, `[a TO *]` and `field:>N` work on `logins_count`, `created_at`, `updated_at`, `last_login`. Dates accept `2026-10-19` and `2026-10-19T21:22:30`. On metadata fields a range is `400`: "invalid query: operator 'greater or equal' is not supported on field '…'".
- **Typed values:** `logins_count:abc` matched users with no logins (treated as 0); `email_verified:maybe` matched unverified users (treated as false).
- **Metadata:** `app_metadata.k:v` and `user_metadata.k:v` match a string, a boolean (`true`/`false`) or a number written bare (`tier:2` matches the number 2, `tier:"2"` matches the string "2"), an element of an array (`lst:a`, `nums:5`) and nested keys (`obj.k:v`). `_exists_:` works on them. `app_metadata:pro` (no key) is `400` ("operator 'equals' requires a key on field 'app_metadata'").
- **Other fields:** `user_id:"auth0|x"` and `user_id:auth0\|x`; `identities.connection`, `identities.provider`, `identities.user_id`; `email_verified`, `blocked`, `last_ip:*`, `username`, `phone_number`, `phone_verified` are searchable.
- **Errors:** an unknown field is `400`: "invalid query: field 'bogus_field' is not searchable". Unbalanced quotes or parentheses, an empty value (`email:`) or a dangling operator give `400` "invalid query: undefined"; a lone `AND` gives "invalid query: 'AND' requires at least one operand on each side". **These search errors carry no `errorCode`.**
- **Sort:** `sort` must match `^(([a-zA-Z0-9_\.]+))\:(1|-1)$` (`400 invalid_query_string` otherwise). Known root fields sort (users without the value come first ascending, last descending). An unknown field or a metadata field is accepted and ignored.
- **Default order** (no `sort`): by `last_login` descending, users who never logged in last.
- **Paging:** `per_page` at most 100 (`400 invalid_query_string`). `(page + 1) × per_page` above 1000 is `400 invalid_paging` ("You can only page through the first 1000 records…"); `page=999&per_page=1` is allowed and empty here. `include_totals=true` returns `{start, limit, length, total, users}`.
- **`fields` with `include_fields=false`** returns everything else.

## Users by email (U5)

`GET /users-by-email?email=` is **case-sensitive**: an uppercase variant of a stored (lowercase) email returns `[]`. Unknown email: `200 []`. Missing or malformed `email`: `400 invalid_query_string`. `fields` works.

## Tickets (U6)

- **Password change:** `201 {"ticket": "https://<tenant host>/u/reset-verify?ticket=<32 letters and digits>#"}`. Forms: `user_id`, or `email` with `connection_id` (`email` alone: "Missing required property: connection_id"; an empty body: "Missing required property: email"; both `400 invalid_body`). Unknown `user_id`: `404 inexistent_user`. **`result_url` with `client_id`** is `400 invalid_body`. `ttl_sec` below 0 is `400 invalid_body`; very large values were accepted; the reference's default is 432000 (5 days) when absent or 0.
- Opening the link redirects to the password form (`/u/reset-password/change?state=…`). After the change the page shows a success message; **no redirect to `result_url` happened and no link to it was shown** (waited 11 s). `mark_email_as_verified: true` set `email_verified`. Reopening a used link shows "Invalid Link" (already used); an unknown ticket shows "Link Expired".
- **Email verification:** `201 {"ticket": "https://<tenant host>/u/email-verification?ticket=<…>#"}`. Opening the link **verifies immediately** (no button). With `result_url` it redirects to `result_url` with these query parameters appended to the existing ones:
  - success: `supportSignUp=true&supportForgotPassword=true&email=<email>&message=Your email was verified. You can continue using the application.&success=true&code=success`;
  - reused link: `email=<email>&message=This URL can be used only once&success=false`;
  - already verified (new ticket): `supportSignUp=true&supportForgotPassword=true&message=This account is already verified.&success=false&code=already-verified`.
  - `email` appears only with `includeEmailInRedirect: true`.
- Without `result_url`: a page "Email Verified / Your email address was successfully verified."; a reused or unknown ticket shows "Error / Your email address could not be verified."; already verified shows "Error / This account is already verified."
- Unknown `user_id`: `404 inexistent_user`. `identity` (`{user_id, provider}`) is accepted. Unknown property: `400 invalid_body`.

## Linking (U7)

- `POST /users/{primary}/identities` with `{provider: "auth0", user_id: "<secondary's id without the prefix>"}` (no `connection_id` needed for a database user) returns **`201`** with the primary's identities. In that response each identity carries `profileData`: the primary's (`email`, `email_verified`, `last_password_reset`), the secondary's (`email`, `email_verified`). `GET` of the primary then shows `profileData` only on the secondary identity.
- **The secondary user stops existing** (`GET` is `404 inexistent_user`; email search no longer finds it; `identities.user_id:<secondary>` finds the primary). Its given/family name and metadata are not kept in `profileData`.
- **Logging in with the secondary's credentials yields the primary user** (`sub` of the primary, the primary's email).
- **Errors:** linking an identity already linked is `409 identity_conflict`; linking the primary to itself is `400 operation_not_supported`; an unknown secondary is `400` with no `errorCode`; a missing `user_id` is `400 invalid_body`; another provider with an unknown user is `400 invalid_body`.
- **`link_with`:** an ID token whose `aud` is not the calling client's ID is `400 invalid_body` ("invalid aud claim"); a malformed token is `400 invalid_body`.
- **Unlink** `DELETE /users/{primary}/identities/auth0/{secondary id}` returns `200` with the remaining identities. **The secondary comes back as a new user** with the same `user_id`, `created_at` = the unlink time, and only `email` and `email_verified` (from its `profileData`), default `name` and `nickname`, no `picture`, metadata or names; `logins_count` restarts. Its password still works. Unlinking an identity that is not linked returns `200` with the identities (no error). Removing the primary identity is `400 delete_main_user_identity`.

## Sessions and refresh tokens (U8)

- **Session object:** `id` (32 characters, letters, digits, `-`, `_`), `user_id`, `created_at`, `updated_at`, `authenticated_at`, `authentication: {methods: [{name: "pwd", timestamp}]}`, `idle_expires_at`, `expires_at`, `device: {initial_user_agent, initial_ip, initial_asn, last_user_agent, last_ip, last_asn}`, `clients: [{client_id}]`, `last_interacted_at`, `cookie: {mode: "persistent"}`.
- **Refresh-token object:** `id` (`dcr_` and 16 letters and digits), `user_id`, `created_at`, `idle_expires_at` and `expires_at` (`null` for non-expiring), `client_id`, `session_id` (`null` for the password grant, set for the code flow), `rotating`, `resource_servers: [{audience, scopes: "<space-separated, including openid profile email address phone>"}]`, `device` as for sessions, `last_exchanged_at` (`null` until used).
- **Lists:** `GET /users/{id}/sessions` → `{sessions, next}`, `GET /users/{id}/refresh-tokens` → `{tokens, next}`, **newest first**, checkpoint paging only: `take` 1–100 (default 50), `from` = the opaque `next`. `next` is present whenever the page is non-empty (also on the last page); an empty list has no `next`. `page`/`per_page`/`include_totals` are ignored. A bad `from` is `400 invalid_query_string`.
- **Unknown user** on these list and delete endpoints: `404 inexistent_user`. **Unknown session or token ID:** `404` with no `errorCode` ("The session does not exist." / "The refresh token does not exist."); a malformed ID is also that `404`.
- **Deletes:** `DELETE /sessions/{id}`, `DELETE /refresh-tokens/{id}`, `DELETE /users/{id}/sessions`, `DELETE /users/{id}/refresh-tokens` all return **`202 {}`**, also when nothing was there. A deleted refresh token gives `invalid_grant` "Unknown or invalid refresh token.".
- **Deleting a user's sessions did not revoke** a refresh token issued in one of them (it still refreshed and stayed listed).

## Grants (U9)

- After a first-party code-flow login against an API with `skip_consent_for_verifiable_first_party_clients: true` and a verifiable (https) callback, **no screen was shown and a user grant was stored**. With the default (`false`), the consent screen was shown and the grant was stored on accept.
- Grant object: `{id (24 hex), clientID, user_id, audience, scope: [sorted, including openid profile offline_access]}`. Note the field name **`clientID`**.
- `GET /grants` filters `user_id`, `client_id`, `audience` (an unknown user is `200 []`); `include_totals=true` gives `{total, start, limit, grants}`.
- Plan 9's reading is confirmed: zeroauthy already stores the grant in this case.

## Import jobs (U10, for Plan 18)

- `POST /jobs/users-imports` (multipart `users`, `connection_id`, `upsert`, `send_completion_email`) → **`202`** `{type: "users_import", status: "pending", connection_id, connection, created_at, id}`. Job IDs: `job_` and 16 letters and digits (`^job_[A-Za-z0-9]{16}$`; anything else is `400 invalid_uri`).
- Completed job: `summary: {failed, updated, inserted, total}`.
- `GET /jobs/{id}/errors` → `[{user: <the record, password_hash masked as "*****">, errors: [{code, message, path?}]}]`; `204` with no body when there are none. Observed codes: `PATTERN` (a `password_hash` that is not bcrypt: `^\$2[ab]?\$10+\$[./A-Za-z0-9]{53}$`, path `passwordHash`), `INVALID_FORMAT` (bad email, path `identities[0].profileData.email`), `DUPLICATED_USER` ("The user already exist and upsert parameter is false", no path).
- An unknown top-level field in a record was ignored (the user was inserted).
- File size and concurrent-job limits were not observed; use the reference values.

## Export jobs (U11, for Plan 18)

- `POST /jobs/users-exports` → **`200`** (not 201) with the job, echoing `connection_id`, `connection`, `format`, `fields`, `limit` when given. Without `connection_id`, every connection is exported.
- Completed job has `location`: a pre-signed object-storage URL, **valid 60 seconds**, to `<job id>/<tenant>.<json|csv>.gz`.
- **JSON:** gzipped newline-delimited objects; keys are the field names (or `export_as`); fields without a value are left out.
- **CSV:** gzipped; without `fields`, the columns are `user_id,email,name,family_name,given_name,phone_number,nickname,username,last_ip,logins_count,created_at,updated_at,deleted_at,last_login,blocked,deleted,email_verified,phone_verified,identities.[0].connection`. String values are quoted and **prefixed with `'`** (formula-injection guard); numbers, booleans and dates are bare; empty values are empty.
- `GET /jobs/{id}/errors` of an export: `204`.
- `POST /jobs/verification-email` → `201 {type: "verification_email", status: "pending", created_at, id}`.

## Delete (U12)

- `DELETE /users/{id}` → **`204`**, and `204` again for an ID already deleted. The user's refresh tokens stop working (`invalid_grant`), its grants are gone, and its tokens are `404` by ID.
- A malformed user ID (not `provider|id`) on any `/users/{id}` path is `400 invalid_uri`; a well-formed unknown ID is `404 inexistent_user`.

## Defaults with a machine login (O1)

With the client-credentials caller: a new API has `skip_consent_for_verifiable_first_party_clients: false` (the consent screen was shown to a first-party application) and `subject_type_authorization` `{user: allow_all, client: require_client_grant}`, as observed with a user login in Plan 9.

## Scopes

Not observed (see Method). The reference lists `read:users` for reads and `update:users` and `update:users_app_metadata` for `PATCH`.
