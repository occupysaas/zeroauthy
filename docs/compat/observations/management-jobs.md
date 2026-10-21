# Management API: jobs (import, export, verification email)

- **Observed:** 2026-10-20
- **Docs:**
  - https://auth0.com/docs/api/management/v2/jobs/post-users-imports, `post-users-exports`, `post-verification-email`, `get-jobs-by-id`, `get-errors`
  - https://auth0.com/docs/manage-users/user-migration/bulk-user-imports
  - https://auth0.com/docs/manage-users/user-migration/bulk-user-import-database-schema-and-examples
  - https://auth0.com/docs/manage-users/user-migration/bulk-user-exports
- **Method** (CLEAN_ROOM.md "Behavior testing against the maintainer's own tenant"):
  - **Tenant:** one of the maintainer's non-live tenants, through the observer M2M application.
  - **Setup:** a throwaway database connection, a second one enabled for no application, a custom-database connection with import mode off, and a throwaway regular web application allowed the password-realm grant. All four were deleted afterwards, which also deleted every imported user.
  - **Hashes:** generated locally (Python `hashlib`, the `argon2` CLI, Go `x/crypto/bcrypt`), never taken from Auth0's examples.
  - **Pacing:** about one request per second.
- Extends `management-users.md` (U10, U11). Where they differ, this note is newer. Auth0's error messages are recorded because zeroauthy returns them on the wire.

## Creating an import (J1)

Each check answers `400` with the `errorCode` shown:

| Request | errorCode | message |
|---|---|---|
| no `users` part | `invalid_body` | `Must provide 'users' file as multipart part.` |
| no `connection_id` part | `invalid_body` | `Must provide 'connection_id' as multipart part.` |
| empty file | `operation_not_supported` | `Users file must not be empty.` |
| malformed `connection_id` | `invalid_body` | `Payload validation error: 'String does not match pattern ^con_[A-Za-z0-9]{16}$' on property connection_id.` |
| unknown connection | `inexistent_connection` | `The connection does not exist.` |
| not a database connection | `operation_not_supported` | `Connection must be a database connection.` |
| enabled for no application | `connection_is_disabled` | `Connection must be enabled.` |
| custom database, import mode off | `operation_not_supported` | `Custom Database Connections without import mode are not allowed.` |

- **Size:** the limit applies to the whole request body, multipart framing included. A request of exactly 512000 bytes is accepted. Anything larger gets `413` with no `errorCode`: `{statusCode: 413, error: "Request Entity Too Large", message: "Payload content length greater than maximum allowed: 512000"}`.
- **Loose fields:** an `upsert` value that is not a boolean (`"maybe"`) and an unknown form field were both accepted (`202`).
- **`external_id`:** echoed in the `202` response and in every later `GET`.

## Malformed files (J2)

Every malformed file is accepted at create (`202`). The job then fails:
- Not JSON, a UTF-8 BOM before the array, or NDJSON: `status: "failed"`, `status_details: "Failed to parse users file JSON when importing users. Make sure it is valid JSON."`.
- A JSON object instead of an array: `status_details: "The users file must provide an array of users to upload using JSON format."`.
- A failed job has no `summary`.
- `[]`: `completed`, with every summary count at 0.
- An array of non-objects (`[1, "x", null]`): `completed` with `failed: 3`. Each error is `{user: <the raw value>, errors: [{code: "INVALID_TYPE", message: "Expected type object but found type integer"}]}` (`string`, `null` likewise), with no `path`.

## Concurrency and progress (J3)

- **Concurrency:** a third import while two are still active gets `429` with no `errorCode`: `{statusCode: 429, error: "Too Many Requests", message: "There are 2 active import users jobs, please wait until some of them are finished and try again"}`.
- **Progress:** while a 4000-user import runs (several minutes), its `GET` still says `status: "pending"`, with no `percentage_done` and no `time_left_seconds`.
- **Completion email:** could not be observed (it goes to the tenant owners' inbox). The reference's default is `true`.

## Upsert and record rules (J4)

- **Matching:** `upsert: true` matches existing users by email.
- **Changed:** `name`, `family_name` and `email_verified` change. `user_metadata` and `app_metadata` are replaced whole, not merged.
- **Absent fields:** a field left out of the record (`given_name`) keeps its old value.
- **Ignored on an existing user:** `blocked: true` (the user stays unblocked), `user_id`, and `password_hash`. The old password still works, and the record still counts as `updated`.
- **`custom_password_hash`:** replaced on a user who never signed in (the new password works, the old one fails). On a user who has signed in, the record fails with `CONFLICT`: `A custom_password_hash was provided, but the user already has password hash defined.`
- **`upsert: false`** on an existing user: `DUPLICATED_USER`, `The user already exist and upsert parameter is false`, no `path`.
- **`user_id` in a record:** `custom-id-123` becomes `auth0|custom-id-123`, and the identity's `user_id` is `custom-id-123`.
- **Empty metadata:** imported users show `user_metadata: {}`.

## Record errors (J5)

The echoed `user` masks `password_hash`, `custom_password_hash.hash.value` and `custom_password_hash.salt.value` as `*****`.

| Record | code | message | path |
|---|---|---|---|
| unknown `algorithm` | `ENUM_MISMATCH` | `Error in custom_password_hash.algorithm property - No enum match for: foo` | `custom_password_hash.algorithm` |
| wrong `hash.encoding` for the algorithm (sha256 + utf8, bcrypt + hex); ldap `{CRYPT}`; bcrypt value not starting `$2` | `ONE_OF_MISSING` | (empty) | `custom_password_hash` |
| scrypt without `keylen` | `OBJECT_MISSING_REQUIRED_PROPERTY` | `Missing required property: keylen` | `custom_password_hash` |
| `salt` on argon2, pbkdf2 or ldap | `OBJECT_ADDITIONAL_PROPERTIES` | `Additional properties not allowed: salt` | `custom_password_hash` |
| hmac without `hash.key` | `OBJECT_MISSING_REQUIRED_PROPERTY` | `Missing required property: key` | `custom_password_hash.hash` |
| both `password_hash` and `custom_password_hash` | `NOT_PASSED` | `Forbidden attribute in appUser: ` | none |
| `password_hash` with cost 12 | `PATTERN` | `Error in passwordHash property - String does not match pattern ^\$2[ab]?\$10+\$[./A-Za-z0-9]{53}$: <the hash, unmasked>` | `passwordHash` |
| reserved `app_metadata.blocked` | `NOT_PASSED` | `Forbidden attribute in app_metadata: blocked` | `blocked` |
| second record with the same email | `NON_UNIQUE_PROPERTY_VALUE` | `Property "email" has non-unique value: <email>` | none |
| second record with the same `user_id` | `DUPLICATED_USER` | `A user with this [email\|phone_number\|username\|user_id] was already provided.` | none |
| bad email | `INVALID_FORMAT` | `Error in identities[0].profileData.email property - Object didn't pass validation for format email: not-an-email` | `identities[0].profileData.email` |
| no email | `OBJECT_MISSING_REQUIRED_PROPERTY` | `Missing required property: email` | none |

- **Duplicates:** the first of two records with the same email is inserted.
- **Accepted and inserted:** an ldap `{CLEARTEXT}` value, an argon2 value that is not a valid PHC string (`$argon2id$garbage`), and `mfa_factors` (J7).

## Signing in after import (J6)

- **Working formats:** users imported with bcrypt (`password_hash`), PBKDF2-SHA256 (PHC), salted SHA-256 (hex, salt prefix), argon2id, and unsalted MD5 all sign in with the password-realm grant. The MD5 password (`abc`) is one the connection's password policy would refuse.
- **Unusable hashes:** the `{CLEARTEXT}` user and the user with the broken argon2 value get `403 invalid_grant`, `Password change required.`, whatever password is sent.
- **No hash:** a user imported without one gets `Wrong email or password.`.
- **After sign-in:** the user's `GET` shows no hash field, and `logins_count` is 1.

## mfa_factors (J7)

A `totp` factor was accepted. The user then shows `multifactor` and `multifactor_last_modified`, so the enrollment was stored, even though the tenant does not use MFA.

## Export (J8)

- **Body checks** (each `400 invalid_body`):
  - `limit: 0`: `Payload validation error: 'Value 0 is less than minimum 1' on property limit (Limit the number of records).`
  - 31 fields: `Payload validation error: 'Array is too long (31), maximum 30' on property fields (List of fields to be included in the CSV. Defaults to a predefined set of fields).`
  - `format: "xml"`: `Payload validation error: 'Invalid value "xml"' on property format (Format of the file. Must be `json` or `csv`).`
  - an unknown property: `Payload validation error: 'Additional properties not allowed: foo'.`
- **Defaults:**
  - **`limit`:** not 5. An export without `limit` wrote every user (about 8000). `limit: 1000000000` was accepted and echoed.
  - **Empty body:** `{}` → `200`, `format: "csv"`, every connection.
- **Field names:**
  - **Unknown names:** accepted. CSV writes an empty column, JSON leaves the key out.
  - **`password_hash`:** accepted as a field name. The JSON rows are `{}`, so it is never exported.
  - **Whole `user_metadata` in CSV:** accepted, and the column is empty.
- **CSV values:**
  - **Header:** `export_as` where given, else the field name.
  - **Numbers and booleans:** written bare (`5`, `true`).
  - **Object and array subfields:** written as empty values.
  - **Strings:** quoted, inner `"` doubled, and a leading `'` added. That includes a value starting with `=`, and values with commas or newlines.
  - **Auth0's dates:** written bare.
- **JSON values:**
  - **Default keys:** without `fields`, the keys are those of the default field set that have a value (`user_id`, `email`, `name`, `nickname`, `created_at`, `updated_at`, `email_verified`, `identities.[0].connection`, …). Metadata is not included.
  - **With `fields`:** the key is `export_as` or the dotted name (`"user_metadata.obj": {"x": 1}`). Whole `user_metadata` for a user without metadata is `{}`, and `identities` is the full array including `profileData`.
- **Row order:** no particular order (not by `user_id`).

## Download links and job reads (J9)

- **`location`:** a pre-signed object-storage URL to `<job id>/<tenant>.<json|csv>.gz`.
- **Fresh link per read:** every `GET /jobs/{id}` of a completed export returns a new `location`.
- **Expiry:** after 65 seconds the earlier link answers `403` (`Request has expired`, `X-Amz-Expires` 60).
- **Unknown job:** a well-formed unknown job ID is `404 inexistent_job`, `The job does not exist`.
- **Malformed job ID:** `400 invalid_uri`, `Path validation error: 'String does not match pattern ^job_[A-Za-z0-9]{16}$: job_x' on property id (ID of the job).`
- **24-hour expiry:** not waited for. The docs say job data is deleted after 24 hours, so zeroauthy answers `404 inexistent_job` then.
- **`GET /jobs/{id}/errors`:**
  - a completed import without errors: `200 []` (this corrects U10's "204 when none");
  - a completed export: `204` with no body;
  - a failed job (import or verification email): `200` with the job object itself.

## Verification email (J10)

- **Success:** `201 {type: "verification_email", status: "pending", created_at, id}`. The answer is the same for an unverified user, an already verified one, a request with the primary `identity`, and one with the application's `client_id`.
- **Errors:**

| Request | errorCode | message |
|---|---|---|
| unknown user | `inexistent_user` | `The user does not exist` |
| `user_id: ""` | `invalid_body` | `Payload validation error: 'Object didn't pass validation for format user-id: ' on property user_id (user_id of the user to send the verification email to).` |
| no `user_id` | `invalid_body` | `Payload validation error: 'Missing required property: user_id'.` |
| identity not on the user | `inexistent_identity` | `The user exists, but does not contain the given identity` |
| unknown property | `invalid_body` | `Payload validation error: 'Additional properties not allowed: foo'.` |
| unknown `client_id` | `inexistent_client` | `The client does not exist` |

- **On this tenant (no email provider):** the job later reads `failed` with no `status_details`.

## Side observation

`PATCH /connections/{id}` with `enabled_clients` is now refused on this tenant (`400 invalid_body`, `Additional properties not allowed: enabled_clients`). `PATCH /connections/{id}/clients` works (`204`). This is the 2026-01-21 changelog deprecation, now enforced. It is a follow-up for the connections API.
