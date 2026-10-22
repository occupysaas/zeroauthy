# User import and export

Import existing database users through **Users → Import and export** in the
console or `POST /api/v2/jobs/users-imports`. Password hashes are accepted in
Auth0's import format. The first successful sign-in replaces the imported
hash with zeroauthy's native argon2id hash, without enforcing a new password
policy or adding a password-history entry. A password change or reset also
replaces the imported hash. Hashes never appear in user reads or exports.

## File and request

The file is a JSON array of user objects. Each needs `email`; optional fields
are `email_verified`, `phone_number`, `phone_verified`, `user_id`, `username`,
`given_name`, `family_name`, `name`, `nickname`, `picture`, `blocked`,
`password_hash`, `custom_password_hash`, `app_metadata`, `user_metadata` and
`mfa_factors`. Unknown top-level fields are ignored. MFA factors are accepted
but ignored until MFA is implemented. Reserved application-metadata names
(such as `email`, `identities`, `blocked` and `__tenant`) are refused.

Use only one of `password_hash` and `custom_password_hash`. `password_hash`
accepts bcrypt at cost 10 with the observed Auth0 prefix/pattern; use
`custom_password_hash` for other bcrypt costs or variants. With neither
field, the user has no password and must choose one through reset.

```bash
curl -sS "https://$HOST/api/v2/jobs/users-imports" \
  -H "Authorization: Bearer $MGMT" \
  -F connection_id="$CONNECTION_ID" -F upsert=false \
  -F send_completion_email=false -F users=@users.json
```

This needs `create:users` and returns `202` with a job ID. The connection
must be a database connection enabled for at least one application. Custom
databases must use import mode; their scripts are not called for bulk import.
The whole multipart request, including framing, must fit within **512000
bytes**. Split larger files; no more than two imports can be active per tenant.
An empty file is refused synchronously. Malformed JSON is accepted as a job
which then fails, so always read the final job status.

```bash
curl -sS "https://$HOST/api/v2/jobs/$JOB_ID" -H "Authorization: Bearer $MGMT"
curl -sS "https://$HOST/api/v2/jobs/$JOB_ID/errors" -H "Authorization: Bearer $MGMT"
```

A running job reads `pending`; terminal states are `completed` and `failed`.
A completed import may still have failed records: inspect `summary` (`total`,
`inserted`, `updated`, `failed`) and `/errors`. Record errors include codes,
messages and paths; password hashes are masked as `*****`. An import without
record errors returns `[]`; a failed job returns the job object. Keep your
original file for corrections because error records cannot recover hashes.
Job records and files expire 24 hours after creation. Workers resume an
interrupted import from its last committed batch, retry once after lease
loss, and fail a job that exceeds two hours from its first claim.

Completion email defaults to enabled. It goes to operators whose tenant list
covers this tenant (including `*`), in English. Configure an email driver
before enabling it. The console and system job list also show a weak-hash count.

## Upserts

`upsert=false` reports existing users as `DUPLICATED_USER`. With `upsert=true`,
users are matched by email within the connection. Supplied profile fields and
`email_verified` replace their values; supplied metadata objects replace the
whole object, rather than merging. On an existing user, `blocked`, `user_id`
and `password_hash` are ignored. `custom_password_hash` can replace an
imported hash only before that user has signed in; once a native password
exists, that record fails with `CONFLICT`. Concurrent sign-in and upsert are
serialized so neither can silently overwrite a newly established password.
Duplicate emails in the same file produce a per-record uniqueness error.

## Hash formats

The following examples use the test password `Pa55w0rd!` and were generated
by `scripts/gen-hash-vectors.py` and `scripts/gen-hash-vectors-kdf.py`, using
independent Python/OpenSSL/argon2 tools. They illustrate migration, not
recommended settings for creating new passwords. Do not use these credentials.
The reproducible five-record E2E fixture is generated with
`python3 scripts/gen-hash-vectors.py --fixture` from those committed vectors.

Hash and salt byte encodings are `hex`, `base64` and `utf8` where the algorithm
allows them. Salt defaults to UTF-8 and prefix position; `suffix` is also
supported. Password encoding defaults to `utf8`; `ascii`, `latin1`, `binary`,
`utf16le` and `ucs2` follow Node Buffer conversion semantics. Bcrypt uses the
first 72 bytes including any salt. HMAC supports MD4, MD5, RIPEMD-160, SHA-1,
SHA-224/256/384/512 and Whirlpool, with a separately encoded key.
PBKDF2 accepts PHC values and documented digest aliases, including Whirlpool
and MDC-2. Scrypt requires `keylen`; defaults are cost 16384, blockSize 8,
parallelization 1. Argon2 accepts i, d and id with versions 16 and 19.
LDAP supports MD5/SMD5, SHA/SSHA and SHA-256/384/512 salted and unsalted forms;
CRYPT and cleartext schemes are refused. Excessive KDF costs are refused;
scrypt and argon2 memory is capped at 1 GiB (including scrypt parallelization buffers).
Additional work limits bound PBKDF2 rounds times output blocks to 50 million,
argon2 time times memory in KiB to 2^32, and scrypt N times r times p to 2^30. An accepted but unusable hash
requires a password reset and cannot authenticate.

### argon2

```json
{
  "email": "argon2@example.test",
  "custom_password_hash": {
    "algorithm": "argon2",
    "hash": {
      "value": "$argon2i$v=19$m=64,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$KJjFKZFkxW8um7/NNWEGC+o+pOZJwJERAhiu6AesO7M",
      "encoding": "utf8"
    }
  }
}
```

### bcrypt

```json
{
  "email": "bcrypt@example.test",
  "custom_password_hash": {
    "algorithm": "bcrypt",
    "hash": {
      "value": "$2a$10$abcdefghijklmnopqrstuutXuLMGzUDkLKWYZMwfQ1jZL/OanUDL2",
      "encoding": "utf8"
    }
  }
}
```

### hmac

```json
{
  "email": "hmac@example.test",
  "custom_password_hash": {
    "algorithm": "hmac",
    "hash": {
      "value": "d066984af460e7509af572905ac543d8",
      "encoding": "hex",
      "digest": "md4",
      "key": {
        "value": "s3cret key",
        "encoding": "utf8"
      }
    }
  }
}
```

### ldap

```json
{
  "email": "ldap@example.test",
  "custom_password_hash": {
    "algorithm": "ldap",
    "hash": {
      "value": "{MD5}66uZZ+Edk7s5OAf4svAyWA==",
      "encoding": "utf8"
    }
  }
}
```

### md4

```json
{
  "email": "md4@example.test",
  "custom_password_hash": {
    "algorithm": "md4",
    "hash": {
      "value": "de44aa98a6122b02f024f74ab0309ed6",
      "encoding": "hex"
    }
  }
}
```

### md5

```json
{
  "email": "md5@example.test",
  "custom_password_hash": {
    "algorithm": "md5",
    "hash": {
      "value": "ebab9967e11d93bb393807f8b2f03258",
      "encoding": "hex"
    }
  }
}
```

### sha1

```json
{
  "email": "sha1@example.test",
  "custom_password_hash": {
    "algorithm": "sha1",
    "hash": {
      "value": "37b3b6617930d3ceb0b5ecef8f0fef6f75e2fef9",
      "encoding": "hex"
    }
  }
}
```

### sha256

```json
{
  "email": "sha256@example.test",
  "custom_password_hash": {
    "algorithm": "sha256",
    "hash": {
      "value": "e30c71407def2d37e443d6a2743992bb515a242cac46054e516d3bdad1ca2b17",
      "encoding": "hex"
    }
  }
}
```

### sha512

```json
{
  "email": "sha512@example.test",
  "custom_password_hash": {
    "algorithm": "sha512",
    "hash": {
      "value": "e205f71776a1fb8cdd16e11818889b6bc3db2ae72503f80fb0fb830b0c7c34ea205d6885f05df0f8a08f6684d0995d4983592a54fcdd7960dd82bdb86b1e6f44",
      "encoding": "hex"
    }
  }
}
```

### pbkdf2

```json
{
  "email": "pbkdf2@example.test",
  "custom_password_hash": {
    "algorithm": "pbkdf2",
    "hash": {
      "value": "$pbkdf2-sha256$i=1000,l=32$ABEiM0RVZneImaq7zN3u/w$1Nhd+jSQU1g3ZP6insHJmyQROq/spzJmIfrLpG1G1xc",
      "encoding": "utf8"
    }
  }
}
```

### scrypt

```json
{
  "email": "scrypt@example.test",
  "custom_password_hash": {
    "algorithm": "scrypt",
    "hash": {
      "value": "66e8db8e8307f30e5d55a38a47cb7a2d56e3ab1d41e16b87068a114ea3db9f1d",
      "encoding": "hex"
    },
    "keylen": 32,
    "salt": {
      "value": "NaCl-scrypt",
      "encoding": "utf8"
    }
  }
}
```

## Weak hashes

Unsalted MD4, MD5 and SHA-1 (including LDAP MD5/SHA) are counted as weak.
Other legacy digests are also unsuitable for new password storage. Prefer
requiring users to reset before resuming access, rather than waiting for the
first successful sign-in to upgrade a weak hash.

A password-change ticket alone does not disable the old password. To force a
reset using the existing Auth0-compatible endpoints:

1. Generate a unique, strong random replacement password for each user and
   `PATCH /api/v2/users/{url-encoded-user-id}` with `{"password":"...",
   "connection":"database-connection-name"}` (`update:users`). This clears
   the imported hash; do not give the replacement password to the user.
2. Revoke both `/api/v2/users/{id}/sessions` and
   `/api/v2/users/{id}/refresh-tokens` with `DELETE` and their respective
   `delete:sessions` and `delete:refresh_tokens` scopes. Already issued access
   tokens remain valid until expiry.
3. `POST /api/v2/tickets/password-change` with `{"user_id":"auth0|..."}`
   (`create:user_tickets`) and deliver the single-use ticket securely, or
   initiate the emailed reset using `/dbconnections/change_password` with
   `client_id`, `connection` and `email`.

Choose replacement passwords that satisfy the connection's password policy.
Do not print replacement passwords or reset tickets in logs.

## Export and download

`POST /api/v2/jobs/users-exports` needs `read:users` and returns `200` with a
job. Its JSON body accepts `connection_id` (omit for every connection),
`format` (`csv`, the default, or `json`), positive `limit` (omit for all), and
`fields`: an array of `{ "name": "email", "export_as": "address" }` objects.
CSV supports at most 30 fields. Metadata subfields use dotted names; whole
metadata objects work in JSON only. JSON output is gzipped newline-delimited
JSON, not a JSON array. CSV is gzipped, includes a header, prefixes strings
with an apostrophe and quotes them; object/array subfields are empty cells.
No format exports password hashes.

Read the completed job for `location`, then GET that URL without a token.
It expires after 60 seconds; read the job again for a fresh link. Treat it as
a temporary bearer credential. Downloads are logged with tenant, job and
remote IP. Files disappear with their job after 24 hours.
