# Upgrading

Read the [changelog](../CHANGELOG.md) for the version you are moving to, then:

1. **Back up** the database (see [deployment](deployment.md#backups)). Make
   sure you still have the master key; the backup is useless without it.
2. **Stop** zeroauthy, on every server that shares the database.
3. **Migrate** with the new binary:

   ```bash
   zeroauthy migrate --config /etc/zeroauthy/zeroauthy.yaml
   ```

   It prints the schema versions it moved between. With
   `storage.auto_migrate: true` (the container image's default), `serve`
   does this at startup instead; back up first all the same.
4. **Start** the new version on every server.

Without `auto_migrate`, `serve` refuses to start against a schema that is
behind the binary ("run zeroauthy migrate") or ahead of it. Storage plugins
must be rebuilt against the new `pkg/storeplugin` when the release notes say
so; see [stability](stability.md).

With the container image:

```bash
docker pull ghcr.io/occupysaas/zeroauthy:<new version>
docker rm -f zeroauthy
docker run ... ghcr.io/occupysaas/zeroauthy:<new version>   # same options as before
```

## Rolling back

Migrations only go forward; there are no down migrations. An older binary
refuses to start on a newer schema. To roll back:

1. Stop the new version everywhere.
2. Restore the database backup taken before the upgrade.
3. Start the old version with the same master key.

Changes made after the upgrade (new users, sessions, settings) are lost with
the restore, so decide quickly.

## MySQL: back up before you migrate

MySQL commits schema changes (DDL) immediately, so a migration cannot be
rolled back if it fails part way. Migrations 20, 21 and 29 onwards resume
safely when rerun, but migrations 1–19 and 22–28 do not: if one of them fails
or the process stops mid-way, the database is left between two schema
versions.

- Take a backup (for example `mysqldump --single-transaction`) before running
  `zeroauthy migrate` against MySQL, or before starting a new version with
  `storage.auto_migrate: true`.
- If a MySQL migration fails, restore the backup, fix the cause, and migrate
  again. Do not just rerun `zeroauthy migrate` on the partly migrated database.

PostgreSQL and SQLite run each migration in a transaction; a failed migration
rolls back and can be retried.

## Plan 35: client authentication, signed requests and token exchange

This release adds `private_key_jwt`, signed authorization requests (JAR),
HS256 and PS256 API tokens and custom token exchange. When you upgrade:

- **Migration 0036** adds the client credential, token exchange profile and
  assertion-replay tables; the nullable `clients` columns
  `client_authentication_methods`, `signed_request_object` and
  `token_exchange`; `resource_servers.signing_secret_sealed`; and
  `pushed_auth_requests.signed`. It is forward only; back up first as above.
- **Published signing keys lose `alg`.** The tenant's JWKS now lists each
  signing key without an `alg` member (RFC 7517 makes it optional), so a
  verifier accepts both RS256 and PS256 tokens signed with that key. `kty`,
  `use`, `kid`, `n` and `e` are unchanged. A verifier that required `alg` in
  the JWK needs a configured algorithm.
- **Discovery changes** when the store supports client credentials: it lists
  `private_key_jwt` in `token_endpoint_auth_methods_supported`, the accepted
  assertion and request-object signing algorithms, and
  `request_parameter_supported: true`.
- **Request object errors.** A malformed, unverifiable or unconfigured signed
  `request` now answers `invalid_request_object`; it used to answer
  `request_not_supported`. An unsigned (`alg` none) object is still
  `request_not_supported`.
- **Throttle rate for custom token exchange.** Tenants initialised before this
  release keep the `pre-custom-token-exchange` rate they were created with,
  8640000 ms. The documented default is 600000 ms: set it with the
  attack-protection API (see [attack protection](attack-protection.md)) to
  get it.
- **Storage plugins** need the `client_credentials.v1` capability for the new
  features. Without it, the new Management API writes answer `501`, and
  `private_key_jwt`, signed requests and token exchange are unavailable; the
  other features keep working. See [stability](stability.md).
