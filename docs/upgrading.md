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

On the first startup after the Plan 45b email-provider change, zeroauthy
moves public credential fields into the existing public config column and
reseals the private credentials. Each provider update is atomic and restart
resumes the backfill. Stop older replicas before starting the new binary.
Rolling back after this conversion requires restoring the pre-upgrade backup
because older releases cannot read the new provider envelope.

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

## Plan 39a: Sign in with Apple

Migration **0037** adds the native-social client JSON column in SQLite,
PostgreSQL and MySQL. Apply migrations before starting the new server, or use
`storage.auto_migrate`; gRPC store plugins must also be rebuilt for the
additive client and identity fields. Existing mobile settings are preserved.
Old clients default to native social login disabled. Check migration numbers
against main before merging concurrent plans.

Apple connections require the operator's Services ID, Team ID, Key ID and
PKCS#8 P-256 `.p8` key. Seed keys use `file://` or `env://` references; Deploy
CLI exports omit the key and imports require explicit credential reinjection.
Enable native Apple separately per application and set its iOS bundle ID.
Facebook and Google switches persist but do not enable their native flows.
See [social connections](social-connections.md) and D-0170.

## Plan 45b flow and API changes

**Organization read scopes.** Before upgrading, update client grants and
request fresh Management API tokens for the operations each integration uses.

| Operation | Required scopes |
|---|---|
| `GET /api/v2/users/{id}/organizations` | `read:organizations` |
| `GET /api/v2/organizations/{id}/members` | `read:organization_members` |
| The member list with roles included | `read:organization_members` and `read:organization_member_roles` |

A token carrying only `read:users` now receives HTTP 403 on the user
organizations endpoint. A roles-only token receives 403 on the member list.
For user searches that filter by connection, move the filter into
`q=identities.connection:"connection_name"`. The legacy `connection` argument
applies only to the unsupported v1 engine.

**Login and MFA.** Users see consent after MFA. Invitation consumption,
membership, login statistics and the new session become durable at successful
authorization. A native passkey MFA exchange already pending at upgrade can
require a fresh login. Codes issued before the MFA snapshot migration omit MFA
from the resulting ID token's `amr`. Newly issued signup verification codes
last 900 seconds. Per-identifier send counters start fresh under their new
connection- and purpose-specific keys.

**Storage.** Apply migrations 0038–0040. They add the brute-force first-denial
claim, verification-ticket organization and authorization-code MFA timestamp,
and index abandoned authenticator cleanup. A block already active at upgrade
may produce one `limit_wc` on its next refusal. Upgrade storage plugins to
support the denial claim, organization-bound verification (Organizations II
version 2), code MFA snapshots and batched factor reads. The email-provider
backfill and rollback requirements are described at the start of this guide.

**Console Management requests and CSP.**

The `/admin/` CSP allows its own origin, the configured HTTPS base-domain
wildcard when present, and the canonical system host. For tenants using
custom hosts, the bundled console sends Management requests to
`/api/console/tenants/{name}/api/v2/*` on the system host. If a reverse
proxy uses path allowlists, allow `/api/console/*` on the system host and
pass the `Authorization` header. The bundled console and server ship together.
Reload an open console after upgrading to pick up the new client and CSP.
Existing tenant Management endpoints and M2M credentials continue to work
on their configured hosts.

## Plan 48: refresh tokens, DPoP and quotas

Back up before applying the forward-only refresh-token migration (numbered
at integration). Old records remain offline and gain no invented proof or
parent history. Upgrade every replica and rebuild plugins for
`refresh_tokens_ii.v1` before enabling the new features.

Overlap behavior is stricter: only the immediately previous rotating token
can be retried inside leeway. Older-token retries revoke the entire family;
serialize refresh and save the latest token. Legacy rotated records without
provable parent history fail closed on retry. Configuration conversion starts
a new lifetime and atomically invalidates the matching previous token set.

Grant deletion now revokes matching refresh tokens. Explicit session revoke
also revokes offline tokens; ordinary logout/session deletion still preserves
offline tokens. Online tokens end with their session. New tenants enable
strict DPoP refresh binding; existing absent/false settings retain per-API
behavior, and existing bound records never lose their key. Public online
clients need DPoP, including nonce retry; see [DPoP](dpop.md).

Stored valid tenant quota defaults remain effective after migration. Limits
are enforced only on successful client-credentials issuance; partial PATCH
preserves omitted limits. Read [refresh tokens and quotas](refresh-tokens.md)
for the Management routes, configuration and console reset-all limitation.
