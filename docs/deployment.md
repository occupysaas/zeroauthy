# Deploying zeroauthy

How to run zeroauthy for real users. Start with the
[quickstart](quickstart.md) to see it work locally, then use
[examples/zeroauthy.yaml](../examples/zeroauthy.yaml) as your configuration.
Every key can also be set as a `ZEROAUTHY_*` environment variable (`__`
between levels); unknown keys stop the server at startup. The
[configuration reference](configuration.md) lists every key, its variable and default.

## Checklist

1. A DNS name for zeroauthy, with a wildcard below it (see [DNS and hosts](#dns-and-hosts)).
2. TLS for those names, terminated by zeroauthy or by a proxy.
3. A database: SQLite for one server, PostgreSQL or MySQL for more.
4. A master key, stored outside the database and backed up separately.
5. An email provider (the default `log` driver only writes emails to the log).
6. Backups of the database and the master key, and a restore you have tried.

## DNS and hosts

zeroauthy picks the tenant from the request's host name.

- Set `server.base_domain`, for example `auth.example.com`. Tenant `acme` is
  then served at `acme.auth.example.com`, and the reserved `system` tenant,
  with the admin console at `/admin/`, at `system.auth.example.com`.
- Create a wildcard DNS record `*.auth.example.com` pointing at zeroauthy (or
  at your proxy). Tenant names are one DNS label.
- Without `base_domain`, set `server.system_host` for the console and give
  every tenant explicit `domains` when you create it.
- Tenants can also have customer-facing [custom domains](custom-domains.md)
  with ownership proof and automatic certificates.

The issuer of every token is `https://<host>/`, so the host your users and
SDKs see must stay stable. Changing `base_domain` changes every tenant's
issuer and Management API audience.

## TLS

SDKs require HTTPS. Choose one:

- **zeroauthy terminates TLS.** Set `server.tls_cert_file` and
  `server.tls_key_file` to a certificate covering `*.<base_domain>` (and
  `server.system_host` if it is outside the base domain). The files are read
  at startup, so restart after renewing them. Get a wildcard certificate from
  any ACME client that supports DNS-01 (certbot, lego, acme.sh).
- **zeroauthy issues the wildcard itself.** With DNS hosted at DigitalOcean,
  `server.acme` plus `server.acme.hosted_wildcard` issues and renews
  `base_domain` and `*.base_domain` through DNS-01. See
  [custom domains](custom-domains.md#deployment-owned-wildcard).
- **A reverse proxy terminates TLS** and forwards plain HTTP to zeroauthy
  (next section).

`server.acme` on its own issues certificates for tenants' custom domains, not
for the base or system hosts. zeroauthy does not send
`Strict-Transport-Security` in 1.0; add it at your proxy or load balancer if
you want it.

### Self-signed TLS for testing

For CI, E2E tests and docker compose setups where zeroauthy stands in for
Auth0, `server.tls_self_signed: true` serves HTTPS without any certificate
files. At every start zeroauthy generates an in-memory ECDSA P-256 CA (valid
30 days) and a certificate it signs for `localhost`, `127.0.0.1`, `::1`, the
system host, `base_domain` and `*.base_domain`, every tenant domain known at
startup, and the names in `server.tls_self_signed_hosts`. Tenant domains
added later through the Management API get their own certificate from the
same CA on first connection; any other server name is refused.

```yaml
server:
  listen: ":8443"
  system_host: "localhost:8443"
  tls_self_signed: true
  tls_self_signed_ca_file: /shared/zeroauthy-ca.pem   # CA certificate only, never its key
  tls_self_signed_hosts: [zeroauthy]                  # e.g. the compose service name
```

Point your test runner at the CA file (`NODE_EXTRA_CA_CERTS`,
`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, a JVM truststore). The CA changes on
every start, so read the file after zeroauthy is up; the startup log shows
its SHA-256 fingerprint and path. With environment variables use
`ZEROAUTHY_SERVER__TLS_SELF_SIGNED=true`,
`ZEROAUTHY_SERVER__TLS_SELF_SIGNED_CA_FILE=...` and a comma-separated
`ZEROAUTHY_SERVER__TLS_SELF_SIGNED_HOSTS=zeroauthy,10.0.0.5`.

This is for testing only: zeroauthy logs a warning, and refuses to start if
it is combined with `tls_cert_file`/`tls_key_file` or `server.acme`. The
[testing guide](testing.md) has a complete compose and CI setup built on it.

## Behind a reverse proxy

Run zeroauthy on an internal port (`server.listen: ":8080"`, no `tls_*`
settings) and have the proxy:

- terminate TLS for `*.<base_domain>`;
- pass the original `Host` header, or set `X-Forwarded-Host` to it;
- append the client's address to `X-Forwarded-For`.

Then tell zeroauthy to trust those headers, and only from the proxy:

```yaml
server:
  listen: ":8080"
  base_domain: auth.example.com
  trust_proxy_headers: true
  trusted_proxy_cidrs: ["10.0.0.10/32"]   # your proxy's address(es)
```

With `trust_proxy_headers`, the tenant comes from `X-Forwarded-Host` and the
client address (used by brute-force protection, logs and sessions) from the
rightmost `X-Forwarded-For` entry, so put exactly one trusted proxy in front.
Without `trusted_proxy_cidrs` the headers are trusted from every peer, and a
client could pick its own tenant or address; zeroauthy logs a warning in that
case. Never enable it when clients can reach zeroauthy directly.

Example with Caddy, which keeps `Host` and sets `X-Forwarded-For` (a wildcard
certificate needs a Caddy build with your DNS provider's module):

```
*.auth.example.com {
  tls { dns <your-dns-provider> }
  reverse_proxy 10.0.0.20:8080
}
```

## Master key

The master key (32 random bytes, base64) encrypts signing keys, client
secrets, connection and provider credentials, MFA secrets and TLS material in
the database.

```bash
openssl rand -base64 32 > /etc/zeroauthy/master.key
chmod 0400 /etc/zeroauthy/master.key
```

Point `security.master_key_file` at it (or pass `ZEROAUTHY_SECURITY__MASTER_KEY`
from a secret manager). Every server sharing a database needs the same key.

- **It cannot be rotated in 1.0.** There is no re-encryption command yet. If
  the key leaks, the only remedy is a fresh installation with new keys and
  secrets.
- **A database backup is useless without it**, and a lost key cannot be
  recovered. Back it up, separately from the database backups, somewhere you
  can reach when the server is gone.
- Anyone holding both a database copy and the key can read every tenant's
  secrets. Store them apart.

## Choosing a database

| Driver | DSN | Use |
|---|---|---|
| SQLite | `sqlite:///var/lib/zeroauthy/zeroauthy.db` | One server. Simplest; the container image default (`/data`). |
| PostgreSQL 14+ | `postgres://user@host:5432/zeroauthy?sslmode=verify-full` | Several servers. Create the database with a UTF-8 `LC_CTYPE`. |
| MySQL 8.0.17+ | `mysql://user:pass@host:3306/zeroauthy?tls=true` | Several servers. MariaDB is not supported. |

Use verified TLS to a remote database: pgx defaults to `sslmode=prefer`,
which an attacker on the network can downgrade, and the MySQL driver sends
plain text unless you add `tls=true` (or `tls=skip-verify` only for testing).
Keep passwords out of the config file (`ZEROAUTHY_STORAGE__DSN`).

Schema changes are applied by `zeroauthy migrate` or by
`storage.auto_migrate: true`; see [upgrading](upgrading.md). `memory://` is
for tests only. Storage plugins (`plugin://`) are described in the README.

## Several servers and job workers

Every server needs the same database, master key and configuration. Each one
runs background job workers (user imports and exports, verification emails,
Actions jobs):

- `jobs.workers` (default 2): Management API jobs per process. Set it to `0`
  on processes that should only serve requests.
- `actions.job_workers` (default 2): durable Actions jobs per process.
- With `server.acme`, `server.acme.deployment_id` must be the same on every
  replica.

The Actions `api.cache` is local to each server, and so are the request
rate limits (`security.rate_limit`, default 50 requests per second with a
burst of 200 per tenant, client IP and endpoint group): with N servers behind
a load balancer a client can reach N times the configured rate, so divide the
rate by the number of replicas if you need a fixed total. Behind a proxy the
limits key on the client address only when the proxy headers are trusted
(above). See [attack protection](attack-protection.md#request-rate-limits).
SQLite cannot be shared between hosts; use PostgreSQL or MySQL for more than
one server.

## Node.js for Actions and custom databases

Actions, custom database scripts and social profile scripts run in Node.js
(22.13 or later; profile scripts need 25 or later). The container image ships
Node 26. With the binary, install Node yourself or set `actions.node` and
`custom_db.node`. Set `actions.cache_dir` to a writable absolute path for a
service account. If tenants are not trusted, also restrict outbound network
access and run zeroauthy under a dedicated user or container; see the security
sections of [Actions](actions.md) and [custom databases](custom-db.md).

## Email

Configure `email.driver: smtp` (or tenant email providers in the console) so
password-reset, verification, MFA and invitation emails reach users. See
[email](email.md).

## Backups

Back up two things, separately:

1. **The database.** SQLite: copy the file while the server is stopped, or
   use `sqlite3 zeroauthy.db ".backup backup.db"` while it runs. PostgreSQL:
   `pg_dump -Fc`. MySQL: `mysqldump --single-transaction`.
2. **The master key**, once, plus your configuration and TLS material.

Test a restore: start a separate zeroauthy with the restored database and the
same master key, and check that you can sign in to the console and get a
token. Always back up before an [upgrade](upgrading.md).

## Health and logs

Two endpoints answer on any host, over the configured listener:

- `GET /healthz` (liveness) returns `{"status":"ok"}` whenever the process
  serves requests. It never touches storage, so a database outage does not
  get a healthy server restarted.
- `GET /readyz` (readiness) checks that storage (the database or storage
  plugin) answers within two seconds: `{"status":"ok"}`, or `503` with
  `{"status":"unavailable"}`. Point load-balancer health checks and
  orchestrator readiness probes here, so a server that cannot reach its
  storage stops receiving traffic.

Logs are JSON on stdout
(`log.format: text` for humans); secrets are scrubbed. Tenant activity logs
and log streams are in [logs](logs.md).
