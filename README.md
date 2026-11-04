# zeroauthy

[![Listed on Remade](docs/pics/listed-on-remade.svg)](https://remade.wiki/)
[![OpenID Certified](https://img.shields.io/badge/OpenID-Certified-F78C40?logo=openid&logoColor=white)](https://openid.net/certification/certified-openid-providers-profiles/)

An open-source, self-hostable identity server that speaks the Auth0
Authentication API. Point an existing Auth0 SDK at a zeroauthy tenant
domain and it works with no code changes.

zeroauthy is a clean-room implementation built from public documentation
and open standards. It is not affiliated with Auth0 or Okta. See
[CLEAN_ROOM.md](CLEAN_ROOM.md).

**OpenID Certified.** zeroauthy is
[certified by the OpenID Foundation](https://openid.net/certification/certified-openid-providers-profiles/)
as an OpenID Connect Provider for the Basic OP, Config OP and Form Post OP
profiles (commit `38b4229`, October 2026). See [docs/conformance.md](docs/conformance.md).

> **Status: 1.0 early preview.** zeroauthy covers what most Auth0 tenants
> use, but not everything yet. Try it, and check the
> [compatibility page](docs/compatibility.md) for the gaps (WebAuthn and
> passkeys, SAML, enterprise directories and more) before relying on it.

**Use it for testing.** zeroauthy also makes a disposable, Auth0-compatible
login server for end-to-end tests: one container seeded with known tenants,
apps and users, so your test suite can run real logins with your Auth0 SDK
locally and in CI. See the [testing guide](docs/testing.md) and the kit in
[examples/testing](examples/testing).

**What works in 1.0**

- The Authentication API and hosted login: authorization code with PKCE,
  refresh token rotation, client credentials, password grants, PAR, the
  device flow, logout, consent, signup and password reset
- MFA (one-time passwords, email, SMS, voice, recovery codes) and
  passwordless email and SMS ([MFA](docs/mfa.md), [passwordless](docs/passwordless.md))
- Database, custom database, Google, Microsoft and generic OAuth 2 / OIDC
  connections
- The Management API for applications, APIs, connections, users, roles,
  organizations, Actions, branding, email and phone, custom domains, logs and
  event streams ([Management API](docs/management-api.md))
- An admin console ([console](docs/console.md)), SQLite, PostgreSQL, MySQL and
  gRPC storage plugins
- Verified with auth0-spa-js, auth0-react, nextjs-auth0, express-openid-connect,
  auth0-auth-js, node-auth0, Auth0.NET, the Auth0 CLI and the Deploy CLI

**Start here:** [quickstart](docs/quickstart.md) (container to SDK login),
[deployment](docs/deployment.md), [upgrading](docs/upgrading.md),
[migrating from Auth0](docs/migrating-from-auth0.md),
[stability promise](docs/stability.md), [security policy](SECURITY.md) and
the [changelog](CHANGELOG.md).

![The zeroauthy admin console: a tenant's applications](docs/pics/console-applications.png)

## Roadmap

zeroauthy aims to be a 1:1, drop-in replacement for Auth0's Authentication
API and Management API; the [compatibility page](docs/compatibility.md) lists
what is still missing. The Authentication API side is complete apart from what the
features below add. The Management API is being built resource by resource,
each with its console screens; the full breakdown is in the
[Management API roadmap](docs/superpowers/specs/2026-10-19-zeroauthy-management-roadmap-design.md).

**Done** (Plans 1–34)

- Core server, signing keys, discovery and JWKS, hosted login and signup,
  authorization code with PKCE, client credentials, password grants, rotating
  refresh tokens, logout, password reset, hosted-page languages
- Storage: memory, SQLite, PostgreSQL, MySQL, gRPC storage plugins
- Custom database connections (Auth0 scripts, import mode)
- Consent and third-party applications, PAR, device flow
- OpenID Certified (Basic, Config, Form Post OP); conformance suite in CI
  (those plus RP-Initiated Logout)
- Management API and console: applications, APIs, client grants, database
  connections, users (with search, identity linking, sessions, refresh tokens,
  grants and tickets), user import/export jobs and verification email
- Tenant email providers and templates, signup welcome and security notices;
  see [docs/email.md](docs/email.md) for active workflows and stored-only limits

**Tenant settings and attack protection (Plan 19)**

- [Tenant settings](docs/tenant-settings.md), [attack protection and automatic blocks](docs/attack-protection.md)

**Signing keys and deployment migration (Plan 20)**

- Managed signing keys, stored-only custom public JWKS, and credential-preserving bootstrap are implemented.
- The pinned Deploy CLI passes local YAML/directory imports with generated or preserved credentials, including organizations, Actions and event streams. Database connections remain excluded from that matrix, and Guardian factor providers cannot be exported because of a bug in the Deploy CLI itself ([MFA](docs/mfa.md#deploy-cli-and-troubleshooting)); the upstream observer lane remains unavailable. See [signing keys](docs/signing-keys.md) and [Deploy CLI migration](docs/deploy-cli.md) for current limits.

**Branding and Universal Login (Plan 22)**

- Tenant branding, themes, bounded page templates, identifier-first login, localized text and transient form partials; console editors with isolated preview. See [branding](docs/branding.md) and the [implementation record](docs/superpowers/plan-22-implementation-record.md) for supported syntax and compatibility limits.

**Custom domains and automatic certificates (Plan 23)**

- Verified domain ownership, shared automatic TLS, authenticated customer proxies,
  domain-bound login and notification links, and console controls. See the
  [operator guide](docs/custom-domains.md) and [acceptance record](docs/superpowers/2026-10-26-plan-23-implementation-record.md).

**Roles, connections and Actions (Plans 24–28)**

- Generic OAuth/OIDC, Google and Microsoft connections; roles and permissions.
- [Actions](docs/actions.md): login and credentials exchange, signup, password
  reset/change and custom email triggers; immutable Modules, durable jobs,
  console and migration tooling. Limits and verification are in the
  [Plan 28 implementation record](docs/superpowers/2026-10-28-plan-28-implementation-record.md).

**Organizations I (Plan 29)**

- Organizations, members, role assignments, enabled connections, hosted prompt
  and picker, claims/refresh checks, branding, Actions context and scoped
  operators. See [Organizations](docs/organizations.md) and the
  [verification record](docs/superpowers/2026-10-28-plan-29-implementation-record.md).

**Organizations II (Plan 30)**

- Invitations, organization application grants, verified discovery domains and
  console controls. See [Organizations](docs/organizations.md) and the
  [implementation record](docs/superpowers/2026-10-29-plan-30-implementation-record.md).

**Logs, log streams and statistics (Plan 31)**

- Searchable tenant logs, live console views, Action execution logs, outbound
  log streams, daily statistics and active-user counts. See
  [Logs](docs/logs.md) for supported destinations and privacy controls.

**Event streams (Plan 32)**

- Transactional CloudEvents for user, organization and enterprise-connection
  changes; guarded webhooks and durable `event-stream` Actions; retries,
  failed-delivery inspection, redelivery and auto-disable; resumable SSE,
  console controls, seed and Deploy CLI support.
- EventBridge configurations are stored disabled, and group events await
  Plan 38. See [Event streams](docs/event-streams.md) for payloads, retention
  and other limits, and the [validation report](docs/superpowers/2026-11-02-plan-32-postfix-validation.md)
  for actual results, skips and conformance outcomes.

**MFA (Plan 33)**

- One-time passwords, email codes, recovery codes, MFA policies,
  remember-browser, hosted MFA prompts, the MFA API and grants, Guardian and
  user authentication-method APIs, and Actions `multifactor` /
  `challengeWith*`. WebAuthn and passkeys move to Plan 33b. See [MFA](docs/mfa.md).

**Passwordless and phone (Plan 34)**

- Email and SMS passwordless connections, magic links and the OTP grant,
  phone providers (Twilio, Amazon SNS, custom through Actions) and templates,
  SMS and voice MFA, phone identifiers and phone password reset. See
  [passwordless](docs/passwordless.md) and [phone providers](docs/phone-providers.md).

**Later** (Plans 33b, 35–48)

| Plan | Area | Depth | Needs |
|---|---|---|---|
| 33b | WebAuthn MFA and passkeys | full | 33 |
| 35 | Client credentials: `private_key_jwt`, JAR, token exchange profiles | short | 27 |
| 36 | Remaining enterprise OIDC: `oidc`, `okta`, Entra extras, connection keys (`waad` sign-in moves to 25) | short | 24, 25 |
| 37 | SAML and WS-Federation (sub-project 4), SCIM, self-service SSO profiles | full | 36 |
| 38 | AD/LDAP connector, Forms and Flows, network ACLs, remaining resources | full | 27, 37 |
| 39 | Additional social providers (Apple, Facebook, GitHub, …) | short (Apple full) | 24 |
| 40 | Actions III: newer triggers, Early Access members, `/userinfo` claims | short | 28, 22 |
| 41 | OIDC protocol extras, CIBA, formal OIDF certification | full | 33, 35 |
| 42 | My Account API and My Organization API | full | 30, 33 |
| 43 | Token Vault and connected accounts | full | 24, 35 |
| 44 | ACUL and the remaining Universal Login modes | full | 22, 29, 33 |
| 45 | Operational hardening sweep | short | — |
| 46 | Release pipeline, packaging, samples | short | 45 |
| 47 | Hosted zeroauthy (multi-tenant SaaS) | full | 29, 31, 46 |
| 48 | Refresh tokens II: rotation conversion, strict leeway, grant-revocation cascade, multi-resource and session-bound tokens | short | 17, 3 |

The roadmap tracks 42 resource groupings; its [coverage table](docs/superpowers/specs/2026-10-19-zeroauthy-management-roadmap-design.md#management-api-coverage-by-resource) records completed and remaining work. Four groups are not planned (Rules, Hooks and
rules-configs, which Auth0 is retiring, and customer-managed encryption keys).

## Quick start

Run the container image (it includes Node.js for Actions and stores SQLite in
the `/data` volume):

```bash
docker run -d --name zeroauthy -p 8443:8443 -v zeroauthy-data:/data \
  -v "$PWD/certs:/certs:ro" \
  -e ZEROAUTHY_SERVER__LISTEN=:8443 \
  -e ZEROAUTHY_SERVER__SYSTEM_HOST=system.localhost:8443 \
  -e ZEROAUTHY_SERVER__TLS_CERT_FILE=/certs/cert.pem \
  -e ZEROAUTHY_SERVER__TLS_KEY_FILE=/certs/key.pem \
  -e ZEROAUTHY_SECURITY__MASTER_KEY="$(cat master.key)" \
  ghcr.io/occupysaas/zeroauthy:1.0.0-rc.1
docker exec zeroauthy zeroauthy admin create --email you@example.com
```

The [quickstart](docs/quickstart.md) walks through the certificate and master
key, the first tenant, application and user, and a login with
express-openid-connect. Release binaries for linux/amd64, linux/arm64 and
darwin/arm64 are on the
[releases page](https://github.com/occupysaas/zeroauthy/releases). For a
server, start from [examples/zeroauthy.yaml](examples/zeroauthy.yaml) and
[deployment](docs/deployment.md).

## Running from source with the test data

This runs the server with the end-to-end test configuration
(`tests/e2e/config.yaml`: memory storage, debug logging, published test
secrets). It is for development, not for real users. It needs Go 1.26.10.

```bash
go build -o bin/zeroauthy ./cmd/zeroauthy

# Self-signed certificate for localhost and the console's system host
# (SDKs require HTTPS).
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:system.localhost" \
  -keyout key.pem -out cert.pem

ZEROAUTHY_SERVER__TLS_CERT_FILE=cert.pem ZEROAUTHY_SERVER__TLS_KEY_FILE=key.pem \
  ./bin/zeroauthy serve --config tests/e2e/config.yaml
```

Then:

```bash
curl --cacert cert.pem https://localhost:8443/.well-known/openid-configuration
curl --cacert cert.pem https://localhost:8443/oauth/token \
  -d grant_type=client_credentials -d client_id=e2e-m2m \
  -d client_secret=e2e-m2m-secret-not-for-production -d audience=https://api.e2e.local
```

### Try the login page

With the quick-start server running, open:

```
https://localhost:8443/authorize?client_id=e2e-spa&response_type=code&redirect_uri=https://localhost:3443/&scope=openid%20profile&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=demo
```

and sign in as `alice@e2e.local` / `Correct-Horse-Battery-9` (test data from
`tests/e2e/seed.yaml`). You are redirected to `https://localhost:3443/?code=…`.

### Open the admin console

The console is served only on the system tenant's host, not on `localhost`.
With the quick-start config (`system_host: system.localhost:8443`) it is at
`https://system.localhost:8443/admin/`. Browsers resolve `*.localhost` to
127.0.0.1; for other clients add `127.0.0.1 system.localhost` to `/etc/hosts`.

The quick-start config stores everything in memory, so the first operator
must be created by the server itself: start it with
`ZEROAUTHY_BOOTSTRAP__ADMIN_EMAIL` set.

```bash
ZEROAUTHY_SERVER__TLS_CERT_FILE=cert.pem ZEROAUTHY_SERVER__TLS_KEY_FILE=key.pem \
ZEROAUTHY_BOOTSTRAP__ADMIN_EMAIL=you@example.com \
  ./bin/zeroauthy serve --config tests/e2e/config.yaml
```

The server writes the one-time setup link to an owner-only (0600) file in the
host's temporary directory and logs its path as `setup_file`, plus the operator
email and one-hour validity. Read that private file on the server, open the link,
and choose a password of at least 12 characters. Delete the file after use, then
sign in at `https://system.localhost:8443/admin/`. Server shutdown leaves the
file available for delivery. Memory storage is lost on restart, and so is the
operator; the next start creates a new private setup file.

`zeroauthy admin create --email you@example.com --config <file>` does the same
from another terminal, but only with persistent storage (SQLite, PostgreSQL,
MySQL): it opens the database directly, so with `memory://` its link points at
data the server never sees.

The built console (`console/dist`) is embedded in the binary at compile time.
After changing the console, run `make console` and then rebuild the binary
(`make build` or the `go build` above); a running server keeps the console it
was built with. See [docs/console.md](docs/console.md) for the screens.

API reference: `https://localhost:8443/docs`. The raw contract is at
`/openapi.yaml`, and its source is [api/authentication.yaml](api/authentication.yaml).

## Configuration

YAML file (`--config`) plus `ZEROAUTHY_*` environment variables. `__`
separates levels: `ZEROAUTHY_STORAGE__DSN=memory://` sets `storage.dsn`.
See the [configuration reference](docs/configuration.md) for every
setting. Tenants, APIs, applications and grants can come from a declarative
[seed file](tests/e2e/seed.yaml); tenants and applications can also be
managed in the [console](docs/console.md) or through the
[Management API](docs/management-api.md). The seed never touches what the
console or the API created. By default the seed is applied at every start and
overwrites what it defines. Set `seed_mode: create_only`
(`ZEROAUTHY_SEED_MODE=create_only`) to have it only create what does not
exist yet (tenants, APIs, applications, grants, connections, users) and change
nothing that does, so edits made in the console survive a restart. In that
mode the console shows no "defined by the seed" banner. `zeroauthy seed`
follows the same setting.
Unknown configuration keys are rejected at startup.

**Actions.** Configure the `actions` section or `ZEROAUTHY_ACTIONS__*`.
Defaults: `node: node`, bundled `npm_cli`,
`registry: https://registry.npmjs.org/`,
`cache_dir: <user cache dir>/zeroauthy/actions-cache`, `max_memory_mb: 256`,
`idle_timeout: 5m`, `build_timeout: 2m`, `max_artifact_mb: 50` (range 1–50),
and `max_concurrent_builds: 2`. Explicit npm/cache paths must be absolute;
`npm_cli` points to `bin/npm-cli.js`. Node ≥22.13 runs Actions; npm and the
registry are needed only on build nodes. Set `cache_dir` explicitly for
services and `registry` to an HTTP(S) offline mirror when needed. See the
[Actions operator guide](docs/actions.md) for dependency restrictions, replica
artifacts, seed ownership, sandbox limits and hardening.

**Event streams.** The `events` section configures retention (default `168h`,
minimum `24h`), the stream quota (default 10 per tenant) and concurrent SSE
connections (default 4 per tenant per server instance). Webhook destinations
require HTTPS and refuse private-network targets by default. See
[Event streams](docs/event-streams.md) for deployment settings, migration and
plugin compatibility.

**Master key.** Signing keys and client secrets are stored envelope-encrypted under a 32-byte
master key. Generate one with `openssl rand -base64 32` and set it as
`ZEROAUTHY_SECURITY__MASTER_KEY` (or point `security.master_key_file` at a
file containing it). It is required for persistent storage; with
`memory://` storage zeroauthy uses an ephemeral key and logs a warning.
The master key cannot be rotated in 1.0, and a database backup is useless
without it: back it up separately ([deployment](docs/deployment.md#master-key)).

**Storage.** `storage.dsn` selects the driver:

| DSN | Driver |
|-----|--------|
| `memory://` | In memory; lost on exit (tests, demos) |
| `sqlite:///var/lib/zeroauthy/zeroauthy.db` | SQLite (pure Go, no CGO); `sqlite://relative.db` is relative to the working directory |
| `postgres://user:pass@host:5432/db?sslmode=require` | PostgreSQL 14+ (`postgresql://` also works); the database needs a UTF-8 `LC_CTYPE` (see below) |
| `mysql://user:pass@host:3306/db` | MySQL 8.0.17+ (MariaDB is not supported) |
| `plugin:///abs/path/to/binary?arg=x&arg=y` | External gRPC storage plugin; each `arg` becomes one argument of the binary. Needs `security.master_key` |

**PostgreSQL locale.** Create the database with a UTF-8 `LC_CTYPE` (for
example `CREATE DATABASE zeroauthy LC_CTYPE 'C.UTF-8' TEMPLATE template0`;
the official container images default to `en_US.utf8`). Under `C` or `POSIX`
PostgreSQL's `lower()` folds ASCII letters only, so case-insensitive user
search and sort would miss non-ASCII matches (`Émilie` vs `émilie`) that the
other drivers find. zeroauthy logs a warning at startup in that case and
still runs.

**Writing a storage plugin.** A plugin is a Go program that calls
`pkg/storeplugin.Serve` with any `store.Store`; `cmd/zeroauthy-store-memory`
is a minimal template. Check your driver by running
`storetest.Run` (package `pkg/storetest`) with a factory that calls
`storeplugin.Open` on your built binary. Transactions work across the
boundary; see decision D-0021 for the protocol.

Plan 20 adds result-returning rotation/revocation, certificate compare-and-set,
and the separate custom public-key repository to the storage contract. Rebuild
storage plugins against the current `pkg/storeplugin`; missing lifecycle RPCs
fail closed with an upgrade diagnostic. Transaction views and tenant deletion
must cover both managed keys and custom sets; run `pkg/storetest` conformance.

The SQL drivers have a schema. Apply pending migrations with
`zeroauthy migrate --config zeroauthy.yaml` before starting a new version,
or set `storage.auto_migrate: true` (`ZEROAUTHY_STORAGE__AUTO_MIGRATE=true`)
to have `serve` migrate at startup. Without it, `serve` refuses to start
against a schema that is behind or ahead of the binary. `zeroauthy seed`
requires a migrated database and ignores `storage.auto_migrate`. Back up the
database before migrating. MySQL commits DDL implicitly, and most early
migrations cannot resume after a partial failure: if a MySQL migration fails,
restore the backup instead of rerunning it. See [upgrading](docs/upgrading.md).

**System tenant and operators.** zeroauthy keeps a reserved tenant named
`system` for itself: its users are the console operators. It is reachable at
`system.<server.base_domain>`, or at `server.system_host`, which is required
when `server.base_domain` is empty (for example `system.localhost:8443`). A `server.system_host` under the base domain must be exactly
`system.<server.base_domain>`. The
server creates it at every start; no other tenant may use the name `system`
or that host. Create an operator with
`zeroauthy admin create --email you@example.com --config zeroauthy.yaml`,
which prints a one-time setup link (valid for one hour) where the operator
chooses a password. Automated installs may set
`ZEROAUTHY_BOOTSTRAP__ADMIN_EMAIL` instead: on a start that finds no
operator, the server creates that one and writes its one-hour setup link to a
private 0600 file in the host's temporary directory. The server log contains only
the `setup_file` path, email and validity. Read the file on the server and delete
it after use; shutdown does not remove it. If file delivery fails after the
operator was persisted, use `admin create` for that email to issue a fresh link.
No password is ever taken from configuration. Operators sign in to the
[admin console](docs/console.md) at `/admin/` on that host.

**Proxies.** Enable `server.trust_proxy_headers` only behind a proxy that
sets `X-Forwarded-Host`, and list that proxy in `server.trusted_proxy_cidrs`;
otherwise clients could choose their own tenant. See
[deployment](docs/deployment.md#behind-a-reverse-proxy).

**Request rate limits.** `security.rate_limit` limits every tenant
Authentication API route with a token bucket per tenant, client IP (IPv6 by
/64) and endpoint group: `token` (`/oauth/token`), `authorize`, `userinfo`,
`discovery` (`/.well-known/*`, JWKS included) and `other` (PAR, device code,
revoke, `/dbconnections/*`, `/passwordless/start`, `/mfa/*`, logout and the
hosted pages). Defaults: `enabled: true`, `rate: 50` (requests per second)
and `burst: 200` for each group, `max_tracked_keys: 50000` buckets per group,
and `max_concurrent_secret_verifications: 0` (GOMAXPROCS, at least 4: legacy
argon2id client secret checks running at once; this cap applies even when the
limiter is disabled). Set a group with, for example,
`ZEROAUTHY_SECURITY__RATE_LIMIT__TOKEN__RATE=20`. The counters are per server
process; see [attack protection](docs/attack-protection.md#request-rate-limits).

## Job workers

`jobs.workers` defaults to 2; set it to 0 to disable workers on a process
while another process handles the shared database queue. `jobs.lease`
defaults to `60s` (minimum `1s`); workers renew every third of the lease.
Environment overrides are `ZEROAUTHY_JOBS__WORKERS` and
`ZEROAUTHY_JOBS__LEASE`. All serving processes must share the same storage
and master key for job reads and export downloads. See
[the import/export guide](docs/user-import.md) for limits and reset advice.

## Custom databases

A database connection can run your own Node.js scripts (`login`, `get_user`,
`create`, `change_password`) against an existing user store, either as the
permanent source of truth or as an import that migrates users on first
login. Scripts written for Auth0 run as written (native addons and a few
blocked built-ins such as `child_process` are the known differences) and
need Node.js 22.13 or later. See [docs/custom-db.md](docs/custom-db.md), including the security
notes for hosting untrusted tenants.

## Releases

Releases are manual: a tagged commit pushed to the `release` branch, then a maintainer's approval in GitHub Actions. See [RELEASING.md](RELEASING.md) for the short checklist and the full walkthrough.

## Development

```bash
make test           # unit + contract + storage conformance tests (memory and SQLite)
make test-sql       # SQL driver tests against PostgreSQL 17 and MySQL 8.4 containers (needs podman or docker)
make generate       # regenerate code from api/authentication.yaml and api/management.yaml
make console        # lint, test and rebuild the admin console (needs Node 22+; then make build to embed it)
make e2e            # Auth0 SDKs against a live zeroauthy on SQLite (needs Node 22+, openssl)
make e2e-events     # Event Streams browser, SDK, CLI, SSE and privacy acceptance
make e2e-deploy     # pinned Deploy CLI YAML/directory round trips
make check-sources  # verify every x-source provenance link
make conformance    # OpenID conformance suite against zeroauthy (podman or docker, Linux; ~10-20 min)
```

## OpenID conformance

zeroauthy is [OpenID Certified](https://openid.net/certification/certified-openid-providers-profiles/) for the Basic OP, Config OP and Form Post OP profiles (commit `38b4229`, approved 2026-10-30). It is also tested against the RP-Initiated Logout OP profile, which OIDF certifies only alongside a session, front-channel or back-channel logout profile; back-channel logout is planned (Plan 41). `make conformance` runs all four plans locally in containers (Linux, podman or docker). Local results pass, with a few accepted warnings and skips. See [docs/conformance.md](docs/conformance.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
