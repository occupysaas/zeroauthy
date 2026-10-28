# zeroauthy

[![Listed on Remade](docs/pics/listed-on-remade.svg)](https://remade.wiki/)

An open-source, self-hostable identity server that speaks the Auth0
Authentication API. Point an existing Auth0 SDK at a zeroauthy tenant
domain and it works with no code changes.

zeroauthy is a clean-room implementation built from public documentation
and open standards. It is not affiliated with Auth0 or Okta. See
[CLEAN_ROOM.md](CLEAN_ROOM.md).

> **Status:** early. Multi-tenant discovery, JWKS, the `client_credentials`
> grant, login with the hosted page, the authorization code + PKCE flow,
> rotating refresh tokens, `/oauth/revoke`, and logout through `/v2/logout`
> and `/oidc/logout` work today (verified with auth0-spa-js, auth0-react and
> nextjs-auth0). Pushed authorization requests ([docs/par.md](docs/par.md)) and
> the device authorization flow ([docs/device-flow.md](docs/device-flow.md))
> are supported too, and so are Auth0's Management API for applications, APIs, client grants and database connections
> ([docs/management-api.md](docs/management-api.md), verified with auth0-cli)
> and an admin console ([docs/console.md](docs/console.md)). See the
> [compatibility matrix](docs/compat/matrix.md).

Tenant-configurable email providers, bounded Liquid templates, previews and
operator test sends are also available. Existing tenants can keep the
server-wide email driver; see [docs/email.md](docs/email.md) for provider,
template and migration guidance.

![The zeroauthy admin console: a tenant's applications](docs/pics/console-applications.png)

## Roadmap

The goal is a 1:1, drop-in replacement for Auth0's Authentication API and
Management API. The Authentication API side is complete apart from what the
features below add. The Management API is being built resource by resource,
each with its console screens; the full breakdown is in the
[Management API roadmap](docs/superpowers/specs/2026-10-19-zeroauthy-management-roadmap-design.md).

**Done** (Plans 1–23)

- Core server, signing keys, discovery and JWKS, hosted login and signup,
  authorization code with PKCE, client credentials, password grants, rotating
  refresh tokens, logout, password reset, hosted-page languages
- Storage: memory, SQLite, PostgreSQL, MySQL, gRPC storage plugins
- Custom database connections (Auth0 scripts, import mode)
- Consent and third-party applications, PAR, device flow
- OpenID conformance in CI (Basic, Config, Form Post, RP-Initiated Logout)
- Management API and console: applications, APIs, client grants, database
  connections, users (with search, identity linking, sessions, refresh tokens,
  grants and tickets), user import/export jobs and verification email
- Tenant email providers and templates, signup welcome and security notices;
  see [docs/email.md](docs/email.md) for active workflows and stored-only limits

**Tenant settings and attack protection (Plan 19)**

- [Tenant settings](docs/tenant-settings.md), [attack protection and automatic blocks](docs/attack-protection.md)

**Signing keys and deployment migration (Plan 20)**

- Managed signing keys, stored-only custom public JWKS, and credential-preserving bootstrap are implemented.
- The pinned Deploy CLI passes local YAML/directory imports for clients, APIs, grants and tenant settings, with generated or preserved credentials. Three handlers await future APIs; the upstream observer lane remains unavailable. See [signing keys](docs/signing-keys.md) and [Deploy CLI migration](docs/deploy-cli.md) for current limits.

**Branding and Universal Login (Plan 22)**

- Tenant branding, themes, bounded page templates, identifier-first login, localized text and transient form partials; console editors with isolated preview. See [branding](docs/branding.md) and the [implementation record](docs/superpowers/plan-22-implementation-record.md) for supported syntax and compatibility limits.

**Custom domains and automatic certificates (Plan 23)**

- Verified domain ownership, shared automatic TLS, authenticated customer proxies,
  domain-bound login and notification links, and console controls. See the
  [operator guide](docs/custom-domains.md) and [acceptance record](docs/superpowers/2026-10-26-plan-23-implementation-record.md).

**Later** (Plans 29–47)

| Plans | Area |
|---|---|
| 29 | Organizations I: organizations, members, roles, enabled connections, login with an organization | full | 26 |
| 30 | Organizations II: invitations, client grants, discovery domains | short | 29, 21 |
| 31 | Logs, log streams, stats | full | 19 |
| 32 | Event streams | short | 31 |
| 33 | MFA I: OTP, email, recovery codes, WebAuthn, policies, the MFA API, user authentication methods | full | 21, 27 |
| 34 | Passwordless and phone: email and SMS connections, phone providers and templates, MFA by SMS and voice | full | 33 |
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

Of the roadmap's 42 resource groupings, 20 are done, 18 are planned and 4 are not planned (Rules, Hooks and
rules-configs, which Auth0 is retiring, and customer-managed encryption keys).

## Quick start

```bash
go build -o bin/zeroauthy ./cmd/zeroauthy

# Self-signed certificate for localhost (SDKs require HTTPS).
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" -keyout key.pem -out cert.pem

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

API reference: `https://localhost:8443/docs`. The raw contract is at
`/openapi.yaml`, and its source is [api/authentication.yaml](api/authentication.yaml).

## Configuration

YAML file (`--config`) plus `ZEROAUTHY_*` environment variables. `__`
separates levels: `ZEROAUTHY_STORAGE__DSN=memory://` sets `storage.dsn`.
See [internal/config/config.go](internal/config/config.go) for every
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

**Master key.** Signing keys and client secrets are stored envelope-encrypted under a 32-byte
master key. Generate one with `openssl rand -base64 32` and set it as
`ZEROAUTHY_SECURITY__MASTER_KEY` (or point `security.master_key_file` at a
file containing it). It is required for persistent storage; with
`memory://` storage zeroauthy uses an ephemeral key and logs a warning.

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
requires a migrated database and ignores `storage.auto_migrate`. MySQL
commits DDL implicitly, so if a migration fails part-way there, clean up the
objects it created by hand before running `zeroauthy migrate` again.

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
operator, the server creates that one and logs the link once. No password is
ever taken from configuration. Operators sign in to the
[admin console](docs/console.md) at `/admin/` on that host.

**Proxies.** Enable `server.trust_proxy_headers` only behind a proxy that
sets `X-Forwarded-Host`; otherwise clients could choose their own tenant.

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

## Development

```bash
make test           # unit + contract + storage conformance tests (memory and SQLite)
make test-sql       # SQL driver tests against PostgreSQL 17 and MySQL 8.4 containers (needs podman or docker)
make generate       # regenerate code from api/authentication.yaml and api/management.yaml
make console        # lint, test and rebuild the admin console (needs Node 22+)
make e2e            # Auth0 SDKs against a live zeroauthy on SQLite (needs Node 22+, openssl)
make check-sources  # verify every x-source provenance link
make conformance    # OpenID conformance suite against zeroauthy (podman or docker, Linux; ~10-20 min)
```

## OpenID conformance

zeroauthy is tested against the OpenID Foundation conformance suite for the Basic OP, Config OP, Form Post OP and RP-Initiated Logout OP profiles. `make conformance` runs all four locally in containers (Linux, podman or docker). Local results pass, with a few accepted warnings and skips; formal certification is pending. See [docs/conformance.md](docs/conformance.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
