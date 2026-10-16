# zeroauthy

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
> nextjs-auth0). See the [compatibility matrix](docs/compat/matrix.md).

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
setting. Tenants, APIs, applications and grants come from a declarative
[seed file](tests/e2e/seed.yaml) until the Management API exists.
Unknown configuration keys are rejected at startup.

**Master key.** Signing keys are stored envelope-encrypted under a 32-byte
master key. Generate one with `openssl rand -base64 32` and set it as
`ZEROAUTHY_SECURITY__MASTER_KEY` (or point `security.master_key_file` at a
file containing it). It is required for persistent storage; with
`memory://` storage zeroauthy uses an ephemeral key and logs a warning.

**Storage.** `storage.dsn` selects the driver:

| DSN | Driver |
|-----|--------|
| `memory://` | In memory; lost on exit (tests, demos) |
| `sqlite:///var/lib/zeroauthy/zeroauthy.db` | SQLite (pure Go, no CGO); `sqlite://relative.db` is relative to the working directory |
| `postgres://user:pass@host:5432/db?sslmode=require` | PostgreSQL 14+ (`postgresql://` also works) |
| `mysql://user:pass@host:3306/db` | MySQL 8.0.17+ (MariaDB is not supported) |
| `plugin:///abs/path/to/binary?arg=x&arg=y` | External gRPC storage plugin; each `arg` becomes one argument of the binary. Needs `security.master_key` |

**Writing a storage plugin.** A plugin is a Go program that calls
`pkg/storeplugin.Serve` with any `store.Store`; `cmd/zeroauthy-store-memory`
is a minimal template. Check your driver by running
`storetest.Run` (package `pkg/storetest`) with a factory that calls
`storeplugin.Open` on your built binary. Transactions work across the
boundary; see decision D-0021 for the protocol.

The SQL drivers have a schema. Apply pending migrations with
`zeroauthy migrate --config zeroauthy.yaml` before starting a new version,
or set `storage.auto_migrate: true` (`ZEROAUTHY_STORAGE__AUTO_MIGRATE=true`)
to have `serve` migrate at startup. Without it, `serve` refuses to start
against a schema that is behind or ahead of the binary. `zeroauthy seed`
requires a migrated database and ignores `storage.auto_migrate`. MySQL
commits DDL implicitly, so if a migration fails part-way there, clean up the
objects it created by hand before running `zeroauthy migrate` again.

**Proxies.** Enable `server.trust_proxy_headers` only behind a proxy that
sets `X-Forwarded-Host`; otherwise clients could choose their own tenant.

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
make generate       # regenerate code from api/authentication.yaml
make e2e            # Auth0 SDKs against a live zeroauthy on SQLite (needs Node 22+, openssl)
make check-sources  # verify every x-source provenance link
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
