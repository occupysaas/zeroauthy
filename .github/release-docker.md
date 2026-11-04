
## Run it with Docker

```sh
docker run -d --name zeroauthy -p 8443:8443 -v zeroauthy-data:/data \
  -e ZEROAUTHY_SERVER__LISTEN=:8443 \
  -e ZEROAUTHY_SERVER__SYSTEM_HOST=localhost:8443 \
  -e ZEROAUTHY_SERVER__TLS_SELF_SIGNED=true \
  -e ZEROAUTHY_SERVER__TLS_SELF_SIGNED_CA_FILE=/data/ca.pem \
  -e ZEROAUTHY_SECURITY__MASTER_KEY="$(openssl rand -base64 32)" \
  -e ZEROAUTHY_BOOTSTRAP__ADMIN_EMAIL=you@example.com \
  ghcr.io/@REPOSITORY@:@VERSION@
```

Images are multi-arch (linux/amd64, linux/arm64). Every setting is a
`ZEROAUTHY_*` environment variable (`__` separates levels:
`ZEROAUTHY_STORAGE__DSN` sets `storage.dsn`); the full list with defaults is
in the [configuration reference](https://github.com/@REPOSITORY@/blob/@TAG@/docs/configuration.md).

| Variable | Needed | Purpose |
| --- | --- | --- |
| `ZEROAUTHY_SERVER__SYSTEM_HOST` | yes | Host (and port) of the admin console and system API |
| `ZEROAUTHY_SECURITY__MASTER_KEY` or `ZEROAUTHY_SECURITY__MASTER_KEY_FILE` | yes | 32-byte base64 key that seals stored secrets. Back it up: it cannot be rotated, and a database backup is useless without it |
| `ZEROAUTHY_STORAGE__DSN` | no | Defaults to SQLite in `/data`; `memory://` for throwaway test runs; `postgres://…` or `mysql://…` |
| `ZEROAUTHY_SERVER__TLS_CERT_FILE` / `ZEROAUTHY_SERVER__TLS_KEY_FILE` | for production | Your certificate. SDKs require HTTPS |
| `ZEROAUTHY_SERVER__TLS_SELF_SIGNED` | for tests | Generates a local CA and certificate at startup; `…_CA_FILE` writes the CA for your test runner to trust |
| `ZEROAUTHY_SEED` | no | Path to a seed file that creates tenants, applications, APIs and users on start |
| `ZEROAUTHY_BOOTSTRAP__ADMIN_EMAIL` | first start | Creates the first console operator and logs where the setup link was written |

**Testing your app against an Auth0-compatible server.** zeroauthy can stand
in for Auth0 in local and CI end-to-end tests with real logins: start the
image with a seed file and `memory://` storage, point your SDK's domain at
it, and throw it away after the run. See the
[testing guide](https://github.com/@REPOSITORY@/blob/@TAG@/docs/testing.md).

Start here: [quickstart](https://github.com/@REPOSITORY@/blob/@TAG@/docs/quickstart.md) ·
[deployment](https://github.com/@REPOSITORY@/blob/@TAG@/docs/deployment.md) ·
[upgrading](https://github.com/@REPOSITORY@/blob/@TAG@/docs/upgrading.md) ·
[compatibility](https://github.com/@REPOSITORY@/blob/@TAG@/docs/compatibility.md).
Verify downloads with `sha256sum -c SHA256SUMS` and
`gh attestation verify <file> --repo @REPOSITORY@`.
