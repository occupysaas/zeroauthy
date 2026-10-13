# zeroauthy

An open-source, self-hostable identity server that speaks the Auth0
Authentication API. Point an existing Auth0 SDK at a zeroauthy tenant
domain and it works with no code changes.

zeroauthy is a clean-room implementation built from public documentation
and open standards. It is not affiliated with Auth0 or Okta. See
[CLEAN_ROOM.md](CLEAN_ROOM.md).

> **Status:** early. Multi-tenant discovery, JWKS and the
> `client_credentials` grant work today. See the
> [compatibility matrix](docs/compat/matrix.md).

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

API reference: `https://localhost:8443/docs`. The raw contract is at
`/openapi.yaml`, and its source is [api/authentication.yaml](api/authentication.yaml).

## Configuration

YAML file (`--config`) plus `ZEROAUTHY_*` environment variables. `__`
separates levels: `ZEROAUTHY_STORAGE__DSN=memory://` sets `storage.dsn`.
See [internal/config/config.go](internal/config/config.go) for every
setting. Tenants, APIs, applications and grants come from a declarative
[seed file](tests/e2e/seed.yaml) until the Management API exists.

## Development

```bash
make test           # unit + contract + storage conformance tests
make generate       # regenerate code from api/authentication.yaml
make e2e            # Auth0 SDKs against a live zeroauthy (needs Node 22+, openssl)
make check-sources  # verify every x-source provenance link
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
