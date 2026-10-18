#!/usr/bin/env bash
# tests/e2e/run-m3.sh: build zeroauthy, serve it over TLS on localhost:8443,
# and run the SDK black-box test against it. Storage is SQLite (auto-migrated),
# so the SQL driver is exercised end to end.
set -euo pipefail
cd "$(dirname "$0")/../.."

work="$(mktemp -d)"
mkdir -p "$work/mail"
export E2E_MAIL_DIR="$work/mail"
pid=""
legacy_pid=""
proxy_pid=""
cleanup() {
  [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
  [[ -n "$legacy_pid" ]] && kill "$legacy_pid" 2>/dev/null || true
  [[ -n "$proxy_pid" ]] && kill "$proxy_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:cli.e2e.test" \
  -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null

if curl -sf -H "Authorization: Bearer e2e-legacy-token" http://127.0.0.1:8099/stats >/dev/null; then
  echo "port 8099 is already in use by another legacy store" >&2
  exit 1
fi
LEGACY_TOKEN=e2e-legacy-token node tests/e2e/legacy-store.mjs >"$work/legacy.log" 2>&1 &
legacy_pid=$!
for _ in $(seq 1 50); do
  curl -sf -H "Authorization: Bearer e2e-legacy-token" http://127.0.0.1:8099/stats >/dev/null && break
  sleep 0.2
done
if ! curl -sf -H "Authorization: Bearer e2e-legacy-token" http://127.0.0.1:8099/stats >/dev/null || ! kill -0 "$legacy_pid" 2>/dev/null; then
  echo "legacy store did not start (is port 8099 in use?)" >&2
  cat "$work/legacy.log" >&2
  exit 1
fi

CGO_ENABLED=0 go build -o "$work/zeroauthy" ./cmd/zeroauthy
# The pinned auth0-cli (m13-mgmt-cli.mjs), built from its module.
AUTH0_CLI_VERSION=v1.37.0
GOBIN="$work/bin" go install "github.com/auth0/auth0-cli/cmd/auth0@$AUTH0_CLI_VERSION"
node tests/e2e/connect-proxy.mjs >"$work/proxy.log" 2>&1 &
proxy_pid=$!

ZEROAUTHY_SERVER__TLS_CERT_FILE="$work/cert.pem" \
ZEROAUTHY_SERVER__TLS_KEY_FILE="$work/key.pem" \
ZEROAUTHY_EMAIL__DIR="$work/mail" \
ZEROAUTHY_STORAGE__DSN="sqlite://$work/e2e.db" \
ZEROAUTHY_STORAGE__AUTO_MIGRATE=true \
ZEROAUTHY_SECURITY__MASTER_KEY="$(openssl rand -base64 32)" \
  "$work/zeroauthy" serve --config tests/e2e/config.yaml >"$work/server.log" 2>&1 &
pid=$!

for _ in $(seq 1 50); do
  curl -sf --cacert "$work/cert.pem" https://localhost:8443/healthz >/dev/null && break
  sleep 0.2
done

status=0
(cd tests/e2e && npm ci --no-audit --no-fund --silent && \
  NODE_ENV=test NODE_EXTRA_CA_CERTS="$work/cert.pem" node m3-client-credentials.mjs && \
  NODE_ENV=test NODE_EXTRA_CA_CERTS="$work/cert.pem" node m3-db-flows.mjs && \
  NODE_ENV=test NODE_EXTRA_CA_CERTS="$work/cert.pem" node m9-custom-db.mjs && \
  AUTH0_BIN="$work/bin/auth0" E2E_CERT="$work/cert.pem" node m13-mgmt-cli.mjs) || status=$?
if [[ $status -ne 0 ]]; then
  echo "--- zeroauthy server log ---"
  cat "$work/server.log"
  echo "--- legacy store log ---"
  cat "$work/legacy.log"
  echo "--- connect proxy log ---"
  cat "$work/proxy.log"
fi
exit $status
