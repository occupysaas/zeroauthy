#!/usr/bin/env bash
# tests/e2e/run-m3.sh: build zeroauthy, serve it over TLS on localhost:8443,
# and run the SDK black-box test against it. Storage is SQLite (auto-migrated),
# so the SQL driver is exercised end to end.
set -euo pipefail
cd "$(dirname "$0")/../.."

# Fixed: tests/e2e/seed.yaml, m9-custom-db.mjs and m9-import.spec.mjs use 8099.
LEGACY_PORT=8099
work="$(mktemp -d)"
mkdir -p "$work/mail"
export E2E_MAIL_DIR="$work/mail"
pids=()

# start CMD...: run in the background in its own session and process group, so
# cleanup kills the whole tree. The pid is left in $started.
started=""
start() {
  setsid "$@" &
  started=$!
  pids+=("$started")
}
cleanup() {
  trap - EXIT INT TERM
  for p in "${pids[@]}"; do kill -TERM -- "-$p" 2>/dev/null || kill "$p" 2>/dev/null || true; done
  sleep 0.3
  for p in "${pids[@]}"; do kill -KILL -- "-$p" 2>/dev/null || true; done
  rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

legacy_stats() {
  curl -sf -H "Authorization: Bearer e2e-legacy-token" "http://127.0.0.1:$LEGACY_PORT/stats" >/dev/null
}

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:cli.e2e.test" \
  -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null

if legacy_stats; then
  echo "port $LEGACY_PORT is already in use by another legacy store" >&2
  exit 1
fi
LEGACY_PORT=$LEGACY_PORT LEGACY_TOKEN=e2e-legacy-token start node tests/e2e/legacy-store.mjs >"$work/legacy.log" 2>&1
legacy_pid=$started
for _ in $(seq 1 50); do
  legacy_stats && break
  sleep 0.2
done
if ! legacy_stats || ! kill -0 "$legacy_pid" 2>/dev/null; then
  echo "legacy store did not start (is port $LEGACY_PORT in use?)" >&2
  cat "$work/legacy.log" >&2
  exit 1
fi

CGO_ENABLED=0 go build -o "$work/zeroauthy" ./cmd/zeroauthy
# The pinned auth0-cli (m13-mgmt-cli.mjs), built from its module.
AUTH0_CLI_VERSION=v1.37.0
GOBIN="$work/bin" go install "github.com/auth0/auth0-cli/cmd/auth0@$AUTH0_CLI_VERSION"
start node tests/e2e/connect-proxy.mjs >"$work/proxy.log" 2>&1

ZEROAUTHY_SERVER__TLS_CERT_FILE="$work/cert.pem" \
ZEROAUTHY_SERVER__TLS_KEY_FILE="$work/key.pem" \
ZEROAUTHY_EMAIL__DIR="$work/mail" \
ZEROAUTHY_STORAGE__DSN="sqlite://$work/e2e.db" \
ZEROAUTHY_STORAGE__AUTO_MIGRATE=true \
ZEROAUTHY_SECURITY__MASTER_KEY="$(openssl rand -base64 32)" \
  start "$work/zeroauthy" serve --config tests/e2e/config.yaml >"$work/server.log" 2>&1
pid=$started

dump_logs() {
  for log in "$work"/*.log; do
    echo "--- $(basename "$log") ---"
    cat "$log"
  done
}

# Fail fast if the server exits (bad config, port in use) instead of polling
# for the full ~10 s; fail if it never becomes healthy.
ready=0
for _ in $(seq 1 50); do
  if curl -sf --cacert "$work/cert.pem" https://localhost:8443/healthz >/dev/null; then
    ready=1
    break
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "zeroauthy exited before becoming ready" >&2
    break
  fi
  sleep 0.2
done
if [[ $ready -ne 1 ]]; then
  echo "zeroauthy did not become ready on https://localhost:8443" >&2
  dump_logs >&2
  exit 1
fi

status=0
npm_log="$work/npm-ci.log"
(cd tests/e2e && npm ci --no-audit --no-fund --silent >"$npm_log" 2>&1) || {
  echo "npm ci failed" >&2
  cat "$npm_log" >&2
  exit 1
}
(cd tests/e2e && \
  NODE_ENV=test NODE_EXTRA_CA_CERTS="$work/cert.pem" node m3-client-credentials.mjs && \
  NODE_ENV=test NODE_EXTRA_CA_CERTS="$work/cert.pem" node m3-db-flows.mjs && \
  NODE_ENV=test NODE_EXTRA_CA_CERTS="$work/cert.pem" node m9-custom-db.mjs && \
  AUTH0_BIN="$work/bin/auth0" E2E_CERT="$work/cert.pem" node m13-mgmt-cli.mjs && \
  AUTH0_BIN="$work/bin/auth0" E2E_CERT="$work/cert.pem" node m14-mgmt-cli.mjs && \
  AUTH0_BIN="$work/bin/auth0" E2E_CERT="$work/cert.pem" node m15-mgmt-cli.mjs) || status=$?
if [[ $status -ne 0 ]]; then
  dump_logs
fi
exit $status
