#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

work="$(mktemp -d)"
mkdir -p "$work/mail"
pids=()
started=""
start() { setsid "$@" & started=$!; pids+=("$started"); }
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

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:cli.e2e.test,DNS:target.cli.e2e.test" \
  -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
CGO_ENABLED=0 go build -o "$work/zeroauthy" ./cmd/zeroauthy
PROXY_PORT=8098 TARGET_PORT=8443 start node tests/e2e/connect-proxy.mjs >"$work/proxy.log" 2>&1
export ZEROAUTHY_SERVER__TLS_CERT_FILE="$work/cert.pem"
export ZEROAUTHY_SERVER__TLS_KEY_FILE="$work/key.pem"
export ZEROAUTHY_STORAGE__AUTO_MIGRATE=true
export ZEROAUTHY_SECURITY__MASTER_KEY="$(openssl rand -base64 32)"
export ZEROAUTHY_EMAIL__DIR="$work/mail"
export ZEROAUTHY_SEED_MODE=create_only
export NODE_EXTRA_CA_CERTS="$work/cert.pem"
export E2E_M20_CONFIG="$PWD/tests/e2e/deploy-cli/config.json"
export E2E_M20_BINARY="$work/zeroauthy"
serve() {
  start "$work/zeroauthy" serve --config tests/e2e/config.yaml >>"$E2E_M20_WORK/server.log" 2>&1
  server_pid="$started"
  for _ in $(seq 1 60); do
    if curl -sf --cacert "$work/cert.pem" https://localhost:8443/healthz >/dev/null; then return; fi
    if ! kill -0 "$server_pid" 2>/dev/null; then break; fi
    sleep 0.2
  done
  echo "Plan 20 local deploy server failed to start" >&2
  tail -20 "$E2E_M20_WORK/server.log" >&2
  return 1
}
stop_server() {
  kill -TERM -- "-$server_pid"
  wait "$server_pid" || true
}
modes=(generated preserved)
formats=(yaml directory)
if [[ -n "${E2E_M20_ONLY_MODE:-}" ]]; then modes=("$E2E_M20_ONLY_MODE"); fi
if [[ -n "${E2E_M20_ONLY_FORMAT:-}" ]]; then formats=("$E2E_M20_ONLY_FORMAT"); fi
for mode in "${modes[@]}"; do
  for format in "${formats[@]}"; do
    export E2E_M20_MODE="$mode" E2E_M20_FORMAT="$format"
    export E2E_M20_WORK="$work/$mode-$format"
    mkdir -m 700 "$E2E_M20_WORK"
    export ZEROAUTHY_STORAGE__DSN="sqlite://$E2E_M20_WORK/e2e.db"
    export ZEROAUTHY_SEED="$E2E_M20_WORK/seed.yaml"
    if [[ "$mode" == preserved ]]; then
      sed '/^  - name: e2ecli-target/,$d' tests/e2e/deploy-cli/seed.yaml >"$ZEROAUTHY_SEED"
    else
      cp tests/e2e/deploy-cli/seed.yaml "$ZEROAUTHY_SEED"
    fi
    serve
    E2E_M20_PHASE=prepare node tests/e2e/m20-deploy-cli.mjs
    stop_server
    # Startup creates signing keys for the offline-bootstrapped tenant. The
    # create-only seed must not overwrite its preserved client credentials.
    serve
    E2E_M20_PHASE=verify node tests/e2e/m20-deploy-cli.mjs
    stop_server
  done
done
echo "Plan 20 deploy-cli: databases,connections,attackProtection unavailable (required APIs outside this milestone)"
echo "Plan 20 upstream lane: unavailable (no observer credentials supplied); no upstream call made"
