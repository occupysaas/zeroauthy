#!/usr/bin/env bash
set -euo pipefail
# Serialize local lanes sharing HTTPS port 8443.
exec 9>/tmp/zeroauthy-e2e8443.lock
flock 9
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
  -addext "subjectAltName=DNS:localhost,DNS:cli.e2e.test,DNS:target.cli.e2e.test,DNS:idp.e2e.test,DNS:*.origin.e2e.test" \
  -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
CGO_ENABLED=0 go build -o "$work/zeroauthy" ./cmd/zeroauthy
# The production app with only federation transport pointed at a local mock
# provider (constructor option); OAuth profile scripts need Node 25+.
node --version | grep -qE '^v(2[5-9]|[3-9][0-9])\.' || { echo "e2e-deploy needs Node 25+ for OAuth profile scripts" >&2; exit 1; }
go build -o "$work/deploy-server" ./tests/e2e/deploy-cli/server
start node tests/e2e/deploy-cli/connect-proxy.mjs >"$work/proxy.log" 2>&1
go build -o "$work/dns-fixture" ./tests/e2e/deploy-cli/dns-fixture
start "$work/dns-fixture" >"$work/dns.log" 2>&1
for _ in $(seq 1 60); do
  if curl -sf http://127.0.0.1:8064/healthz >/dev/null; then break; fi
  sleep 0.2
done
export ZEROAUTHY_SERVER__CUSTOM_DOMAINS__DNS_RESOLVER=127.0.0.1:8063
export ZEROAUTHY_SERVER__CUSTOM_DOMAINS__ORIGIN_DOMAIN=origin.e2e.test
export ZEROAUTHY_SERVER__TRUSTED_PROXY_CIDRS=127.0.0.0/8
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
  E2E_IDP_LISTEN="127.0.0.1:$((serve_port + 2))" start "$work/deploy-server" >>"$E2E_M20_WORK/server.log" 2>&1
  server_pid="$started"
  for _ in $(seq 1 60); do
    if curl -sf --cacert "$work/cert.pem" https://localhost:${serve_port}/healthz >/dev/null; then return; fi
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
    export E2E_M20_SOURCE_DSN="sqlite://$E2E_M20_WORK/source.db"
    export E2E_M20_TARGET_DSN="sqlite://$E2E_M20_WORK/target.db"
    export E2E_M20_SOURCE_SEED="$E2E_M20_WORK/source-seed.yaml"
    export E2E_M20_TARGET_SEED="$E2E_M20_WORK/target-seed.yaml"
    node --input-type=module -e 'import fs from "node:fs"; import yaml from "./tests/e2e/node_modules/js-yaml/index.js"; const fixture=yaml.load(fs.readFileSync("tests/e2e/deploy-cli/seed.yaml","utf8")); fs.writeFileSync(process.env.E2E_M20_SOURCE_SEED,yaml.dump({tenants:[fixture.tenants[0]]})); fs.writeFileSync(process.env.E2E_M20_TARGET_SEED,yaml.dump({tenants:[fixture.tenants[1]]}));'
    export ZEROAUTHY_STORAGE__DSN="$E2E_M20_SOURCE_DSN" ZEROAUTHY_SEED="$E2E_M20_SOURCE_SEED" ZEROAUTHY_SERVER__LISTEN=:8443
    serve_port=8443
    serve
    source_pid="$server_pid"
    # The offline bootstrap requires an existing schema but an absent target
    # tenant. Migrate the separate destination before the preserved-ID lane.
    ZEROAUTHY_STORAGE__DSN="$E2E_M20_TARGET_DSN" "$work/zeroauthy" migrate --config tests/e2e/config.yaml >"$E2E_M20_WORK/target-migration.log" 2>&1
    E2E_M20_PHASE=prepare node tests/e2e/m20-deploy-cli.mjs
    export ZEROAUTHY_STORAGE__DSN="$E2E_M20_TARGET_DSN" ZEROAUTHY_SEED="$E2E_M20_TARGET_SEED" ZEROAUTHY_SERVER__LISTEN=:8444
    serve_port=8444
    serve
    E2E_M20_PHASE=verify node tests/e2e/m20-deploy-cli.mjs
    stop_server
    server_pid="$source_pid"
    stop_server
  done
done
echo "Plan 20 deploy-cli: databases,attackProtection unavailable (required APIs outside this milestone)"
echo "Plan 20 upstream lane: unavailable (no observer credentials supplied); no upstream call made"
