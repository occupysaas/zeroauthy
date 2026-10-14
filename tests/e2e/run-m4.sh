#!/usr/bin/env bash
# tests/e2e/run-m4.sh: build zeroauthy, serve it and a test SPA over TLS,
# and drive auth0-spa-js in Chromium with Playwright.
# E2E_IN_CONTAINER=1 runs Playwright in the official container image
# (docker or podman) instead of on the host.
set -euo pipefail
cd "$(dirname "$0")/../.."

work="$(mktemp -d)"
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$work"; }
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" \
  -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
chmod 644 "$work/key.pem"

CGO_ENABLED=0 go build -o "$work/zeroauthy" ./cmd/zeroauthy
ZEROAUTHY_SERVER__TLS_CERT_FILE="$work/cert.pem" ZEROAUTHY_SERVER__TLS_KEY_FILE="$work/key.pem" \
  "$work/zeroauthy" serve --config tests/e2e/config.yaml >"$work/server.log" 2>&1 &
pids+=($!)

cd tests/e2e
npm ci --no-audit --no-fund --silent
E2E_CERT="$work/cert.pem" E2E_KEY="$work/key.pem" node spa-server.mjs >"$work/spa.log" 2>&1 &
pids+=($!)

for url in https://localhost:8443/healthz https://localhost:3443/; do
  for _ in $(seq 1 50); do curl -sf --cacert "$work/cert.pem" "$url" >/dev/null && break; sleep 0.2; done
done

status=0
if [[ "${E2E_IN_CONTAINER:-0}" == 1 ]]; then
  runtime="$(command -v docker || command -v podman)"
  "$runtime" run --rm --network host --ipc host \
    -v "$PWD:/e2e" -v "$work:$work:ro" -w /e2e \
    -e NODE_EXTRA_CA_CERTS="$work/cert.pem" \
    mcr.microsoft.com/playwright:v1.64.0-noble npx playwright test || status=$?
else
  npx playwright install chromium >/dev/null
  NODE_EXTRA_CA_CERTS="$work/cert.pem" npx playwright test || status=$?
fi
if [[ $status -ne 0 ]]; then
  echo "--- zeroauthy log ---"; cat "$work/server.log"
  echo "--- spa log ---"; cat "$work/spa.log"
fi
exit $status
