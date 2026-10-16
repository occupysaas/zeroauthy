#!/usr/bin/env bash
# tests/e2e/run-browser.sh: build zeroauthy, serve it and the test apps over
# TLS, and drive the browser SDK specs (m*-*.spec.mjs) with Playwright.
# Storage is SQLite (auto-migrated), so the SQL driver is exercised end to end.
# E2E_IN_CONTAINER=1 runs Playwright in the official container image
# (docker or podman) instead of on the host.
set -euo pipefail
cd "$(dirname "$0")/../.."

work="$(mktemp -d)"
mkdir -p "$work/mail"
export E2E_MAIL_DIR="$work/mail"
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$work"; }
trap cleanup EXIT

# wait_for URL: poll until it answers, failing fast after ~20 s.
wait_for() {
  for _ in $(seq 1 100); do
    curl -sf --cacert "$work/cert.pem" -o /dev/null "$1" && return 0
    sleep 0.2
  done
  echo "timed out waiting for $1" >&2
  return 1
}

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" \
  -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
chmod 644 "$work/key.pem"

LEGACY_TOKEN=e2e-legacy-token node tests/e2e/legacy-store.mjs >"$work/legacy.log" 2>&1 &
pids+=($!)
for _ in $(seq 1 50); do
  curl -sf -H "Authorization: Bearer e2e-legacy-token" http://127.0.0.1:8099/stats >/dev/null && break
  sleep 0.2
done
if ! curl -sf -H "Authorization: Bearer e2e-legacy-token" http://127.0.0.1:8099/stats >/dev/null || ! kill -0 "${pids[-1]}" 2>/dev/null; then
  echo "legacy store did not start (is port 8099 in use?)" >&2
  cat "$work/legacy.log" >&2
  exit 1
fi

CGO_ENABLED=0 go build -o "$work/zeroauthy" ./cmd/zeroauthy
ZEROAUTHY_SERVER__TLS_CERT_FILE="$work/cert.pem" ZEROAUTHY_SERVER__TLS_KEY_FILE="$work/key.pem" \
  ZEROAUTHY_EMAIL__DIR="$work/mail" ZEROAUTHY_STORAGE__DSN="sqlite://$work/e2e.db" \
  ZEROAUTHY_STORAGE__AUTO_MIGRATE=true ZEROAUTHY_SECURITY__MASTER_KEY="$(openssl rand -base64 32)" \
  "$work/zeroauthy" serve --config tests/e2e/config.yaml >"$work/server.log" 2>&1 &
pids+=($!)

cd tests/e2e
npm ci --no-audit --no-fund --silent
npx esbuild react/app.jsx --bundle --minify --format=iife --jsx=automatic \
  --define:process.env.NODE_ENV='"production"' --outfile="$work/react.js" --log-level=warning
E2E_CERT="$work/cert.pem" E2E_KEY="$work/key.pem" E2E_REACT_BUNDLE="$work/react.js" \
  node spa-server.mjs >"$work/spa.log" 2>&1 &
pids+=($!)
export NEXT_TELEMETRY_DISABLED=1
npx next build next-app >"$work/next-build.log" 2>&1 || { cat "$work/next-build.log"; exit 1; }
AUTH0_DOMAIN=https://localhost:8443 AUTH0_CLIENT_ID=e2e-next \
  AUTH0_CLIENT_SECRET=e2e-next-secret-not-for-production \
  AUTH0_SECRET="$(openssl rand -hex 32)" APP_BASE_URL=http://localhost:3000 \
  NODE_EXTRA_CA_CERTS="$work/cert.pem" \
  npx next start next-app -p 3000 >"$work/next.log" 2>&1 &
pids+=($!)

status=0
wait_for https://localhost:8443/healthz && wait_for https://localhost:3443/ && wait_for http://localhost:3000/ || status=$?

if [[ $status -eq 0 ]]; then
  if [[ "${E2E_IN_CONTAINER:-0}" == 1 ]]; then
    runtime="$(command -v docker || command -v podman)"
    "$runtime" run --rm --network host --ipc host \
      -v "$PWD:/e2e" -v "$work:$work:ro" -v "$work/mail:$work/mail" -w /e2e \
      -e NODE_EXTRA_CA_CERTS="$work/cert.pem" -e E2E_MAIL_DIR="$work/mail" \
      mcr.microsoft.com/playwright:v1.64.0-noble npx playwright test || status=$?
  else
    npx playwright install chromium >/dev/null
    NODE_EXTRA_CA_CERTS="$work/cert.pem" npx playwright test || status=$?
  fi
fi
if [[ $status -ne 0 ]]; then
  for log in "$work"/*.log; do echo "--- $(basename "$log") ---"; cat "$log"; done
fi
exit $status
