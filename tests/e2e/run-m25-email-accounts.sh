#!/usr/bin/env bash
# make e2e-email-accounts: two zeroauthy nodes and mock Google/OAuth 2/OIDC providers;
# the real pinned node-auth0 SDK and Auth0 CLI, and Playwright logins through
# actual code exchanges. No live provider is ever contacted.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec 9>/tmp/zeroauthy-e2e-social.lock
flock 9
work=$(mktemp -d)
pids=()
start() { setsid "$@" & pids+=("$!"); }
cleanup() {
 trap - EXIT INT TERM
 for p in "${pids[@]}"; do kill -TERM -- "-$p" 2>/dev/null || true; done
 if [[ ${E2E_KEEP_WORK:-0} == 1 ]]; then echo "Plan25 artifacts: $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
node --version | grep -qE '^v(2[5-9]|[3-9][0-9])\.' || { echo "e2e-email-accounts needs Node 25+ for profile scripts" >&2; exit 1; }
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Plan25 local test root' \
 -addext 'subjectAltName=DNS:sdk.e2e.test,DNS:idp.e2e.test,DNS:system.e2e.test,DNS:callback.e2e.test,DNS:cli.e2e.test,DNS:email.custom.e2e.test,DNS:*.origin.e2e.test' \
 -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
export E2E_CERT="$work/cert.pem" E2E_KEY="$work/key.pem" E2E_DATABASE="$work/social.db" E2E_SETUP_FILE="$work/setup" E2E_SEED="$work/seed.yaml"
export NODE_EXTRA_CA_CERTS="$work/cert.pem"
cat > "$work/seed.yaml" <<'YAML'
tenants:
  - name: social
    friendly_name: Social acceptance
    domains: [sdk.e2e.test]
    skip_non_verifiable_callback_uri_confirmation_prompt: true
    default_directory: Username-Password-Authentication
    clients:
      - {client_id: m24-admin, app_type: non_interactive, client_secret: m24-admin-secret-not-for-production, grant_types: [client_credentials]}
      - {client_id: m24-reader, app_type: non_interactive, client_secret: m24-reader-secret-not-for-production, grant_types: [client_credentials]}
      - client_id: m24-spa
        name: Social browser
        app_type: spa
        grant_types: [authorization_code, refresh_token]
        callbacks: [https://callback.e2e.test/]
    client_grants:
      - client_id: m24-admin
        audience: https://sdk.e2e.test/api/v2/
        scopes: [read:connections, create:connections, update:connections, delete:connections, read:users, create:users, update:users, delete:users, read:clients, read:custom_domains, create:custom_domains, update:custom_domains, delete:custom_domains]
      - client_id: m24-reader
        audience: https://sdk.e2e.test/api/v2/
        scopes: [read:users, read:user_idp_tokens]
    connections:
      - name: Username-Password-Authentication
        is_domain_connection: true
        enabled_clients: [m24-spa]
YAML
go build -o "$work/harness" ./tests/e2e/social/harness
start "$work/harness" >"$work/server.log" 2>&1
PROXY_PORT=9198 TARGET_PORT=9543 start node tests/e2e/connect-proxy.mjs >"$work/proxy.log" 2>&1
PROXY_PORT=9199 TARGET_PORT=9544 start node tests/e2e/connect-proxy.mjs >"$work/proxy2.log" 2>&1
for _ in $(seq 1 150); do
 if curl -fsS http://127.0.0.1:9173/healthz >/dev/null 2>&1 && curl -s http://127.0.0.1:9198 >/dev/null && curl -s http://127.0.0.1:9199 >/dev/null; then break; fi
 sleep 0.1
done
if ! curl -fsS http://127.0.0.1:9173/healthz >/dev/null; then cat "$work/server.log"; exit 1; fi
export E2E_M25=1 E2E_M25_DOMAIN_FILE="$work/domain.json"
node tests/e2e/m25-node-auth0.mjs setup
( cd tests/e2e && ./node_modules/.bin/playwright test m25-email-accounts.spec.mjs --config playwright.config.mjs --output "$work/playwright-results" )
node tests/e2e/m25-node-auth0.mjs verify
if [[ -z ${AUTH0_BIN:-} ]]; then GOBIN="$work/bin" go install github.com/auth0/auth0-cli/cmd/auth0@v1.37.0; export AUTH0_BIN="$work/bin/auth0"; fi
node tests/e2e/m25-mgmt-cli.mjs
