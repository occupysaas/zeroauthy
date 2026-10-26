#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
node --test tests/e2e/domains/client.test.mjs
work=$(mktemp -d)
pids=()
start() { setsid "$@" & pids+=("$!"); }
cleanup() {
 trap - EXIT INT TERM
 for p in "${pids[@]}"; do kill -TERM -- "-$p" 2>/dev/null || true; done
 if [[ ${E2E_KEEP_WORK:-0} == 1 ]]; then echo "Plan23 artifacts: $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Plan23 local test root' \
 -addext 'subjectAltName=DNS:sdk.e2e.test,DNS:cli.e2e.test,DNS:system.e2e.test,DNS:*.domains.e2e.test,DNS:*.origin.e2e.test' \
 -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
export E2E_CERT="$work/cert.pem" E2E_KEY="$work/key.pem" E2E_DATABASE="$work/domains.db" E2E_SETUP_FILE="$work/setup" E2E_SEED="$work/seed.yaml"
export NODE_EXTRA_CA_CERTS="$work/cert.pem"
cat > "$work/seed.yaml" <<'YAML'
tenants:
  - name: domains
    friendly_name: Domain acceptance
    domains: [sdk.e2e.test]
    skip_non_verifiable_callback_uri_confirmation_prompt: true
    default_directory: Username-Password-Authentication
    clients:
      - client_id: m23-admin
        app_type: non_interactive
        client_secret: m23-admin-secret-not-for-production
        grant_types: [client_credentials]
      - client_id: m23-spa
        name: Domain browser
        app_type: spa
        grant_types: [authorization_code, refresh_token]
        callbacks: [https://callback.e2e.test/]
        allowed_logout_urls: [https://callback.e2e.test/]
    client_grants:
      - client_id: m23-admin
        audience: https://sdk.e2e.test/api/v2/
        scopes: [read:custom_domains, create:custom_domains, update:custom_domains, delete:custom_domains, read:branding, update:branding, create:branding, delete:branding, create:users, read:users, create:user_tickets, read:attack_protection, update:attack_protection, read:anomaly_blocks]
    connections:
      - name: Username-Password-Authentication
        is_domain_connection: true
        enabled_clients: [m23-spa]
  - name: secondary
    friendly_name: Secondary domains
    domains: [cli.e2e.test]
    clients:
      - client_id: m23-admin
        app_type: non_interactive
        client_secret: m23-admin-secret-not-for-production
        grant_types: [client_credentials]
    client_grants:
      - client_id: m23-admin
        audience: https://cli.e2e.test/api/v2/
        scopes: [read:custom_domains, create:custom_domains, update:custom_domains, delete:custom_domains]
YAML
go build -o "$work/harness" ./tests/e2e/domains/harness
start "$work/harness" >"$work/server.log" 2>&1
PROXY_PORT=9098 TARGET_PORT=9443 start node tests/e2e/connect-proxy.mjs >"$work/proxy.log" 2>&1
PROXY_PORT=9099 TARGET_PORT=9444 start node tests/e2e/connect-proxy.mjs >"$work/proxy2.log" 2>&1
for _ in $(seq 1 100); do
 if curl -fsS http://127.0.0.1:9073/healthz >/dev/null 2>&1 && curl -s http://127.0.0.1:9098 >/dev/null && curl -s http://127.0.0.1:9099 >/dev/null; then break; fi
 sleep 0.1
done
if ! curl -fsS http://127.0.0.1:9073/healthz >/dev/null; then cat "$work/server.log"; exit 1; fi
export E2E_ADMIN_SETUP_URL_M23="$(cat "$work/setup")"
if [[ ${E2E_M23_BROWSER_ONLY:-0} != 1 ]]; then
 node tests/e2e/m23-node-auth0.mjs
 if [[ -z ${AUTH0_BIN:-} ]]; then GOBIN="$work/bin" go install github.com/auth0/auth0-cli/cmd/auth0@v1.37.0; export AUTH0_BIN="$work/bin/auth0"; fi
 "$AUTH0_BIN" --version | head -1
 node tests/e2e/m23-mgmt-cli.mjs
fi
if [[ ${E2E_M23_SKIP_BROWSER:-0} != 1 ]]; then
 cd tests/e2e
 ./node_modules/.bin/playwright test m23-domains.spec.mjs --config playwright.config.mjs --output "$work/playwright-results"
fi
