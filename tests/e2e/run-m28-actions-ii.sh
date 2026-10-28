#!/usr/bin/env bash
# Plan28 local SQLite/SDK/CLI/browser acceptance. Reuses the original federation
# fixture's two real server nodes, local provider and DNS-proof control plane.
set -euo pipefail
cd "$(dirname "$0")/../.."
for tool in node go openssl curl tar flock; do
 command -v "$tool" >/dev/null || { echo "e2e-actions-ii unavailable: missing $tool" >&2; exit 1; }
done
export AUTH0_BIN="${AUTH0_BIN:-$(command -v auth0 || true)}"
[[ -x "$AUTH0_BIN" && -x tests/e2e/node_modules/.bin/playwright ]] || { echo "e2e-actions-ii unavailable: pinned Auth0 CLI and installed Playwright are required" >&2; exit 1; }
"$AUTH0_BIN" --version | grep -q "1.37.0" || { echo "e2e-actions-ii unavailable: Auth0 CLI 1.37.0 is required" >&2; exit 1; }
exec 9>/tmp/zeroauthy-e2e-social.lock
flock 9
work=$(mktemp -d)
pids=()
start() { setsid "$@" & pids+=("$!"); }
cleanup() {
 trap - EXIT INT TERM
 for p in "${pids[@]}"; do kill -TERM -- "-$p" 2>/dev/null || true; done
 if [[ ${E2E_KEEP_WORK:-0} == 1 ]]; then echo "Plan28 artifacts: $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Plan28 local test root' \
 -addext 'subjectAltName=DNS:sdk.e2e.test,DNS:idp.e2e.test,DNS:system.e2e.test,DNS:callback.e2e.test,DNS:rbac.custom.e2e.test,DNS:*.origin.e2e.test' \
 -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
export E2E_CERT="$work/cert.pem" E2E_KEY="$work/key.pem" E2E_DATABASE="$work/rbac.db" E2E_SETUP_FILE="$work/setup" E2E_SEED="$work/seed.yaml"
export E2E_M28=1 E2E_M28_STATE="$work/actions-ii.json"
export E2E_M27=1 E2E_M27_STATE="$work/actions.json" E2E_ACTIONS_CACHE="$work/actions-cache" E2E_NPM_REGISTRY=http://127.0.0.1:9187/
export NODE_EXTRA_CA_CERTS="$work/cert.pem" E2E_M26=1 E2E_M26_STATE="$work/rbac.json"
cat > "$work/seed.yaml" <<'YAML'
tenants:
  - name: rbac
    friendly_name: RBAC acceptance
    domains: [sdk.e2e.test]
    skip_non_verifiable_callback_uri_confirmation_prompt: true
    default_directory: Username-Password-Authentication
    clients:
      - {client_id: m24-admin, app_type: non_interactive, client_secret: m24-admin-secret-not-for-production, grant_types: [client_credentials]}
      - {client_id: m24-reader, app_type: non_interactive, client_secret: m24-reader-secret-not-for-production, grant_types: [client_credentials]}
      - {client_id: m26-password, app_type: regular_web, client_secret: m26-password-secret-not-for-production, grant_types: [password, 'http://auth0.com/oauth/grant-type/password-realm', refresh_token]}
      - client_id: m24-spa
        web_origins: [https://callback.e2e.test]
        name: Actions browser
        redirection_policy: open_redirect_protection
        app_type: spa
        grant_types: [authorization_code, refresh_token]
        callbacks: [https://callback.e2e.test/, https://callback.e2e.test/spa]
    client_grants:
      - client_id: m24-admin
        audience: https://sdk.e2e.test/api/v2/
        scopes: [read:client_grants, create:client_grants, update:client_grants, delete:client_grants, read:actions, create:actions, update:actions, delete:actions, read:roles, create:roles, update:roles, delete:roles, read:role_members, create:role_members, delete:role_members, read:users, create:users, update:users, delete:users, read:resource_servers, create:resource_servers, update:resource_servers, delete:resource_servers, read:connections, create:connections, update:connections, delete:connections, read:email_provider, create:email_provider, update:email_provider, delete:email_provider, read:email_templates, create:email_templates, update:email_templates, create:user_tickets, read:clients, create:clients, update:clients, delete:clients, read:custom_domains, create:custom_domains, update:custom_domains, delete:custom_domains]
      - client_id: m24-reader
        audience: https://sdk.e2e.test/api/v2/
        scopes: [read:users]
    connections:
      - name: Username-Password-Authentication
        is_domain_connection: true
        enabled_clients: [m24-spa, m26-password]
YAML
node tests/e2e/fixtures/npm-registry/build.mjs "$work/registry"
start node tests/e2e/fixtures/npm-registry/serve.mjs "$work/registry" >"$work/registry.log" 2>&1
export E2E_NPM_REGISTRY
go build -o "$work/harness" ./tests/e2e/social/harness
start "$work/harness" >"$work/server.log" 2>&1
PROXY_PORT=9198 TARGET_PORT=9543 start node tests/e2e/connect-proxy.mjs >"$work/proxy.log" 2>&1
PROXY_PORT=9199 TARGET_PORT=9544 start node tests/e2e/connect-proxy.mjs >"$work/proxy2.log" 2>&1
for _ in $(seq 1 150); do
 if curl -fsS http://127.0.0.1:9173/healthz >/dev/null 2>&1 && curl -s http://127.0.0.1:9198 >/dev/null && curl -s http://127.0.0.1:9199 >/dev/null; then break; fi
 sleep 0.1
done
if ! curl -fsS http://127.0.0.1:9173/healthz >/dev/null; then cat "$work/server.log"; exit 1; fi
node tests/e2e/m28-actions-ii.mjs
export E2E_M26_SETUP_URL="$(cat "$work/setup")"
( cd tests/e2e && ./node_modules/.bin/playwright test m28-actions-ii.spec.mjs --config playwright.config.mjs --output "$work/playwright-results" )
