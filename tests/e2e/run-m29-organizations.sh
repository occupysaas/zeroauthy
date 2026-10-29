#!/usr/bin/env bash
# Plan29 local SQLite/SDK/CLI/browser acceptance. Reuses the original federation
# fixture's two real server nodes, local provider and DNS-proof control plane.
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
 if [[ ${E2E_KEEP_WORK:-0} == 1 ]]; then echo "Plan29 artifacts: $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Plan29 local test root' \
 -addext 'subjectAltName=DNS:sdk.e2e.test,DNS:idp.e2e.test,DNS:system.e2e.test,DNS:callback.e2e.test,DNS:rbac.custom.e2e.test,DNS:*.origin.e2e.test' \
 -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
export E2E_CERT="$work/cert.pem" E2E_KEY="$work/key.pem" E2E_DATABASE="$work/organizations.db" E2E_SETUP_FILE="$work/setup" E2E_SEED="$work/seed.yaml"
export NODE_EXTRA_CA_CERTS="$work/cert.pem" E2E_M29=1 E2E_M29_STATE="$work/organizations.json"
cat > "$work/seed.yaml" <<'YAML'
tenants:
  - name: organizations
    friendly_name: Organizations acceptance
    domains: [sdk.e2e.test]
    skip_non_verifiable_callback_uri_confirmation_prompt: true
    default_directory: Username-Password-Authentication
    clients:
      - {client_id: m24-admin, app_type: non_interactive, client_secret: m24-admin-secret-not-for-production, grant_types: [client_credentials]}
      - {client_id: m24-reader, app_type: non_interactive, client_secret: m24-reader-secret-not-for-production, grant_types: [client_credentials]}
      - {client_id: m26-password, app_type: regular_web, client_secret: m26-password-secret-not-for-production, grant_types: [password, 'http://auth0.com/oauth/grant-type/password-realm', refresh_token]}
      - client_id: m24-spa
        name: RBAC browser
        app_type: spa
        grant_types: [authorization_code, refresh_token]
        callbacks: [https://callback.e2e.test/, https://callback.e2e.test/org-spa]
        web_origins: [https://callback.e2e.test]
        organization_usage: allow
      - {client_id: m29-pre, app_type: spa, grant_types: [authorization_code], callbacks: [https://callback.e2e.test/], organization_usage: require, organization_require_behavior: pre_login_prompt, organization_discovery_methods: [organization_name]}
      - {client_id: m29-picker, app_type: spa, grant_types: [authorization_code], callbacks: [https://callback.e2e.test/], organization_usage: require, organization_require_behavior: post_login_prompt}
    client_grants:
      - client_id: m24-admin
        audience: https://sdk.e2e.test/api/v2/
        scopes: [read:organizations, create:organizations, update:organizations, delete:organizations, read:organization_connections, create:organization_connections, update:organization_connections, delete:organization_connections, read:organization_members, create:organization_members, delete:organization_members, read:organization_member_roles, create:organization_member_roles, delete:organization_member_roles, read:organization_member_effective_roles, read:organization_client_grants, read:roles, create:roles, update:roles, delete:roles, read:role_members, create:role_members, delete:role_members, read:users, create:users, update:users, delete:users, read:resource_servers, create:resource_servers, update:resource_servers, delete:resource_servers, read:connections, create:connections, update:connections, delete:connections, read:clients, create:clients, update:clients, delete:clients, read:custom_domains, create:custom_domains, update:custom_domains, delete:custom_domains]
      - client_id: m24-reader
        audience: https://sdk.e2e.test/api/v2/
        scopes: [read:users]
    connections:
      - name: Username-Password-Authentication
        is_domain_connection: true
        enabled_clients: [m24-spa, m26-password, m29-pre, m29-picker]
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
node tests/e2e/m29-node-auth0.mjs
if [[ -z ${AUTH0_BIN:-} ]] && command -v auth0 >/dev/null; then export AUTH0_BIN="$(command -v auth0)"; fi
if [[ -z ${AUTH0_BIN:-} ]]; then GOBIN="$work/bin" go install github.com/auth0/auth0-cli/cmd/auth0@v1.37.0; export AUTH0_BIN="$work/bin/auth0"; fi
node tests/e2e/m29-mgmt-cli.mjs
export E2E_M29_SETUP_URL="$(cat "$work/setup")"
( cd tests/e2e && ./node_modules/.bin/playwright test m29-organizations.spec.mjs --config playwright.config.mjs --output "$work/playwright-results" )
