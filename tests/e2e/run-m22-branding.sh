#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cp tests/e2e/seed.yaml "$work/seed.yaml"
cat >> "$work/seed.yaml" <<'YAML'
  - name: secondary
    friendly_name: Secondary branding tenant
    domains: [secondary.localhost:8443]
    default_directory: Username-Password-Authentication
    clients:
      - client_id: e2e-m17-admin
        app_type: non_interactive
        client_secret: e2e-m17-admin-secret-not-for-production
        grant_types: [client_credentials]
      - client_id: e2e-spa
        app_type: spa
        grant_types: [authorization_code]
        callbacks: [https://localhost:3443/]
        allowed_logout_urls: [https://localhost:3443/]
        web_origins: [https://localhost:3443]
        allowed_origins: [https://localhost:3443]
    client_grants:
      - client_id: e2e-m17-admin
        audience: https://secondary.localhost:8443/api/v2/
        scopes: [read:branding, update:branding, create:branding, delete:branding, read:prompts, update:prompts]
    connections:
      - name: Username-Password-Authentication
        is_domain_connection: true
        enabled_clients: [e2e-spa]
YAML
E2E_M22_HARNESS=1 ZEROAUTHY_SEED="$work/seed.yaml" ./tests/e2e/run-browser.sh m22-console.spec.mjs
