#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cp tests/e2e/seed.yaml "$work/seed.yaml"
cat >>"$work/seed.yaml" <<'YAML'
  - name: secondary
    friendly_name: Secondary email tenant
    domains: [secondary.localhost:8443]
    default_directory: Username-Password-Authentication
    clients:
      - client_id: e2e-m17-admin
        name: M21 secondary management client
        app_type: non_interactive
        client_secret: e2e-m17-admin-secret-not-for-production
        grant_types: [client_credentials]
      - client_id: e2e-spa
        name: M21 secondary signup client
        app_type: spa
        grant_types: [authorization_code]
        callbacks: [https://localhost:3443/]
        allowed_logout_urls: [https://localhost:3443/]
        web_origins: [https://localhost:3443]
        allowed_origins: [https://localhost:3443]
    client_grants:
      - client_id: e2e-m17-admin
        audience: https://secondary.localhost:8443/api/v2/
        scopes: [read:email_provider, create:email_provider, update:email_provider, delete:email_provider, read:email_templates, create:email_templates, update:email_templates]
    connections:
      - name: Username-Password-Authentication
        is_domain_connection: true
        enabled_clients: [e2e-spa]
YAML
E2E_M21_HARNESS=1 ZEROAUTHY_SEED="$work/seed.yaml" \
  ZEROAUTHY_EMAIL__ALLOW_LOCAL_SMTP=127.0.0.1:2526 \
  ./tests/e2e/run-browser.sh m21-console.spec.mjs
