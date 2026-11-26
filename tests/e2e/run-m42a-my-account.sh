#!/usr/bin/env bash
# Plan 42a acceptance: the My Account API on a production SQLite server, a
# browser application using @auth0/auth0-spa-js 2.28.3 with a virtual
# passkey authenticator, raw error requests and a log audit.
set -euo pipefail
cd "$(dirname "$0")/../.."
export FORCE_COLOR=0
unset NO_COLOR
for tool in node go openssl curl flock setsid; do command -v "$tool" >/dev/null || { echo "Plan42a missing $tool" >&2; exit 1; }; done
[[ -x tests/e2e/node_modules/.bin/playwright ]] || { echo 'Install tests/e2e dependencies with npm ci' >&2; exit 1; }
# Ports 9543 and 9198 are shared with the other hosted lanes.
exec 9>/tmp/zeroauthy-e2e-social.lock
flock 9
umask 077
root=$(mktemp -d "${E2E_ARTIFACT_DIR:-${TMPDIR:-/tmp}}/plan42a-XXXXXX")
export E2E_M42A_WORK="$root" E2E_CHROMIUM="${E2E_CHROMIUM:-$(command -v chromium || true)}"
pids=()
start() { setsid "$@" & pids+=("$!"); }
stop() { for p in "${pids[@]}"; do kill -TERM -- "-$p" 2>/dev/null || true; done; for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done; pids=(); }
cleanup() { trap - EXIT INT TERM; stop; echo "Plan42a protected artifacts: $root"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Plan42a local root' -addext 'subjectAltName=DNS:acct.e2e.test,DNS:app.acct.e2e.test,DNS:system.e2e.test,IP:127.0.0.1' -keyout "$root/key.pem" -out "$root/cert.pem" 2>/dev/null
openssl rand -base64 32 > "$root/master.key"
export NODE_EXTRA_CA_CERTS="$root/cert.pem" SSL_CERT_FILE="$root/cert.pem"
export E2E_M42A_CREDENTIALS="$(node -e "const{randomBytes}=require('node:crypto');console.log(JSON.stringify(Object.fromEntries(['admin','password'].map(k=>[k,randomBytes(24).toString('base64url')+'Aa1!']))))")"
node --input-type=module <<'JS'
import {writeFile} from 'node:fs/promises';import {dump} from './tests/e2e/node_modules/js-yaml/index.js';
const s=JSON.parse(process.env.E2E_M42A_CREDENTIALS),origin='https://acct.e2e.test',app='https://app.acct.e2e.test';
const me=['read:me:factors','read:me:authentication_methods','create:me:authentication_methods','update:me:authentication_methods','delete:me:authentication_methods'];
const seed={tenants:[{name:'acct',domains:['acct.e2e.test'],default_directory:'Username-Password-Authentication',skip_non_verifiable_callback_uri_confirmation_prompt:true,
 my_account_api:{active:true},
 clients:[{client_id:'m42a-admin',app_type:'non_interactive',client_secret:s.admin,grant_types:['client_credentials']},
  {client_id:'m42a-spa',name:'Plan42a app',app_type:'spa',is_first_party:true,token_endpoint_auth_method:'none',grant_types:['authorization_code','refresh_token'],callbacks:[app+'/'],allowed_logout_urls:[app+'/'],web_origins:[app],allowed_origins:[app]}],
 client_grants:[{client_id:'m42a-admin',audience:origin+'/api/v2/',scopes:['read:prompts','update:prompts','read:guardian_factors','update:guardian_factors','read:connections','update:connections','create:users','read:users']},
  {client_id:'m42a-spa',audience:origin+'/me/',subject_type:'user',scopes:me}],
 connections:[{name:'Username-Password-Authentication',is_domain_connection:true,enabled_clients:['m42a-spa']}]}]};
await writeFile(process.env.E2E_M42A_WORK+'/seed.yaml',dump(seed),{mode:0o600});
JS
cat > "$root/config.yaml" <<YAML
server:
  listen: 127.0.0.1:9543
  system_host: system.e2e.test
  tls_cert_file: $root/cert.pem
  tls_key_file: $root/key.pem
storage:
  dsn: sqlite://$root/acceptance.db
  auto_migrate: true
security:
  master_key_file: $root/master.key
seed: $root/seed.yaml
seed_mode: create_only
log:
  level: debug
  format: json
YAML
go build -o "$root/zeroauthy" ./cmd/zeroauthy
PROXY_PORT=9198 TARGET_PORT=9543 start node tests/e2e/connect-proxy.mjs >"$root/proxy.log" 2>&1
start "$root/zeroauthy" serve -c "$root/config.yaml" >"$root/server.log" 2>&1
server_pid=${pids[-1]}
ready=false
for _ in $(seq 1 300); do if curl -fsS --cacert "$root/cert.pem" https://127.0.0.1:9543/healthz >/dev/null 2>&1; then ready=true; break; fi; kill -0 "$server_pid" 2>/dev/null || break; sleep 0.1; done
[[ "$ready" == true ]] || { echo 'Plan42a server did not become ready; inspect protected server.log' >&2; exit 1; }
node tests/e2e/m42a-my-account.mjs setup
node tests/e2e/m42a-my-account.mjs raw
(cd tests/e2e && E2E_M42A=1 ./node_modules/.bin/playwright test m42a-my-account.spec.mjs --config playwright.config.mjs --output "$root/playwright-results")
stop
node tests/e2e/m42a-my-account.mjs audit
printf '%s\n' 'Plan42a acceptance: SPA SDK login, TOTP and passkey enrollment, rename, delete, raw errors and log audit passed'
