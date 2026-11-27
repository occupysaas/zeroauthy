#!/usr/bin/env bash
# Plan 41b acceptance: Dynamic Client Registration and Client ID Metadata
# Documents on a SQLite server whose outbound policy reaches only a local
# metadata document host: raw RFC 7591 requests, Management CIMD preview and
# registration, a seeded CIMD client, a default grant for third-party
# applications, an @auth0/auth0-spa-js 2.28.3 login with a registered
# client, a PKCE code flow whose client_id is a document URL, and a log
# audit.
set -euo pipefail
cd "$(dirname "$0")/../.."
export FORCE_COLOR=0
unset NO_COLOR
for tool in node go openssl curl flock setsid; do command -v "$tool" >/dev/null || { echo "Plan41b missing $tool" >&2; exit 1; }; done
[[ -x tests/e2e/node_modules/.bin/playwright ]] || { echo 'Install tests/e2e dependencies with npm ci' >&2; exit 1; }
# Ports 9543 and 9198 are shared with the other hosted lanes.
exec 9>/tmp/zeroauthy-e2e-social.lock
flock 9
umask 077
root=$(mktemp -d "${E2E_ARTIFACT_DIR:-${TMPDIR:-/tmp}}/plan41b-XXXXXX")
export E2E_M41B_WORK="$root" E2E_CHROMIUM="${E2E_CHROMIUM:-$(command -v chromium || true)}"
pids=()
start() { setsid "$@" & pids+=("$!"); }
stop() { for p in "${pids[@]}"; do kill -TERM -- "-$p" 2>/dev/null || true; done; for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done; pids=(); }
cleanup() { trap - EXIT INT TERM; stop; echo "Plan41b protected artifacts: $root"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Plan41b local root' -addext 'subjectAltName=DNS:dcr.e2e.test,DNS:closed.e2e.test,DNS:app.dcr.e2e.test,DNS:system.e2e.test,DNS:cimd.example.com,IP:127.0.0.1' -keyout "$root/key.pem" -out "$root/cert.pem" 2>/dev/null
openssl rand -base64 32 > "$root/master.key"
export NODE_EXTRA_CA_CERTS="$root/cert.pem" SSL_CERT_FILE="$root/cert.pem"
export E2E_M41B_CREDENTIALS="$(node -e "const{randomBytes}=require('node:crypto');console.log(JSON.stringify(Object.fromEntries(['admin','password'].map(k=>[k,randomBytes(24).toString('base64url')+'Aa1!']))))")"
node --input-type=module <<'JS'
import {writeFile} from 'node:fs/promises';import {dump} from './tests/e2e/node_modules/js-yaml/index.js';
const s=JSON.parse(process.env.E2E_M41B_CREDENTIALS),origin='https://dcr.e2e.test',api='https://api.dcr.e2e.test',db='Username-Password-Authentication';
const seed={tenants:[
 {name:'dcr',domains:['dcr.e2e.test'],default_directory:db,
  settings:{flags:{enable_dynamic_client_registration:true},dynamic_client_registration_security_mode:'permissive',
   client_id_metadata_document_supported:true,client_id_metadata_document_dynamic_registration_supported:true},
  cimd_clients:['https://cimd.example.com/client.json'],
  resource_servers:[{identifier:api,name:'Plan41b API',scopes:[{value:'read:things'}]}],
  clients:[{client_id:'m41b-admin',app_type:'non_interactive',client_secret:s.admin,grant_types:['client_credentials']}],
  client_grants:[{client_id:'m41b-admin',audience:origin+'/api/v2/',scopes:['read:clients','create:clients','update:clients','read:client_grants','create:client_grants']}],
  connections:[{name:db,is_domain_connection:true}],
  users:[{connection:db,email:'user@dcr.e2e.local',password:s.password,email_verified:true}]},
 {name:'closed',domains:['closed.e2e.test']}]};
await writeFile(process.env.E2E_M41B_WORK+'/seed.yaml',dump(seed),{mode:0o600});
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
go build -o "$root/zeroauthy" ./tests/e2e/m41b/server
PROXY_PORT=9198 TARGET_PORT=9543 start node tests/e2e/connect-proxy.mjs >"$root/proxy.log" 2>&1
start "$root/zeroauthy" -c "$root/config.yaml" -app https://app.dcr.e2e.test >"$root/server.log" 2>&1
server_pid=${pids[-1]}
ready=false
for _ in $(seq 1 300); do if curl -fsS --cacert "$root/cert.pem" https://127.0.0.1:9543/healthz >/dev/null 2>&1; then ready=true; break; fi; kill -0 "$server_pid" 2>/dev/null || break; sleep 0.1; done
[[ "$ready" == true ]] || { echo 'Plan41b server did not become ready; inspect protected server.log' >&2; exit 1; }
node tests/e2e/m41b-dcr.mjs setup
node tests/e2e/m41b-dcr.mjs raw
sleep 1 # let the registration bucket refill after the burst
(cd tests/e2e && E2E_M41B=1 ./node_modules/.bin/playwright test m41b-dcr.spec.mjs --config playwright.config.mjs --output "$root/playwright-results")
stop
node tests/e2e/m41b-dcr.mjs audit
printf '%s\n' 'Plan41b acceptance: registration, errors, rate limit, discovery, CIMD preview and register, seeded CIMD client, default third-party grant, spa-js login, CIMD code flow and log audit passed'
