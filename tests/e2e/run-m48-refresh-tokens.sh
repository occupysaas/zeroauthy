#!/usr/bin/env bash
# Plan 48 dedicated acceptance: production SQLite server, pinned SDKs/browser,
# CLI and actual Deploy CLI four-cell round trip. Artifacts stay private.
set -euo pipefail
cd "$(dirname "$0")/../.."
export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.11}"
export FORCE_COLOR=0
unset NO_COLOR
for tool in node go openssl curl flock setsid python3; do command -v "$tool" >/dev/null || { echo "Plan48 missing $tool" >&2; exit 1; }; done
[[ -x tests/e2e/node_modules/.bin/playwright ]] || { echo 'Install existing tests/e2e lockfile dependencies with npm ci' >&2; exit 1; }
export AUTH0_BIN="${AUTH0_BIN:-$(command -v auth0 || true)}"
[[ -x "$AUTH0_BIN" ]] && "$AUTH0_BIN" --version | grep -q '1.37.0' || { echo 'Plan48 requires pinned Auth0 CLI 1.37.0' >&2; exit 1; }
exec 9>/tmp/zeroauthy-e2e-social.lock
flock 9
umask 077
root=$(mktemp -d "${E2E_ARTIFACT_DIR:-${TMPDIR:-/tmp}}/plan48-XXXXXX")
export E2E_M48_WORK="$root" E2E_CHROMIUM="${E2E_CHROMIUM:-$(command -v chromium || true)}"
pids=()
start() { setsid "$@" & pids+=("$!"); }
stop() { for p in "${pids[@]}"; do kill -TERM -- "-$p" 2>/dev/null || true; done; for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done; pids=(); }
cleanup() { trap - EXIT INT TERM; stop; echo "Plan48 protected artifacts: $root"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Plan48 local root' -addext 'subjectAltName=DNS:refresh.e2e.test,DNS:callback.e2e.test,IP:127.0.0.1' -keyout "$root/key.pem" -out "$root/cert.pem" 2>/dev/null
openssl rand -base64 32 > "$root/master.key"
export NODE_EXTRA_CA_CERTS="$root/cert.pem" SSL_CERT_FILE="$root/cert.pem"
export E2E_M48_CREDENTIALS="$(node -e "const{randomBytes}=require('node:crypto');console.log(JSON.stringify(Object.fromEntries(['admin','web','quota','password'].map(k=>[k,randomBytes(24).toString('base64url')+'Aa1!']))))")"
node --input-type=module <<'JS'
import {writeFile} from 'node:fs/promises';import {dump} from './tests/e2e/node_modules/js-yaml/index.js';
const s=JSON.parse(process.env.E2E_M48_CREDENTIALS),origin='https://refresh.e2e.test',api='https://api.refresh.e2e.test';
const scopes=['read:clients','update:clients','read:resource_servers','update:resource_servers','read:users','create:users','read:refresh_tokens','update:refresh_tokens','delete:refresh_tokens','read:sessions','update:sessions','delete:sessions','read:grants','delete:grants','read:tenant_settings','update:tenant_settings'];
const seed={tenants:[{name:'refresh',domains:['refresh.e2e.test'],default_directory:'Username-Password-Authentication',skip_non_verifiable_callback_uri_confirmation_prompt:true,clients:[{client_id:'m48-admin',app_type:'non_interactive',client_secret:s.admin,grant_types:['client_credentials']},{client_id:'m48-quota',app_type:'non_interactive',client_secret:s.quota,grant_types:['client_credentials']},{client_id:'m48-web',app_type:'regular_web',is_first_party:true,client_secret:s.web,grant_types:['authorization_code','password','refresh_token'],callbacks:['https://callback.e2e.test/']},{client_id:'m48-public',app_type:'spa',is_first_party:true,token_endpoint_auth_method:'none',grant_types:['authorization_code','refresh_token'],callbacks:['https://callback.e2e.test/'],allowed_logout_urls:['https://callback.e2e.test/']}],resource_servers:[{identifier:api,name:'Plan48 original API',allow_offline_access:true,allow_online_access:true,skip_consent_for_verifiable_first_party_clients:true,proof_of_possession:{mechanism:'dpop',required:false},scopes:[{value:'read:one'}]},{identifier:'https://second.refresh.e2e.test',name:'Plan48 additional API',allow_offline_access:true,skip_consent_for_verifiable_first_party_clients:true,scopes:[{value:'read:two'}]}],client_grants:[{client_id:'m48-admin',audience:origin+'/api/v2/',scopes},{client_id:'m48-quota',audience:api,scopes:['read:one']}],connections:[{name:'Username-Password-Authentication',is_domain_connection:true,enabled_clients:['m48-web','m48-public']}]}]};
await writeFile(process.env.E2E_M48_WORK+'/seed.yaml',dump(seed),{mode:0o600});
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
  level: info
  format: json
YAML
go build -o "$root/zeroauthy" ./cmd/zeroauthy
PROXY_PORT=9198 TARGET_PORT=9543 start node tests/e2e/connect-proxy.mjs >"$root/proxy.log" 2>&1
start "$root/zeroauthy" serve -c "$root/config.yaml" >"$root/server.log" 2>&1
server_pid=${pids[-1]}
ready=false
for _ in $(seq 1 300); do if curl -fsS --cacert "$root/cert.pem" https://127.0.0.1:9543/healthz >/dev/null 2>&1; then ready=true; break; fi; kill -0 "$server_pid" 2>/dev/null || break; sleep 0.1; done
[[ "$ready" == true ]] || { echo 'Plan48 server did not become ready; inspect protected server.log' >&2; exit 1; }
node tests/e2e/m48-node-auth0.mjs setup
(cd tests/e2e && ./node_modules/.bin/playwright test m48-refresh-tokens.spec.mjs --config playwright.config.mjs --output "$root/playwright-results")
node tests/e2e/m48-node-auth0.mjs sdk
# Pinned CLI uses only local Management API; no login or upstream tenant.
node --input-type=module <<'JS'
import {spawnSync} from 'node:child_process';import {mkdir,writeFile} from 'node:fs/promises';import {secrets,work} from './tests/e2e/m48-node-auth0.mjs';
const configHome=work+'/cli-config';await mkdir(configHome,{mode:0o700});
const r=spawnSync(process.env.AUTH0_BIN,['api','get','tenants/settings','--no-input','--no-color'],{env:{PATH:process.env.PATH,XDG_CONFIG_HOME:configHome,HTTPS_PROXY:'http://127.0.0.1:9198',SSL_CERT_FILE:process.env.SSL_CERT_FILE,AUTH0_CLI_ANALYTICS:'false',AUTH0_AGENT_MODE:'false',AUTH0_CLI_AUTH_MODE:'env',AUTH0_DOMAIN:'refresh.e2e.test',AUTH0_CLIENT_ID:'m48-admin',AUTH0_CLIENT_SECRET:secrets().admin},encoding:'utf8',timeout:90000});await writeFile(work+'/cli.log',(r.stdout??'')+(r.stderr??''),{mode:0o600});if(r.status!==0)throw Error('pinned CLI local API failed; inspect protected cli.log');JSON.parse(r.stdout);console.log('Plan48 pinned auth0-cli api passed');
JS
stop
python3 - "$root/acceptance.db" "$root/stored-sinks.jsonl" <<'PYDUMP'
import json,sqlite3,sys
with sqlite3.connect(sys.argv[1]) as db, open(sys.argv[2],'w') as out:
 db.row_factory=sqlite3.Row
 for table in ('tenant_logs','action_executions'):
  for row in db.execute('SELECT * FROM '+table):
   out.write(json.dumps({k:(v.decode(errors='replace') if isinstance(v,bytes) else v) for k,v in dict(row).items()})+'\n')
PYDUMP
node tests/e2e/m48-node-auth0.mjs audit
# This lane owns another lock and independent private servers; current ones are stopped.
./tests/e2e/run-m48-refresh-tokens-deploy.sh
printf '%s\n' 'Plan48 acceptance: browser, SDK, protocols, CLI, audit and four Deploy cells passed'
