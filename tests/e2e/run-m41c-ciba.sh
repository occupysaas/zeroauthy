#!/usr/bin/env bash
# Plan 41c acceptance: CIBA with the email channel on a production SQLite
# server: discovery, refusals, identical answers for unknown and unverified
# users, pending and slow_down polls, the async_approval email (dir mail
# driver), approval and denial in Chromium, the token poll, single
# redemption, and a log audit.
set -euo pipefail
cd "$(dirname "$0")/../.."
export FORCE_COLOR=0
unset NO_COLOR
for tool in node go openssl curl flock setsid; do command -v "$tool" >/dev/null || { echo "Plan41c missing $tool" >&2; exit 1; }; done
[[ -x tests/e2e/node_modules/.bin/playwright ]] || { echo 'Install tests/e2e dependencies with npm ci' >&2; exit 1; }
# Ports 9543 and 9198 are shared with the other hosted lanes.
exec 9>/tmp/zeroauthy-e2e-social.lock
flock 9
umask 077
root=$(mktemp -d "${E2E_ARTIFACT_DIR:-${TMPDIR:-/tmp}}/plan41c-XXXXXX")
export E2E_M41C_WORK="$root" E2E_CHROMIUM="${E2E_CHROMIUM:-$(command -v chromium || true)}"
pids=()
start() { setsid "$@" & pids+=("$!"); }
stop() { for p in "${pids[@]}"; do kill -TERM -- "-$p" 2>/dev/null || true; done; for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done; pids=(); }
cleanup() { trap - EXIT INT TERM; stop; echo "Plan41c protected artifacts: $root"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Plan41c local root' -addext 'subjectAltName=DNS:ciba.e2e.test,DNS:system.e2e.test,DNS:localhost,IP:127.0.0.1' -keyout "$root/key.pem" -out "$root/cert.pem" 2>/dev/null
openssl rand -base64 32 > "$root/master.key"
export NODE_EXTRA_CA_CERTS="$root/cert.pem" SSL_CERT_FILE="$root/cert.pem"
export E2E_M41C_CREDENTIALS="$(node -e "const{randomBytes}=require('node:crypto');console.log(JSON.stringify(Object.fromEntries(['admin','agent','password'].map(k=>[k,randomBytes(24).toString('base64url')+'Aa1!']))))")"
node --input-type=module <<'JS'
import {writeFile} from 'node:fs/promises';import {dump} from './tests/e2e/node_modules/js-yaml/index.js';
const s=JSON.parse(process.env.E2E_M41C_CREDENTIALS),origin='https://ciba.e2e.test',db='Username-Password-Authentication';
const seed={tenants:[{name:'ciba',domains:['ciba.e2e.test'],default_directory:db,
 clients:[{client_id:'m41c-admin',app_type:'non_interactive',client_secret:s.admin,grant_types:['client_credentials']},
  {client_id:'agent',name:'Agent backend',app_type:'regular_web',client_secret:s.agent,grant_types:['authorization_code','refresh_token','urn:openid:params:grant-type:ciba'],async_approval_notification_channels:['email'],refresh_token:{rotation_type:'rotating',expiration_type:'expiring'}}],
 client_grants:[{client_id:'m41c-admin',audience:origin+'/api/v2/',scopes:['read:users','read:logs','create:email_templates','update:email_templates','read:email_templates']}],
 connections:[{name:db,enabled_clients:['agent']}],
 users:[{connection:db,email:'alice@ciba.e2e.local',password:s.password,email_verified:true},{connection:db,email:'bob@ciba.e2e.local',password:s.password,email_verified:false}]}]};
await writeFile(process.env.E2E_M41C_WORK+'/seed.yaml',dump(seed),{mode:0o600});
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
email:
  driver: dir
  dir: $root/mail
seed: $root/seed.yaml
seed_mode: create_only
log:
  level: debug
  format: json
YAML
go build -o "$root/zeroauthy" ./cmd/zeroauthy
mkdir -p "$root/mail"
PROXY_PORT=9198 TARGET_PORT=9543 start node tests/e2e/connect-proxy.mjs >"$root/proxy.log" 2>&1
start "$root/zeroauthy" serve -c "$root/config.yaml" >"$root/server.log" 2>&1
server_pid=${pids[-1]}
ready=false
for _ in $(seq 1 300); do if curl -fsS --cacert "$root/cert.pem" https://127.0.0.1:9543/healthz >/dev/null 2>&1; then ready=true; break; fi; kill -0 "$server_pid" 2>/dev/null || break; sleep 0.1; done
[[ "$ready" == true ]] || { echo 'Plan41c server did not become ready; inspect protected server.log' >&2; exit 1; }
node tests/e2e/m41c-ciba.mjs setup
node tests/e2e/m41c-ciba.mjs raw
(cd tests/e2e && E2E_M41C=1 ./node_modules/.bin/playwright test m41c-ciba.spec.mjs --config playwright.config.mjs --output "$root/playwright-results")
node tests/e2e/m41c-ciba.mjs events
stop
node tests/e2e/m41c-ciba.mjs audit
printf '%s\n' 'Plan41c acceptance: discovery, refusals, no oracle, polling, email approval and denial, tokens, single redemption and log audit passed'
