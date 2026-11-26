#!/usr/bin/env bash
# Plan 42a acceptance: the My Account API on a production SQLite server, a
# browser application using @auth0/auth0-spa-js 2.28.3 with a virtual
# passkey authenticator, raw error requests and a log audit.
set -euo pipefail
cd "$(dirname "$0")/../.."
export FORCE_COLOR=0
unset NO_COLOR
for tool in node go openssl curl flock setsid; do command -v "$tool" >/dev/null || { echo "Plan42b missing $tool" >&2; exit 1; }; done
[[ -x tests/e2e/node_modules/.bin/playwright ]] || { echo 'Install tests/e2e dependencies with npm ci' >&2; exit 1; }
# Ports 9543 and 9198 are shared with the other hosted lanes.
exec 9>/tmp/zeroauthy-e2e-social.lock
flock 9
umask 077
root=$(mktemp -d "${E2E_ARTIFACT_DIR:-${TMPDIR:-/tmp}}/plan42b-XXXXXX")
export E2E_M42B_WORK="$root" E2E_CHROMIUM="${E2E_CHROMIUM:-$(command -v chromium || true)}"
pids=()
start() { setsid "$@" & pids+=("$!"); }
stop() { for p in "${pids[@]}"; do kill -TERM -- "-$p" 2>/dev/null || true; done; for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done; pids=(); }
cleanup() { trap - EXIT INT TERM; stop; echo "Plan42b protected artifacts: $root"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Plan42b local root' -addext 'subjectAltName=DNS:acct.e2e.test,DNS:app.acct.e2e.test,DNS:system.e2e.test,IP:127.0.0.1' -keyout "$root/key.pem" -out "$root/cert.pem" 2>/dev/null
openssl rand -base64 32 > "$root/master.key"
export NODE_EXTRA_CA_CERTS="$root/cert.pem" SSL_CERT_FILE="$root/cert.pem"
export E2E_M42B_CREDENTIALS="$(node -e "const{randomBytes}=require('node:crypto');console.log(JSON.stringify(Object.fromEntries(['admin','password'].map(k=>[k,randomBytes(24).toString('base64url')+'Aa1!']))))")"
node --input-type=module <<'JS'
import {writeFile} from 'node:fs/promises';import {dump} from './tests/e2e/node_modules/js-yaml/index.js';
const s=JSON.parse(process.env.E2E_M42B_CREDENTIALS),origin='https://acct.e2e.test',app='https://app.acct.e2e.test',org=origin+'/my-org/';
const mo=['read:my_org:configuration','read:my_org:details','update:my_org:details','read:my_org:members','delete:my_org:memberships','read:my_org:member_roles','create:my_org:member_roles','delete:my_org:member_roles','read:my_org:member_invitations','create:my_org:member_invitations','delete:my_org:member_invitations','read:my_org:user_stores'];
const db='Username-Password-Authentication',m=(email)=>({email,connection:db});
const seed={tenants:[{name:'acct',domains:['acct.e2e.test'],default_directory:db,skip_non_verifiable_callback_uri_confirmation_prompt:true,
 my_organization_api:{active:true},
 roles:[{name:'Org Admin',my_organization_visible:true,permissions:mo.map(p=>({resource_server_identifier:org,permission_name:p}))},{name:'Member',my_organization_visible:true}],
 clients:[{client_id:'m42b-admin',app_type:'non_interactive',client_secret:s.admin,grant_types:['client_credentials']},
  {client_id:'m42b-spa',name:'Plan42b portal',app_type:'spa',is_first_party:true,token_endpoint_auth_method:'none',organization_usage:'allow',grant_types:['authorization_code','refresh_token'],callbacks:[app+'/'],allowed_logout_urls:[app+'/'],web_origins:[app],allowed_origins:[app],
   my_organization_configuration:{allowed_strategies:['oidc'],connection_deletion_behavior:'allow',invitation_landing_client_id:'m42b-spa',enforce_permission_ceiling:true}}],
 client_grants:[{client_id:'m42b-admin',audience:origin+'/api/v2/',scopes:['read:organizations','create:email_templates','update:email_templates','read:email_templates','update:clients']},
  {client_id:'m42b-spa',audience:org,subject_type:'user',scopes:mo}],
 connections:[{name:db,is_domain_connection:true,enabled_clients:['m42b-spa']}],
 users:[{connection:db,email:'alice@acme.e2e.local',password:s.password,email_verified:true},{connection:db,email:'bob@acme.e2e.local',password:s.password,email_verified:true},{connection:db,email:'carol@other.e2e.local',password:s.password,email_verified:true}],
 organizations:[{name:'acme',display_name:'Acme',connections:[{name:db}],members:[m('alice@acme.e2e.local'),m('bob@acme.e2e.local')],member_roles:[{member:m('alice@acme.e2e.local'),roles:['Org Admin']},{member:m('bob@acme.e2e.local'),roles:['Member']}]},
  {name:'other',display_name:'Other',connections:[{name:db}],members:[m('carol@other.e2e.local')],member_roles:[{member:m('carol@other.e2e.local'),roles:['Org Admin']}]}]}]};
await writeFile(process.env.E2E_M42B_WORK+'/seed.yaml',dump(seed),{mode:0o600});
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
[[ "$ready" == true ]] || { echo 'Plan42b server did not become ready; inspect protected server.log' >&2; exit 1; }
node tests/e2e/m42b-my-org.mjs setup
node tests/e2e/m42b-my-org.mjs raw
(cd tests/e2e && E2E_M42B=1 ./node_modules/.bin/playwright test m42b-my-org.spec.mjs --config playwright.config.mjs --output "$root/playwright-results")
stop
node tests/e2e/m42b-my-org.mjs audit
printf '%s\n' 'Plan42b acceptance: organization logins, details, members, roles, invitations, isolation, raw errors and log audit passed'
