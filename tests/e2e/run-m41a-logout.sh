#!/usr/bin/env bash
# Plan 41a real SQLite/SDK/browser acceptance; all credentials are generated.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec 9>/tmp/zeroauthy-e2e-social.lock
flock 9
umask 077
work=$(mktemp -d)
export E2E_M41A_WORK="$work" E2E_M41A=1
export E2E_CHROMIUM="${E2E_CHROMIUM:-$(command -v chromium || true)}"
pids=()
cleanup() {
 trap - EXIT INT TERM
 for p in "${pids[@]}"; do kill -TERM -- "-$p" 2>/dev/null || true; done
 echo "Plan 41a private artifacts: $work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Plan41a local test root' \
 -addext 'subjectAltName=DNS:localhost,DNS:example.com,DNS:system.e2e.test,IP:127.0.0.1' \
 -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
export NODE_EXTRA_CA_CERTS="$work/cert.pem" SSL_CERT_FILE="$work/cert.pem"
export ZEROAUTHY_SECURITY__MASTER_KEY="$(openssl rand -base64 32)"
node --input-type=module <<'JS'
import {randomBytes} from 'node:crypto';
import {writeFile} from 'node:fs/promises';
import {dump} from './tests/e2e/node_modules/js-yaml/index.js';
const work=process.env.E2E_M41A_WORK,credentials={admin:randomBytes(32).toString('hex'),web:randomBytes(32).toString('hex'),password:'Za-'+randomBytes(24).toString('hex')};
await writeFile(`${work}/private-credentials.json`,JSON.stringify(credentials),{mode:0o600});
const callback='https://127.0.0.1:9643';
const doc={tenants:[{name:'logout',domains:['localhost:9543'],default_directory:'DB',default_audience:'https://api.example.test',skip_non_verifiable_callback_uri_confirmation_prompt:true,guardian:{factors:{otp:true}},resource_servers:[{identifier:'https://api.example.test',allow_offline_access:true}],clients:[
 {client_id:'m41a-admin',name:'Logout admin',app_type:'non_interactive',client_secret:credentials.admin,grant_types:['client_credentials']},
 {client_id:'m41a-web',name:'Express logout app',app_type:'regular_web',client_secret:credentials.web,token_endpoint_auth_method:'client_secret_basic',grant_types:['authorization_code','refresh_token'],callbacks:[`${callback}/callback`],allowed_logout_urls:[callback],oidc_logout:{backchannel_logout_urls:[`${callback}/backchannel-logout`]}},
 {client_id:'m41a-spa',name:'Other logout app',app_type:'spa',grant_types:['authorization_code','refresh_token'],callbacks:[`${callback}/raw`],allowed_logout_urls:[`${callback}/raw`]},
],client_grants:[{client_id:'m41a-admin',audience:'https://localhost:9543/api/v2/',scopes:['read:clients','create:clients','update:clients','delete:clients','read:users','create:users','update:users','read:sessions','update:sessions','delete:sessions','read:authentication_methods','create:authentication_methods']}],connections:[
 {name:'DB',enabled_clients:['m41a-web','m41a-spa']},
 {name:'Enterprise',strategy:'oidc',enabled_clients:['m41a-spa'],options:{type:'front_channel',client_id:'integration',scope:'openid',issuer:'https://example.com',authorization_endpoint:'https://example.com/authorize',jwks_uri:'https://example.com/jwks'}}
],users:[{connection:'DB',email:'alice@example.test',password:credentials.password,email_verified:true,name:'Fixture Alice'}]}]};
await writeFile(`${work}/seed.yaml`,dump(doc),{mode:0o600});
JS
go build -o "$work/harness" ./tests/e2e/logout-server
setsid "$work/harness" >"$work/server.log" 2>&1 & pids+=("$!")
for _ in $(seq 1 200); do
 if curl -fsS --cacert "$work/cert.pem" https://localhost:9543/healthz --noproxy '*' >/dev/null 2>&1; then break; fi
 kill -0 "${pids[0]}" 2>/dev/null || { echo 'Plan41a fixture failed; inspect protected server.log' >&2; exit 1; }
 sleep 0.1
done
node tests/e2e/m41a-node-auth0.mjs
(cd tests/e2e && ./node_modules/.bin/playwright test m41a-logout.spec.mjs --config playwright.config.mjs --output "$work/playwright-results") >"$work/playwright.log" 2>&1 || { echo 'Plan41a browser acceptance failed; inspect protected playwright.log' >&2; exit 1; }
node tests/e2e/m41a-node-auth0.mjs audit
# The Deploy CLI has its own port lock; run after the browser fixture exits.
kill -TERM -- "-${pids[0]}"
wait "${pids[0]}" || true
if [[ ${E2E_M41A_DEPLOY:-1} == 1 ]]; then ./tests/e2e/run-m41a-logout-deploy.sh; fi
