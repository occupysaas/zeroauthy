#!/usr/bin/env bash
# Complete Apple acceptance: local cross-site upstream, real SDK/CLI/browser,
# raw native exchange, runtime-secret audit, then actual Deploy CLI four cells.
set -euo pipefail
cd "$(dirname "$0")/../.."
export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.11}"
export E2E_M39A=1
export E2E_CHROMIUM="${E2E_CHROMIUM:-$(command -v chromium || true)}"
export AUTH0_BIN="${AUTH0_BIN:-$(command -v auth0 || true)}"
[[ -x "$AUTH0_BIN" ]] && "$AUTH0_BIN" --version | grep -q '1.37.0' || { echo 'e2e-apple requires Auth0 CLI 1.37.0' >&2; exit 1; }
node --test tests/e2e/apple-discovery.test.mjs
(
exec 9>/tmp/zeroauthy-e2e-social.lock
flock 9
umask 077
work=$(mktemp -d)
export E2E_APPLE_WORK="$work"
pids=()
start() { setsid "$@" & pids+=("$!"); }
cleanup() {
 trap - EXIT INT TERM
 for p in "${pids[@]}"; do kill -TERM -- "-$p" 2>/dev/null || true; done
 if [[ ${E2E_KEEP_WORK:-0} == 1 ]]; then echo "Apple runtime artifacts: $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Apple local test root' \
 -addext 'subjectAltName=DNS:sdk.e2e.test,DNS:apple.idp.test,DNS:system.e2e.test,DNS:callback.e2e.test' \
 -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$work/apple.p8" 2>/dev/null
chmod 600 "$work/apple.p8"
export E2E_CERT="$work/cert.pem" E2E_KEY="$work/key.pem" E2E_DATABASE="$work/apple.db" E2E_SETUP_FILE="$work/setup" E2E_SEED="$work/seed.yaml" E2E_APPLE_KEY="$work/apple.p8"
export NODE_EXTRA_CA_CERTS="$work/cert.pem" E2E_APPLE_SEED_SECRET="$(cat "$work/apple.p8")"
node --input-type=module <<'JS'
import {writeFile} from 'node:fs/promises';
import {dump} from './tests/e2e/node_modules/js-yaml/index.js';
const native=(id,enabled=true,secret)=>({client_id:id,name:id,app_type:'native',token_endpoint_auth_method:secret?'client_secret_post':'none',...(secret?{client_secret:secret}:{}),native_social_login:{apple:{enabled},google:{enabled:true},facebook:{enabled:true}},mobile:{ios:{team_id:'ABCDE12345',app_bundle_identifier:'test.apple.native'}}});
const scopes=['read:connections','create:connections','update:connections','delete:connections','read:users','read:clients','read:logs','create:token_exchange_profiles'];
const apple=name=>({name,strategy:'apple',enabled_clients:[],options:{client_id:'test.apple.web',team_id:'ABCDE12345',kid:'ABCDE67890',app_secret:name==='seed-file'?'file://apple.p8':'env://E2E_APPLE_SEED_SECRET'}});
const seed={tenants:[{name:'apple',domains:['sdk.e2e.test'],skip_non_verifiable_callback_uri_confirmation_prompt:true,clients:[{client_id:'m24-admin',app_type:'non_interactive',client_secret:'m24-admin-secret-not-for-production',grant_types:['client_credentials']},{client_id:'m24-spa',app_type:'spa',grant_types:['authorization_code'],callbacks:['https://callback.e2e.test/']},native('apple-native'),native('apple-confidential',true,'apple-confidential-fixture-secret'),native('apple-disabled',false)],client_grants:[{client_id:'m24-admin',audience:'https://sdk.e2e.test/api/v2/',scopes}],connections:[apple('seed-file'),apple('seed-env')]}]};
await writeFile(process.env.E2E_SEED,dump(seed),{mode:0o600});
JS
go build -o "$work/harness" ./tests/e2e/social/harness
start "$work/harness" >"$work/server.log" 2>&1
PROXY_PORT=9198 TARGET_PORT=9543 start node tests/e2e/connect-proxy.mjs >"$work/proxy.log" 2>&1
PROXY_PORT=9199 TARGET_PORT=9544 start node tests/e2e/connect-proxy.mjs >"$work/proxy2.log" 2>&1
for _ in $(seq 1 150); do
 if curl -fsS http://127.0.0.1:9173/healthz >/dev/null 2>&1 && curl -s http://127.0.0.1:9198 >/dev/null; then break; fi
 sleep 0.1
done
curl -fsS http://127.0.0.1:9173/healthz >/dev/null || { echo 'Apple harness startup failed; inspect protected server.log' >&2; exit 1; }
node tests/e2e/m39a-native.mjs setup | tee "$work/sdk.log"
(cd tests/e2e && ./node_modules/.bin/playwright test m39a-apple.spec.mjs --config playwright.config.mjs --output "$work/playwright-results") | tee "$work/browser.log"
node tests/e2e/m39a-native.mjs | tee "$work/native.log"
node tests/e2e/m39a-apple-audit.mjs | tee "$work/audit.log"
)
./tests/e2e/run-m39a-apple-deploy.sh
echo 'Apple acceptance: browser, native, SDK, CLI, seed file/env, runtime audit and four Deploy CLI cells passed (no optional lanes or skips)'
