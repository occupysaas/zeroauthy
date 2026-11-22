#!/usr/bin/env bash
# make e2e-github: the GitHub social connection (Plan 39c, spec §9 G4 and G6).
# Two zeroauthy nodes and a local GitHub-shaped upstream (OAuth authorize and
# token endpoints, REST /user and /user/emails), Playwright logins through
# actual code exchanges, then the pinned Deploy CLI exporting and importing a
# GitHub connection with explicit secret reinjection and logging in to the
# imported tenant. No live GitHub is ever contacted.
set -euo pipefail
cd "$(dirname "$0")/../.."
export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.11}"
export E2E_M39C=1 E2E_GITHUB_BASE='https://idp.e2e.test/github'
export E2E_CHROMIUM="${E2E_CHROMIUM:-$(command -v chromium || true)}"
node --version | grep -qE '^v(2[5-9]|[3-9][0-9])\.' || { echo 'e2e-github needs Node 25+' >&2; exit 1; }
exec 9>/tmp/zeroauthy-e2e-social.lock
flock 9
umask 077
work=$(mktemp -d)
export E2E_GITHUB_WORK="$work"
pids=()
start() { setsid "$@" & pids+=("$!"); }
cleanup() {
 trap - EXIT INT TERM
 for p in "${pids[@]}"; do kill -TERM -- "-$p" 2>/dev/null || true; done
 if [[ ${E2E_KEEP_WORK:-0} == 1 ]]; then echo "GitHub artifacts: $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=GitHub local test root' \
 -addext 'subjectAltName=DNS:sdk.e2e.test,DNS:alt.e2e.test,DNS:other.e2e.test,DNS:idp.e2e.test,DNS:system.e2e.test,DNS:callback.e2e.test,DNS:source.e2e.test,DNS:yaml.target.e2e.test,DNS:directory.target.e2e.test' \
 -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
export E2E_CERT="$work/cert.pem" E2E_KEY="$work/key.pem" E2E_DATABASE="$work/github.db" E2E_SETUP_FILE="$work/setup" E2E_SEED="$work/seed.yaml"
export NODE_EXTRA_CA_CERTS="$work/cert.pem"
node --input-type=module <<'JS'
import {writeFile} from 'node:fs/promises';
import {dump} from './tests/e2e/node_modules/js-yaml/index.js';
const m2m=(id,name)=>({client_id:id,name,app_type:'non_interactive',client_secret:`${id}-secret-not-for-production`,grant_types:['client_credentials']});
const grant=(client,host,scopes)=>({client_id:client,audience:`https://${host}/api/v2/`,scopes});
const deployScopes=['read:clients','create:clients','update:clients','delete:clients','read:connections','create:connections','update:connections','delete:connections','read:connections_options','update:connections_options','read:users'];
const deployTenant=(name,host)=>({name,domains:[host],skip_non_verifiable_callback_uri_confirmation_prompt:true,clients:[m2m(`${name}-admin`,`${name} admin`)],client_grants:[grant(`${name}-admin`,host,deployScopes)]});
const seed={tenants:[
 {name:'github',friendly_name:'GitHub acceptance',domains:['sdk.e2e.test','alt.e2e.test'],skip_non_verifiable_callback_uri_confirmation_prompt:true,default_directory:'Username-Password-Authentication',
  clients:[{...m2m('m24-admin','GitHub admin'),client_secret:'m24-admin-secret-not-for-production'},{...m2m('m24-reader','GitHub reader'),client_secret:'m24-reader-secret-not-for-production'},
   {client_id:'m24-spa',name:'GitHub browser',app_type:'spa',grant_types:['authorization_code'],callbacks:['https://callback.e2e.test/']}],
  client_grants:[grant('m24-admin','sdk.e2e.test',['read:connections','create:connections','update:connections','delete:connections','read:users','create:users','update:users','delete:users','read:clients']),
   grant('m24-reader','sdk.e2e.test',['read:users','read:user_idp_tokens'])],
  connections:[{name:'Username-Password-Authentication',is_domain_connection:true,enabled_clients:['m24-spa']}]},
 // Another tenant whose client holds read:user_idp_tokens for its own API only.
 {name:'other',domains:['other.e2e.test'],clients:[m2m('other-reader','Other reader')],client_grants:[grant('other-reader','other.e2e.test',['read:users','read:user_idp_tokens'])]},
 // Deploy CLI source and the two fresh import targets (YAML, directory).
 deployTenant('ghsource','source.e2e.test'),deployTenant('ghtarget-yaml','yaml.target.e2e.test'),deployTenant('ghtarget-directory','directory.target.e2e.test'),
]};
await writeFile(process.env.E2E_SEED,dump(seed),{mode:0o600});
JS
go build -o "$work/harness" ./tests/e2e/social/harness
go build -o "$work/prepare" ./tests/e2e/deploy-cli
export E2E_GITHUB_PREPARER="$work/prepare"
start "$work/harness" >"$work/server.log" 2>&1
PROXY_PORT=9198 TARGET_PORT=9543 start node tests/e2e/connect-proxy.mjs >"$work/proxy.log" 2>&1
PROXY_PORT=9199 TARGET_PORT=9544 start node tests/e2e/connect-proxy.mjs >"$work/proxy2.log" 2>&1
for _ in $(seq 1 150); do
 if curl -fsS http://127.0.0.1:9173/healthz >/dev/null 2>&1 && curl -s http://127.0.0.1:9198 >/dev/null && curl -s http://127.0.0.1:9199 >/dev/null; then break; fi
 sleep 0.1
done
curl -fsS http://127.0.0.1:9173/healthz >/dev/null || { echo 'GitHub harness startup failed; inspect protected server.log' >&2; exit 1; }
(cd tests/e2e && ./node_modules/.bin/playwright test m39c-github.spec.mjs --config playwright.config.mjs --output "$work/playwright-results") | tee "$work/browser.log"
for format in yaml directory; do E2E_GITHUB_FORMAT="$format" node tests/e2e/m39c-github-deploy.mjs | tee "$work/deploy-$format.log"; done
echo 'GitHub acceptance: browser lane and Deploy CLI YAML/directory lanes passed (no optional lanes or skips)'
