#!/usr/bin/env bash
# make e2e-saml: Plan 37a SAML 2.0 against pinned third-party libraries.
# zeroauthy as identity provider for @node-saml/node-saml (SP-initiated login
# and signed single logout), and as service provider for a samlify identity
# provider (SP-initiated login and upstream single logout), driven through
# Playwright; then the Deploy CLI four-cell round trip. All keys, secrets and
# passwords are generated per run; no external host is contacted.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec 9>/tmp/zeroauthy-e2e-social.lock
flock 9
umask 077
work=$(mktemp -d)
export E2E_M37A_WORK="$work" E2E_M37A=1
export E2E_CHROMIUM="${E2E_CHROMIUM:-$(command -v chromium || true)}"
pids=()
cleanup() {
 trap - EXIT INT TERM
 for p in "${pids[@]}"; do kill -TERM -- "-$p" 2>/dev/null || true; done
 if [[ ${E2E_KEEP_WORK:-0} == 1 ]]; then echo "Plan 37a private artifacts: $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Plan37a local test root' \
 -addext 'subjectAltName=DNS:localhost,DNS:system.localhost,IP:127.0.0.1' \
 -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
# Throwaway SAML signing keys: the samlify IdP and the node-saml SP.
for party in idp sp; do
 openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=Plan37a throwaway $party" \
  -keyout "$work/$party-key.pem" -out "$work/$party-cert.pem" 2>/dev/null
done
export NODE_EXTRA_CA_CERTS="$work/cert.pem" SSL_CERT_FILE="$work/cert.pem"
node --input-type=module <<'JS'
import {randomBytes} from 'node:crypto';
import {readFile,writeFile} from 'node:fs/promises';
import {dump} from './tests/e2e/node_modules/js-yaml/index.js';
const work=process.env.E2E_M37A_WORK,credentials={admin:randomBytes(32).toString('hex'),password:'Za-'+randomBytes(24).toString('hex')};
await writeFile(`${work}/private-credentials.json`,JSON.stringify(credentials),{mode:0o600});
const sp='https://127.0.0.1:9653',idp='https://127.0.0.1:9663';
const idpCert=(await readFile(`${work}/idp-cert.pem`,'utf8')).trim(),spCert=(await readFile(`${work}/sp-cert.pem`,'utf8')).trim();
const doc={tenants:[{name:'saml',domains:['localhost:9543'],default_directory:'DB',skip_non_verifiable_callback_uri_confirmation_prompt:true,clients:[
 {client_id:'m37a-admin',name:'SAML admin',app_type:'non_interactive',client_secret:credentials.admin,grant_types:['client_credentials']},
 // zeroauthy is the IdP for this node-saml service provider.
 {client_id:'m37a-sp',name:'node-saml service provider',app_type:'regular_web',client_secret:randomBytes(32).toString('hex'),callbacks:[`${sp}/acs`],
  addons:{samlp:{audience:'urn:e2e:node-saml',signingCert:spCert,mappings:{email:'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'},logout:{callback:`${sp}/slo`,slo_enabled:true}}}},
 // An OIDC application logging in through the samlify IdP.
 {client_id:'m37a-app',name:'SAML federated app',app_type:'spa',grant_types:['authorization_code'],callbacks:[`${sp}/raw`],allowed_logout_urls:[`${sp}/raw`]},
],client_grants:[{client_id:'m37a-admin',audience:'https://localhost:9543/api/v2/',scopes:['read:clients','update:clients','read:connections','update:connections','read:users','read:sessions']}],connections:[
 {name:'DB',enabled_clients:['m37a-sp']},
 {name:'corp-saml',strategy:'samlp',enabled_clients:['m37a-app'],options:{signInEndpoint:`${idp}/sso`,signOutEndpoint:`${idp}/slo`,signingCert:idpCert,fieldsMap:{email:'mail',name:'displayName'}}},
],users:[{connection:'DB',email:'alice@example.test',password:credentials.password,email_verified:true,name:'Fixture Alice'}]}]};
await writeFile(`${work}/seed.yaml`,dump(doc),{mode:0o600});
JS
CGO_ENABLED=0 go build -o "$work/zeroauthy" ./cmd/zeroauthy
mkdir "$work/mail"
ZEROAUTHY_SECURITY__MASTER_KEY="$(openssl rand -base64 32)" \
ZEROAUTHY_SERVER__TLS_CERT_FILE="$work/cert.pem" ZEROAUTHY_SERVER__TLS_KEY_FILE="$work/key.pem" \
ZEROAUTHY_SERVER__LISTEN=:9543 ZEROAUTHY_SERVER__SYSTEM_HOST=system.localhost:9543 \
ZEROAUTHY_STORAGE__DSN="sqlite://$work/saml.db" ZEROAUTHY_STORAGE__AUTO_MIGRATE=true \
ZEROAUTHY_SEED="$work/seed.yaml" ZEROAUTHY_SEED_MODE=create_only ZEROAUTHY_EMAIL__DIR="$work/mail" \
 setsid "$work/zeroauthy" serve --config tests/e2e/config.yaml >"$work/server.log" 2>&1 & pids+=("$!")
for _ in $(seq 1 200); do
 if curl -fsS --cacert "$work/cert.pem" https://localhost:9543/healthz --noproxy '*' >/dev/null 2>&1; then break; fi
 kill -0 "${pids[0]}" 2>/dev/null || { echo 'Plan 37a server failed to start; inspect protected server.log' >&2; exit 1; }
 sleep 0.1
done
(cd tests/e2e && ./node_modules/.bin/playwright test m37a-saml.spec.mjs --config playwright.config.mjs --output "$work/playwright-results") >"$work/playwright.log" 2>&1 || { tail -n 60 "$work/playwright.log" | grep -v -i -E 'SAMLResponse=|SAMLRequest=' >&2; echo 'Plan 37a browser acceptance failed; inspect protected playwright.log' >&2; exit 1; }
grep -E 'passed|skipped|failed' "$work/playwright.log" | tail -3
node tests/e2e/m37a-saml-audit.mjs
kill -TERM -- "-${pids[0]}"
wait "${pids[0]}" || true
./tests/e2e/run-m37a-saml-deploy.sh
echo 'SAML acceptance: node-saml SP, samlify IdP, single logout both directions and Deploy CLI four cells passed (no skips)'
