#!/usr/bin/env bash
# make e2e-wsfed: Plan 37b WS-Federation over real HTTPS and a real browser.
# zeroauthy as WS-Fed identity provider for a relying-party fixture, and as
# relying party (adfs connection) of a WS-Fed identity-provider fixture. Both
# fixtures sign and verify with the pinned xml-crypto (node-saml's XML
# signature library), not zeroauthy's own code. Then the Deploy CLI
# four-cell round trip. All keys, secrets and passwords are generated per
# run; no external host is contacted.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec 9>/tmp/zeroauthy-e2e-social.lock
flock 9
umask 077
work=$(mktemp -d)
export E2E_M37B_WORK="$work" E2E_M37B=1
export E2E_CHROMIUM="${E2E_CHROMIUM:-$(command -v chromium || true)}"
pids=()
cleanup() {
 trap - EXIT INT TERM
 for p in "${pids[@]}"; do kill -TERM -- "-$p" 2>/dev/null || true; done
 if [[ ${E2E_KEEP_WORK:-0} == 1 ]]; then echo "Plan 37b private artifacts: $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Plan37b local test root' \
 -addext 'subjectAltName=DNS:localhost,DNS:system.localhost,IP:127.0.0.1' \
 -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
# Throwaway signing key of the WS-Fed identity-provider fixture.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Plan37b throwaway STS' \
 -keyout "$work/idp-key.pem" -out "$work/idp-cert.pem" 2>/dev/null
export NODE_EXTRA_CA_CERTS="$work/cert.pem" SSL_CERT_FILE="$work/cert.pem"
node --input-type=module <<'JS'
import {randomBytes} from 'node:crypto';
import {readFile,writeFile} from 'node:fs/promises';
import {dump} from './tests/e2e/node_modules/js-yaml/index.js';
const work=process.env.E2E_M37B_WORK,credentials={password:'Za-'+randomBytes(24).toString('hex')};
await writeFile(`${work}/private-credentials.json`,JSON.stringify(credentials),{mode:0o600});
const rp='https://127.0.0.1:9673',idp='https://127.0.0.1:9683';
const der=(await readFile(`${work}/idp-cert.pem`,'utf8')).split('\n').filter(l=>l&&!l.startsWith('-----')).join('');
const metadata=`<EntityDescriptor entityID="urn:e2e:sts" xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><RoleDescriptor xsi:type="fed:SecurityTokenServiceType" protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706"><KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>${der}</X509Certificate></X509Data></KeyInfo></KeyDescriptor><fed:PassiveRequestorEndpoint><EndpointReference xmlns="http://www.w3.org/2005/08/addressing"><Address>${idp}/adfs/ls/</Address></EndpointReference></fed:PassiveRequestorEndpoint></RoleDescriptor></EntityDescriptor>`;
const doc={tenants:[{name:'wsfed',domains:['localhost:9545'],default_directory:'DB',skip_non_verifiable_callback_uri_confirmation_prompt:true,clients:[
 // zeroauthy is the WS-Fed IdP for this relying party.
 {client_id:'m37b-rp',name:'WS-Fed relying party',app_type:'regular_web',client_secret:randomBytes(32).toString('hex'),callbacks:[`${rp}/callback`],allowed_logout_urls:[`${rp}/bye`],
  client_aliases:['urn:e2e:wsfed-rp'],addons:{wsfed:{}}},
 // An OIDC application logging in through the WS-Fed IdP fixture.
 {client_id:'m37b-app',name:'ADFS federated app',app_type:'spa',grant_types:['authorization_code'],callbacks:[`${rp}/raw`],allowed_logout_urls:[`${rp}/raw`]},
],connections:[
 {name:'DB',enabled_clients:['m37b-rp']},
 {name:'corp-adfs',strategy:'adfs',enabled_clients:['m37b-app'],options:{fedMetadataXml:metadata}},
],users:[{connection:'DB',email:'alice@example.test',password:credentials.password,email_verified:true,name:'Fixture Alice'}]}]};
await writeFile(`${work}/seed.yaml`,dump(doc),{mode:0o600});
JS
CGO_ENABLED=0 go build -o "$work/zeroauthy" ./cmd/zeroauthy
mkdir "$work/mail"
ZEROAUTHY_SECURITY__MASTER_KEY="$(openssl rand -base64 32)" \
ZEROAUTHY_SERVER__TLS_CERT_FILE="$work/cert.pem" ZEROAUTHY_SERVER__TLS_KEY_FILE="$work/key.pem" \
ZEROAUTHY_SERVER__LISTEN=:9545 ZEROAUTHY_SERVER__SYSTEM_HOST=system.localhost:9545 \
ZEROAUTHY_STORAGE__DSN="sqlite://$work/wsfed.db" ZEROAUTHY_STORAGE__AUTO_MIGRATE=true \
ZEROAUTHY_SEED="$work/seed.yaml" ZEROAUTHY_SEED_MODE=create_only ZEROAUTHY_EMAIL__DIR="$work/mail" \
 setsid "$work/zeroauthy" serve --config tests/e2e/config.yaml >"$work/server.log" 2>&1 & pids+=("$!")
for _ in $(seq 1 200); do
 if curl -fsS --cacert "$work/cert.pem" https://localhost:9545/healthz --noproxy '*' >/dev/null 2>&1; then break; fi
 kill -0 "${pids[0]}" 2>/dev/null || { echo 'Plan 37b server failed to start; inspect protected server.log' >&2; exit 1; }
 sleep 0.1
done
(cd tests/e2e && ./node_modules/.bin/playwright test m37b-wsfed.spec.mjs --config playwright.config.mjs --output "$work/playwright-results") >"$work/playwright.log" 2>&1 || { tail -n 60 "$work/playwright.log" | grep -v -i -E 'wresult=' >&2; echo 'Plan 37b browser acceptance failed; inspect protected playwright.log' >&2; exit 1; }
grep -E 'passed|skipped|failed' "$work/playwright.log" | tail -3
node tests/e2e/m37b-wsfed-audit.mjs
kill -TERM -- "-${pids[0]}"
wait "${pids[0]}" || true
./tests/e2e/run-m37b-wsfed-deploy.sh
echo 'WS-Federation acceptance: relying-party fixture, identity-provider fixture, sign-out both directions and Deploy CLI four cells passed (no skips)'
