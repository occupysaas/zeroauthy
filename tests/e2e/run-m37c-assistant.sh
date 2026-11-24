#!/usr/bin/env bash
# make e2e-self-service: Plan 37c Phase B over real HTTPS and a real browser.
# The pinned node-auth0 SDK creates a self-service profile and an SSO
# ticket; Playwright opens the ticket as the customer administrator,
# configures a SAML connection against a samlify identity provider,
# signs in through it, creates a SCIM token and finishes; the used ticket
# then opens nothing, and the server log holds neither the ticket nor the
# SCIM token. All keys and secrets are generated per run.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec 9>/tmp/zeroauthy-e2e-social.lock
flock 9
umask 077
work=$(mktemp -d)
export E2E_M37C_WORK="$work" E2E_M37C=1
export E2E_CHROMIUM="${E2E_CHROMIUM:-$(command -v chromium || true)}"
pids=()
cleanup() {
 trap - EXIT INT TERM
 for p in "${pids[@]}"; do kill -TERM -- "-$p" 2>/dev/null || true; done
 if [[ ${E2E_KEEP_WORK:-0} == 1 ]]; then echo "Plan 37c private artifacts: $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Plan37c local test root' \
 -addext 'subjectAltName=DNS:localhost,DNS:system.localhost,IP:127.0.0.1' \
 -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Plan37c throwaway customer IdP' \
 -keyout "$work/idp-key.pem" -out "$work/idp-cert.pem" 2>/dev/null
export NODE_EXTRA_CA_CERTS="$work/cert.pem" SSL_CERT_FILE="$work/cert.pem"
export E2E_M37C_ADMIN_SECRET="$(openssl rand -hex 24)"
node --input-type=module <<'JS'
import {writeFile} from 'node:fs/promises';
import {dump} from './tests/e2e/node_modules/js-yaml/index.js';
const host='localhost:9548';
const scopes=['read:connections','read:users','read:self_service_profiles','create:self_service_profiles','update:self_service_profiles','read:self_service_profile_custom_texts',
 'update:self_service_profile_custom_texts','create:sso_access_tickets','delete:sso_access_tickets','read:scim_config'];
const doc={tenants:[{name:'ssso',domains:[host],default_directory:'DB',skip_non_verifiable_callback_uri_confirmation_prompt:true,clients:[
 {client_id:'m37c-admin',name:'Self-service admin',app_type:'non_interactive',client_secret:process.env.E2E_M37C_ADMIN_SECRET,grant_types:['client_credentials']},
 {client_id:'m37c-app',name:'Partner portal',app_type:'spa',grant_types:['authorization_code'],callbacks:['https://127.0.0.1:9694/raw']}],
 client_grants:[{client_id:'m37c-admin',audience:`https://${host}/api/v2/`,scopes}],connections:[{name:'DB'}]}]};
await writeFile(`${process.env.E2E_M37C_WORK}/seed.yaml`,dump(doc),{mode:0o600});
JS
CGO_ENABLED=0 go build -o "$work/zeroauthy" ./cmd/zeroauthy
mkdir "$work/mail"
ZEROAUTHY_SECURITY__MASTER_KEY="$(openssl rand -base64 32)" \
ZEROAUTHY_SERVER__TLS_CERT_FILE="$work/cert.pem" ZEROAUTHY_SERVER__TLS_KEY_FILE="$work/key.pem" \
ZEROAUTHY_SERVER__LISTEN=:9548 ZEROAUTHY_SERVER__SYSTEM_HOST=system.localhost:9548 \
ZEROAUTHY_STORAGE__DSN="sqlite://$work/ssso.db" ZEROAUTHY_STORAGE__AUTO_MIGRATE=true \
ZEROAUTHY_SEED="$work/seed.yaml" ZEROAUTHY_SEED_MODE=create_only ZEROAUTHY_EMAIL__DIR="$work/mail" \
 setsid "$work/zeroauthy" serve --config tests/e2e/config.yaml >"$work/server.log" 2>&1 & pids+=("$!")
for _ in $(seq 1 200); do
 if curl -fsS --cacert "$work/cert.pem" https://localhost:9548/healthz --noproxy '*' >/dev/null 2>&1; then break; fi
 kill -0 "${pids[0]}" 2>/dev/null || { echo 'Plan 37c server failed to start; inspect protected server.log' >&2; exit 1; }
 sleep 0.1
done
(cd tests/e2e && ./node_modules/.bin/playwright test m37c-assistant.spec.mjs --config playwright.config.mjs --output "$work/playwright-results") >"$work/playwright.log" 2>&1 || { tail -n 60 "$work/playwright.log" | grep -v -i -E 'SAMLResponse=|ticket=' >&2; echo 'Plan 37c browser acceptance failed; inspect protected playwright.log' >&2; exit 1; }
grep -E 'passed|skipped|failed' "$work/playwright.log" | tail -3
kill -TERM -- "-${pids[0]}"
wait "${pids[0]}" || true
node --input-type=module -e '
import {readFile} from "node:fs/promises";
const w=process.env.E2E_M37C_WORK, log=await readFile(w+"/server.log","utf8"), secrets=JSON.parse(await readFile(w+"/issued.json","utf8"));
if(secrets.length<2)throw new Error("issued secrets not recorded");
for(const s of secrets)if(log.includes(s))throw new Error("a ticket or SCIM token reached the server log");
if(log.includes(process.env.E2E_M37C_ADMIN_SECRET))throw new Error("the admin secret reached the server log");
console.log("Plan 37c assistant log audit: no ticket, SCIM token or admin secret in the server log");'
echo 'Self-service SSO acceptance: node-auth0 profile and ticket, assistant SAML setup against samlify, sign-in through the new connection, SCIM token, single use and log audit passed (no skips)'
