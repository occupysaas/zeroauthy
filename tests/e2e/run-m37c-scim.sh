#!/usr/bin/env bash
# make e2e-scim: Plan 37c inbound SCIM 2.0 over real HTTPS. The pinned
# node-auth0 SDK configures SCIM and tokens and manages groups through the
# Management API; an in-house RFC 7644 client (m37c-scim.mjs) provisions
# users and groups with the payload shapes Microsoft Entra ID and Okta send.
# Then the pinned Deploy CLI round trip of scim_configuration. All secrets
# are generated per run; no external host is contacted.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec 9>/tmp/zeroauthy-e2e-scim.lock
flock 9
umask 077
work=$(mktemp -d)
export E2E_M37C_WORK="$work"
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
export NODE_EXTRA_CA_CERTS="$work/cert.pem" SSL_CERT_FILE="$work/cert.pem"
export E2E_M37C_ADMIN_SECRET="$(openssl rand -hex 24)"
node --input-type=module <<'JS'
import {writeFile} from 'node:fs/promises';
import {dump} from './tests/e2e/node_modules/js-yaml/index.js';
const host='localhost:9547';
const scopes=['read:connections','read:users','update:users','delete:users','read:roles','create:roles','read:scim_config','create:scim_config','update:scim_config','delete:scim_config',
 'read:scim_token','create:scim_token','delete:scim_token','read:groups','delete:groups','read:group_members','read:group_roles','create:group_roles','delete:group_roles','read:user_role_source_groups'];
const okta=(name)=>({name,strategy:'okta',options:{domain:`${name}.okta.e2e.test`,client_id:`${name}-client`,client_secret:'unused-'+name,scope:'openid profile email'}});
const doc={tenants:[{name:'scim',domains:[host],clients:[{client_id:'m37c-admin',name:'SCIM admin',app_type:'non_interactive',client_secret:process.env.E2E_M37C_ADMIN_SECRET,grant_types:['client_credentials']}],
 client_grants:[{client_id:'m37c-admin',audience:`https://${host}/api/v2/`,scopes}],connections:[{name:'DB'},okta('corp-okta'),okta('other-okta')]}]};
await writeFile(`${process.env.E2E_M37C_WORK}/seed.yaml`,dump(doc),{mode:0o600});
JS
CGO_ENABLED=0 go build -o "$work/zeroauthy" ./cmd/zeroauthy
mkdir "$work/mail"
ZEROAUTHY_SECURITY__MASTER_KEY="$(openssl rand -base64 32)" \
ZEROAUTHY_SERVER__TLS_CERT_FILE="$work/cert.pem" ZEROAUTHY_SERVER__TLS_KEY_FILE="$work/key.pem" \
ZEROAUTHY_SERVER__LISTEN=:9547 ZEROAUTHY_SERVER__SYSTEM_HOST=system.localhost:9547 \
ZEROAUTHY_STORAGE__DSN="sqlite://$work/scim.db" ZEROAUTHY_STORAGE__AUTO_MIGRATE=true \
ZEROAUTHY_SEED="$work/seed.yaml" ZEROAUTHY_SEED_MODE=create_only ZEROAUTHY_EMAIL__DIR="$work/mail" \
 setsid "$work/zeroauthy" serve --config tests/e2e/config.yaml >"$work/server.log" 2>&1 & pids+=("$!")
for _ in $(seq 1 200); do
 if curl -fsS --cacert "$work/cert.pem" https://localhost:9547/healthz --noproxy '*' >/dev/null 2>&1; then break; fi
 kill -0 "${pids[0]}" 2>/dev/null || { echo 'Plan 37c server failed to start; inspect protected server.log' >&2; exit 1; }
 sleep 0.1
done
(cd tests/e2e && node m37c-scim.mjs) || { echo 'Plan 37c SCIM acceptance failed; inspect protected artifacts (E2E_KEEP_WORK=1)' >&2; exit 1; }
kill -TERM -- "-${pids[0]}"
wait "${pids[0]}" || true
# The server log must not contain any SCIM token issued in this run.
node --input-type=module -e '
import {readFile} from "node:fs/promises";
const w=process.env.E2E_M37C_WORK, log=await readFile(w+"/server.log","utf8"), secrets=JSON.parse(await readFile(w+"/issued-tokens.json","utf8"));
if(secrets.length<3)throw new Error("too few issued tokens recorded");
for(const s of secrets)if(log.includes(s))throw new Error("a SCIM token reached the server log");
if(log.includes(process.env.E2E_M37C_ADMIN_SECRET))throw new Error("the admin secret reached the server log");
console.log("Plan 37c log audit: no SCIM token or admin secret in the server log");'
./tests/e2e/run-m37c-scim-deploy.sh
echo 'SCIM acceptance: node-auth0 configuration, tokens and groups, RFC 7644 Entra/Okta provisioning, isolation, deprovisioning, log audit and Deploy CLI cells passed (no skips)'
