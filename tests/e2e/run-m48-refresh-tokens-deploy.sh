#!/usr/bin/env bash
# Actual pinned Deploy CLI, Plan 48 refresh-token and sender-constraint settings. This is called
# by the refresh-token acceptance lane or directly; it uses the existing proxy.
set -euo pipefail
exec 9>/tmp/zeroauthy-e2e8443.lock
flock 9
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
chmod 700 "$work"
pids=()
started=''
start() { setsid "$@" & started=$!; pids+=("$started"); }
cleanup() {
 trap - EXIT INT TERM
 for p in "${pids[@]}"; do kill -TERM -- "-$p" 2>/dev/null || true; done
 if [[ ${E2E_KEEP_WORK:-0} == 1 ]]; then echo "Refresh token Deploy CLI artifacts: $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Refresh token deploy test root' \
 -addext 'subjectAltName=DNS:localhost,DNS:cli.e2e.test,DNS:target.cli.e2e.test' \
 -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
CGO_ENABLED=0 go build -o "$work/zeroauthy" ./cmd/zeroauthy
export E2E_M48_BINARY="$work/zeroauthy"
start node tests/e2e/deploy-cli/connect-proxy.mjs >"$work/proxy.log" 2>&1
export ZEROAUTHY_SERVER__TLS_CERT_FILE="$work/cert.pem" ZEROAUTHY_SERVER__TLS_KEY_FILE="$work/key.pem"
export ZEROAUTHY_STORAGE__AUTO_MIGRATE=true ZEROAUTHY_SEED_MODE=create_only
export ZEROAUTHY_SECURITY__MASTER_KEY="$(openssl rand -base64 32)"
export E2E_M48_SOURCE_ADMIN_SECRET="$(openssl rand -hex 24)" E2E_M48_TARGET_ADMIN_SECRET="$(openssl rand -hex 24)"
export NODE_EXTRA_CA_CERTS="$work/cert.pem" SSL_CERT_FILE="$work/cert.pem"
export ZEROAUTHY_EMAIL__DIR="$work/mail"
mkdir "$work/mail"
serve() {
 start "$work/zeroauthy" serve --config tests/e2e/config.yaml >"$E2E_M48_DEPLOY_WORK/$1-server.log" 2>&1
 server_pid=$started
 for _ in $(seq 1 100); do
  if curl -fsS --cacert "$work/cert.pem" "https://localhost:$2/healthz" >/dev/null 2>&1; then return; fi
  if ! kill -0 "$server_pid" 2>/dev/null; then break; fi
  sleep 0.1
 done
 echo "Refresh token deploy $1 server failed to start; inspect protected artifacts" >&2
 return 1
}
for mode in generated preserved; do
 for format in yaml directory; do
  export E2E_M48_MODE="$mode" E2E_M48_FORMAT="$format" E2E_M48_DEPLOY_WORK="$work/$mode-$format"
  mkdir -m 700 "$E2E_M48_DEPLOY_WORK"
  export E2E_M48_SOURCE_DSN="sqlite://$E2E_M48_DEPLOY_WORK/source.db" E2E_M48_TARGET_DSN="sqlite://$E2E_M48_DEPLOY_WORK/target.db"
  export E2E_M48_TARGET_SEED="$E2E_M48_DEPLOY_WORK/target-seed.yaml"
  node --input-type=module <<'JS'
import {writeFile} from 'node:fs/promises';
import {dump} from './tests/e2e/node_modules/js-yaml/index.js';
const scopes=['read:clients','create:clients','update:clients','delete:clients','read:resource_servers','create:resource_servers','update:resource_servers','delete:resource_servers','read:tenant_settings','update:tenant_settings','read:organizations','create:organizations','update:organizations','delete:organizations','read:connections','read:client_grants','read:organization_connections','read:organization_client_grants','read:organization_discovery_domains','read:organization_clients'];
for(const side of ['source','target']){
 const host=side==='source'?'cli.e2e.test':'target.cli.e2e.test';
 const client=`refresh-${side}-admin`;
 const doc={tenants:[{name:`refresh-${side}`,domains:[host],clients:[{client_id:client,name:`Refresh token ${side} admin`,app_type:'non_interactive',client_secret:process.env[`E2E_M48_${side.toUpperCase()}_ADMIN_SECRET`],grant_types:['client_credentials']}],client_grants:[{client_id:client,audience:`https://${host}/api/v2/`,scopes}]}]};
 await writeFile(`${process.env.E2E_M48_DEPLOY_WORK}/${side}-seed.yaml`,dump(doc),{mode:0o600});
}
JS
  export ZEROAUTHY_STORAGE__DSN="$E2E_M48_SOURCE_DSN" ZEROAUTHY_SEED="$E2E_M48_DEPLOY_WORK/source-seed.yaml" ZEROAUTHY_SERVER__LISTEN=:8443
  serve source 8443
  source_pid=$server_pid
  ZEROAUTHY_STORAGE__DSN="$E2E_M48_TARGET_DSN" "$work/zeroauthy" migrate --config tests/e2e/config.yaml >"$E2E_M48_DEPLOY_WORK/target-migration.log" 2>&1
  E2E_M48_PHASE=prepare node tests/e2e/m48-refresh-tokens-deploy.mjs
  export ZEROAUTHY_STORAGE__DSN="$E2E_M48_TARGET_DSN" ZEROAUTHY_SEED="$E2E_M48_TARGET_SEED" ZEROAUTHY_SERVER__LISTEN=:8444
  serve target 8444
  E2E_M48_PHASE=verify node tests/e2e/m48-refresh-tokens-deploy.mjs
  kill -TERM -- "-$server_pid"; wait "$server_pid"
  kill -TERM -- "-$source_pid"; wait "$source_pid"
 done
done
echo 'Refresh token deploy: four cells passed (YAML/directory × generated/preserved client IDs)'
