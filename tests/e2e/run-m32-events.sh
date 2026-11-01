#!/usr/bin/env bash
# Plan32 acceptance uses the shipped binary/app.New and a real SQLite database.
# Every receiver body is checked with the production frozen-catalog validator.
set -euo pipefail
cd "$(dirname "$0")/../.."
export GOTOOLCHAIN=go1.26.7
# Playwright sets FORCE_COLOR in its workers; omit NO_COLOR to avoid conflicts.
unset NO_COLOR
export FORCE_COLOR=0
for tool in node go openssl curl flock python3 setsid; do
 command -v "$tool" >/dev/null || { echo "e2e-events unavailable: missing $tool" >&2; exit 1; }
done
export AUTH0_BIN="${AUTH0_BIN:-$(command -v auth0 || true)}"
[[ -x "$AUTH0_BIN" && -x tests/e2e/node_modules/.bin/playwright ]] || { echo 'e2e-events unavailable: install tests/e2e dependencies and Auth0 CLI 1.37.0' >&2; exit 1; }
"$AUTH0_BIN" --version | grep -q '1.37.0' || { echo 'e2e-events requires Auth0 CLI 1.37.0' >&2; exit 1; }
# Shared proxy/service ports serialize with the existing social/Actions fixtures.
exec 9>/tmp/zeroauthy-e2e-social.lock
flock 9
umask 077
work=$(mktemp -d "${E2E_ARTIFACT_DIR:-/tmp}/plan32-XXXXXX")
export E2E_M32_WORK="$work" E2E_CHROMIUM="${E2E_CHROMIUM:-$(command -v chromium || true)}"
pids=()
start() { setsid "$@" & pids+=("$!"); }
cleanup() {
 trap - EXIT INT TERM
 for p in "${pids[@]}"; do kill -TERM -- "-$p" 2>/dev/null || true; done
 for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done
 if [[ ${E2E_KEEP_WORK:-0} == 1 ]]; then echo "Plan32 artifacts: $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for name in responses.jsonl browser-responses.jsonl browser-console.jsonl cli.jsonl receiver.jsonl; do : > "$work/$name"; done
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Plan32 local test root' \
 -addext 'subjectAltName=DNS:sdk.e2e.test,DNS:system.e2e.test,DNS:callback.e2e.test,IP:127.0.0.1' \
 -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
openssl rand -base64 32 > "$work/master.key"
export E2E_CERT="$work/cert.pem" NODE_EXTRA_CA_CERTS="$work/cert.pem" SSL_CERT_FILE="$work/cert.pem"
cat > "$work/seed.yaml" <<'YAML'
tenants:
  - name: events
    friendly_name: Plan32 Events acceptance
    domains: [sdk.e2e.test]
    skip_non_verifiable_callback_uri_confirmation_prompt: true
    default_directory: Username-Password-Authentication
    clients:
      - {client_id: m32-admin, app_type: non_interactive, client_secret: Plan32-Management-Secret-2026, grant_types: [client_credentials]}
      - {client_id: m32-password, app_type: regular_web, client_secret: Plan32-Password-Client-Secret-2026, grant_types: ['http://auth0.com/oauth/grant-type/password-realm']}
      - {client_id: m32-spa, name: Plan32 Browser, app_type: spa, grant_types: [authorization_code], callbacks: ['https://callback.e2e.test/'], web_origins: ['https://callback.e2e.test']}
    client_grants:
      - client_id: m32-admin
        audience: https://sdk.e2e.test/api/v2/
        scopes: [read:logs, read:events, read:event_streams, create:event_streams, update:event_streams, delete:event_streams, read:event_deliveries, update:event_deliveries, read:users, create:users, update:users, delete:users, read:actions, create:actions, update:actions, read:connections, create:connections]
    connections:
      - name: Username-Password-Authentication
        is_domain_connection: true
        enabled_clients: [m32-spa, m32-password]
YAML
cat > "$work/config.yaml" <<YAML
server:
  listen: 127.0.0.1:9543
  system_host: system.e2e.test
  tls_cert_file: $work/cert.pem
  tls_key_file: $work/key.pem
storage:
  dsn: sqlite://$work/events.db
  auto_migrate: true
security:
  master_key_file: $work/master.key
seed: $work/seed.yaml
seed_mode: create_only
actions:
  cache_dir: $work/actions-cache
  registry: http://127.0.0.1:9187/
events:
  allow_private_networks: true
log:
  level: info
  format: json
YAML
node -e 'const [a,b]=process.versions.node.split(".").map(Number);if(a<22||(a===22&&b<13))process.exit(1)'
go build -o "$work/event-validator" ./tests/e2e/event-validator
go build -o "$work/zeroauthy" ./cmd/zeroauthy
"$work/zeroauthy" migrate -c "$work/config.yaml" > "$work/migrate.log" 2>&1
# CLI setup output is a credential: keep it 0600, outside the server log audit.
# No bootstrap.admin_email, so the production server never logs a setup URL.
"$work/zeroauthy" admin create -c "$work/config.yaml" --email operator32@e2e.local > "$work/operator-setup.txt" 2> "$work/bootstrap.stderr"
start node tests/e2e/m32-events-cli.mjs receiver > "$work/receiver.log" 2>&1
PROXY_PORT=9198 TARGET_PORT=9543 start node tests/e2e/connect-proxy.mjs > "$work/proxy.log" 2>&1
start "$work/zeroauthy" serve -c "$work/config.yaml" > "$work/server.log" 2>&1
server_pid=${pids[-1]}
ready() {
 for _ in $(seq 1 300); do
  if curl -fsS --cacert "$work/cert.pem" --resolve sdk.e2e.test:9543:127.0.0.1 https://sdk.e2e.test:9543/healthz --noproxy '*' >/dev/null 2>&1; then return; fi
  kill -0 "$server_pid" 2>/dev/null || { cat "$work"/server*.log >&2; return 1; }
  sleep 0.1
 done
 echo 'e2e-events: production app did not become ready' >&2; return 1
}
ready
node tests/e2e/m32-events-node.mjs setup
( cd tests/e2e && ./node_modules/.bin/playwright test m32-event-streams.spec.mjs --config playwright.config.mjs --output "$work/playwright-results" )
node tests/e2e/m32-events-node.mjs sdk
node tests/e2e/m32-events-cli.mjs cli
node tests/e2e/m32-events-node.mjs resume
kill -TERM -- "-$server_pid"
wait "$server_pid"
# All columns of all three event tables, including sealed configuration.
# The legitimate user credential hash is independently extracted before deletion.
python3 - "$work" <<'PYDUMP'
import json, pathlib, sqlite3, sys
work=pathlib.Path(sys.argv[1])
with sqlite3.connect(work/'events.db') as db:
 db.row_factory=sqlite3.Row
 with (work/'event-rows.jsonl').open('w') as out:
  for table in ['tenant_events','event_streams','event_deliveries']:
   for row in db.execute('SELECT * FROM '+table):
    value={k:v.decode() if isinstance(v,bytes) else v for k,v in dict(row).items()}
    out.write(json.dumps({'table':table,'value':value})+'\n')
PYDUMP
node tests/e2e/m32-events-node.mjs audit
echo 'Plan32 e2e-events acceptance passed (production app/SQLite; pinned SDK/CLI/Playwright, local HTTPS only)'
