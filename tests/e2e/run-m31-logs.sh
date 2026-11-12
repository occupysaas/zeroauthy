#!/usr/bin/env bash
# Plan31 acceptance uses the shipped binary/app.New: recorder and delivery worker
# are production wiring, SQLite persists across a real process restart.
set -euo pipefail
cd "$(dirname "$0")/../.."
export GOTOOLCHAIN=go1.26.11
# Playwright sets FORCE_COLOR in its workers; omit NO_COLOR to avoid conflicts.
unset NO_COLOR
export FORCE_COLOR=0
for tool in node go openssl curl flock python3 setsid; do
 command -v "$tool" >/dev/null || { echo "e2e-logs unavailable: missing $tool" >&2; exit 1; }
done
export AUTH0_BIN="${AUTH0_BIN:-$(command -v auth0 || true)}"
[[ -x "$AUTH0_BIN" && -x tests/e2e/node_modules/.bin/playwright ]] || { echo 'e2e-logs unavailable: install tests/e2e dependencies and Auth0 CLI 1.37.0' >&2; exit 1; }
"$AUTH0_BIN" --version | grep -q '1.37.0' || { echo 'e2e-logs requires Auth0 CLI 1.37.0' >&2; exit 1; }
# Shared proxy/service ports serialize with the existing social/Actions fixtures.
exec 9>/tmp/zeroauthy-e2e-social.lock
flock 9
umask 077
work=$(mktemp -d "${E2E_ARTIFACT_DIR:-/tmp}/plan31-XXXXXX")
export E2E_M31_WORK="$work" E2E_CHROMIUM="${E2E_CHROMIUM:-$(command -v chromium || true)}"
pids=()
start() { setsid "$@" & pids+=("$!"); }
cleanup() {
 trap - EXIT INT TERM
 for p in "${pids[@]}"; do kill -TERM -- "-$p" 2>/dev/null || true; done
 for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done
 if [[ ${E2E_KEEP_WORK:-0} == 1 ]]; then echo "Plan31 artifacts: $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for name in monitoring.jsonl browser-monitoring.jsonl browser-console.jsonl cli.jsonl cli-tail.jsonl cli-tail.stderr; do : > "$work/$name"; done
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Plan31 local test root' \
 -addext 'subjectAltName=DNS:sdk.e2e.test,DNS:system.e2e.test,DNS:callback.e2e.test' \
 -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
openssl rand -base64 32 > "$work/master.key"
export E2E_CERT="$work/cert.pem" NODE_EXTRA_CA_CERTS="$work/cert.pem"
cat > "$work/seed.yaml" <<'YAML'
tenants:
  - name: logs
    friendly_name: Plan31 Logs acceptance
    domains: [sdk.e2e.test]
    skip_non_verifiable_callback_uri_confirmation_prompt: true
    default_directory: Username-Password-Authentication
    clients:
      - {client_id: m31-admin, app_type: non_interactive, client_secret: Plan31-Management-Secret-2026, grant_types: [client_credentials]}
      - {client_id: m31-password, app_type: regular_web, client_secret: Plan31-Password-Client-Secret-2026, grant_types: ['http://auth0.com/oauth/grant-type/password-realm']}
      - {client_id: m31-spa, name: Plan31 Browser, app_type: spa, grant_types: [authorization_code], callbacks: ['https://callback.e2e.test/'], web_origins: ['https://callback.e2e.test']}
    client_grants:
      - client_id: m31-admin
        audience: https://sdk.e2e.test/api/v2/
        scopes: [read:logs, read:logs_users, read:stats, read:log_streams, create:log_streams, update:log_streams, delete:log_streams, read:users, create:users, update:users, read:actions, create:actions, update:actions, read:connections, create:connections]
    connections:
      - name: Username-Password-Authentication
        is_domain_connection: true
        enabled_clients: [m31-spa, m31-password]
YAML
cat > "$work/config.yaml" <<YAML
server:
  listen: 127.0.0.1:9543
  system_host: system.e2e.test
  tls_cert_file: $work/cert.pem
  tls_key_file: $work/key.pem
storage:
  dsn: sqlite://$work/logs.db
  auto_migrate: true
security:
  master_key_file: $work/master.key
seed: $work/seed.yaml
seed_mode: create_only
actions:
  cache_dir: $work/actions-cache
  registry: http://127.0.0.1:9187/
logs:
  streams:
    allow_insecure_http: true
    allow_private_networks: true
log:
  level: info
  format: json
YAML
go build -o "$work/zeroauthy" ./cmd/zeroauthy
"$work/zeroauthy" migrate -c "$work/config.yaml" > "$work/migrate.log" 2>&1
# CLI setup output is a credential: keep it 0600, outside the server log audit.
# No bootstrap.admin_email, so the production server never logs a setup URL.
"$work/zeroauthy" admin create -c "$work/config.yaml" --email operator31@e2e.local > "$work/operator-setup.txt" 2> "$work/bootstrap.stderr"
start node tests/e2e/m31-logs-cli.mjs receiver > "$work/receiver.log" 2>&1
PROXY_PORT=9198 TARGET_PORT=9543 start node tests/e2e/connect-proxy.mjs > "$work/proxy.log" 2>&1
start "$work/zeroauthy" serve -c "$work/config.yaml" > "$work/server.log" 2>&1
server_pid=${pids[-1]}
ready() {
 for _ in $(seq 1 300); do
  if curl -fsS --cacert "$work/cert.pem" --resolve sdk.e2e.test:9543:127.0.0.1 https://sdk.e2e.test:9543/healthz --noproxy '*' >/dev/null 2>&1; then return; fi
  kill -0 "$server_pid" 2>/dev/null || { cat "$work"/server*.log >&2; return 1; }
  sleep 0.1
 done
 echo 'e2e-logs: production app did not become ready' >&2; return 1
}
ready
node tests/e2e/m31-node-auth0.mjs setup
node tests/e2e/m31-logs-cli.mjs create
browser_status=0
( cd tests/e2e && ./node_modules/.bin/playwright test m31-logs.spec.mjs --config playwright.config.mjs --output "$work/playwright-results" ) || browser_status=$?
node tests/e2e/m31-node-auth0.mjs check
node tests/e2e/m31-node-auth0.mjs prepare-restart
kill -TERM -- "-$server_pid"
wait "$server_pid"
start "$work/zeroauthy" serve -c "$work/config.yaml" > "$work/server-restart.log" 2>&1
server_pid=${pids[-1]}
ready
node tests/e2e/m31-node-auth0.mjs verify-restart
cli_status=0
node tests/e2e/m31-logs-cli.mjs verify || cli_status=$?
kill -TERM -- "-$server_pid"
wait "$server_pid"
# Export every log field and execution field, including indexed search projection,
# from SQLite. Never dump users/password hashes, Action source or wrapped secrets.
python3 - "$work" <<'PY'
import json, pathlib, sqlite3, sys
work = pathlib.Path(sys.argv[1])
with sqlite3.connect(work / 'logs.db') as db:
    db.row_factory = sqlite3.Row
    for table, name in [('tenant_logs','log-rows.jsonl'), ('action_executions','execution-rows.jsonl')]:
        with (work / name).open('w') as out:
            for row in db.execute('SELECT * FROM ' + table):
                value = {k: v.decode() if isinstance(v, bytes) else v for k, v in dict(row).items()}
                out.write(json.dumps(value) + '\n')
PY
node tests/e2e/m31-logs-cli.mjs audit
if [[ $browser_status != 0 || $cli_status != 0 ]]; then echo 'Plan31 browser/CLI acceptance failed; other checks completed, inspect retained artifacts' >&2; exit 1; fi
echo 'Plan31 e2e-logs acceptance passed (production app/SQLite; local endpoints only)'
