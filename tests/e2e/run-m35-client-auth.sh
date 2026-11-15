#!/usr/bin/env bash
# Plan 35 acceptance (spec §8): the production app, pinned auth0-auth-js,
# node-auth0, express-oauth2-jwt-bearer, auth0-cli 1.37.0 and the Deploy CLI
# 9.1.0 handlers prove private_key_jwt, JAR/PAR, HS256/PS256 API signing and
# custom token exchange, then a representative-secret audit scans every sink.
#
# Backends: E2E_M35_BACKENDS (default "sqlite"; "memory" also works, postgres
# and mysql use isolated SQL-test DSNs). Lanes: E2E_M35_LANES (default
# "browser sdk exchange deploy cli audit"); the browser lane needs the
# operator console, so it runs on SQLite only.
set -euo pipefail
cd "$(dirname "$0")/../.."
export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.11}"
unset NO_COLOR
export FORCE_COLOR=0
for tool in node go openssl curl flock setsid python3 sha256sum; do
 command -v "$tool" >/dev/null || { echo "e2e-client-auth unavailable: missing $tool" >&2; exit 1; }
done
export AUTH0_BIN="${AUTH0_BIN:-$(command -v auth0 || true)}"
[[ -x tests/e2e/node_modules/.bin/playwright ]] || { echo "e2e-client-auth unavailable: install tests/e2e dependencies (npm ci in tests/e2e)" >&2; exit 1; }
node -e 'const [a,b]=process.versions.node.split(".").map(Number);if(a<22||(a===22&&b<13))process.exit(1)' || { echo "e2e-client-auth unavailable: Node 22.13+ required" >&2; exit 1; }
lanes="${E2E_M35_LANES:-browser sdk exchange deploy cli audit}"
if [[ " $lanes " == *" cli "* ]]; then
 [[ -x "$AUTH0_BIN" ]] || { echo "e2e-client-auth unavailable: install the pinned Auth0 CLI 1.37.0 or drop the cli lane" >&2; exit 1; }
 "$AUTH0_BIN" --version | grep -q '1.37.0' || { echo "e2e-client-auth unavailable: Auth0 CLI is not 1.37.0" >&2; exit 1; }
fi
# Ports 9543/9198/9186 are shared with the other hosted lanes.
exec 9>/tmp/zeroauthy-e2e-social.lock
flock 9
umask 077
root=$(mktemp -d "${E2E_ARTIFACT_DIR:-${TMPDIR:-/tmp}}/plan35-XXXXXX")
export E2E_CHROMIUM="${E2E_CHROMIUM:-$(command -v chromium || true)}"
pids=()
start() { setsid "$@" & pids+=("$!"); }
stop() { for p in "${pids[@]}"; do kill -TERM -- "-$p" 2>/dev/null || true; done; for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done; pids=(); }
cleanup() { trap - EXIT INT TERM; stop; echo "Plan35 artifacts: $root"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Plan35 local test root' \
 -addext 'subjectAltName=DNS:sdk.e2e.test,DNS:system.e2e.test,DNS:callback.e2e.test,IP:127.0.0.1' \
 -keyout "$root/key.pem" -out "$root/cert.pem" 2>/dev/null
openssl rand -base64 32 > "$root/master.key"
export E2E_KEY="$root/key.pem" E2E_CERT="$root/cert.pem" NODE_EXTRA_CA_CERTS="$root/cert.pem" SSL_CERT_FILE="$root/cert.pem"
cat > "$root/seed.yaml" <<'YAML'
tenants:
  - name: sdk
    friendly_name: Plan35 client authentication acceptance
    domains: [sdk.e2e.test]
    skip_non_verifiable_callback_uri_confirmation_prompt: true
    pushed_authorization_requests_supported: true
    default_directory: Username-Password-Authentication
    clients:
      - {client_id: m35-admin, app_type: non_interactive, client_secret: Plan35-Management-Secret-2026, grant_types: [client_credentials]}
      - {client_id: m35-backend, name: Plan35 Backend, app_type: non_interactive, is_first_party: true, client_secret: Plan35-Backend-Secret-Before-Keys-2026, grant_types: [client_credentials]}
      - client_id: m35-web
        name: Plan35 Web
        app_type: regular_web
        is_first_party: true
        client_secret: Plan35-Web-Secret-Before-Keys-2026
        callbacks: ['https://callback.e2e.test/']
        grant_types: [authorization_code, refresh_token]
      - client_id: m35-bridge
        name: Plan35 Bridge
        app_type: regular_web
        is_first_party: true
        client_secret: Plan35-Bridge-Client-Secret-2026
        grant_types: [refresh_token]
    client_grants:
      - client_id: m35-admin
        audience: https://sdk.e2e.test/api/v2/
        scopes: [read:clients, create:clients, update:clients, delete:clients, read:client_credentials, create:client_credentials, update:client_credentials, delete:client_credentials, read:client_grants, create:client_grants, update:client_grants, delete:client_grants, read:resource_servers, create:resource_servers, update:resource_servers, delete:resource_servers, read:token_exchange_profiles, create:token_exchange_profiles, update:token_exchange_profiles, delete:token_exchange_profiles, read:actions, create:actions, update:actions, delete:actions, read:users, create:users, update:users, delete:users, read:connections, update:connections, read:logs, read:logs_users, read:log_streams, create:log_streams, read:attack_protection, update:attack_protection]
    connections:
      - name: Username-Password-Authentication
        is_domain_connection: true
        enabled_clients: [m35-web, m35-bridge]
YAML
go build -o "$root/zeroauthy" ./cmd/zeroauthy
for backend in ${E2E_M35_BACKENDS:-sqlite}; do
 export E2E_M35_WORK="$root/$backend" E2E_M35_BACKEND="$backend"
 mkdir -m 700 "$E2E_M35_WORK"
 git rev-parse HEAD > "$E2E_M35_WORK/source-head.txt"
 git diff --binary > "$E2E_M35_WORK/source.patch"
 sha256sum tests/e2e/m35-*.mjs tests/e2e/run-m35-client-auth.sh > "$E2E_M35_WORK/harness-sha256.txt"
 node --version > "$E2E_M35_WORK/node-version.txt"
 go version > "$E2E_M35_WORK/go-version.txt"
 for name in responses.jsonl browser-responses.jsonl browser-console.jsonl cli.jsonl receiver.jsonl private-secrets.jsonl logs-export.jsonl migrate.log bootstrap.stderr stored-sinks.jsonl; do : > "$E2E_M35_WORK/$name"; done
 case "$backend" in
  sqlite)
   # The database file lives on tmpfs when available (same driver and
   # schema); it is copied into the artifacts afterwards.
   sqlite_dir="${E2E_M35_SQLITE_DIR:-}"
   if [[ -z "$sqlite_dir" && -d /dev/shm && -w /dev/shm ]]; then sqlite_dir=$(mktemp -d /dev/shm/plan35-sqlite-XXXXXX); fi
   sqlite_dir="${sqlite_dir:-$E2E_M35_WORK}"
   dsn="sqlite://$sqlite_dir/client-auth.db";;
  memory) dsn='memory://' ;;
  postgres) dsn="${ZA_TEST_POSTGRES_DSN:?set isolated ZA_TEST_POSTGRES_DSN}" ;;
  mysql) dsn="${ZA_TEST_MYSQL_DSN:?set isolated ZA_TEST_MYSQL_DSN}" ;;
  *) echo "unknown client-auth backend: $backend" >&2; exit 1;;
 esac
 cat > "$E2E_M35_WORK/config.yaml" <<YAML
server:
  listen: 127.0.0.1:9543
  system_host: system.e2e.test
  tls_cert_file: $root/cert.pem
  tls_key_file: $root/key.pem
storage:
  dsn: $dsn
  auto_migrate: true
security:
  master_key_file: $root/master.key
seed: $root/seed.yaml
seed_mode: create_only
actions:
  cache_dir: $E2E_M35_WORK/actions-cache
  registry: http://127.0.0.1:9187/
logs:
  streams:
    allow_insecure_http: true
    allow_private_networks: true
log:
  level: info
  format: json
YAML
 if [[ "$backend" != memory ]]; then
  "$root/zeroauthy" migrate -c "$E2E_M35_WORK/config.yaml" > "$E2E_M35_WORK/migrate.log" 2>&1
  "$root/zeroauthy" admin create -c "$E2E_M35_WORK/config.yaml" --email operator35@e2e.local > "$E2E_M35_WORK/operator-setup.txt" 2> "$E2E_M35_WORK/bootstrap.stderr"
 fi
 start node tests/e2e/m35-cli.mjs receiver > "$E2E_M35_WORK/receiver.log" 2>&1
 PROXY_PORT=9198 TARGET_PORT=9543 start node tests/e2e/connect-proxy.mjs > "$E2E_M35_WORK/proxy.log" 2>&1
 start "$root/zeroauthy" serve -c "$E2E_M35_WORK/config.yaml" > "$E2E_M35_WORK/server.log" 2>&1
 server_pid=${pids[-1]}
 for _ in $(seq 1 300); do
  if curl -fsS --cacert "$root/cert.pem" --resolve sdk.e2e.test:9543:127.0.0.1 https://sdk.e2e.test:9543/healthz --noproxy '*' >/dev/null 2>&1; then break; fi
  kill -0 "$server_pid" 2>/dev/null || { cat "$E2E_M35_WORK/server.log" >&2; exit 1; }
  sleep 0.1
 done
 node tests/e2e/m35-node.mjs setup
 if [[ "$backend" == sqlite && " $lanes " == *" browser "* ]]; then
  (cd tests/e2e && ./node_modules/.bin/playwright test m35-client-auth.spec.mjs --config playwright.config.mjs --output "$E2E_M35_WORK/playwright-results" ${E2E_M35_GREP:+--grep "$E2E_M35_GREP"})
 fi
 for lane in $lanes; do
  case "$lane" in
   browser) ;;
   sdk) node tests/e2e/m35-node.mjs sdk ;;
   exchange) node tests/e2e/m35-node.mjs exchange ;;
   deploy) node tests/e2e/m35-cli.mjs deploy ;;
   cli) node tests/e2e/m35-cli.mjs cli ;;
   audit) node tests/e2e/m35-node.mjs snapshot ;;
   *) echo "unknown client-auth lane: $lane" >&2; exit 1;;
  esac
 done
 # Drain the app (flushing log streams) while the receiver is still alive.
 kill -TERM -- "-$server_pid"
 wait "$server_pid" || true
 stop
 if [[ " $lanes " == *" audit "* ]]; then
  if [[ "$backend" == sqlite ]]; then
   python3 - "$E2E_M35_WORK" "$sqlite_dir/client-auth.db" <<'PYDUMP'
import json,pathlib,sqlite3,sys
work=pathlib.Path(sys.argv[1])
with sqlite3.connect(sys.argv[2]) as db:
 db.row_factory=sqlite3.Row
 with (work/'stored-sinks.jsonl').open('w') as out:
  for table in ['tenant_logs','action_executions']:
   for row in db.execute('SELECT * FROM '+table):
    value={k:(v.decode(errors='replace') if isinstance(v,bytes) else v) for k,v in dict(row).items()}
    out.write(json.dumps({'table':table,'value':value})+'\n')
PYDUMP
  fi
  node tests/e2e/m35-node.mjs audit
 fi
 if [[ "$backend" == sqlite && "$sqlite_dir" != "$E2E_M35_WORK" ]]; then
  cp "$sqlite_dir"/client-auth.db* "$E2E_M35_WORK/" 2>/dev/null || true
  [[ -n "${E2E_M35_SQLITE_DIR:-}" ]] || rm -rf "$sqlite_dir"
 fi
 echo "Plan35 client-auth $backend selected lanes passed: $lanes"
done
