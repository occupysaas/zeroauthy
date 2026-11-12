#!/usr/bin/env bash
# Plan 33b acceptance (spec §15): the production app with two Plan 23 style
# custom domains (DNS-proof fixture, verified through the public API), a second
# tenant, Chromium CDP virtual authenticators, pinned auth-js/node-auth0/Deploy
# CLI/auth0-cli, and a representative-secret audit of every sink.
#
# Backends: E2E_M33B_BACKENDS (default "sqlite memory"); postgres and mysql use
# the existing SQL-test DSNs. Lanes: E2E_M33B_LANES (default
# "browser native sdk cli audit"); the browser lane runs on SQLite only.
# TLS mode (Task 1 spike): ignoreHTTPSErrors alone is enough for create,
# button get and conditional get, so no SPKI pin is passed to Chromium.
set -euo pipefail
cd "$(dirname "$0")/../.."
export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.11}"
unset NO_COLOR
export FORCE_COLOR=0
for tool in node go openssl curl flock setsid python3 sha256sum; do
 command -v "$tool" >/dev/null || { echo "e2e-passkeys unavailable: missing $tool" >&2; exit 1; }
done
export AUTH0_BIN="${AUTH0_BIN:-$(command -v auth0 || true)}"
[[ -x tests/e2e/node_modules/.bin/playwright ]] || { echo "e2e-passkeys unavailable: install tests/e2e dependencies (npm ci in tests/e2e)" >&2; exit 1; }
node -e 'const [a,b]=process.versions.node.split(".").map(Number);if(a<22||(a===22&&b<13))process.exit(1)' || { echo "e2e-passkeys unavailable: Node 22.13+ required" >&2; exit 1; }
lanes="${E2E_M33B_LANES:-browser native sdk cli audit}"
if [[ " $lanes " == *" cli "* ]]; then
 [[ -x "$AUTH0_BIN" ]] || { echo "e2e-passkeys unavailable: install the pinned Auth0 CLI 1.37.0 or drop the cli lane" >&2; exit 1; }
 "$AUTH0_BIN" --version | grep -q '1.37.0' || { echo "e2e-passkeys unavailable: Auth0 CLI is not 1.37.0" >&2; exit 1; }
fi
# Ports 9543/9545/9198/9199/9185/9186 are shared with the other hosted lanes;
# the DNS-proof fixture's 8063/8064 with the Deploy CLI lane.
exec 9>/tmp/zeroauthy-e2e-social.lock
flock 9
exec 8>/tmp/zeroauthy-e2e8443.lock
flock 8
umask 077
root=$(mktemp -d "${E2E_ARTIFACT_DIR:-${TMPDIR:-/tmp}}/plan33b-XXXXXX")
export E2E_CHROMIUM="${E2E_CHROMIUM:-$(command -v chromium || true)}"
pids=()
start() { setsid "$@" & pids+=("$!"); }
stop() { for p in "${pids[@]}"; do kill -TERM -- "-$p" 2>/dev/null || true; done; for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done; pids=(); }
cleanup() { trap - EXIT INT TERM; stop; if [[ -n "${sqlite_dir:-}" && "$sqlite_dir" == /dev/shm/plan33b-sqlite-* ]]; then cp "$sqlite_dir"/passkeys.db* "$root/sqlite/" 2>/dev/null || true; rm -rf "$sqlite_dir"; fi; echo "Plan33b artifacts: $root"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Plan33b local test root' \
 -addext 'subjectAltName=DNS:e2e.test,DNS:*.e2e.test,DNS:sdk.e2e.test,DNS:other.e2e.test,DNS:legacy.e2e.test,DNS:system.e2e.test,DNS:callback.e2e.test,DNS:*.domains.e2e.test,DNS:*.origin.e2e.test,DNS:*.hosted.e2e.test,IP:127.0.0.1' \
 -keyout "$root/key.pem" -out "$root/cert.pem" 2>/dev/null
openssl rand -base64 32 > "$root/master.key"
export E2E_KEY="$root/key.pem" E2E_CERT="$root/cert.pem" NODE_EXTRA_CA_CERTS="$root/cert.pem" SSL_CERT_FILE="$root/cert.pem"
cat > "$root/seed.yaml" <<'YAML'
tenants:
  - name: sdk
    friendly_name: Plan33b passkeys acceptance
    domains: [sdk.e2e.test]
    skip_non_verifiable_callback_uri_confirmation_prompt: true
    default_directory: Username-Password-Authentication
    clients:
      - {client_id: m33b-admin, app_type: non_interactive, client_secret: Plan33b-Management-Secret-2026, grant_types: [client_credentials]}
      - {client_id: m33b-spa, name: Plan33b Browser, app_type: spa, grant_types: [authorization_code], callbacks: ['https://callback.e2e.test/'], allowed_logout_urls: ['https://callback.e2e.test/'], web_origins: ['https://callback.e2e.test']}
      - client_id: m33b-native
        name: Plan33b Native
        app_type: regular_web
        is_first_party: true
        client_secret: Plan33b-Native-Client-Secret-2026
        callbacks: ['https://callback.e2e.test/']
        web_origins: ['https://app.domains.e2e.test']
        grant_types: [password, 'urn:okta:params:oauth:grant-type:webauthn', 'http://auth0.com/oauth/grant-type/mfa-otp', 'http://auth0.com/oauth/grant-type/mfa-oob', 'http://auth0.com/oauth/grant-type/mfa-recovery-code']
      - client_id: m33b-org-native
        name: Plan33b Organization Native
        app_type: regular_web
        is_first_party: true
        client_secret: Plan33b-Native-Client-Secret-2026
        callbacks: ['https://callback.e2e.test/']
        web_origins: ['https://app.domains.e2e.test']
        organization_usage: require
        grant_types: ['urn:okta:params:oauth:grant-type:webauthn']
    client_grants:
      - client_id: m33b-admin
        audience: https://sdk.e2e.test/api/v2/
        scopes: [read:guardian_factors, update:guardian_factors, read:mfa_policies, update:mfa_policies, read:guardian_enrollments, delete:guardian_enrollments, create:guardian_enrollment_tickets, read:authentication_methods, create:authentication_methods, update:authentication_methods, delete:authentication_methods, read:tenant_settings, update:tenant_settings, read:users, create:users, update:users, delete:users, read:actions, create:actions, update:actions, delete:actions, read:logs, read:logs_users, create:log_streams, read:log_streams, create:event_streams, read:event_streams, read:connections, update:connections, create:connections, delete:connections, read:prompts, update:prompts, read:custom_domains, create:custom_domains, update:custom_domains, delete:custom_domains, read:clients, create:clients, update:clients, delete:clients, read:resource_servers, read:organizations, create:organizations, update:organizations, delete:organizations, create:organization_members, read:organization_members, delete:organization_members, create:organization_connections, read:organization_connections, update:organization_connections, delete:organization_connections, create:user_tickets, read:email_provider, create:email_provider, update:email_provider, read:email_templates, create:email_templates, update:email_templates, read:attack_protection, update:attack_protection]
    connections:
      - name: Username-Password-Authentication
        is_domain_connection: true
        enabled_clients: [m33b-spa, m33b-native, m33b-org-native]
  - name: other
    friendly_name: Plan33b second tenant
    domains: [other.e2e.test]
    skip_non_verifiable_callback_uri_confirmation_prompt: true
    default_directory: Username-Password-Authentication
    clients:
      - {client_id: m33b-admin, app_type: non_interactive, client_secret: Plan33b-Management-Secret-2026, grant_types: [client_credentials]}
      - {client_id: m33b-spa, name: Plan33b Other Browser, app_type: spa, grant_types: [authorization_code], callbacks: ['https://callback.e2e.test/'], web_origins: ['https://callback.e2e.test']}
    client_grants:
      - client_id: m33b-admin
        audience: https://other.e2e.test/api/v2/
        scopes: [read:users, create:users, read:connections, update:connections, read:prompts, update:prompts, read:logs]
    connections:
      - name: Username-Password-Authentication
        is_domain_connection: true
        enabled_clients: [m33b-spa]
YAML
# Journey 12: an older plugin without webauthn.v1 serves this tenant.
cat > "$root/legacy-seed.yaml" <<'YAML'
tenants:
  - name: legacy
    friendly_name: Plan33b older plugin
    domains: [legacy.e2e.test]
    skip_non_verifiable_callback_uri_confirmation_prompt: true
    default_directory: Username-Password-Authentication
    clients:
      - {client_id: m33b-admin, app_type: non_interactive, client_secret: Plan33b-Management-Secret-2026, grant_types: [client_credentials]}
      - {client_id: m33b-spa, name: Plan33b Legacy Browser, app_type: spa, grant_types: [authorization_code], callbacks: ['https://callback.e2e.test/'], web_origins: ['https://callback.e2e.test']}
      - {client_id: m33b-native, app_type: regular_web, is_first_party: true, client_secret: Plan33b-Native-Client-Secret-2026, grant_types: ['urn:okta:params:oauth:grant-type:webauthn']}
    client_grants:
      - client_id: m33b-admin
        audience: https://legacy.e2e.test/api/v2/
        scopes: [read:users, create:users, read:connections, update:connections, read:prompts, update:prompts, read:guardian_factors, update:guardian_factors, read:mfa_policies, update:mfa_policies, read:authentication_methods, create:authentication_methods]
    connections:
      - name: Username-Password-Authentication
        is_domain_connection: true
        enabled_clients: [m33b-spa, m33b-native]
YAML
go build -o "$root/zeroauthy" ./cmd/zeroauthy
go build -o "$root/legacy-store" ./tests/e2e/m33b-legacy-store
go build -o "$root/dns-fixture" ./tests/e2e/deploy-cli/dns-fixture
for backend in ${E2E_M33B_BACKENDS:-sqlite memory}; do
 export E2E_M33B_WORK="$root/$backend" E2E_M33B_BACKEND="$backend"
 mkdir -m 700 "$E2E_M33B_WORK"
 git rev-parse HEAD > "$E2E_M33B_WORK/source-head.txt"
 git diff --binary > "$E2E_M33B_WORK/source.patch"
 sha256sum tests/e2e/m33b-*.mjs tests/e2e/run-m33b-passkeys.sh tests/e2e/m33b-legacy-store/main.go > "$E2E_M33B_WORK/harness-sha256.txt"
 node --version > "$E2E_M33B_WORK/node-version.txt"
 go version > "$E2E_M33B_WORK/go-version.txt"
 for name in responses.jsonl browser-responses.jsonl browser-console.jsonl browser-navigation.jsonl cli.jsonl receiver.jsonl private-secrets.jsonl migrate.log bootstrap.stderr legacy-server.log stored-sinks.jsonl; do : > "$E2E_M33B_WORK/$name"; done
 case "$backend" in
  sqlite)
   # This host's disk fsync can exceed SQLite's busy timeout under the hosted
   # flows; the database file lives on tmpfs (same SQLite driver and schema)
   # unless E2E_M33B_SQLITE_DIR names another directory. Copied back below.
   sqlite_dir="${E2E_M33B_SQLITE_DIR:-}"
   if [[ -z "$sqlite_dir" && -d /dev/shm && -w /dev/shm ]]; then sqlite_dir=$(mktemp -d /dev/shm/plan33b-sqlite-XXXXXX); fi
   sqlite_dir="${sqlite_dir:-$E2E_M33B_WORK}"
   dsn="sqlite://$sqlite_dir/passkeys.db";;
  memory) dsn='memory://' ;;
  postgres) dsn="${ZA_TEST_POSTGRES_DSN:?set isolated ZA_TEST_POSTGRES_DSN}" ;;
  mysql) dsn="${ZA_TEST_MYSQL_DSN:?set isolated ZA_TEST_MYSQL_DSN}" ;;
  *) echo "unknown passkeys backend: $backend" >&2; exit 1;;
 esac
 config() { # $1 file, $2 listen, $3 dsn, $4 seed
  cat > "$1" <<YAML
server:
  listen: $2
  system_host: system.e2e.test
  tls_cert_file: $root/cert.pem
  tls_key_file: $root/key.pem
  trusted_proxy_cidrs: [127.0.0.0/8]
  custom_domains:
    dns_resolver: 127.0.0.1:8063
    origin_domain: origin.e2e.test
storage:
  dsn: $3
  auto_migrate: true
security:
  master_key_file: $root/master.key
  webauthn:
    restrict_shared_rp_ids: true
seed: $4
seed_mode: create_only
actions:
  cache_dir: $E2E_M33B_WORK/actions-cache
  registry: http://127.0.0.1:9187/
logs:
  streams:
    allow_insecure_http: true
    allow_private_networks: true
events:
  allow_private_networks: true
email:
  allow_local_smtp: ["127.0.0.1:9185"]
log:
  level: info
  format: json
YAML
 }
 config "$E2E_M33B_WORK/config.yaml" 127.0.0.1:9543 "$dsn" "$root/seed.yaml"
 if [[ "$backend" != memory ]]; then
  "$root/zeroauthy" migrate -c "$E2E_M33B_WORK/config.yaml" > "$E2E_M33B_WORK/migrate.log" 2>&1
  "$root/zeroauthy" admin create -c "$E2E_M33B_WORK/config.yaml" --email operator33b@e2e.local > "$E2E_M33B_WORK/operator-setup.txt" 2> "$E2E_M33B_WORK/bootstrap.stderr"
 fi
 start "$root/dns-fixture" > "$E2E_M33B_WORK/dns.log" 2>&1
 start node tests/e2e/m33b-cli.mjs receiver > "$E2E_M33B_WORK/receiver.log" 2>&1
 PROXY_PORT=9198 TARGET_PORT=9543 start node tests/e2e/connect-proxy.mjs > "$E2E_M33B_WORK/proxy.log" 2>&1
 start "$root/zeroauthy" serve -c "$E2E_M33B_WORK/config.yaml" > "$E2E_M33B_WORK/server.log" 2>&1
 server_pid=${pids[-1]}
 browser=0
 if [[ "$backend" == sqlite && " $lanes " == *" browser "* ]]; then browser=1; fi
 if [[ $browser == 1 ]]; then
  # Journey 12 beside the main server: the production app over the plugin
  # protocol to a memory store that does not negotiate webauthn.v1.
  config "$E2E_M33B_WORK/legacy-config.yaml" 127.0.0.1:9545 "plugin://$root/legacy-store" "$root/legacy-seed.yaml"
  PROXY_PORT=9199 TARGET_PORT=9545 start node tests/e2e/connect-proxy.mjs > "$E2E_M33B_WORK/legacy-proxy.log" 2>&1
  start "$root/zeroauthy" serve -c "$E2E_M33B_WORK/legacy-config.yaml" > "$E2E_M33B_WORK/legacy-server.log" 2>&1
  legacy_pid=${pids[-1]}
 fi
 ready() { # $1 port, $2 host, $3 pid, $4 log
  for _ in $(seq 1 300); do
   if curl -fsS --cacert "$root/cert.pem" --resolve "$2:$1:127.0.0.1" "https://$2:$1/healthz" --noproxy '*' >/dev/null 2>&1; then return 0; fi
   kill -0 "$3" 2>/dev/null || { cat "$4" >&2; return 1; }
   sleep 0.1
  done
  echo "server on $1 did not become ready" >&2; return 1
 }
 ready 9543 sdk.e2e.test "$server_pid" "$E2E_M33B_WORK/server.log"
 [[ $browser == 1 ]] && ready 9545 legacy.e2e.test "$legacy_pid" "$E2E_M33B_WORK/legacy-server.log"
 curl -fsS http://127.0.0.1:8064/healthz >/dev/null
 node tests/e2e/m33b-node.mjs setup
 if [[ $browser == 1 ]]; then
  (cd tests/e2e && ./node_modules/.bin/playwright test m33b-passkeys.spec.mjs --config playwright.config.mjs --output "$E2E_M33B_WORK/playwright-results" ${E2E_M33B_GREP:+--grep "$E2E_M33B_GREP"})
 fi
 for lane in $lanes; do
  case "$lane" in
   browser) ;;
   native) node tests/e2e/m33b-native.mjs ;;
   sdk) node tests/e2e/m33b-node.mjs sdk; node tests/e2e/m33b-node.mjs deploy ;;
   cli) node tests/e2e/m33b-cli.mjs cli ;;
   audit) node tests/e2e/m33b-node.mjs snapshot ;;
   *) echo "unknown passkeys lane: $lane" >&2; exit 1;;
  esac
 done
 stop
 if [[ " $lanes " == *" audit "* ]]; then
  if [[ "$backend" == sqlite ]]; then
   python3 - "$E2E_M33B_WORK" "$sqlite_dir/passkeys.db" <<'PYDUMP'
import json,pathlib,sqlite3,sys
work=pathlib.Path(sys.argv[1])
with sqlite3.connect(sys.argv[2]) as db:
 db.row_factory=sqlite3.Row
 with (work/'stored-sinks.jsonl').open('w') as out:
  for table in ['tenant_logs','action_executions','tenant_events','event_deliveries']:
   for row in db.execute('SELECT * FROM '+table):
    value={k:(v.decode(errors='replace') if isinstance(v,bytes) else v) for k,v in dict(row).items()}
    out.write(json.dumps({'table':table,'value':value})+'\n')
PYDUMP
  fi
  node tests/e2e/m33b-node.mjs audit
 fi
 if [[ "$backend" == sqlite && "$sqlite_dir" != "$E2E_M33B_WORK" ]]; then
  cp "$sqlite_dir"/passkeys.db* "$E2E_M33B_WORK/" 2>/dev/null || true
  [[ -n "${E2E_M33B_SQLITE_DIR:-}" ]] || rm -rf "$sqlite_dir"
 fi
 echo "Plan33b passkeys $backend selected lanes passed: $lanes"
done
