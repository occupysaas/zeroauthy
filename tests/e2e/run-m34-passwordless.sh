#!/usr/bin/env bash
# Production app, pinned SDK/CLI, local SMTP/phone transports and real sink scans.
# Run all browser/client/privacy lanes on SQLite and memory by default.
# E2E_M34_BACKENDS adds PostgreSQL/MySQL with isolated complete SQL-test DSNs.
set -euo pipefail
cd "$(dirname "$0")/../.."
export GOTOOLCHAIN=go1.26.10
unset NO_COLOR
export FORCE_COLOR=0
for tool in node go openssl curl flock setsid python3 sha256sum; do
 command -v "$tool" >/dev/null || { echo "e2e-passwordless unavailable: missing $tool" >&2; exit 1; }
done
export AUTH0_BIN="${AUTH0_BIN:-$(command -v auth0 || true)}"
[[ -x "$AUTH0_BIN" && -x tests/e2e/node_modules/.bin/playwright ]] || { echo "e2e-passwordless unavailable: install the pinned Auth0 CLI and tests/e2e dependencies" >&2; exit 1; }
"$AUTH0_BIN" --version | grep -q '1.37.0'
node -e 'const [a,b]=process.versions.node.split(".").map(Number);if(a<22||(a===22&&b<13))process.exit(1)'
exec 9>/tmp/zeroauthy-e2e-social.lock
flock 9
umask 077
root=$(mktemp -d "${E2E_ARTIFACT_DIR:-${TMPDIR:-/tmp}}/plan34-XXXXXX")
export E2E_CHROMIUM="${E2E_CHROMIUM:-$(command -v chromium || true)}"
pids=()
start() { setsid "$@" & pids+=("$!"); }
stop() { for p in "${pids[@]}"; do kill -TERM -- "-$p" 2>/dev/null || true; done; for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done; pids=(); }
cleanup() { trap - EXIT INT TERM; stop; echo "Plan34 artifacts: $root"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Plan34 local test root' -addext 'subjectAltName=DNS:sdk.e2e.test,DNS:system.e2e.test,DNS:callback.e2e.test,IP:127.0.0.1' -keyout "$root/key.pem" -out "$root/cert.pem" 2>/dev/null
openssl rand -base64 32 > "$root/master.key"
export E2E_KEY="$root/key.pem" E2E_CERT="$root/cert.pem" NODE_EXTRA_CA_CERTS="$root/cert.pem" SSL_CERT_FILE="$root/cert.pem"
cat > "$root/seed.yaml" <<'YAML'
tenants:
  - name: passwordless
    friendly_name: Plan34 passwordless acceptance
    domains: [sdk.e2e.test]
    skip_non_verifiable_callback_uri_confirmation_prompt: true
    default_directory: Username-Password-Authentication
    clients:
      - {client_id: m34-admin, app_type: non_interactive, client_secret: Plan34-Management-Secret-2026, grant_types: [client_credentials]}
      - {client_id: m34-password, app_type: regular_web, callbacks: ['https://callback.e2e.test/'], client_secret: Plan34-Password-Client-Secret-2026, grant_types: [authorization_code, 'http://auth0.com/oauth/grant-type/passwordless/otp', password, 'http://auth0.com/oauth/grant-type/password-realm', 'http://auth0.com/oauth/grant-type/mfa-otp', 'http://auth0.com/oauth/grant-type/mfa-oob', 'http://auth0.com/oauth/grant-type/mfa-recovery-code']}
      - {client_id: m34-other, app_type: regular_web, client_secret: Plan34-Password-Client-Secret-2026, grant_types: [authorization_code, 'http://auth0.com/oauth/grant-type/passwordless/otp', password, 'http://auth0.com/oauth/grant-type/mfa-otp']}
      - {client_id: m34-spa, name: Plan34 Browser, app_type: spa, grant_types: [authorization_code, 'http://auth0.com/oauth/grant-type/passwordless/otp'], callbacks: ['https://callback.e2e.test/'], allowed_logout_urls: ['https://callback.e2e.test/'], web_origins: ['https://callback.e2e.test']}
      - {client_id: m34-second, name: Plan34 Second, app_type: spa, grant_types: [authorization_code, 'http://auth0.com/oauth/grant-type/passwordless/otp'], callbacks: ['https://callback.e2e.test/'], web_origins: ['https://callback.e2e.test']}
    client_grants:
      - client_id: m34-admin
        audience: https://sdk.e2e.test/api/v2/
        scopes: [read:clients, create:clients, update:clients, delete:clients, read:connections, create:connections, update:connections, delete:connections, read:phone_providers, create:phone_providers, update:phone_providers, delete:phone_providers, read:phone_templates, create:phone_templates, update:phone_templates, delete:phone_templates, read:attack_protection, update:attack_protection, read:guardian_factors, update:guardian_factors, read:mfa_policies, update:mfa_policies, read:guardian_enrollments, delete:guardian_enrollments, create:guardian_enrollment_tickets, read:authentication_methods, create:authentication_methods, update:authentication_methods, delete:authentication_methods, read:tenant_settings, update:tenant_settings, read:users, create:users, update:users, delete:users, read:actions, create:actions, update:actions, delete:actions, read:logs, create:log_streams, read:log_streams, create:event_streams, read:event_streams, read:email_provider, create:email_provider, update:email_provider, create:email_templates, read:email_templates, update:email_templates]
    connections:
      - name: Username-Password-Authentication
        is_domain_connection: true
        enabled_clients: [m34-spa, m34-second, m34-password, m34-other]
YAML
go build -o "$root/zeroauthy" ./cmd/zeroauthy
go build -o "$root/phone-fakes" ./tests/e2e/phone-fakes
go build -o "$root/sql-sinks" ./tests/e2e/sql-sinks
export ZA_TEST_MODE=1 ZA_TEST_PHONE_ENDPOINTS="twilio=http://127.0.0.1:9184,sns=http://127.0.0.1:9184,gateway=https://127.0.0.1:9183/gateway"
for backend in ${E2E_M34_BACKENDS:-sqlite memory}; do
 export E2E_M34_BACKEND="$backend"
 export E2E_M34_WORK="$root/$backend"
 mkdir -m 700 "$E2E_M34_WORK"
 git rev-parse HEAD > "$E2E_M34_WORK/source-head.txt"
 git diff --binary > "$E2E_M34_WORK/source.patch"
 sha256sum tests/e2e/m34*.mjs tests/e2e/run-m34-passwordless.sh tests/e2e/sql-sinks/main.go > "$E2E_M34_WORK/harness-sha256.txt"
 node --version > "$E2E_M34_WORK/node-version.txt"
 go version > "$E2E_M34_WORK/go-version.txt"
 for name in responses.jsonl browser-responses.jsonl browser-console.jsonl cli.jsonl receiver.jsonl private-secrets.jsonl migrate.log bootstrap.stderr; do : > "$E2E_M34_WORK/$name"; done
 case "$backend" in
  sqlite) dsn="sqlite://$E2E_M34_WORK/passwordless.db";;
  memory) dsn='memory://' ;;
  postgres) dsn="${ZA_TEST_POSTGRES_DSN:?set isolated ZA_TEST_POSTGRES_DSN}" ;;
  mysql) dsn="${ZA_TEST_MYSQL_DSN:?set isolated ZA_TEST_MYSQL_DSN}" ;;
  *) echo "unknown passwordless backend: $backend" >&2; exit 1;;
 esac
 cat > "$E2E_M34_WORK/config.yaml" <<YAML
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
bootstrap:
  admin_email: operator34@e2e.local
actions:
  cache_dir: $E2E_M34_WORK/actions-cache
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
 if [[ "$backend" != memory ]]; then
  "$root/zeroauthy" migrate -c "$E2E_M34_WORK/config.yaml" > "$E2E_M34_WORK/migrate.log" 2>&1
  "$root/zeroauthy" admin create -c "$E2E_M34_WORK/config.yaml" --email operator34@e2e.local > "$E2E_M34_WORK/operator-setup.txt" 2> "$E2E_M34_WORK/bootstrap.stderr"
 fi
 export E2E_M34_DSN="$dsn"
 start "$root/phone-fakes" -listen 127.0.0.1:9184 -tls-listen 127.0.0.1:9183 -cert "$root/cert.pem" -key "$root/key.pem" -log "$E2E_M34_WORK/private-phone.jsonl" > "$E2E_M34_WORK/phone-fakes.log" 2>&1
 start node tests/e2e/m34-cli.mjs receiver > "$E2E_M34_WORK/receiver.log" 2>&1
 PROXY_PORT=9198 TARGET_PORT=9543 start node tests/e2e/connect-proxy.mjs > "$E2E_M34_WORK/proxy.log" 2>&1
 start "$root/zeroauthy" serve -c "$E2E_M34_WORK/config.yaml" > "$E2E_M34_WORK/server.log" 2>&1
 server_pid=${pids[-1]}
 for _ in $(seq 1 300); do
  if curl -fsS --cacert "$root/cert.pem" --resolve sdk.e2e.test:9543:127.0.0.1 https://sdk.e2e.test:9543/healthz --noproxy '*' >/dev/null 2>&1; then break; fi
  kill -0 "$server_pid" 2>/dev/null || { cat "$E2E_M34_WORK/server.log" >&2; exit 1; }
  sleep 0.1
 done
 if [[ "$backend" == memory ]]; then
  python3 - "$E2E_M34_WORK" <<'PYSETUP'
import json,pathlib,sys
work=pathlib.Path(sys.argv[1])
for line in (work/'server.log').read_text().splitlines():
 try: event=json.loads(line)
 except ValueError: continue
 if 'setup_file' in event:
  private=pathlib.Path(event['setup_file'])
  link=next(v for v in private.read_text().splitlines() if v.startswith('https://'))
  (work/'operator-setup.txt').write_text(link+'\n')
  (work/'operator-setup.txt').chmod(0o600)
  private.unlink()
  break
else: raise RuntimeError('memory operator bootstrap did not deliver a private setup file')
PYSETUP
 fi
 node tests/e2e/m34-node.mjs setup
 if [[ " ${E2E_M34_LANES:-browser grants sdk cli audit} " == *" browser "* ]]; then
  (cd tests/e2e && ./node_modules/.bin/playwright test m34-passwordless.spec.mjs --grep "${E2E_M34_GREP:-.*}" --config playwright.config.mjs --output "$E2E_M34_WORK/playwright-results")
 fi
 for lane in ${E2E_M34_LANES:-grants sdk cli audit}; do
  case "$lane" in
   browser) ;;
   sdk) node tests/e2e/m34-node.mjs sdk ;;
   cli) node tests/e2e/m34-cli.mjs cli ;;
   grants) node tests/e2e/m34-grants.mjs ;;
   audit) node tests/e2e/m34-node.mjs snapshot ;;
   *) echo "unknown passwordless lane: $lane" >&2; exit 1;;
  esac
 done
 # Drain the app while the delivery sinks remain alive.
 kill -TERM -- "-$server_pid"
 wait "$server_pid"
 server_pid=
 stop
 if [[ " ${E2E_M34_LANES:-grants sdk cli audit} " == *" audit "* ]]; then
  if [[ "$backend" != memory ]]; then
   "$root/sql-sinks" > "$E2E_M34_WORK/stored-sinks.jsonl"
  else
   : > "$E2E_M34_WORK/stored-sinks.jsonl"
  fi
  node tests/e2e/m34-node.mjs audit
 fi
 echo "Plan34 passwordless $backend selected lanes passed: ${E2E_M34_LANES:-grants sdk cli audit}"
done
