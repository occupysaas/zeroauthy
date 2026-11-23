#!/usr/bin/env bash
# make e2e-ad: Plan 38a AD/LDAP connections with the real AD/LDAP Connector.
# auth0/ad-ldap-connector is pinned to v8.0.5 (commit below) and runs,
# unchanged, in a pinned node:22 container next to its own mock LDAP server
# (tests/e2e/ad/mock-ldap.cjs adds the anonymous bind and password modify
# the mock lacks). The pinned node-auth0 SDK creates the ad connection and
# reads its status; Playwright signs in through the connector; the SDK
# changes the directory password through it. Keys, secrets and the
# zeroauthy TLS certificate are generated per run; the mock directory's
# fixture password comes from the connector's repository.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec 9>/tmp/zeroauthy-e2e-ad.lock
flock 9
umask 077
CONNECTOR_REPO=https://github.com/auth0/ad-ldap-connector.git
CONNECTOR_TAG=v8.0.5
CONNECTOR_SHA=474ff00e0cb687fdc9d70acd84588c07d4e90519
NODE_IMAGE=docker.io/library/node@sha256:e13726ca604184d7a91fcacab1fc09eefd642dc28e79ac34e85540dd93b78cfb # node:22.23.5-bookworm
runtime="$(command -v docker || command -v podman || true)"
[[ -n "$runtime" ]] || { echo 'make e2e-ad needs docker or podman' >&2; exit 1; }
work=$(mktemp -d)
export E2E_M38A_WORK="$work" E2E_M38A=1
export E2E_CHROMIUM="${E2E_CHROMIUM:-$(command -v chromium || true)}"
container="za-e2e-ad-$$"
pids=()
cleanup() {
 trap - EXIT INT TERM
 "$runtime" rm -f "$container" >/dev/null 2>&1 || true
 for p in "${pids[@]}"; do kill -TERM -- "-$p" 2>/dev/null || true; done
 if [[ ${E2E_KEEP_WORK:-0} == 1 ]]; then echo "Plan 38a private artifacts: $work"; else
  # Files the container wrote may belong to a user-namespace ID (rootless
  # podman): remove them through the runtime first.
  [[ -d "$work/connector-run" ]] && "$runtime" run --rm --user "$(id -u):$(id -g)" -v "$work/connector-run:/work" "$NODE_IMAGE" rm -rf /work/node_modules /work/data >/dev/null 2>&1 || true
  rm -rf "$work" 2>/dev/null || true
 fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
fail() {
 echo "$1" >&2
 for log in server connector playwright-first playwright-changed; do
  [[ -f "$work/$log.log" ]] && { echo "--- $log.log (tail) ---" >&2; tail -n 40 "$work/$log.log" | grep -v -i -E 'password|signingKey|/p/ad/' >&2; }
 done
 exit 1
}

# The connector at the pinned commit.
git clone -q --depth 1 --branch "$CONNECTOR_TAG" "$CONNECTOR_REPO" "$work/connector-src" 2>/dev/null
got=$(git -C "$work/connector-src" rev-parse HEAD)
[[ "$got" == "$CONNECTOR_SHA" ]] || fail "connector tag $CONNECTOR_TAG is $got, not the pinned $CONNECTOR_SHA"
directory_password=$(node -e 'const d=require(process.argv[1]);console.log(d["cn=jdoe,ou=users,dc=example,dc=org"].userPassword)' "$work/connector-src/mock-ldap/mock_ldap_data.json")

mkdir -p "$work/ca" "$work/mail" "$work/connector-run"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Plan38a local test root' \
 -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
cp "$work/cert.pem" "$work/ca/zeroauthy-test.pem"
chmod 0755 "$work/ca" && chmod 0644 "$work/ca/zeroauthy-test.pem"
export NODE_EXTRA_CA_CERTS="$work/cert.pem"
admin_secret="m38a-$(openssl rand -hex 24)"
node -e 'require("fs").writeFileSync(process.argv[1],JSON.stringify({admin:process.argv[2],directoryPassword:process.argv[3],newPassword:"Za-"+require("crypto").randomBytes(18).toString("hex")}),{mode:0o600})' \
 "$work/private-credentials.json" "$admin_secret" "$directory_password"
cat > "$work/seed.yaml" <<YAML
tenants:
  - name: adcorp
    domains: ["localhost:9565"]
    default_directory: Username-Password-Authentication
    skip_non_verifiable_callback_uri_confirmation_prompt: true
    clients:
      - {client_id: m38a-admin, app_type: non_interactive, client_secret: "$admin_secret", grant_types: [client_credentials]}
      - {client_id: m38a-spa, name: AD browser, app_type: spa, grant_types: [authorization_code], callbacks: ["https://callback.invalid/cb"]}
    client_grants:
      - client_id: m38a-admin
        audience: https://localhost:9565/api/v2/
        scopes: [read:connections, create:connections, update:connections, read:users, update:users, read:clients]
    connections:
      - {name: Username-Password-Authentication, enabled_clients: [m38a-admin]}
YAML

CGO_ENABLED=0 go build -o "$work/zeroauthy" ./cmd/zeroauthy
ZEROAUTHY_SECURITY__MASTER_KEY="$(openssl rand -base64 32)" \
ZEROAUTHY_SERVER__TLS_CERT_FILE="$work/cert.pem" ZEROAUTHY_SERVER__TLS_KEY_FILE="$work/key.pem" \
ZEROAUTHY_SERVER__LISTEN=:9565 ZEROAUTHY_SERVER__SYSTEM_HOST=system.localhost:9565 \
ZEROAUTHY_STORAGE__DSN="sqlite://$work/ad.db" ZEROAUTHY_STORAGE__AUTO_MIGRATE=true \
ZEROAUTHY_SEED="$work/seed.yaml" ZEROAUTHY_SEED_MODE=create_only ZEROAUTHY_EMAIL__DIR="$work/mail" \
 setsid "$work/zeroauthy" serve --config tests/e2e/config.yaml >"$work/server.log" 2>&1 & pids+=("$!")
for _ in $(seq 1 200); do
 if curl -fsS --cacert "$work/cert.pem" https://localhost:9565/healthz --noproxy '*' >/dev/null 2>&1; then break; fi
 kill -0 "${pids[0]}" 2>/dev/null || fail 'Plan 38a server failed to start'
 sleep 0.1
done

node tests/e2e/m38a-ad-sdk.mjs setup || fail 'SDK setup failed'

# The connector, provisioned with the ticket. Its dependencies install
# inside the container (isolated-vm is native); the CA goes to
# SSL_CA_PATH, which replaces Node's list (lib/add_certs.js).
cp -r "$work/connector-src/." "$work/connector-run/"
chmod -R a+rwX "$work/connector-run"
# TS_KEYRING_BACKEND=null selects cross-keychain's null backend: the
# connector reads its LDAP bind password from the OS keychain at start, and
# CI runners have no secret service (the suite searches anonymously). The
# container runs as the invoking user so the run directory stays removable.
"$runtime" run -d --name "$container" --network host --user "$(id -u):$(id -g)" -e HOME=/tmp -e TS_KEYRING_BACKEND=null \
 -v "$work/connector-run:/work" -v "$PWD/tests/e2e/ad:/e2e:ro" -v "$work/ca:/certs:ro" \
 -e SSL_CA_PATH=/certs -e NODE_EXTRA_CA_CERTS=/certs/zeroauthy-test.pem -e OVERRIDE_CONFIG=false \
 -e PROVISIONING_TICKET="$(cat "$work/ticket")" -e LDAP_URL=ldap://127.0.0.1:4444 -e LDAP_BASE=dc=example,dc=org \
 -e ANONYMOUS_SEARCH_ENABLED=true -e 'LDAP_USER_BY_NAME=(&(objectClass=inetOrgPerson)(uid={0}))' \
 -e 'LDAP_SEARCH_QUERY=(&(objectClass=inetOrgPerson)(|(cn={0})(givenName={0})(sn={0})(uid={0})))' \
 -e 'LDAP_SEARCH_ALL_QUERY=(objectClass=inetOrgPerson)' -e 'LDAP_SEARCH_GROUPS=(member={0})' \
 -e ENABLE_WRITE_BACK=true -e SERVER_URL=http://127.0.0.1:4001 -e PORT=4001 \
 "$NODE_IMAGE" sh -c 'cd /work && npm ci --no-audit --no-fund >/tmp/npm.log 2>&1 || { cat /tmp/npm.log; exit 1; }; (node /e2e/mock-ldap.cjs /work &) && sleep 1 && exec node server.js' >/dev/null
( "$runtime" logs -f "$container" >"$work/connector.log" 2>&1 & )
node tests/e2e/m38a-ad-sdk.mjs online || fail 'the connector did not come online'

run_spec() {
 (cd tests/e2e && E2E_M38A_PHASE="$1" ./node_modules/.bin/playwright test m38a-ad.spec.mjs --config playwright.config.mjs --output "$work/playwright-results-$1") \
  >"$work/playwright-$1.log" 2>&1 || fail "Plan 38a browser acceptance ($1) failed"
 grep -E 'passed|skipped|failed' "$work/playwright-$1.log" | tail -2
}
run_spec first
node tests/e2e/m38a-ad-deploy.mjs || fail 'Deploy CLI round trip failed'
node tests/e2e/m38a-ad-sdk.mjs user || fail 'SDK user check failed'
node tests/e2e/m38a-ad-sdk.mjs password || fail 'SDK password change failed'
for _ in $(seq 1 50); do grep -q 'mock-ldap: password changed for cn=jdoe' "$work/connector.log" && break; sleep 0.2; done
grep -q 'mock-ldap: password changed for cn=jdoe' "$work/connector.log" || fail 'the directory did not receive the password change'
run_spec changed
"$runtime" stop -t 5 "$container" >/dev/null
node tests/e2e/m38a-ad-sdk.mjs offline || fail 'status still online after the connector stopped'
node tests/e2e/m38a-ad-audit.mjs || fail 'log audit failed'
kill -TERM -- "-${pids[0]}"
echo 'AD/LDAP acceptance: real connector v8.0.5 provisioned by ticket, hub authentication, logins (wrong password, escaping), groups, Deploy CLI round trip, password change through the connector, status online/offline and log audit passed (no skips)'
