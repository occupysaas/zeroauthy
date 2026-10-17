#!/usr/bin/env bash
# tests/conformance/run.sh: run OpenID Foundation conformance test plans
# against a seeded zeroauthy built from the working tree. See README.md.
#
#   ./tests/conformance/run.sh [basic|config|formpost|logout ...]
#
# With no arguments it runs all four plans. The exit status is
# run-test-plan.py's. Results go to tests/conformance/results/<timestamp>/.
# Environment:
#   CONFORMANCE_RUNTIME  podman (default) or docker
#   CONFORMANCE_KEEP=1   leave the containers and run directory up afterwards
set -euo pipefail
cd "$(dirname "$0")/../.."
repo="$PWD"
here="$repo/tests/conformance"

runtime="${CONFORMANCE_RUNTIME:-podman}"
case "$runtime" in
  podman) compose=(podman-compose) ;;
  docker) compose=(docker compose) ;;
  *) echo "CONFORMANCE_RUNTIME must be podman or docker, not '$runtime'" >&2; exit 2 ;;
esac

# plan name -> "test-plan[variants] config-file". The Config plan fixes its
# own variants (discovery, static_client) and rejects them if passed again.
declare -A plan_spec=(
  [basic]="oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client] basic.json"
  [config]="oidcc-config-certification-test-plan config.json"
  [formpost]="oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client] formpost.json"
  [logout]="oidcc-rp-initiated-logout-certification-test-plan[client_registration=static_client] logout.json"
)
plans=("$@")
[[ ${#plans[@]} -gt 0 ]] || plans=(basic config formpost logout)
runner_args=()
for p in "${plans[@]}"; do
  if [[ -z "${plan_spec[$p]:-}" ]]; then
    echo "unknown plan '$p' (expected basic, config, formpost or logout)" >&2
    exit 2
  fi
  read -r spec cfg <<<"${plan_spec[$p]}"
  if [[ ! -f "$here/configs/$cfg" ]]; then
    echo "plan '$p' has no suite configuration yet: tests/conformance/configs/$cfg" >&2
    exit 2
  fi
  runner_args+=("$spec" "$here/configs/$cfg")
done

# The suite's runner script, from the pinned release (not vendored).
tag="$(tr -d '[:space:]' <"$here/suite-version")"
cache="$here/.cache/$tag"
if [[ ! -x "$cache/venv/bin/python" || ! -f "$cache/scripts/run-test-plan.py" ]]; then
  rm -rf "$cache"
  mkdir -p "$cache/scripts/certs-keys"
  for f in run-test-plan.py conformance.py test_plan_parser.py requirements.txt; do
    curl -sfL --retry 3 -o "$cache/scripts/$f" \
      "https://gitlab.com/openid/conformance-suite/-/raw/$tag/scripts/$f"
  done
  python3 -m venv "$cache/venv"
  "$cache/venv/bin/pip" install --quiet --disable-pip-version-check -r "$cache/scripts/requirements.txt"
fi

work="$(mktemp -d)"
results="$here/results/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$results" "$work/tls" "$work/data/mail"
chmod 755 "$work"
project="za-conformance-$$"
export CONFORMANCE_IMAGE_TAG="$tag" CONFORMANCE_WORK="$work" CONFORMANCE_REPO="$repo"
export ZEROAUTHY_MASTER_KEY="$(openssl rand -base64 32)"
dc() { "${compose[@]}" -p "$project" -f "$here/compose.yml" "$@"; }

cleanup() {
  status=$?
  dc logs --no-color zeroauthy >"$results/zeroauthy.log" 2>&1 || true
  dc logs --no-color server >"$results/suite-server.log" 2>&1 || true
  if [[ "${CONFORMANCE_KEEP:-0}" == 1 ]]; then
    echo "CONFORMANCE_KEEP=1: compose project $project and $work are still up."
    echo "  tear down: CONFORMANCE_IMAGE_TAG=$tag CONFORMANCE_WORK=$work CONFORMANCE_REPO=$repo ZEROAUTHY_MASTER_KEY=x ${compose[*]} -p $project -f $here/compose.yml down -v; rm -rf $work"
  else
    dc down -v >/dev/null 2>&1 || true
    rm -rf "$work" 2>/dev/null || true
  fi
  exit $status
}
trap cleanup EXIT

# Per-run CA, and a certificate for zeroauthy signed by it.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=zeroauthy conformance CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
  -keyout "$work/tls/ca-key.pem" -out "$work/tls/ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=zeroauthy.conformance.test" \
  -keyout "$work/tls/key.pem" -out "$work/tls/cert.csr" 2>/dev/null
openssl x509 -req -in "$work/tls/cert.csr" -CA "$work/tls/ca.pem" -CAkey "$work/tls/ca-key.pem" \
  -CAcreateserial -days 1 -out "$work/tls/cert.pem" \
  -extfile <(printf 'subjectAltName=DNS:zeroauthy.conformance.test\nextendedKeyUsage=serverAuth\n') 2>/dev/null
rm -f "$work/tls/ca-key.pem" "$work/tls/cert.csr"
chmod 644 "$work/tls/"*

# The suite JVM's truststore: the JDK's default CAs plus ours.
suite_image="registry.gitlab.com/openid/conformance-suite:$tag"
"$runtime" run --rm -v "$work/tls:/tls" --entrypoint sh "$suite_image" -c '
  cp "$JAVA_HOME/lib/security/cacerts" /tls/truststore.p12 && chmod 644 /tls/truststore.p12 &&
  keytool -importcert -noprompt -alias zeroauthy-conformance-ca -file /tls/ca.pem \
    -keystore /tls/truststore.p12 -storepass changeit >/dev/null'

CGO_ENABLED=0 go build -o "$work/zeroauthy" ./cmd/zeroauthy

# wait_for NAME CMD...: retry CMD for up to ~3 minutes (the suite's JVM is slow to start).
wait_for() {
  local name="$1"; shift
  for _ in $(seq 1 180); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "timed out waiting for $name" >&2
  return 1
}

suite="https://localhost.emobix.co.uk:8443/"
dc up -d mongodb server nginx >/dev/null
wait_for "the suite at $suite" curl -skf "${suite}api/runner/available"

dc up -d zeroauthy >/dev/null
in_suite() { dc exec -T server curl -sf --cacert /run/conformance/ca.pem "$@"; }
wait_for zeroauthy in_suite -o /dev/null https://zeroauthy.conformance.test:8443/healthz
# The suite's own view of zeroauthy: name resolution and CA trust.
in_suite -o /dev/null -w 'suite -> zeroauthy discovery: HTTP %{http_code}\n' \
  https://zeroauthy.conformance.test:8443/.well-known/openid-configuration

status=0
CONFORMANCE_SERVER="$suite" CONFORMANCE_DEV_MODE=1 \
  "$cache/venv/bin/python" "$cache/scripts/run-test-plan.py" --verbose \
  --export-dir "$results" \
  --expected-failures-file "$here/expected-failures.json" \
  --expected-skips-file "$here/expected-skips.json" \
  "${runner_args[@]}" 2>&1 | tee "$results/runner.log" || status=$? # pipefail: the runner's status

echo
echo "Summary (results in ${results#"$repo"/}):"
"$here/summarize.sh" "$results/runner.log"
exit $status
