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

# plan name -> "test-plan[variants] config-file". Each plan fixes some
# variants itself and rejects them if passed again (see the plan classes,
# e.g. OIDCCBasicTestPlan.java at the pinned tag): Config fixes
# server_metadata and client_registration; Basic and Form Post fix
# response_type, client_auth_type (client_secret_basic, plus one
# client_secret_post module) and response_mode; RP-initiated logout fixes
# server_metadata, client_auth_type and response_mode.
declare -A plan_spec=(
  [basic]="oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client] basic.json"
  [config]="oidcc-config-certification-test-plan config.json"
  [formpost]="oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client] formpost.json"
  [logout]="oidcc-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client] logout.json"
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

tag="$(tr -d '[:space:]' <"$here/suite-version")"
cache="$here/.cache/$tag"
work="$(mktemp -d)"
results="$here/results/$(date -u +%Y%m%dT%H%M%SZ)"
project="za-conformance-$$"
started=0
dc() { "${compose[@]}" -p "$project" -f "$here/compose.yml" "$@"; }
# dc_detached: dc in its own session, so a Ctrl-C (sent to the whole
# foreground process group) cannot kill a teardown in progress.
dc_detached() { setsid -w "${compose[@]}" -p "$project" -f "$here/compose.yml" "$@" </dev/null; }

cleanup() {
  local status=$?
  trap '' INT TERM # finish the teardown even if interrupted again
  if [[ $started == 1 ]]; then
    dc_detached logs --no-color zeroauthy >"$results/zeroauthy.log" 2>&1 || true
    dc_detached logs --no-color server >"$results/suite-server.log" 2>&1 || true
  fi
  if [[ "${CONFORMANCE_KEEP:-0}" == 1 && $started == 1 ]]; then
    echo "CONFORMANCE_KEEP=1: compose project $project and $work are still up."
    echo "  tear down: CONFORMANCE_IMAGE_TAG=$tag CONFORMANCE_WORK=$work CONFORMANCE_REPO=$repo ZEROAUTHY_MASTER_KEY=x ${compose[*]} -p $project -f $here/compose.yml down -v; rm -rf $work"
  else
    [[ $started == 0 ]] || dc_detached down -v >/dev/null 2>&1 || true
    rm -rf "$work" 2>/dev/null || true
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$results" "$work/tls" "$work/data/mail"
chmod 755 "$work"

if (exec 3<>/dev/tcp/127.0.0.1/8443) 2>/dev/null; then
  echo "conformance: something already listens on 127.0.0.1:8443" >&2
  echo "Hints: stop the e2e suite or a leftover conformance run; see: $runtime ps -a --filter name=za-conformance-" >&2
  exit 1
fi

# zeroauthy from the working tree: a compile error fails before anything is pulled.
CGO_ENABLED=0 go build -o "$work/zeroauthy" ./cmd/zeroauthy

# The suite's runner script, from the pinned release (not vendored). Every
# downloaded file is checked against suite-files.sha256 on every run, and the
# venv installs only the hash-pinned requirements.txt. .ok marks a complete
# cache; anything else is rebuilt from scratch.
if [[ ! -f "$cache/.ok" ]]; then
  echo "building the suite runner cache in ${cache#"$repo"/}"
  rm -rf "$cache"
  mkdir -p "$cache/scripts/certs-keys"
  for f in run-test-plan.py conformance.py test_plan_parser.py requirements.txt; do
    curl -sfL --retry 3 -o "$cache/scripts/$f" \
      "https://gitlab.com/openid/conformance-suite/-/raw/$tag/scripts/$f"
  done
fi
if ! (cd "$cache/scripts" && grep -v '^#' "$here/suite-files.sha256" | sha256sum -c --strict --quiet -); then
  echo "suite files in ${cache#"$repo"/}/scripts do not match tests/conformance/suite-files.sha256." >&2
  echo "If suite-version was bumped on purpose, update suite-files.sha256 after reviewing the new files;" >&2
  echo "otherwise delete ${cache#"$repo"/} and retry." >&2
  exit 1
fi
if [[ ! -f "$cache/.ok" ]]; then
  python3 -m venv "$cache/venv"
  "$cache/venv/bin/pip" install --quiet --disable-pip-version-check --require-hashes --no-deps \
    -r "$here/requirements.txt"
  touch "$cache/.ok"
fi

export CONFORMANCE_IMAGE_TAG="$tag" CONFORMANCE_WORK="$work" CONFORMANCE_REPO="$repo"
ZEROAUTHY_MASTER_KEY="$(openssl rand -base64 32)"
export ZEROAUTHY_MASTER_KEY

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

# startup_failed WHAT: show what compose said and how to clean up, then fail.
startup_failed() {
  echo "conformance: $1" >&2
  echo "--- compose output ---" >&2
  cat "$work/compose-up.log" >&2 2>/dev/null || true
  echo "--- container logs ---" >&2
  dc logs --no-color --tail 30 server nginx zeroauthy >&2 2>&1 || true
  echo "Hints: host port 8443 must be free (the e2e suite and leftover conformance runs use it)." >&2
  echo "  leftover projects: $runtime ps -a --filter name=za-conformance-" >&2
  echo "  remove them:       $runtime ps -aq --filter name=za-conformance- | xargs -r $runtime rm -f$([[ $runtime == podman ]] && echo ' --depend')" >&2
  echo "  (then remove their networks: $runtime network ls -q --filter name=za-conformance- | xargs -r $runtime network rm)" >&2
  exit 1
}

suite="https://localhost.emobix.co.uk:8443/"
started=1
dc up -d mongodb server nginx >"$work/compose-up.log" 2>&1 || startup_failed "could not start the suite containers"
wait_for "the suite at $suite" curl -skf "${suite}api/runner/available" ||
  startup_failed "the suite did not answer at ${suite}api/runner/available"

dc up -d zeroauthy >>"$work/compose-up.log" 2>&1 || startup_failed "could not start the zeroauthy container"
in_suite() { dc exec -T server curl -sf --cacert /run/conformance/ca.pem "$@"; }
wait_for zeroauthy in_suite -o /dev/null https://zeroauthy.conformance.test:8443/healthz ||
  startup_failed "zeroauthy did not become healthy at https://zeroauthy.conformance.test:8443/healthz"
# The suite's own view of zeroauthy: name resolution and CA trust.
in_suite -o /dev/null -w 'suite -> zeroauthy discovery: HTTP %{http_code}\n' \
  https://zeroauthy.conformance.test:8443/.well-known/openid-configuration ||
  startup_failed "the suite could not fetch zeroauthy's discovery document"

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
