#!/usr/bin/env bash
# Runs the local ACME issuance lanes against the pinned Pebble fixture.
# Usage: run-acme.sh [http01,tlsalpn]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
lanes=${1:-http01,tlsalpn}
run=()
for lane in ${lanes//,/ }; do
	case $lane in
	http01) run+=(TestPebbleHTTP01) ;;
	tlsalpn) run+=(TestPebbleTLSALPN01) ;;
	*) echo "unknown lane $lane" >&2; exit 2 ;;
	esac
done
pattern=$(IFS='|'; echo "${run[*]}")

# podman-compose talks to Podman directly (no Docker API socket needed).
if command -v podman-compose >/dev/null; then
	compose=(podman-compose -f "$here/compose.yaml")
else
	compose=(docker compose -f "$here/compose.yaml")
fi
work=$(mktemp -d)
cleanup() { "${compose[@]}" down --timeout 5 >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
"${compose[@]}" up -d >/dev/null
podman cp zeroauthy-domains-pebble:/test/certs/pebble.minica.pem "$work/minica.pem"
for _ in $(seq 1 50); do
	curl -fsS --cacert "$work/minica.pem" https://localhost:14000/dir >/dev/null 2>&1 && break
	sleep 0.2
done
curl -fsS --cacert "$work/minica.pem" https://localhost:14000/dir >/dev/null

cd "$root"
ZA_ACME_DIRECTORY=https://localhost:14000/dir \
ZA_ACME_MANAGEMENT=https://localhost:15000 \
ZA_ACME_CA_FILE="$work/minica.pem" \
	go test -tags=domainintegration -run "$pattern" ./internal/certificates -count=1 -v
