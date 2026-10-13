#!/usr/bin/env bash
# scripts/check-sources.sh: verify every x-source URL in an OpenAPI file is reachable.
set -euo pipefail
spec="${1:?usage: check-sources.sh <openapi.yaml>}"
fail=0
while read -r url; do
  code=$(curl -sL -o /dev/null -w '%{http_code}' --max-time 20 "$url" || echo 000)
  if [[ "$code" != 200 ]]; then
    echo "UNREACHABLE ($code): $url"
    fail=1
  else
    echo "ok: $url"
  fi
done < <(awk '/x-source:/{f=1;next} f&&/^[[:space:]]*- https:/{print $2;next} {f=0}' "$spec" | sort -u)
exit $fail
