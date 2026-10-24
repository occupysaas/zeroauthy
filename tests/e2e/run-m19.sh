#!/usr/bin/env bash
# SQL-backed. Deferred until Plan 19 Task 12. Never contacts provider services.
set -euo pipefail
cd "$(dirname "$0")/../.."
go test ./tests/e2e/protection-server -run '^TestM19Two(InstancesRestart|HTTPInstances)$' -count=1
E2E_M19_HARNESS=1 tests/e2e/run-browser.sh m19-console.spec.mjs
