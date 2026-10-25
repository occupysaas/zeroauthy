#!/usr/bin/env bash
# SQL-backed Plan 20 signing lifecycle checks. Uses an isolated SQLite file.
set -euo pipefail
cd "$(dirname "$0")/../.."
go test ./tests/e2e/signing-server -run '^TestM20' -count=1
go test ./internal/keys -run '^TestM20CustomKeyForgery$' -count=1
E2E_M20_HARNESS=1 tests/e2e/run-browser.sh m20-console.spec.mjs
