#!/usr/bin/env bash
# scripts/test-sql.sh: start PostgreSQL and MySQL in containers (podman,
# falling back to docker), run the SQL driver tests against them, and remove
# the containers. SQLite tests need no containers and always run.
set -euo pipefail
cd "$(dirname "$0")/.."
rt="$(command -v podman || command -v docker)"
pg="zeroauthy-test-pg-$$" my="zeroauthy-test-my-$$"
cleanup() { "$rt" rm -f "$pg" "$my" >/dev/null 2>&1 || true; }
trap cleanup EXIT

"$rt" run -d --rm --name "$pg" -e POSTGRES_PASSWORD=zeroauthy -p 127.0.0.1:55432:5432 docker.io/library/postgres:17 >/dev/null
"$rt" run -d --rm --name "$my" -e MYSQL_ROOT_PASSWORD=zeroauthy -p 127.0.0.1:53306:3306 docker.io/library/mysql:8.4 >/dev/null

for _ in $(seq 1 120); do "$rt" exec "$pg" pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; done
for _ in $(seq 1 120); do "$rt" exec "$my" mysqladmin ping -h 127.0.0.1 -pzeroauthy --silent >/dev/null 2>&1 && break; sleep 1; done

export ZEROAUTHY_TEST_POSTGRES_DSN="postgres://postgres:zeroauthy@127.0.0.1:55432/postgres?sslmode=disable"
export ZEROAUTHY_TEST_MYSQL_DSN="mysql://root:zeroauthy@127.0.0.1:53306/"
go test -race -count=1 "${@:-./internal/store/sqlstore/...}"
