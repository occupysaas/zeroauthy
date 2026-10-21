#!/usr/bin/env bash
# scripts/test-sql.sh: start PostgreSQL and MySQL in containers (podman,
# falling back to docker), run the SQL driver tests against them, and remove
# the containers. Host ports default to 55432 (PostgreSQL) and 53306 (MySQL);
# override with ZEROAUTHY_TEST_PG_PORT and ZEROAUTHY_TEST_MYSQL_PORT. Needs PostgreSQL 14+ and MySQL 8.0.17+ (utf8mb4_0900_bin). SQLite tests need no containers and always run.
set -euo pipefail
cd "$(dirname "$0")/.."
rt="$(command -v podman || command -v docker || true)"
[ -n "$rt" ] || { echo "test-sql.sh: neither podman nor docker is available" >&2; exit 1; }
pg_port="${ZEROAUTHY_TEST_PG_PORT:-55432}" my_port="${ZEROAUTHY_TEST_MYSQL_PORT:-53306}"
pg="zeroauthy-test-pg-$$" my="zeroauthy-test-my-$$"
cleanup() { "$rt" rm -f "$pg" "$my" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# The containers are throwaway, so their data lives on tmpfs and durability
# is off: the suites make thousands of small transactions, and with fsync on
# they mostly wait on the disk.
"$rt" run -d --rm --name "$pg" -e POSTGRES_PASSWORD=zeroauthy -p "127.0.0.1:$pg_port:5432" \
  --tmpfs /var/lib/postgresql/data docker.io/library/postgres:17 \
  -c fsync=off -c synchronous_commit=off -c full_page_writes=off >/dev/null
"$rt" run -d --rm --name "$my" -e MYSQL_ROOT_PASSWORD=zeroauthy -p "127.0.0.1:$my_port:3306" \
  --tmpfs /var/lib/mysql docker.io/library/mysql:8.4 \
  --innodb-flush-log-at-trx-commit=0 --sync-binlog=0 --skip-log-bin --innodb-doublewrite=OFF >/dev/null

wait_for() { # name, command...
  local name="$1"; shift
  for _ in $(seq 1 120); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  echo "test-sql.sh: $name did not become ready within 120s" >&2
  return 1
}
wait_for postgres "$rt" exec "$pg" pg_isready -h 127.0.0.1 -U postgres
wait_for mysql "$rt" exec "$my" mysqladmin ping -h 127.0.0.1 -pzeroauthy --silent

export ZA_TEST_POSTGRES_DSN="postgres://postgres:zeroauthy@127.0.0.1:$pg_port/postgres?sslmode=disable"
export ZA_TEST_MYSQL_DSN="mysql://root:zeroauthy@127.0.0.1:$my_port/"
go test -race -count=1 "${@:-./internal/store/sqlstore/...}"
