# Repository agent rules

## Plan 19 database-test hold

While implementing Plan 19 (`docs/superpowers/plans/2026-10-21-zeroauthy-plan-19-tenant-settings-attack-protection.md`), do not run **any database-backed test until all implementation tasks (Tasks 1–11) are done**. This includes SQLite, PostgreSQL, MySQL, SQL-backed gRPC or plugin tests, database-backed integration and browser tests, `./scripts/test-sql.sh`, and broad test commands that would select any of them.

Write database tests and compile affected code as needed. Before Task 12, run only focused tests confirmed to use in-memory stores or mocks. In Task 12, run the deferred database tests and report their actual results. Never label a deferred test as passing.

This rule takes precedence over earlier per-task test commands in the Plan 19 implementation plan.
