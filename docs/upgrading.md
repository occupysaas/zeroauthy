# Upgrading

## MySQL: back up before you migrate

MySQL commits schema changes (DDL) immediately, so a migration cannot be
rolled back if it fails part way. Migrations 20, 21 and 29 onwards resume
safely when rerun, but migrations 1–19 and 22–28 do not: if one of them fails
or the process stops mid-way, the database is left between two schema
versions.

- Take a backup (for example `mysqldump --single-transaction`) before running
  `zeroauthy migrate` against MySQL, or before starting a new version with
  `storage.auto_migrate: true`.
- If a MySQL migration fails, restore the backup, fix the cause, and migrate
  again. Do not just rerun `zeroauthy migrate` on the partly migrated database.

PostgreSQL and SQLite run each migration in a transaction; a failed migration
rolls back and can be retried.
