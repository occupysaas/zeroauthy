# Upgrading

Read the [changelog](../CHANGELOG.md) for the version you are moving to, then:

1. **Back up** the database (see [deployment](deployment.md#backups)). Make
   sure you still have the master key; the backup is useless without it.
2. **Stop** zeroauthy, on every server that shares the database.
3. **Migrate** with the new binary:

   ```bash
   zeroauthy migrate --config /etc/zeroauthy/zeroauthy.yaml
   ```

   It prints the schema versions it moved between. With
   `storage.auto_migrate: true` (the container image's default), `serve`
   does this at startup instead; back up first all the same.
4. **Start** the new version on every server.

Without `auto_migrate`, `serve` refuses to start against a schema that is
behind the binary ("run zeroauthy migrate") or ahead of it. Storage plugins
must be rebuilt against the new `pkg/storeplugin` when the release notes say
so; see [stability](stability.md).

With the container image:

```bash
docker pull ghcr.io/occupysaas/zeroauthy:<new version>
docker rm -f zeroauthy
docker run ... ghcr.io/occupysaas/zeroauthy:<new version>   # same options as before
```

## Rolling back

Migrations only go forward; there are no down migrations. An older binary
refuses to start on a newer schema. To roll back:

1. Stop the new version everywhere.
2. Restore the database backup taken before the upgrade.
3. Start the old version with the same master key.

Changes made after the upgrade (new users, sessions, settings) are lost with
the restore, so decide quickly.

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
