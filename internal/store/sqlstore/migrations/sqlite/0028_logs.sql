-- Times use fixed-width UTC text with nanoseconds including the ordinary Go zero time.
-- Logs are immutable; sequences are allocated only under the tenant write lock.
CREATE TABLE tenant_logs (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, log_id VARCHAR(56),
 date VARCHAR(30) NOT NULL, committed_at VARCHAR(30) NOT NULL, type VARCHAR(255) NOT NULL,
 user_id TEXT NOT NULL, client_id TEXT NOT NULL,
 connection_id TEXT NOT NULL, organization_id TEXT NOT NULL,
 ip VARCHAR(255) NOT NULL, body BLOB NOT NULL,
 UNIQUE (tenant_id, log_id)
);
CREATE INDEX tenant_logs_seq ON tenant_logs (tenant_id, seq);
CREATE INDEX tenant_logs_user_seq ON tenant_logs (tenant_id, user_id, seq);
CREATE INDEX tenant_logs_type_seq ON tenant_logs (tenant_id, type, seq);
CREATE INDEX tenant_logs_date ON tenant_logs (tenant_id, date);
CREATE INDEX tenant_logs_purge ON tenant_logs (date, seq);
CREATE TABLE log_streams (
 tenant_id TEXT NOT NULL, id VARCHAR(255) NOT NULL, config TEXT NOT NULL,
 status VARCHAR(32) NOT NULL, start_from VARCHAR(30) NOT NULL, checkpoint BIGINT NOT NULL,
 lease_owner VARCHAR(255) NOT NULL, lease_until VARCHAR(30) NOT NULL, next_at VARCHAR(30) NOT NULL,
 failing_since VARCHAR(30) NOT NULL, last_success_at VARCHAR(30) NOT NULL, failures INTEGER NOT NULL,
 last_error_class VARCHAR(255) NOT NULL, version INTEGER NOT NULL,
 created_at VARCHAR(30) NOT NULL, updated_at VARCHAR(30) NOT NULL,
 PRIMARY KEY (tenant_id, id)
);
CREATE INDEX log_streams_due ON log_streams (status, next_at, lease_until);
CREATE TABLE log_stats_daily (
 tenant_id TEXT NOT NULL, day VARCHAR(30) NOT NULL, logins BIGINT NOT NULL,
 signups BIGINT NOT NULL, leaked_passwords BIGINT NOT NULL,
 created_at VARCHAR(30) NOT NULL, updated_at VARCHAR(30) NOT NULL,
 PRIMARY KEY (tenant_id, day)
);
