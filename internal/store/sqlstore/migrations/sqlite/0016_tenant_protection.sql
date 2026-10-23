-- Plan 19: policy, session mode and shared atomic protection state. Times are Unix microseconds.
ALTER TABLE tenants ADD COLUMN support_email TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN support_url TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN picture_url TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN ephemeral_session_lifetime BIGINT NOT NULL DEFAULT 0;
ALTER TABLE tenants ADD COLUMN idle_ephemeral_session_lifetime BIGINT NOT NULL DEFAULT 0;
ALTER TABLE tenants ADD COLUMN session_cookie_mode TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN protection_initialized BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE tenants ADD COLUMN settings_extra TEXT NOT NULL DEFAULT 'null';
ALTER TABLE tenants ADD COLUMN settings_presence TEXT NOT NULL DEFAULT 'null';
ALTER TABLE tenants ADD COLUMN protection_settings TEXT NOT NULL DEFAULT 'null';
ALTER TABLE sessions ADD COLUMN cookie_mode TEXT NOT NULL DEFAULT '';
CREATE TABLE protection_buckets (
 tenant_id TEXT NOT NULL, bucket_id TEXT NOT NULL,
 kind TEXT NOT NULL, connection_id TEXT NOT NULL,
 identifier TEXT NOT NULL, ip TEXT NOT NULL,
 generation TEXT NOT NULL, algorithm TEXT NOT NULL,
 capacity BIGINT NOT NULL, window_us BIGINT NOT NULL, refill_us BIGINT NOT NULL, lockout_us BIGINT NOT NULL,
 tokens DOUBLE PRECISION NOT NULL, failures BIGINT NOT NULL, reserved BIGINT NOT NULL,
 next_sequence BIGINT NOT NULL,
 updated_at BIGINT NOT NULL, blocked_until BIGINT NOT NULL, expires_at BIGINT NOT NULL,
 PRIMARY KEY (tenant_id, bucket_id)
);
CREATE INDEX protection_buckets_expiry ON protection_buckets (expires_at);
CREATE INDEX protection_buckets_lookup ON protection_buckets (tenant_id, kind, connection_id);
CREATE INDEX protection_buckets_identifier ON protection_buckets (tenant_id, identifier);
CREATE INDEX protection_buckets_ip ON protection_buckets (tenant_id, ip);
CREATE TABLE protection_receipts (
 tenant_id TEXT NOT NULL, id TEXT NOT NULL, reserved_at BIGINT NOT NULL,
 completed BOOLEAN NOT NULL, outcome TEXT NOT NULL, expires_at BIGINT NOT NULL,
 PRIMARY KEY (tenant_id, id)
);
CREATE INDEX protection_receipts_expiry ON protection_receipts (expires_at);
CREATE TABLE protection_reservations (
 tenant_id TEXT NOT NULL, receipt_id TEXT NOT NULL, bucket_id TEXT NOT NULL,
 generation TEXT NOT NULL, admission_sequence BIGINT NOT NULL, outcome TEXT NOT NULL,
 PRIMARY KEY (tenant_id, receipt_id, bucket_id)
);
CREATE INDEX protection_reservations_bucket ON protection_reservations (tenant_id, bucket_id);
CREATE TABLE protection_proofs (
 proof_hash TEXT NOT NULL PRIMARY KEY, expires_at BIGINT NOT NULL
);
CREATE INDEX protection_proofs_expiry ON protection_proofs (expires_at);
CREATE TABLE protection_risk_events (
 tenant_id TEXT NOT NULL, attempt_id TEXT NOT NULL, ip TEXT NOT NULL,
 occurred_at BIGINT NOT NULL, expires_at BIGINT NOT NULL,
 PRIMARY KEY (tenant_id, attempt_id)
);
CREATE INDEX protection_risk_lookup ON protection_risk_events (tenant_id, ip, occurred_at);
CREATE INDEX protection_risk_expiry ON protection_risk_events (expires_at);
