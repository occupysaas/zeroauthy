-- Plan 19: policy, session mode and shared atomic protection state. Times are Unix microseconds.
ALTER TABLE tenants ADD COLUMN support_email LONGTEXT NOT NULL DEFAULT ('');
ALTER TABLE tenants ADD COLUMN support_url LONGTEXT NOT NULL DEFAULT ('');
ALTER TABLE tenants ADD COLUMN picture_url LONGTEXT NOT NULL DEFAULT ('');
ALTER TABLE tenants ADD COLUMN ephemeral_session_lifetime BIGINT NOT NULL DEFAULT 0;
ALTER TABLE tenants ADD COLUMN idle_ephemeral_session_lifetime BIGINT NOT NULL DEFAULT 0;
ALTER TABLE tenants ADD COLUMN session_cookie_mode VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN protection_initialized BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE tenants ADD COLUMN settings_extra LONGTEXT NOT NULL DEFAULT ('null');
ALTER TABLE tenants ADD COLUMN settings_presence LONGTEXT NOT NULL DEFAULT ('null');
ALTER TABLE tenants ADD COLUMN protection_settings LONGTEXT NOT NULL DEFAULT ('null');
ALTER TABLE sessions ADD COLUMN cookie_mode VARCHAR(255) NOT NULL DEFAULT '';
CREATE TABLE protection_buckets (
 tenant_id VARCHAR(191) COLLATE utf8mb4_0900_bin NOT NULL, bucket_id VARCHAR(191) COLLATE utf8mb4_0900_bin NOT NULL,
 kind VARCHAR(255) NOT NULL, connection_id VARCHAR(255) NOT NULL,
 identifier VARCHAR(255) NOT NULL, ip VARCHAR(255) NOT NULL,
 generation VARCHAR(255) NOT NULL, algorithm VARCHAR(255) NOT NULL,
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
 tenant_id VARCHAR(191) COLLATE utf8mb4_0900_bin NOT NULL, id VARCHAR(191) COLLATE utf8mb4_0900_bin NOT NULL, reserved_at BIGINT NOT NULL,
 completed BOOLEAN NOT NULL, outcome VARCHAR(255) NOT NULL, expires_at BIGINT NOT NULL,
 PRIMARY KEY (tenant_id, id)
);
CREATE INDEX protection_receipts_expiry ON protection_receipts (expires_at);
CREATE TABLE protection_reservations (
 tenant_id VARCHAR(191) COLLATE utf8mb4_0900_bin NOT NULL, receipt_id VARCHAR(191) COLLATE utf8mb4_0900_bin NOT NULL, bucket_id VARCHAR(191) COLLATE utf8mb4_0900_bin NOT NULL,
 generation VARCHAR(255) NOT NULL, admission_sequence BIGINT NOT NULL, outcome VARCHAR(255) NOT NULL,
 PRIMARY KEY (tenant_id, receipt_id, bucket_id)
);
CREATE INDEX protection_reservations_bucket ON protection_reservations (tenant_id, bucket_id);
CREATE TABLE protection_proofs (
 proof_hash VARCHAR(191) COLLATE utf8mb4_0900_bin NOT NULL PRIMARY KEY, expires_at BIGINT NOT NULL
);
CREATE INDEX protection_proofs_expiry ON protection_proofs (expires_at);
CREATE TABLE protection_risk_events (
 tenant_id VARCHAR(191) COLLATE utf8mb4_0900_bin NOT NULL, attempt_id VARCHAR(191) COLLATE utf8mb4_0900_bin NOT NULL, ip VARCHAR(255) NOT NULL,
 occurred_at BIGINT NOT NULL, expires_at BIGINT NOT NULL,
 PRIMARY KEY (tenant_id, attempt_id)
);
CREATE INDEX protection_risk_lookup ON protection_risk_events (tenant_id, ip, occurred_at);
CREATE INDEX protection_risk_expiry ON protection_risk_events (expires_at);
