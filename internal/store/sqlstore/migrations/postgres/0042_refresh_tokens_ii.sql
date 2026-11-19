ALTER TABLE refresh_tokens ADD COLUMN parent_id TEXT NOT NULL DEFAULT '';
ALTER TABLE refresh_tokens ADD COLUMN access TEXT NOT NULL DEFAULT 'offline';
ALTER TABLE refresh_tokens ADD COLUMN dpop_jkt TEXT NOT NULL DEFAULT '';
ALTER TABLE refresh_tokens ADD COLUMN metadata TEXT;
ALTER TABLE refresh_tokens ADD COLUMN device TEXT;
ALTER TABLE refresh_tokens ADD COLUMN last_exchanged_at BIGINT;
ALTER TABLE refresh_tokens ADD COLUMN insertion_order BIGINT NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN metadata TEXT;
ALTER TABLE auth_transactions ADD COLUMN dpop_jkt TEXT NOT NULL DEFAULT '';
ALTER TABLE auth_codes ADD COLUMN dpop_jkt TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN token_quota TEXT;
ALTER TABLE clients ADD COLUMN require_proof_of_possession BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE organizations ADD COLUMN token_quota TEXT;
ALTER TABLE tenants ADD COLUMN default_token_quota TEXT;
ALTER TABLE resource_servers ADD COLUMN proof_of_possession TEXT;
ALTER TABLE resource_servers ADD COLUMN allow_online_access BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE resource_servers ADD COLUMN allow_online_access_with_ephemeral_sessions BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE refresh_token_sequences (
 tenant_id TEXT PRIMARY KEY,
 last_order BIGINT NOT NULL
);
CREATE INDEX refresh_tokens_tuple ON refresh_tokens (tenant_id,user_id,client_id,audience);
CREATE INDEX refresh_tokens_session ON refresh_tokens (tenant_id,session_id);
CREATE INDEX refresh_tokens_family_created ON refresh_tokens (tenant_id,family_id,created_at);
CREATE INDEX refresh_tokens_family_order ON refresh_tokens (tenant_id,family_id,insertion_order);

CREATE TABLE dpop_proofs (
 tenant_id TEXT NOT NULL,
 origin TEXT NOT NULL,
 jkt TEXT NOT NULL,
 jti_hash TEXT NOT NULL,
 expires_at BIGINT NOT NULL,
 PRIMARY KEY (tenant_id,origin,jkt,jti_hash)
);
CREATE INDEX dpop_proofs_expiry ON dpop_proofs (expires_at);

CREATE TABLE token_quota_counters (
 tenant_id TEXT NOT NULL,
 subject_kind TEXT NOT NULL,
 subject_id TEXT NOT NULL,
 bucket TEXT NOT NULL,
 window_start BIGINT NOT NULL,
 resets_at BIGINT NOT NULL,
 count BIGINT NOT NULL DEFAULT 0,
 warned INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY (tenant_id,subject_kind,subject_id,bucket,window_start)
);
CREATE INDEX token_quota_expiry ON token_quota_counters (resets_at);
