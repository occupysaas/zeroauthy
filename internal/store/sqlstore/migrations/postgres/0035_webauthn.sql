ALTER TABLE sessions ADD COLUMN auth_methods TEXT NULL;
ALTER TABLE clients ADD COLUMN mobile TEXT NULL;
ALTER TABLE tenants ADD COLUMN domain_rp_ids TEXT NULL;
CREATE TABLE webauthn_snoozes (tenant_id VARCHAR(255) NOT NULL, user_id VARCHAR(255) NOT NULL, kind VARCHAR(32) NOT NULL, scope_hash VARCHAR(64) NOT NULL, until_at BIGINT NOT NULL, PRIMARY KEY (tenant_id,user_id,kind,scope_hash));
CREATE INDEX webauthn_snoozes_until ON webauthn_snoozes (until_at);
