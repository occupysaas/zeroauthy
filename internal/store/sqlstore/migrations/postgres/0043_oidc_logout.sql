ALTER TABLE clients ADD COLUMN oidc_support TEXT NULL;
ALTER TABLE clients ADD COLUMN oidc_logout TEXT NULL;
ALTER TABLE clients ADD COLUMN id_token_alg VARCHAR(16) NOT NULL DEFAULT '';
ALTER TABLE auth_codes ADD COLUMN acr VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE refresh_tokens ADD COLUMN acr VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN client_organizations TEXT NULL;
CREATE TABLE global_revocation_jtis (tenant_id VARCHAR(255) NOT NULL, connection_id VARCHAR(255) NOT NULL, jti_hash VARCHAR(64) NOT NULL, expires_at BIGINT NOT NULL, PRIMARY KEY (tenant_id,connection_id,jti_hash));
CREATE INDEX global_revocation_jtis_expires ON global_revocation_jtis (expires_at);
