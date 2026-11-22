ALTER TABLE clients ADD COLUMN addons TEXT NULL;
ALTER TABLE sessions ADD COLUMN saml_participants TEXT NULL;
CREATE TABLE saml_replay (tenant_id VARCHAR(255) NOT NULL, connection_id VARCHAR(255) NOT NULL, assertion_hash VARCHAR(64) NOT NULL, expires_at BIGINT NOT NULL, PRIMARY KEY (tenant_id,connection_id,assertion_hash));
CREATE INDEX saml_replay_expires ON saml_replay (expires_at);
