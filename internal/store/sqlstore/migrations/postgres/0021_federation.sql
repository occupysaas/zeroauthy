ALTER TABLE connections ADD COLUMN federation_revision BIGINT NOT NULL DEFAULT 0;
ALTER TABLE connections ADD COLUMN federation_secrets_sealed BYTEA NULL;
ALTER TABLE tenants ADD COLUMN identity_epoch BIGINT NOT NULL DEFAULT 0;
CREATE TABLE federation_attempts (tenant_id TEXT NOT NULL, state_hash TEXT NOT NULL, transaction_id TEXT NOT NULL, connection_id TEXT NOT NULL, revision BIGINT NOT NULL, identity_epoch BIGINT NOT NULL, cookie_hash TEXT NOT NULL, origin TEXT NOT NULL, callback_url TEXT NOT NULL, issuer TEXT NOT NULL, endpoints TEXT NOT NULL, sealed_proof BYTEA NULL, expires_at BIGINT NOT NULL, status VARCHAR(16) NOT NULL, superseded BOOLEAN NOT NULL DEFAULT FALSE, created_at BIGINT NOT NULL, PRIMARY KEY (tenant_id, state_hash), FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE);
CREATE TABLE federated_identities (tenant_id TEXT NOT NULL, connection_id TEXT NOT NULL, subject TEXT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY (tenant_id, connection_id, subject));
CREATE TABLE federated_tokens (tenant_id TEXT NOT NULL, connection_id TEXT NOT NULL, subject TEXT NOT NULL, sealed BYTEA NOT NULL, PRIMARY KEY (tenant_id, connection_id, subject), FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE);
CREATE INDEX federation_attempts_tx ON federation_attempts (tenant_id, transaction_id);
CREATE INDEX federation_attempts_expiry ON federation_attempts (expires_at);
CREATE INDEX federated_identities_user ON federated_identities (tenant_id, user_id);
