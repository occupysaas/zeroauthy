ALTER TABLE signing_keys ADD COLUMN certificate_der BYTEA;
ALTER TABLE signing_keys ADD COLUMN current_since BIGINT NULL;
ALTER TABLE signing_keys ADD COLUMN current_until BIGINT NULL;
ALTER TABLE signing_keys ADD COLUMN revoked_at BIGINT NULL;

CREATE TABLE custom_signing_keys (
  tenant_id TEXT PRIMARY KEY,
  jwks BYTEA NOT NULL
);
