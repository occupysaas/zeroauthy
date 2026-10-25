ALTER TABLE signing_keys
  ADD COLUMN certificate_der LONGBLOB NULL,
  ADD COLUMN current_since BIGINT NULL,
  ADD COLUMN current_until BIGINT NULL,
  ADD COLUMN revoked_at BIGINT NULL;

CREATE TABLE custom_signing_keys (
  tenant_id VARCHAR(64) NOT NULL,
  jwks LONGBLOB NOT NULL,
  PRIMARY KEY (tenant_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
