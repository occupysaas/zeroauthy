-- The system tenant and console operators (Plan 13). reserved marks the
-- tenant zeroauthy runs for itself, seeded a tenant the seed file defines.
ALTER TABLE tenants
  ADD COLUMN reserved BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN seeded BOOLEAN NOT NULL DEFAULT FALSE;
CREATE TABLE operators (
  tenant_id VARCHAR(64) NOT NULL,
  user_id VARCHAR(255) NOT NULL,
  tenants LONGTEXT NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
