-- The system tenant and console operators (Plan 13). reserved marks the
-- tenant zeroauthy runs for itself, seeded a tenant the seed file defines.
ALTER TABLE tenants ADD COLUMN reserved BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE tenants ADD COLUMN seeded BOOLEAN NOT NULL DEFAULT FALSE;
CREATE TABLE operators (
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  tenants TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, user_id)
);
