-- Pushed authorization requests (Plan 10). Defaults keep existing rows'
-- behaviour: PAR off for every tenant, not required by any client.
ALTER TABLE tenants ADD COLUMN pushed_authorization_requests_supported BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE clients ADD COLUMN require_pushed_authorization_requests BOOLEAN NOT NULL DEFAULT FALSE;
CREATE TABLE pushed_auth_requests (
  tenant_id VARCHAR(64) NOT NULL,
  id_hash VARCHAR(255) NOT NULL,
  client_id VARCHAR(255) NOT NULL,
  params LONGTEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  used_at BIGINT NULL,
  PRIMARY KEY (tenant_id, id_hash),
  KEY pushed_auth_requests_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
