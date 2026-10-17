-- Device authorization grant (Plan 11). Empty tenant settings select the
-- defaults (base-20 charset, no mask).
ALTER TABLE tenants ADD COLUMN device_flow_charset VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN device_flow_mask VARCHAR(255) NOT NULL DEFAULT '';
CREATE TABLE device_codes (
  tenant_id VARCHAR(64) NOT NULL,
  device_code_hash VARCHAR(255) NOT NULL,
  user_code_hash VARCHAR(255) NOT NULL,
  client_id VARCHAR(255) NOT NULL,
  scopes LONGTEXT NOT NULL,
  audience VARCHAR(255) NOT NULL,
  status VARCHAR(32) NOT NULL,
  user_id VARCHAR(255) NOT NULL,
  granted_scopes LONGTEXT NOT NULL,
  last_polled_at BIGINT NULL,
  expired_reported_at BIGINT NULL,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, device_code_hash),
  UNIQUE KEY device_codes_user_code (tenant_id, user_code_hash),
  KEY device_codes_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
