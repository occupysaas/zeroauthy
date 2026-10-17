-- Device authorization grant (Plan 11). Empty tenant settings select the
-- defaults (base-20 charset, no mask).
ALTER TABLE tenants ADD COLUMN device_flow_charset TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN device_flow_mask TEXT NOT NULL DEFAULT '';
CREATE TABLE device_codes (
  tenant_id TEXT NOT NULL,
  device_code_hash TEXT NOT NULL,
  user_code_hash TEXT NOT NULL,
  client_id TEXT NOT NULL,
  scopes TEXT NOT NULL,
  audience TEXT NOT NULL,
  status TEXT NOT NULL,
  user_id TEXT NOT NULL,
  granted_scopes TEXT NOT NULL,
  last_polled_at BIGINT NULL,
  expired_reported_at BIGINT NULL,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, device_code_hash),
  UNIQUE (tenant_id, user_code_hash)
);
CREATE INDEX device_codes_expires ON device_codes (expires_at);
