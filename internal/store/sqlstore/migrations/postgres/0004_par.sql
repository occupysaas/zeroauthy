-- Pushed authorization requests (Plan 10). Defaults keep existing rows'
-- behaviour: PAR off for every tenant, not required by any client.
ALTER TABLE tenants ADD COLUMN pushed_authorization_requests_supported BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE clients ADD COLUMN require_pushed_authorization_requests BOOLEAN NOT NULL DEFAULT FALSE;
CREATE TABLE pushed_auth_requests (
  tenant_id TEXT NOT NULL,
  id_hash TEXT NOT NULL,
  client_id TEXT NOT NULL,
  params TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  used_at BIGINT NULL,
  PRIMARY KEY (tenant_id, id_hash)
);
CREATE INDEX pushed_auth_requests_expires ON pushed_auth_requests (expires_at);
