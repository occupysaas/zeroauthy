-- Plan 41c: CIBA requests and the client's async approval channels.
ALTER TABLE clients ADD COLUMN async_approval_notification_channels TEXT NULL;
CREATE TABLE ciba_requests (
  tenant_id VARCHAR(255) NOT NULL,
  id_hash VARCHAR(128) NOT NULL,
  ticket_hash VARCHAR(128) NOT NULL,
  origin TEXT NOT NULL,
  client_id VARCHAR(255) NOT NULL,
  user_id TEXT NOT NULL,
  scopes TEXT NOT NULL,
  audience TEXT NOT NULL,
  binding_message TEXT NOT NULL,
  status VARCHAR(16) NOT NULL,
  granted_scopes TEXT NOT NULL,
  action_effects BLOB NULL,
  auth_time BIGINT NOT NULL,
  mfa_at BIGINT NOT NULL,
  poll_interval INTEGER NOT NULL,
  last_polled_at BIGINT NULL,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id_hash),
  UNIQUE (tenant_id, ticket_hash)
);
CREATE INDEX ciba_requests_pending ON ciba_requests (tenant_id, status, expires_at);
CREATE INDEX ciba_requests_client ON ciba_requests (tenant_id, client_id);
CREATE INDEX ciba_requests_expiry ON ciba_requests (expires_at);
