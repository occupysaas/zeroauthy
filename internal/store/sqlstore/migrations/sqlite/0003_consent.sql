-- Consent, third-party applications and API access policies (Plan 9).
-- Defaults keep existing rows' behaviour: first-party clients, APIs that
-- skip consent for them and allow all user flows, client-credentials grants.
ALTER TABLE tenants ADD COLUMN skip_non_verifiable_callback_uri_confirmation_prompt BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE tenants ADD COLUMN use_scope_descriptions_for_consent BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE clients ADD COLUMN is_first_party BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE clients ADD COLUMN third_party_security_mode TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN redirection_policy TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN skip_non_verifiable_callback_uri_confirmation_prompt BOOLEAN NULL;
ALTER TABLE resource_servers ADD COLUMN skip_consent_for_verifiable_first_party_clients BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE resource_servers ADD COLUMN user_policy TEXT NOT NULL DEFAULT '';
ALTER TABLE resource_servers ADD COLUMN client_policy TEXT NOT NULL DEFAULT '';
ALTER TABLE connections ADD COLUMN is_domain_connection BOOLEAN NOT NULL DEFAULT FALSE;
-- SQLite cannot change a UNIQUE constraint in place: rebuild client_grants.
CREATE TABLE client_grants_new (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  audience TEXT NOT NULL,
  scopes TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  subject_type TEXT NOT NULL DEFAULT 'client',
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, client_id, audience, subject_type)
);
INSERT INTO client_grants_new (tenant_id, id, client_id, audience, scopes, created_at, subject_type)
  SELECT tenant_id, id, client_id, audience, scopes, created_at, 'client' FROM client_grants;
DROP TABLE client_grants;
ALTER TABLE client_grants_new RENAME TO client_grants;
CREATE TABLE user_grants (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  audience TEXT NOT NULL,
  scopes TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, client_id, user_id, audience)
);
CREATE INDEX user_grants_user ON user_grants (tenant_id, user_id);
