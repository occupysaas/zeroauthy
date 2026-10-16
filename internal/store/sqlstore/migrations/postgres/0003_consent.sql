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
ALTER TABLE client_grants ADD COLUMN subject_type TEXT NOT NULL DEFAULT 'client';
ALTER TABLE client_grants DROP CONSTRAINT client_grants_tenant_id_client_id_audience_key;
ALTER TABLE client_grants ADD CONSTRAINT client_grants_client_audience_subject UNIQUE (tenant_id, client_id, audience, subject_type);
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
