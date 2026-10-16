-- Consent, third-party applications and API access policies (Plan 9).
-- Defaults keep existing rows' behaviour: first-party clients, APIs that
-- skip consent for them and allow all user flows, client-credentials grants.
ALTER TABLE tenants
  ADD COLUMN skip_non_verifiable_callback_uri_confirmation_prompt BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN use_scope_descriptions_for_consent BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE clients
  ADD COLUMN is_first_party BOOLEAN NOT NULL DEFAULT TRUE,
  ADD COLUMN third_party_security_mode VARCHAR(16) NOT NULL DEFAULT '',
  ADD COLUMN redirection_policy VARCHAR(32) NOT NULL DEFAULT '',
  ADD COLUMN skip_non_verifiable_callback_uri_confirmation_prompt BOOLEAN NULL;
ALTER TABLE resource_servers
  ADD COLUMN skip_consent_for_verifiable_first_party_clients BOOLEAN NOT NULL DEFAULT TRUE,
  ADD COLUMN user_policy VARCHAR(32) NOT NULL DEFAULT '',
  ADD COLUMN client_policy VARCHAR(32) NOT NULL DEFAULT '';
ALTER TABLE connections ADD COLUMN is_domain_connection BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE client_grants
  ADD COLUMN subject_type VARCHAR(16) NOT NULL DEFAULT 'client',
  DROP INDEX client_grants_client_audience,
  ADD UNIQUE KEY client_grants_client_audience_subject (tenant_id, client_id, audience, subject_type);
CREATE TABLE user_grants (
  tenant_id VARCHAR(64) NOT NULL,
  id VARCHAR(255) NOT NULL,
  client_id VARCHAR(255) NOT NULL,
  user_id VARCHAR(255) NOT NULL,
  audience VARCHAR(255) NOT NULL,
  scopes LONGTEXT NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  grant_key BINARY(32) AS (UNHEX(SHA2(CONCAT_WS(CHAR(10), client_id, user_id, audience), 256))) STORED,
  PRIMARY KEY (tenant_id, id),
  UNIQUE KEY user_grants_key (tenant_id, grant_key),
  KEY user_grants_user (tenant_id, user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
