CREATE TABLE tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  friendly_name TEXT NOT NULL,
  default_audience TEXT NOT NULL,
  allowed_logout_urls TEXT NOT NULL,
  enabled_locales TEXT NOT NULL,
  custom_text TEXT NOT NULL,
  session_lifetime INTEGER NOT NULL,
  idle_session_lifetime INTEGER NOT NULL,
  logo_url TEXT NOT NULL,
  primary_color TEXT NOT NULL,
  default_directory TEXT NOT NULL,
  created_at BIGINT NOT NULL
);
CREATE TABLE tenant_domains (
  domain TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  position INTEGER NOT NULL
);
CREATE INDEX tenant_domains_tenant ON tenant_domains (tenant_id);
CREATE TABLE clients (
  tenant_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  name TEXT NOT NULL,
  app_type TEXT NOT NULL,
  secrets TEXT NOT NULL,
  token_endpoint_auth_method TEXT NOT NULL,
  grant_types TEXT NOT NULL,
  callbacks TEXT NOT NULL,
  allowed_logout_urls TEXT NOT NULL,
  web_origins TEXT NOT NULL,
  allowed_origins TEXT NOT NULL,
  id_token_lifetime INTEGER NOT NULL,
  refresh_token TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, client_id)
);
CREATE TABLE resource_servers (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  identifier TEXT NOT NULL,
  name TEXT NOT NULL,
  scopes TEXT NOT NULL,
  signing_alg TEXT NOT NULL,
  token_lifetime INTEGER NOT NULL,
  allow_offline_access INTEGER NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, identifier)
);
CREATE TABLE client_grants (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  audience TEXT NOT NULL,
  scopes TEXT NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, client_id, audience)
);
CREATE TABLE signing_keys (
  tenant_id TEXT NOT NULL,
  kid TEXT NOT NULL,
  alg TEXT NOT NULL,
  status TEXT NOT NULL,
  private_key BLOB NOT NULL,
  public_jwk BLOB NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, kid)
);
CREATE UNIQUE INDEX signing_keys_active ON signing_keys (tenant_id, status) WHERE status IN ('current', 'next');
CREATE TABLE connections (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  name TEXT NOT NULL,
  strategy TEXT NOT NULL,
  enabled_clients TEXT NOT NULL,
  disable_signup INTEGER NOT NULL,
  requires_username INTEGER NOT NULL,
  password_min_length INTEGER NOT NULL,
  password_character_classes INTEGER NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, name)
);
CREATE TABLE users (
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  email TEXT NOT NULL,
  email_verified INTEGER NOT NULL,
  username TEXT NOT NULL,
  name TEXT NOT NULL,
  nickname TEXT NOT NULL,
  picture TEXT NOT NULL,
  given_name TEXT NOT NULL,
  family_name TEXT NOT NULL,
  user_metadata TEXT NOT NULL,
  blocked INTEGER NOT NULL,
  identities TEXT NOT NULL,
  last_login BIGINT NULL,
  logins_count INTEGER NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, user_id)
);
CREATE TABLE user_logins (
  tenant_id TEXT NOT NULL,
  connection TEXT NOT NULL,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  user_id TEXT NOT NULL,
  PRIMARY KEY (tenant_id, connection, kind, value)
);
CREATE INDEX user_logins_user ON user_logins (tenant_id, user_id);
CREATE TABLE sessions (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  user_id TEXT NOT NULL,
  connection TEXT NOT NULL,
  authenticated_at BIGINT NOT NULL,
  client_ids TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  idle_expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, token_hash)
);
CREATE INDEX sessions_user ON sessions (tenant_id, user_id);
CREATE INDEX sessions_expires ON sessions (expires_at);
CREATE INDEX sessions_idle ON sessions (idle_expires_at);
CREATE TABLE auth_transactions (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  cookie_hash TEXT NOT NULL,
  csrf_token TEXT NOT NULL,
  client_id TEXT NOT NULL,
  params TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX auth_transactions_expires ON auth_transactions (expires_at);
CREATE TABLE auth_codes (
  tenant_id TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  user_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  scopes TEXT NOT NULL,
  audience TEXT NOT NULL,
  nonce TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,
  auth_time BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  used_at BIGINT NULL,
  replayed_at BIGINT NULL,
  PRIMARY KEY (tenant_id, code_hash)
);
CREATE INDEX auth_codes_expires ON auth_codes (expires_at);
CREATE TABLE refresh_tokens (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  family_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  scopes TEXT NOT NULL,
  audience TEXT NOT NULL,
  auth_time BIGINT NOT NULL,
  rotating INTEGER NOT NULL,
  expires_at BIGINT NOT NULL,
  idle_expires_at BIGINT NOT NULL,
  rotated_at BIGINT NULL,
  revoked_at BIGINT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, token_hash)
);
CREATE INDEX refresh_tokens_family ON refresh_tokens (tenant_id, family_id);
CREATE INDEX refresh_tokens_user ON refresh_tokens (tenant_id, user_id);
CREATE INDEX refresh_tokens_expires ON refresh_tokens (expires_at);
CREATE INDEX refresh_tokens_idle ON refresh_tokens (idle_expires_at);
CREATE TABLE password_reset_tickets (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  user_id TEXT NOT NULL,
  connection TEXT NOT NULL,
  client_id TEXT NOT NULL,
  lang TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  used_at BIGINT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, token_hash)
);
CREATE INDEX password_reset_tickets_user ON password_reset_tickets (tenant_id, user_id);
CREATE INDEX password_reset_tickets_expires ON password_reset_tickets (expires_at);
