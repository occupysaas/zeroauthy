CREATE TABLE tenants (
  id VARCHAR(64) NOT NULL,
  name VARCHAR(255) NOT NULL,
  friendly_name TEXT NOT NULL,
  default_audience TEXT NOT NULL,
  allowed_logout_urls LONGTEXT NOT NULL,
  enabled_locales LONGTEXT NOT NULL,
  custom_text LONGTEXT NOT NULL,
  session_lifetime INTEGER NOT NULL,
  idle_session_lifetime INTEGER NOT NULL,
  logo_url TEXT NOT NULL,
  primary_color VARCHAR(255) NOT NULL,
  default_directory VARCHAR(255) NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY tenants_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE TABLE tenant_domains (
  domain VARCHAR(255) NOT NULL,
  tenant_id VARCHAR(64) NOT NULL,
  position INTEGER NOT NULL,
  PRIMARY KEY (domain),
  KEY tenant_domains_tenant (tenant_id),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE TABLE clients (
  tenant_id VARCHAR(64) NOT NULL,
  client_id VARCHAR(255) NOT NULL,
  name TEXT NOT NULL,
  app_type VARCHAR(255) NOT NULL,
  secrets LONGTEXT NOT NULL,
  token_endpoint_auth_method VARCHAR(255) NOT NULL,
  grant_types LONGTEXT NOT NULL,
  callbacks LONGTEXT NOT NULL,
  allowed_logout_urls LONGTEXT NOT NULL,
  web_origins LONGTEXT NOT NULL,
  allowed_origins LONGTEXT NOT NULL,
  id_token_lifetime INTEGER NOT NULL,
  refresh_token LONGTEXT NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE TABLE resource_servers (
  tenant_id VARCHAR(64) NOT NULL,
  id VARCHAR(255) NOT NULL,
  identifier VARCHAR(255) NOT NULL,
  name TEXT NOT NULL,
  scopes LONGTEXT NOT NULL,
  signing_alg VARCHAR(255) NOT NULL,
  token_lifetime INTEGER NOT NULL,
  allow_offline_access BOOLEAN NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE KEY resource_servers_identifier (tenant_id, identifier)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE TABLE client_grants (
  tenant_id VARCHAR(64) NOT NULL,
  id VARCHAR(255) NOT NULL,
  client_id VARCHAR(255) NOT NULL,
  audience VARCHAR(255) NOT NULL,
  scopes LONGTEXT NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE KEY client_grants_client_audience (tenant_id, client_id, audience)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE TABLE signing_keys (
  tenant_id VARCHAR(64) NOT NULL,
  kid VARCHAR(255) NOT NULL,
  alg VARCHAR(255) NOT NULL,
  status VARCHAR(16) NOT NULL,
  private_key LONGBLOB NOT NULL,
  public_jwk LONGBLOB NOT NULL,
  created_at BIGINT NOT NULL,
  active_status VARCHAR(16) GENERATED ALWAYS AS (CASE WHEN status IN ('current', 'next') THEN status END) STORED,
  PRIMARY KEY (tenant_id, kid),
  UNIQUE KEY signing_keys_active (tenant_id, active_status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE TABLE connections (
  tenant_id VARCHAR(64) NOT NULL,
  id VARCHAR(255) NOT NULL,
  name VARCHAR(255) NOT NULL,
  strategy VARCHAR(255) NOT NULL,
  enabled_clients LONGTEXT NOT NULL,
  disable_signup BOOLEAN NOT NULL,
  requires_username BOOLEAN NOT NULL,
  password_min_length INTEGER NOT NULL,
  password_character_classes INTEGER NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE KEY connections_name (tenant_id, name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE TABLE users (
  tenant_id VARCHAR(64) NOT NULL,
  user_id VARCHAR(255) NOT NULL,
  email TEXT NOT NULL,
  email_verified BOOLEAN NOT NULL,
  username TEXT NOT NULL,
  name TEXT NOT NULL,
  nickname TEXT NOT NULL,
  picture TEXT NOT NULL,
  given_name TEXT NOT NULL,
  family_name TEXT NOT NULL,
  user_metadata LONGTEXT NOT NULL,
  blocked BOOLEAN NOT NULL,
  identities LONGTEXT NOT NULL,
  last_login BIGINT NULL,
  logins_count INTEGER NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE TABLE user_logins (
  tenant_id VARCHAR(64) NOT NULL,
  connection VARCHAR(255) NOT NULL,
  kind VARCHAR(16) NOT NULL,
  value VARCHAR(255) NOT NULL,
  user_id VARCHAR(255) NOT NULL,
  PRIMARY KEY (tenant_id, connection, kind, value),
  KEY user_logins_user (tenant_id, user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE TABLE sessions (
  tenant_id VARCHAR(64) NOT NULL,
  id VARCHAR(255) NOT NULL,
  token_hash VARCHAR(255) NOT NULL,
  user_id VARCHAR(255) NOT NULL,
  connection VARCHAR(255) NOT NULL,
  authenticated_at BIGINT NOT NULL,
  client_ids LONGTEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  idle_expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE KEY sessions_token_hash (tenant_id, token_hash),
  KEY sessions_user (tenant_id, user_id),
  KEY sessions_expires (expires_at),
  KEY sessions_idle (idle_expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE TABLE auth_transactions (
  tenant_id VARCHAR(64) NOT NULL,
  id VARCHAR(255) NOT NULL,
  cookie_hash VARCHAR(255) NOT NULL,
  csrf_token VARCHAR(255) NOT NULL,
  client_id VARCHAR(255) NOT NULL,
  params LONGTEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  KEY auth_transactions_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE TABLE auth_codes (
  tenant_id VARCHAR(64) NOT NULL,
  code_hash VARCHAR(255) NOT NULL,
  client_id VARCHAR(255) NOT NULL,
  redirect_uri TEXT NOT NULL,
  user_id VARCHAR(255) NOT NULL,
  session_id VARCHAR(255) NOT NULL,
  scopes LONGTEXT NOT NULL,
  audience VARCHAR(255) NOT NULL,
  nonce TEXT NOT NULL,
  code_challenge VARCHAR(255) NOT NULL,
  code_challenge_method VARCHAR(255) NOT NULL,
  auth_time BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  used_at BIGINT NULL,
  replayed_at BIGINT NULL,
  PRIMARY KEY (tenant_id, code_hash),
  KEY auth_codes_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE TABLE refresh_tokens (
  tenant_id VARCHAR(64) NOT NULL,
  id VARCHAR(255) NOT NULL,
  token_hash VARCHAR(255) NOT NULL,
  family_id VARCHAR(255) NOT NULL,
  client_id VARCHAR(255) NOT NULL,
  user_id VARCHAR(255) NOT NULL,
  session_id VARCHAR(255) NOT NULL,
  scopes LONGTEXT NOT NULL,
  audience VARCHAR(255) NOT NULL,
  auth_time BIGINT NOT NULL,
  rotating BOOLEAN NOT NULL,
  expires_at BIGINT NOT NULL,
  idle_expires_at BIGINT NOT NULL,
  rotated_at BIGINT NULL,
  revoked_at BIGINT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE KEY refresh_tokens_token_hash (tenant_id, token_hash),
  KEY refresh_tokens_family (tenant_id, family_id),
  KEY refresh_tokens_user (tenant_id, user_id),
  KEY refresh_tokens_expires (expires_at),
  KEY refresh_tokens_idle (idle_expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE TABLE password_reset_tickets (
  tenant_id VARCHAR(64) NOT NULL,
  id VARCHAR(255) NOT NULL,
  token_hash VARCHAR(255) NOT NULL,
  user_id VARCHAR(255) NOT NULL,
  connection VARCHAR(255) NOT NULL,
  client_id VARCHAR(255) NOT NULL,
  lang VARCHAR(255) NOT NULL,
  expires_at BIGINT NOT NULL,
  used_at BIGINT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE KEY password_reset_tickets_token_hash (tenant_id, token_hash),
  KEY password_reset_tickets_user (tenant_id, user_id),
  KEY password_reset_tickets_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
