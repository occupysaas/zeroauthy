-- Management API (Plan 17): user fields. phone_number and phone_verified are
-- profile fields, last_ip is set by each login, and version is maintained by
-- the store: it moves when a password, the email or the blocked flag changes,
-- so tokens issued before can be told apart.
ALTER TABLE users
  ADD COLUMN phone_number VARCHAR(255) NOT NULL DEFAULT '',
  ADD COLUMN phone_verified BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN last_ip VARCHAR(255) NOT NULL DEFAULT '',
  ADD COLUMN version BIGINT NOT NULL DEFAULT 0;

-- FindByEmail looks users up by (tenant, email), and the default user list
-- orders a tenant's users by last_login. email is TEXT, so the index
-- takes a prefix.
CREATE INDEX users_email ON users (tenant_id, email(255));
CREATE INDEX users_last_login ON users (tenant_id, last_login);

-- Sessions record when and from where they were last used (the Management
-- API lists them). Sessions that exist take their creation time.
ALTER TABLE sessions
  ADD COLUMN updated_at BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN last_interacted_at BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN initial_ip VARCHAR(255) NOT NULL DEFAULT '',
  ADD COLUMN initial_user_agent LONGTEXT NOT NULL,
  ADD COLUMN last_ip VARCHAR(255) NOT NULL DEFAULT '',
  ADD COLUMN last_user_agent LONGTEXT NOT NULL;
UPDATE sessions SET updated_at = created_at, last_interacted_at = created_at;

-- Password reset tickets can carry a result URL, and verify the email.
ALTER TABLE password_reset_tickets
  ADD COLUMN result_url LONGTEXT NOT NULL,
  ADD COLUMN include_email_in_redirect BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN mark_email_verified BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE email_verification_tickets (
  tenant_id VARCHAR(64) NOT NULL,
  id VARCHAR(255) NOT NULL,
  token_hash VARCHAR(255) NOT NULL,
  user_id VARCHAR(255) NOT NULL,
  connection VARCHAR(255) NOT NULL,
  client_id VARCHAR(255) NOT NULL,
  result_url LONGTEXT NOT NULL,
  include_email_in_redirect BOOLEAN NOT NULL,
  lang VARCHAR(255) NOT NULL,
  expires_at BIGINT NOT NULL,
  used_at BIGINT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE KEY email_verification_tickets_token_hash (tenant_id, token_hash),
  KEY email_verification_tickets_user (tenant_id, user_id),
  KEY email_verification_tickets_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
