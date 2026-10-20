-- Management API (Plan 17): user fields. phone_number and phone_verified are
-- profile fields, last_ip is set by each login, and version is maintained by
-- the store: it moves when a password, the email or the blocked flag changes,
-- so tokens issued before can be told apart.
ALTER TABLE users ADD COLUMN phone_number TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN phone_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN last_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN version BIGINT NOT NULL DEFAULT 0;

-- FindByEmail looks users up by (tenant, email), and the default user list
-- orders a tenant's users by last_login.
CREATE INDEX users_email ON users (tenant_id, email);
CREATE INDEX users_last_login ON users (tenant_id, last_login);
-- Sessions record when and from where they were last used (the Management
-- API lists them). Sessions that exist take their creation time.
ALTER TABLE sessions ADD COLUMN updated_at BIGINT NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN last_interacted_at BIGINT NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN initial_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN initial_user_agent TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN last_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN last_user_agent TEXT NOT NULL DEFAULT '';
UPDATE sessions SET updated_at = created_at, last_interacted_at = created_at;

-- Password reset tickets can carry a result URL, and verify the email.
ALTER TABLE password_reset_tickets ADD COLUMN result_url TEXT NOT NULL DEFAULT '';
ALTER TABLE password_reset_tickets ADD COLUMN include_email_in_redirect BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE password_reset_tickets ADD COLUMN mark_email_verified BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE email_verification_tickets (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  user_id TEXT NOT NULL,
  connection TEXT NOT NULL,
  client_id TEXT NOT NULL,
  result_url TEXT NOT NULL,
  include_email_in_redirect BOOLEAN NOT NULL,
  email TEXT NOT NULL,
  lang TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  used_at BIGINT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, token_hash)
);
CREATE INDEX email_verification_tickets_user ON email_verification_tickets (tenant_id, user_id);
CREATE INDEX email_verification_tickets_expires ON email_verification_tickets (expires_at);
