ALTER TABLE auth_codes ADD COLUMN mfa_at BIGINT NULL;
CREATE INDEX mfa_authenticators_pending ON mfa_authenticators (confirmed,created_at);
