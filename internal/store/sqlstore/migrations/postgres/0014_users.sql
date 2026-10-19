-- Management API (Plan 17): user fields. phone_number and phone_verified are
-- profile fields, last_ip is set by each login, and version is maintained by
-- the store: it moves when a password, the email or the blocked flag changes,
-- so tokens issued before can be told apart.
ALTER TABLE users ADD COLUMN phone_number TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN phone_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN last_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN version BIGINT NOT NULL DEFAULT 0;
