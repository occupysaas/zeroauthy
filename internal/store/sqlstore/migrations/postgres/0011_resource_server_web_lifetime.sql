-- Management API (Plan 14): the lifetime Auth0 gives tokens of implicit and
-- hybrid flows; zeroauthy stores and reports it (0 = the default).
ALTER TABLE resource_servers ADD COLUMN token_lifetime_for_web INTEGER NOT NULL DEFAULT 0;
