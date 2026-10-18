-- Management API (Plan 14): a client grant may allow every scope its API
-- defines, now and later (Auth0's allow_all_scopes); scopes is then empty.
ALTER TABLE client_grants ADD COLUMN allow_all_scopes BOOLEAN NOT NULL DEFAULT FALSE;
