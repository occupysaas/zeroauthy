-- Management API foundation (Plan 13): is_system marks an API zeroauthy
-- defines itself, such as each tenant's Management API.
ALTER TABLE resource_servers ADD COLUMN is_system BOOLEAN NOT NULL DEFAULT FALSE;
