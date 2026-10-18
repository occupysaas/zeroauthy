-- Management API (Plan 14): origin records who created a resource server or
-- a client grant ('api' for the Management API, which the seed never
-- touches, '' for the seed or zeroauthy itself); indexes serve the
-- audience and subject_type filters of the client grant list. The client_id
-- filter uses the unique key (tenant_id, client_id, audience, subject_type).
ALTER TABLE resource_servers ADD COLUMN origin TEXT NOT NULL DEFAULT '';
ALTER TABLE client_grants ADD COLUMN origin TEXT NOT NULL DEFAULT '';
CREATE INDEX client_grants_audience ON client_grants (tenant_id, audience);
CREATE INDEX client_grants_subject_type ON client_grants (tenant_id, subject_type);
