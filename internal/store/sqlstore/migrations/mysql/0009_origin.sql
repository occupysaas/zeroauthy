-- Management API (Plan 13): origin records who created a client or a
-- tenant; 'api' for the Management or system API, which the seed never
-- touches, and '' for the seed or zeroauthy itself.
ALTER TABLE clients ADD COLUMN origin VARCHAR(16) NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN origin VARCHAR(16) NOT NULL DEFAULT '';
