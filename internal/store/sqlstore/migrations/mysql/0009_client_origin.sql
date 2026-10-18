-- Management API applications (Plan 13): origin records who created a
-- client; 'api' for the Management API, which the seed never touches, and
-- '' for the seed or zeroauthy itself.
ALTER TABLE clients ADD COLUMN origin VARCHAR(16) NOT NULL DEFAULT '';
