ALTER TABLE clients ADD COLUMN client_aliases TEXT NULL;
ALTER TABLE clients ADD COLUMN form_template TEXT NULL;
CREATE TABLE client_aliases (tenant_id VARCHAR(255) NOT NULL, alias_hash VARCHAR(64) NOT NULL, alias TEXT NOT NULL, client_id VARCHAR(255) NOT NULL, PRIMARY KEY (tenant_id,alias_hash));
CREATE INDEX client_aliases_client ON client_aliases (tenant_id, client_id);
