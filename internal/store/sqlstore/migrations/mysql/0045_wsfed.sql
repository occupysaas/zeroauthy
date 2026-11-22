ALTER TABLE clients ADD COLUMN client_aliases LONGTEXT NULL;
ALTER TABLE clients ADD COLUMN form_template LONGTEXT NULL;
CREATE TABLE client_aliases (tenant_id VARCHAR(255) NOT NULL, alias_hash VARCHAR(64) NOT NULL, alias TEXT NOT NULL, client_id VARCHAR(255) NOT NULL, PRIMARY KEY (tenant_id,alias_hash)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE INDEX client_aliases_client ON client_aliases (tenant_id, client_id);
