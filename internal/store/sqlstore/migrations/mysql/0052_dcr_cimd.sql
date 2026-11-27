ALTER TABLE clients ADD COLUMN external_metadata LONGTEXT NULL;
CREATE TABLE client_external_ids (tenant_id VARCHAR(255) NOT NULL, id_hash VARCHAR(64) NOT NULL, external_client_id TEXT NOT NULL, client_id VARCHAR(255) NOT NULL, PRIMARY KEY (tenant_id,id_hash)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE INDEX client_external_ids_client ON client_external_ids (tenant_id, client_id);
ALTER TABLE client_grants ADD COLUMN default_for VARCHAR(32) NOT NULL DEFAULT '';
