CREATE TABLE hosted_login_configs (tenant_id VARCHAR(64) NOT NULL, revision BIGINT NOT NULL, config LONGTEXT NOT NULL, PRIMARY KEY (tenant_id), FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
ALTER TABLE auth_transactions ADD COLUMN hosted_state LONGTEXT NULL;
ALTER TABLE auth_transactions ADD COLUMN hosted_revision BIGINT NOT NULL DEFAULT 0;
