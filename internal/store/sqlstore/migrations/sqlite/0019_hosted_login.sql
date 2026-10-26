CREATE TABLE hosted_login_configs (tenant_id TEXT PRIMARY KEY, revision BIGINT NOT NULL, config TEXT NOT NULL, FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE);
ALTER TABLE auth_transactions ADD COLUMN hosted_state TEXT NOT NULL DEFAULT '{}';
ALTER TABLE auth_transactions ADD COLUMN hosted_revision BIGINT NOT NULL DEFAULT 0;
