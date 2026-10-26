CREATE TABLE hosted_login_configs (tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE, revision BIGINT NOT NULL, config TEXT NOT NULL);
ALTER TABLE auth_transactions ADD COLUMN hosted_state TEXT NOT NULL DEFAULT '{}';
ALTER TABLE auth_transactions ADD COLUMN hosted_revision BIGINT NOT NULL DEFAULT 0;
