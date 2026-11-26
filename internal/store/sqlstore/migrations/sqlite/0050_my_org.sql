CREATE TABLE my_org_client_configs (tenant_id VARCHAR(255) NOT NULL, client_id VARCHAR(255) NOT NULL, doc TEXT NOT NULL, PRIMARY KEY (tenant_id,client_id));
CREATE TABLE my_org_visible_roles (tenant_id VARCHAR(255) NOT NULL, role_id VARCHAR(255) NOT NULL, PRIMARY KEY (tenant_id,role_id));
