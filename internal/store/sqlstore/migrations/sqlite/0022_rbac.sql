ALTER TABLE resource_servers ADD COLUMN enforce_policies BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE resource_servers ADD COLUMN token_dialect TEXT NOT NULL DEFAULT '';
CREATE TABLE rbac_roles (tenant_id TEXT NOT NULL, id TEXT NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL, PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,name));
CREATE TABLE rbac_user_roles (tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, role_id TEXT NOT NULL, PRIMARY KEY (tenant_id,user_id,role_id));
CREATE INDEX rbac_role_users ON rbac_user_roles (tenant_id,role_id,user_id);
CREATE TABLE rbac_role_permissions (tenant_id TEXT NOT NULL, role_id TEXT NOT NULL, api_id TEXT NOT NULL, permission_name TEXT NOT NULL, PRIMARY KEY (tenant_id,role_id,api_id,permission_name));
CREATE INDEX rbac_role_api ON rbac_role_permissions (tenant_id,api_id);
CREATE TABLE rbac_user_permissions (tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, api_id TEXT NOT NULL, permission_name TEXT NOT NULL, PRIMARY KEY (tenant_id,user_id,api_id,permission_name));
CREATE INDEX rbac_user_api ON rbac_user_permissions (tenant_id,api_id);
