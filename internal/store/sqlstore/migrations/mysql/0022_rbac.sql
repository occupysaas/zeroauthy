ALTER TABLE resource_servers ADD COLUMN enforce_policies BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE resource_servers ADD COLUMN token_dialect VARCHAR(32) NOT NULL DEFAULT '';
CREATE TABLE rbac_roles (tenant_id VARCHAR(64) NOT NULL, id VARBINARY(255) NOT NULL, name VARBINARY(512) NOT NULL, description TEXT NOT NULL, PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,name)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE TABLE rbac_user_roles (tenant_id VARCHAR(64) NOT NULL, user_id VARBINARY(1280) NOT NULL, role_id VARBINARY(255) NOT NULL, PRIMARY KEY (tenant_id,user_id,role_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE INDEX rbac_role_users ON rbac_user_roles (tenant_id,role_id,user_id);
CREATE TABLE rbac_role_permissions (tenant_id VARCHAR(64) NOT NULL, role_id VARBINARY(255) NOT NULL, api_id VARBINARY(255) NOT NULL, permission_name VARBINARY(1120) NOT NULL, PRIMARY KEY (tenant_id,role_id,api_id,permission_name)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE INDEX rbac_role_api ON rbac_role_permissions (tenant_id,api_id);
CREATE TABLE rbac_user_permissions (tenant_id VARCHAR(64) NOT NULL, user_id VARBINARY(1280) NOT NULL, api_id VARBINARY(255) NOT NULL, permission_name VARBINARY(1120) NOT NULL, PRIMARY KEY (tenant_id,user_id,api_id,permission_name)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE INDEX rbac_user_api ON rbac_user_permissions (tenant_id,api_id);
