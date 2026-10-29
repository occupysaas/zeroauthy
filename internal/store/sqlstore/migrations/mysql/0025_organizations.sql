-- Organizations (Plan 29). Tenant-inclusive keys; dependent rows are removed
-- by the stores in the caller's transaction, not by foreign keys, like RBAC.
CREATE TABLE organizations (tenant_id VARCHAR(64) NOT NULL, id VARBINARY(255) NOT NULL, name VARBINARY(512) NOT NULL, display_name LONGTEXT NOT NULL, branding LONGTEXT NULL, metadata LONGTEXT NULL, third_party_client_access VARCHAR(16) NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,name)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE TABLE organization_connections (tenant_id VARCHAR(64) NOT NULL, organization_id VARBINARY(255) NOT NULL, connection_id VARBINARY(255) NOT NULL, assign_membership_on_login BOOLEAN NOT NULL, show_as_button BOOLEAN NOT NULL, is_signup_enabled BOOLEAN NOT NULL, PRIMARY KEY (tenant_id,organization_id,connection_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE INDEX organization_connections_by_connection ON organization_connections (tenant_id,connection_id,organization_id);
CREATE TABLE organization_members (tenant_id VARCHAR(64) NOT NULL, organization_id VARBINARY(255) NOT NULL, user_id VARBINARY(1280) NOT NULL, PRIMARY KEY (tenant_id,organization_id,user_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE INDEX organization_members_by_user ON organization_members (tenant_id,user_id,organization_id);
CREATE TABLE organization_member_roles (tenant_id VARCHAR(64) NOT NULL, organization_id VARBINARY(255) NOT NULL, user_id VARBINARY(1280) NOT NULL, role_id VARBINARY(255) NOT NULL, PRIMARY KEY (tenant_id,organization_id,user_id,role_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE INDEX organization_member_roles_by_role ON organization_member_roles (tenant_id,role_id,organization_id,user_id);
CREATE INDEX organization_member_roles_by_user ON organization_member_roles (tenant_id,user_id,organization_id);
-- The organization an authorization or refresh family was bound to; empty
-- for non-organization tokens.
ALTER TABLE auth_codes ADD COLUMN organization_id VARBINARY(255) NOT NULL DEFAULT '';
ALTER TABLE refresh_tokens ADD COLUMN organization_id VARBINARY(255) NOT NULL DEFAULT '';
