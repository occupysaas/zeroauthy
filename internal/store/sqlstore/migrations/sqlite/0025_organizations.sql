-- Organizations (Plan 29). Tenant-inclusive keys; dependent rows are removed
-- by the stores in the caller's transaction, not by foreign keys, like RBAC.
CREATE TABLE organizations (tenant_id TEXT NOT NULL, id TEXT NOT NULL, name TEXT NOT NULL, display_name TEXT NOT NULL, branding TEXT NULL, metadata TEXT NULL, third_party_client_access TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,name));
CREATE TABLE organization_connections (tenant_id TEXT NOT NULL, organization_id TEXT NOT NULL, connection_id TEXT NOT NULL, assign_membership_on_login BOOLEAN NOT NULL, show_as_button BOOLEAN NOT NULL, is_signup_enabled BOOLEAN NOT NULL, PRIMARY KEY (tenant_id,organization_id,connection_id));
CREATE INDEX organization_connections_by_connection ON organization_connections (tenant_id,connection_id,organization_id);
CREATE TABLE organization_members (tenant_id TEXT NOT NULL, organization_id TEXT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY (tenant_id,organization_id,user_id));
CREATE INDEX organization_members_by_user ON organization_members (tenant_id,user_id,organization_id);
CREATE TABLE organization_member_roles (tenant_id TEXT NOT NULL, organization_id TEXT NOT NULL, user_id TEXT NOT NULL, role_id TEXT NOT NULL, PRIMARY KEY (tenant_id,organization_id,user_id,role_id));
CREATE INDEX organization_member_roles_by_role ON organization_member_roles (tenant_id,role_id,organization_id,user_id);
CREATE INDEX organization_member_roles_by_user ON organization_member_roles (tenant_id,user_id,organization_id);
-- The organization an authorization or refresh family was bound to; empty
-- for non-organization tokens.
ALTER TABLE auth_codes ADD COLUMN organization_id TEXT NOT NULL DEFAULT '';
ALTER TABLE refresh_tokens ADD COLUMN organization_id TEXT NOT NULL DEFAULT '';
-- Client organization settings (D-0055); empty or NULL while unset.
ALTER TABLE clients ADD COLUMN organization_usage TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN organization_require_behavior TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN organization_discovery_methods TEXT NULL;
