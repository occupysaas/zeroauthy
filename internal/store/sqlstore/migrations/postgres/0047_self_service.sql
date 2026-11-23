CREATE TABLE self_service_profiles (tenant_id TEXT NOT NULL, id TEXT NOT NULL, name TEXT NOT NULL, doc TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (tenant_id,id));
CREATE UNIQUE INDEX self_service_profiles_name ON self_service_profiles (tenant_id,name);
CREATE TABLE self_service_custom_texts (tenant_id TEXT NOT NULL, profile_id TEXT NOT NULL, language TEXT NOT NULL, page TEXT NOT NULL, doc TEXT NOT NULL, PRIMARY KEY (tenant_id,profile_id,language,page));
CREATE TABLE sso_tickets (tenant_id TEXT NOT NULL, id TEXT NOT NULL, profile_id TEXT NOT NULL, token_hash TEXT NOT NULL, doc TEXT NOT NULL, created_at BIGINT NOT NULL, expires_at BIGINT NOT NULL, revoked_at BIGINT NULL, used_at BIGINT NULL, PRIMARY KEY (tenant_id,id));
CREATE UNIQUE INDEX sso_tickets_hash ON sso_tickets (tenant_id,token_hash);
CREATE INDEX sso_tickets_profile ON sso_tickets (tenant_id,profile_id);
CREATE TABLE connection_profiles (tenant_id TEXT NOT NULL, id TEXT NOT NULL, name TEXT NOT NULL, doc TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (tenant_id,id));
CREATE UNIQUE INDEX connection_profiles_name ON connection_profiles (tenant_id,name);
