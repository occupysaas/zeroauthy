ALTER TABLE users ADD COLUMN phone_normalized VARCHAR(64) NULL;
CREATE INDEX users_phone_normalized ON users (tenant_id,phone_normalized);
CREATE TABLE phone_providers (tenant_id VARCHAR(255) NOT NULL, id VARCHAR(255) NOT NULL, name VARCHAR(64) NOT NULL, disabled BOOLEAN NOT NULL, configuration TEXT NOT NULL, sealed_credentials BLOB NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id));
CREATE TABLE phone_templates (tenant_id VARCHAR(255) NOT NULL, id VARCHAR(255) NOT NULL, type VARCHAR(64) NOT NULL, disabled BOOLEAN NOT NULL, content TEXT NOT NULL, customizable BOOLEAN NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,type));
CREATE TABLE passwordless_codes (tenant_id VARCHAR(255) NOT NULL, connection_id VARCHAR(255) NOT NULL, identifier VARCHAR(255) NOT NULL, kind VARCHAR(16) NOT NULL, client_id VARCHAR(255) NOT NULL, code_hash VARCHAR(255) NOT NULL, request TEXT NOT NULL, attempts BIGINT NOT NULL, expires_at BIGINT NOT NULL, created_at BIGINT NOT NULL, PRIMARY KEY (tenant_id,connection_id,identifier,kind));
CREATE INDEX passwordless_codes_hash ON passwordless_codes (tenant_id,code_hash);
CREATE INDEX passwordless_codes_expiry ON passwordless_codes (expires_at);
