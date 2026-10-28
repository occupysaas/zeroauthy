CREATE TABLE actions (tenant_id TEXT NOT NULL, id TEXT NOT NULL, name TEXT NOT NULL, trigger_id VARCHAR(64) NOT NULL, runtime VARCHAR(32) NOT NULL, code TEXT NOT NULL, dependencies TEXT NOT NULL, secrets TEXT NOT NULL, draft_build_id TEXT NOT NULL, deployed_version_id TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,name), FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE);
CREATE INDEX actions_by_trigger ON actions (tenant_id,trigger_id,created_at,id);
CREATE TABLE action_versions (tenant_id TEXT NOT NULL, id TEXT NOT NULL, action_id TEXT NOT NULL, number INTEGER NOT NULL, code TEXT NOT NULL, runtime VARCHAR(32) NOT NULL, build_id TEXT NOT NULL, dependencies TEXT NOT NULL, secrets TEXT NOT NULL, created_at BIGINT NOT NULL, PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,action_id,number), FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE);
CREATE TABLE action_builds (tenant_id TEXT NOT NULL, id TEXT NOT NULL, status VARCHAR(16) NOT NULL, requested TEXT NOT NULL, resolved TEXT NOT NULL, errors TEXT NOT NULL, artifact_sha256 VARCHAR(128) NOT NULL, built_at BIGINT NOT NULL, PRIMARY KEY (tenant_id,id), FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE);
CREATE TABLE action_artifacts (tenant_id TEXT NOT NULL, build_id TEXT NOT NULL, data BLOB NOT NULL, PRIMARY KEY (tenant_id,build_id), FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE);
CREATE TABLE action_bindings (tenant_id TEXT NOT NULL, trigger_id VARCHAR(64) NOT NULL, position INTEGER NOT NULL, id TEXT NOT NULL, action_id TEXT NOT NULL, display_name TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (tenant_id,trigger_id,position), FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE);
CREATE INDEX action_bindings_by_action ON action_bindings (tenant_id,action_id);
CREATE TABLE action_executions (tenant_id TEXT NOT NULL, id TEXT NOT NULL, trigger_id VARCHAR(64) NOT NULL, status VARCHAR(32) NOT NULL, results TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (tenant_id,id), FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE);
CREATE INDEX action_executions_by_created ON action_executions (created_at);
CREATE TABLE action_continues (tenant_id TEXT NOT NULL, state_hash TEXT NOT NULL, session_id TEXT NOT NULL, sealed BLOB NOT NULL, expires_at BIGINT NOT NULL, created_at BIGINT NOT NULL, PRIMARY KEY (tenant_id,state_hash), FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE);
CREATE INDEX action_continues_by_expiry ON action_continues (expires_at);
ALTER TABLE auth_codes ADD COLUMN action_effects BLOB NULL;
ALTER TABLE device_codes ADD COLUMN action_effects BLOB NULL;

-- Initialization survives deliberately empty lists and Action deletion.
CREATE TABLE action_binding_sets (tenant_id TEXT NOT NULL, trigger_id VARCHAR(64) NOT NULL, PRIMARY KEY (tenant_id,trigger_id), FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE);
INSERT INTO action_binding_sets (tenant_id,trigger_id) SELECT DISTINCT tenant_id,trigger_id FROM action_bindings;
