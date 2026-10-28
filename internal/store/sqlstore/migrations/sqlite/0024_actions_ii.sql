-- Module names remain reusable after deletion. A hidden module retains only
-- versions pinned by immutable Action versions or queued jobs.
CREATE TABLE action_modules (tenant_id TEXT NOT NULL, id TEXT NOT NULL, name TEXT NOT NULL, live_name TEXT NULL, code TEXT NOT NULL, dependencies TEXT NOT NULL, secrets TEXT NOT NULL, draft_build_id TEXT NOT NULL, latest_version_number INTEGER NOT NULL, all_changes_published BOOLEAN NOT NULL, deleted BOOLEAN NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,live_name), FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE);
CREATE TABLE action_module_versions (tenant_id TEXT NOT NULL, id TEXT NOT NULL, module_id TEXT NOT NULL, number INTEGER NOT NULL, code TEXT NOT NULL, build_id TEXT NOT NULL, dependencies TEXT NOT NULL, secrets TEXT NOT NULL, created_at BIGINT NOT NULL, PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,module_id,number), FOREIGN KEY (tenant_id,module_id) REFERENCES action_modules(tenant_id,id) ON DELETE CASCADE);
-- JSON arrays store complete resolved ID/name/number pins in the same snapshot
-- as each Action; existing drafts and versions acquire an empty array.
ALTER TABLE actions ADD COLUMN modules TEXT NOT NULL DEFAULT '[]';
ALTER TABLE action_versions ADD COLUMN modules TEXT NOT NULL DEFAULT '[]';
CREATE TABLE action_jobs (tenant_id TEXT NOT NULL, id TEXT NOT NULL, trigger_id VARCHAR(64) NOT NULL, status VARCHAR(16) NOT NULL, sealed BLOB NOT NULL, attempts INTEGER NOT NULL, next_at BIGINT NOT NULL, lease_until BIGINT NOT NULL, execution_ids TEXT NOT NULL, module_version_ids TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (tenant_id,id), FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE);
CREATE INDEX action_jobs_due ON action_jobs (status,next_at,created_at,tenant_id,id);
CREATE INDEX action_jobs_by_tenant_status ON action_jobs (tenant_id,status);
ALTER TABLE password_reset_tickets ADD COLUMN challenge_passed_at BIGINT NULL;
ALTER TABLE password_reset_tickets ADD COLUMN challenge_result_url TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN last_password_reset BIGINT NULL;
