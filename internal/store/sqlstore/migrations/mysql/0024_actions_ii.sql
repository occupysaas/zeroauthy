-- Module names remain reusable after deletion. A hidden module retains only
-- versions pinned by immutable Action versions or queued jobs.
CREATE TABLE action_modules (tenant_id VARCHAR(64) NOT NULL, id VARBINARY(255) NOT NULL, name VARBINARY(1020) NOT NULL, live_name VARBINARY(1020) NULL, code LONGTEXT NOT NULL, dependencies LONGTEXT NOT NULL, secrets LONGTEXT NOT NULL, draft_build_id VARBINARY(255) NOT NULL, latest_version_number INTEGER NOT NULL, all_changes_published BOOLEAN NOT NULL, deleted BOOLEAN NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,live_name), FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE TABLE action_module_versions (tenant_id VARCHAR(64) NOT NULL, id VARBINARY(255) NOT NULL, module_id VARBINARY(255) NOT NULL, number INTEGER NOT NULL, code LONGTEXT NOT NULL, build_id VARBINARY(255) NOT NULL, dependencies LONGTEXT NOT NULL, secrets LONGTEXT NOT NULL, created_at BIGINT NOT NULL, PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,module_id,number), FOREIGN KEY (tenant_id,module_id) REFERENCES action_modules(tenant_id,id) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
-- JSON arrays store complete resolved ID/name/number pins in the same snapshot
-- as each Action; existing drafts and versions acquire an empty array.
ALTER TABLE actions ADD COLUMN modules LONGTEXT NOT NULL DEFAULT ('[]');
ALTER TABLE action_versions ADD COLUMN modules LONGTEXT NOT NULL DEFAULT ('[]');
CREATE TABLE action_jobs (tenant_id VARCHAR(64) NOT NULL, id VARBINARY(255) NOT NULL, trigger_id VARCHAR(64) NOT NULL, status VARCHAR(16) NOT NULL, sealed LONGBLOB NOT NULL, attempts INTEGER NOT NULL, next_at BIGINT NOT NULL, lease_until BIGINT NOT NULL, execution_ids LONGTEXT NOT NULL, module_version_ids LONGTEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (tenant_id,id), FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE INDEX action_jobs_due ON action_jobs (status,next_at,created_at,tenant_id,id);
CREATE INDEX action_jobs_by_tenant_status ON action_jobs (tenant_id,status);
ALTER TABLE password_reset_tickets ADD COLUMN challenge_passed_at BIGINT NULL;
ALTER TABLE password_reset_tickets ADD COLUMN challenge_result_url LONGTEXT NOT NULL DEFAULT ('');
ALTER TABLE users ADD COLUMN last_password_reset BIGINT NULL;
