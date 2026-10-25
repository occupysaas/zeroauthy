CREATE TABLE email_provider_revisions (tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE, revision BIGINT NOT NULL);
CREATE TABLE email_providers (tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE, name TEXT NOT NULL, enabled BOOLEAN NOT NULL, default_from TEXT NOT NULL, public_config TEXT NOT NULL, sealed_credentials BYTEA NOT NULL, revision BIGINT NOT NULL);
CREATE TABLE email_templates (tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, name TEXT NOT NULL, fields TEXT NOT NULL, revision BIGINT NOT NULL, PRIMARY KEY (tenant_id, name));
CREATE TABLE email_notifications (tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, subject_id TEXT NOT NULL, purpose TEXT NOT NULL, event_key TEXT NOT NULL, count INTEGER NOT NULL, expires_at BIGINT NULL, PRIMARY KEY (tenant_id, subject_id, purpose, event_key));
CREATE INDEX email_notifications_expiry ON email_notifications (expires_at);
