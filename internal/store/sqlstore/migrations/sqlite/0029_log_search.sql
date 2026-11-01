-- Search only Go-decoded inventory strings encoded as ASCII hex JSON.
-- The bounded Go backfill preserves original log bodies, including JSON values
-- outside database JSON Unicode/numeric limits.
ALTER TABLE tenant_logs ADD COLUMN searchable_body TEXT NOT NULL DEFAULT '{}';
