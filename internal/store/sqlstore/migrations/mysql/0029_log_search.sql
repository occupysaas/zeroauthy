-- ASCII hex projection; LONGTEXT accommodates large searchable string values.
-- The Go migration runner makes this implicit-commit DDL resumable.
ALTER TABLE tenant_logs ADD COLUMN searchable_body LONGTEXT NOT NULL DEFAULT ('{}');
