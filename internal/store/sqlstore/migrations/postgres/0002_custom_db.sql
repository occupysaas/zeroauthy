-- Custom database connections and users' app_metadata. Defaults make existing
-- rows plain connections and nil metadata.
ALTER TABLE connections ADD COLUMN enabled_database_customization BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE connections ADD COLUMN import_mode BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE connections ADD COLUMN custom_scripts TEXT NOT NULL DEFAULT 'null';
ALTER TABLE connections ADD COLUMN configuration_sealed BYTEA NULL;
ALTER TABLE connections ADD COLUMN set_user_root_attributes TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN app_metadata TEXT NOT NULL DEFAULT 'null';
