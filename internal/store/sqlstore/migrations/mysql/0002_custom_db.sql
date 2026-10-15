-- Custom database connections and users' app_metadata. Defaults make existing
-- rows plain connections and nil metadata. Expression defaults on TEXT
-- columns need MySQL 8.0.13+.
ALTER TABLE connections
  ADD COLUMN enabled_database_customization BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN import_mode BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN custom_scripts LONGTEXT NOT NULL DEFAULT ('null'),
  ADD COLUMN configuration_sealed LONGBLOB NULL,
  ADD COLUMN set_user_root_attributes VARCHAR(32) NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN app_metadata LONGTEXT NOT NULL DEFAULT ('null');
