-- Management API (Plan 15): database connection settings. password_options
-- (JSON) replaces the two password policy columns; brute_force_protection,
-- the username limits (0 = not set), origin (who created the connection:
-- 'api' for the Management API, which the seed never touches, '' otherwise)
-- and extra (the options zeroauthy stores without interpreting) are new.
-- password_history keeps the newest password hashes of a user, by seq.
ALTER TABLE connections ADD COLUMN password_options TEXT NOT NULL DEFAULT 'null';
ALTER TABLE connections ADD COLUMN brute_force_protection BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE connections ADD COLUMN username_min INTEGER NOT NULL DEFAULT 0;
ALTER TABLE connections ADD COLUMN username_max INTEGER NOT NULL DEFAULT 0;
ALTER TABLE connections ADD COLUMN origin TEXT NOT NULL DEFAULT '';
ALTER TABLE connections ADD COLUMN extra TEXT NOT NULL DEFAULT 'null';
-- Existing rows: the old minimum length and class count become the complexity
-- half of password_options, as store.LegacyComplexity maps them: 4 classes are
-- all four character types, 3 are three of the four, 1 and 2 keep their count
-- in min_character_classes. The login throttle is on for them, as it was.
UPDATE connections SET password_options = '{"complexity":{"min_length":' || CAST(password_min_length AS TEXT) || ',"character_types":["uppercase","lowercase","number","special"],"character_type_rule":"all"}}' WHERE password_character_classes >= 4;
UPDATE connections SET password_options = '{"complexity":{"min_length":' || CAST(password_min_length AS TEXT) || ',"character_types":["uppercase","lowercase","number","special"],"character_type_rule":"three_of_four"}}' WHERE password_character_classes = 3;
UPDATE connections SET password_options = '{"complexity":{"min_length":' || CAST(password_min_length AS TEXT) || ',"min_character_classes":' || CAST(password_character_classes AS TEXT) || '}}' WHERE password_character_classes IN (1, 2);
UPDATE connections SET password_options = '{"complexity":{"min_length":' || CAST(password_min_length AS TEXT) || '}}' WHERE password_character_classes < 1;
ALTER TABLE connections DROP COLUMN password_min_length;
ALTER TABLE connections DROP COLUMN password_character_classes;
CREATE TABLE password_history (
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  seq BIGINT NOT NULL,
  hash BYTEA NOT NULL,
  PRIMARY KEY (tenant_id, user_id, seq)
);
