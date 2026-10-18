-- Management API (Plan 15): database connection settings. password_options
-- (JSON) replaces the two password policy columns; brute_force_protection,
-- the username limits (0 = not set), origin (who created the connection:
-- 'api' for the Management API, which the seed never touches, '' otherwise)
-- and extra (the options zeroauthy stores without interpreting) are new.
-- password_history keeps the newest password hashes of a user, by seq.
ALTER TABLE connections
  ADD COLUMN password_options LONGTEXT NOT NULL DEFAULT ('null'),
  ADD COLUMN brute_force_protection BOOLEAN NOT NULL DEFAULT TRUE,
  ADD COLUMN username_min INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN username_max INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN origin VARCHAR(16) NOT NULL DEFAULT '',
  ADD COLUMN extra LONGTEXT NOT NULL DEFAULT ('null');
-- Existing rows: the old minimum length and class count become the complexity
-- half of password_options, as store.LegacyComplexity maps them: 4 classes are
-- all four character types, 3 are three of the four, 1 and 2 keep their count
-- in min_character_classes. The login throttle is on for them, as it was.
UPDATE connections SET password_options = CONCAT('{"complexity":{"min_length":', CAST(password_min_length AS CHAR), ',"character_types":["uppercase","lowercase","number","special"],"character_type_rule":"all"}}') WHERE password_character_classes >= 4;
UPDATE connections SET password_options = CONCAT('{"complexity":{"min_length":', CAST(password_min_length AS CHAR), ',"character_types":["uppercase","lowercase","number","special"],"character_type_rule":"three_of_four"}}') WHERE password_character_classes = 3;
UPDATE connections SET password_options = CONCAT('{"complexity":{"min_length":', CAST(password_min_length AS CHAR), ',"min_character_classes":', CAST(password_character_classes AS CHAR), '}}') WHERE password_character_classes IN (1, 2);
UPDATE connections SET password_options = CONCAT('{"complexity":{"min_length":', CAST(password_min_length AS CHAR), '}}') WHERE password_character_classes < 1;
ALTER TABLE connections
  DROP COLUMN password_min_length,
  DROP COLUMN password_character_classes;
CREATE TABLE password_history (
  tenant_id VARCHAR(64) NOT NULL,
  user_id VARCHAR(255) NOT NULL,
  seq BIGINT NOT NULL,
  hash VARBINARY(1024) NOT NULL,
  PRIMARY KEY (tenant_id, user_id, seq)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
