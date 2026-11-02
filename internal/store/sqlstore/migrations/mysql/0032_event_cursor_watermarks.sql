-- Historical purges before this migration cannot be inferred from global
-- sequence gaps. Start unknown history at zero; record every future removal.
CREATE TABLE event_cursor_watermarks (
 tenant_id VARCHAR(255) PRIMARY KEY,
 purged_seq BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
