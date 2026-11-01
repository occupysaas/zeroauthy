-- Immutable outbox sequences are allocated under the tenant lock through commit.
-- Fixed-width UTC times retain nanoseconds and preserve chronological comparison.
CREATE TABLE tenant_events (
 seq BIGINT AUTO_INCREMENT PRIMARY KEY, tenant_id VARCHAR(255) NOT NULL,
 event_id VARCHAR(255) NOT NULL, type VARCHAR(255) NOT NULL,
 event_time VARCHAR(30) NOT NULL, committed_at VARCHAR(30) NOT NULL,
 body LONGBLOB NOT NULL, UNIQUE (tenant_id,event_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE INDEX tenant_events_seq ON tenant_events (tenant_id,seq);
CREATE INDEX tenant_events_type_seq ON tenant_events (tenant_id,type,seq);
CREATE INDEX tenant_events_time ON tenant_events (tenant_id,event_time);
CREATE INDEX tenant_events_purge ON tenant_events (event_time,seq);
CREATE TABLE event_streams (
 tenant_id VARCHAR(255) NOT NULL, id VARCHAR(255) NOT NULL,
 name VARCHAR(255) NOT NULL, status VARCHAR(32) NOT NULL, config LONGTEXT NOT NULL,
 checkpoint BIGINT NOT NULL, lease_owner VARCHAR(255) NOT NULL,
 lease_until VARCHAR(30) NOT NULL, consecutive_failures INTEGER NOT NULL,
 total_failures INTEGER NOT NULL, version INTEGER NOT NULL,
 created_at VARCHAR(30) NOT NULL, updated_at VARCHAR(30) NOT NULL,
 PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE INDEX event_streams_lease ON event_streams (lease_until);
CREATE TABLE event_deliveries (
 tenant_id VARCHAR(255) NOT NULL, stream_id VARCHAR(255) NOT NULL,
 event_id VARCHAR(255) NOT NULL, type VARCHAR(255) NOT NULL,
 status VARCHAR(32) NOT NULL, attempts LONGTEXT NOT NULL, queued BOOLEAN NOT NULL,
 event_time VARCHAR(30) NOT NULL, updated_at VARCHAR(30) NOT NULL,
 PRIMARY KEY (tenant_id,stream_id,event_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE INDEX event_deliveries_time ON event_deliveries (tenant_id,stream_id,event_time);
CREATE INDEX event_deliveries_queue ON event_deliveries (queued,tenant_id,stream_id);
CREATE INDEX event_deliveries_event ON event_deliveries (tenant_id,event_id);
