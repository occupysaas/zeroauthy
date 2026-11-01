-- Execution listing uses stable keyset ordering and immutable Action IDs.
CREATE INDEX action_executions_order ON action_executions (tenant_id,created_at,id);
CREATE INDEX action_executions_trigger_order ON action_executions (tenant_id,trigger_id,created_at,id);
CREATE TABLE action_execution_actions (tenant_id VARCHAR(64) NOT NULL, execution_id VARBINARY(255) NOT NULL, action_id VARBINARY(255) NOT NULL, PRIMARY KEY (tenant_id,action_id,execution_id), FOREIGN KEY (tenant_id,execution_id) REFERENCES action_executions(tenant_id,id) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
