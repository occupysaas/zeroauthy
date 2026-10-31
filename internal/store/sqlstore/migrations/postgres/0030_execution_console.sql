-- Execution listing uses stable keyset ordering and immutable Action IDs.
CREATE INDEX action_executions_order ON action_executions (tenant_id,created_at,id COLLATE "C");
CREATE INDEX action_executions_trigger_order ON action_executions (tenant_id,trigger_id,created_at,id COLLATE "C");
CREATE TABLE action_execution_actions (tenant_id TEXT NOT NULL, execution_id TEXT NOT NULL, action_id TEXT NOT NULL, PRIMARY KEY (tenant_id,action_id,execution_id), FOREIGN KEY (tenant_id,execution_id) REFERENCES action_executions(tenant_id,id) ON DELETE CASCADE);
