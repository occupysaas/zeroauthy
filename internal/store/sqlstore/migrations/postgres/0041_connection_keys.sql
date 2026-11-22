CREATE TABLE connection_keys (
 tenant_id VARCHAR(255) NOT NULL,
 connection_id VARCHAR(255) NOT NULL,
 kid VARCHAR(255) NOT NULL,
 key_use VARCHAR(16) NOT NULL,
 alg VARCHAR(32) NOT NULL,
 state VARCHAR(16) NOT NULL,
 cert_der BYTEA NOT NULL,
 private_sealed BYTEA NOT NULL,
 current_since BIGINT NULL,
 created_at BIGINT NOT NULL,
 PRIMARY KEY (tenant_id,connection_id,kid),
 UNIQUE (tenant_id,connection_id,key_use,state),
 FOREIGN KEY (tenant_id,connection_id) REFERENCES connections(tenant_id,id) ON DELETE CASCADE
);
