-- Management API jobs (Plan 18): user import and export. A worker claims a
-- job with a lease (lease_owner, lease_until) and renews it while it works;
-- a job whose lease runs out is claimed again once. input is the import
-- file until the job ends; the export file is kept in job_files, in chunks,
-- and the failed records of an import in job_errors. params and the error
-- columns hold JSON.
CREATE TABLE jobs (
  tenant_id VARCHAR(64) NOT NULL,
  id VARCHAR(255) NOT NULL,
  type VARCHAR(64) NOT NULL,
  status VARCHAR(16) NOT NULL,
  connection_id VARCHAR(255) NOT NULL,
  connection VARCHAR(255) NOT NULL,
  external_id VARCHAR(255) NOT NULL,
  params LONGTEXT NOT NULL,
  input LONGBLOB NULL,
  progress BIGINT NOT NULL,
  summary_failed BIGINT NOT NULL,
  summary_updated BIGINT NOT NULL,
  summary_inserted BIGINT NOT NULL,
  summary_total BIGINT NOT NULL,
  status_details LONGTEXT NOT NULL,
  attempts BIGINT NOT NULL,
  lease_owner VARCHAR(255) NOT NULL,
  lease_until BIGINT NOT NULL,
  first_claimed_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  file_size BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id),
  KEY jobs_claim (status, created_at),
  KEY jobs_list (tenant_id, created_at),
  KEY jobs_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE TABLE job_errors (
  tenant_id VARCHAR(64) NOT NULL,
  job_id VARCHAR(255) NOT NULL,
  idx BIGINT NOT NULL,
  user_data LONGTEXT NOT NULL,
  errors LONGTEXT NOT NULL,
  PRIMARY KEY (tenant_id, job_id, idx)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
CREATE TABLE job_files (
  tenant_id VARCHAR(64) NOT NULL,
  job_id VARCHAR(255) NOT NULL,
  seq BIGINT NOT NULL,
  data LONGBLOB NOT NULL,
  PRIMARY KEY (tenant_id, job_id, seq)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin;
