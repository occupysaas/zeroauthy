-- Management API jobs (Plan 18): user import and export. A worker claims a
-- job with a lease (lease_owner, lease_until) and renews it while it works;
-- a job whose lease runs out is claimed again once. input is the import
-- file until the job ends; the export file is kept in job_files, in chunks,
-- and the failed records of an import in job_errors. params and the error
-- columns hold JSON.
CREATE TABLE jobs (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  type TEXT NOT NULL,
  status TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  connection TEXT NOT NULL,
  external_id TEXT NOT NULL,
  params TEXT NOT NULL,
  input BLOB NULL,
  progress BIGINT NOT NULL,
  summary_failed BIGINT NOT NULL,
  summary_updated BIGINT NOT NULL,
  summary_inserted BIGINT NOT NULL,
  summary_total BIGINT NOT NULL,
  status_details TEXT NOT NULL,
  attempts BIGINT NOT NULL,
  lease_owner TEXT NOT NULL,
  lease_until BIGINT NOT NULL,
  first_claimed_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  file_size BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
CREATE TABLE job_errors (
  tenant_id TEXT NOT NULL,
  job_id TEXT NOT NULL,
  idx BIGINT NOT NULL,
  user_data TEXT NOT NULL,
  errors TEXT NOT NULL,
  PRIMARY KEY (tenant_id, job_id, idx)
);
CREATE TABLE job_files (
  tenant_id TEXT NOT NULL,
  job_id TEXT NOT NULL,
  seq BIGINT NOT NULL,
  data BLOB NOT NULL,
  PRIMARY KEY (tenant_id, job_id, seq)
);
CREATE INDEX jobs_claim ON jobs (status, created_at);
CREATE INDEX jobs_list ON jobs (tenant_id, created_at);
CREATE INDEX jobs_expires ON jobs (expires_at);
