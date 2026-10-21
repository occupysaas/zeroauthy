package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type jobs struct{ s *Store }

func (s *Store) Jobs() store.Jobs { return jobs{s} }

const jobCols = `tenant_id, id, type, status, connection_id, connection, external_id, params, input, progress,
 summary_failed, summary_updated, summary_inserted, summary_total, status_details, attempts, lease_owner,
 lease_until, first_claimed_at, created_at, updated_at, expires_at, file_size`

// jobListCols is jobCols without the import file, which List leaves out.
const jobListCols = `tenant_id, id, type, status, connection_id, connection, external_id, params, NULL, progress,
 summary_failed, summary_updated, summary_inserted, summary_total, status_details, attempts, lease_owner,
 lease_until, first_claimed_at, created_at, updated_at, expires_at, file_size`

// claimable is the WHERE condition of a job a worker may take: pending and
// not expired, or processing with a lapsed lease and an attempt left. It
// takes (now, now, JobMaxAttempts).
const claimable = `((status = 'pending' AND expires_at >= ?) OR (status = 'processing' AND lease_until < ? AND attempts < ?))`

func (r jobs) Create(ctx context.Context, j *store.Job) error {
	params, err := toJSON(j.Params)
	if err != nil {
		return err
	}
	var input any // NULL when there is no file
	if len(j.Input) > 0 {
		input = j.Input
	}
	_, err = r.s.write(ctx, nil, `INSERT INTO jobs (`+jobCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		j.TenantID, j.ID, string(j.Type), string(j.Status), j.ConnectionID, j.Connection, j.ExternalID, params, input,
		j.Progress, j.Summary.Failed, j.Summary.Updated, j.Summary.Inserted, j.Summary.Total, j.StatusDetails,
		j.Attempts, j.LeaseOwner, micros(j.LeaseUntil), micros(j.FirstClaimedAt), micros(j.CreatedAt),
		micros(j.UpdatedAt), micros(j.ExpiresAt), j.FileSize)
	return r.s.conflict(err)
}

func (r jobs) Get(ctx context.Context, tenantID, id string) (*store.Job, error) {
	j, err := scanJob(r.s.queryRow(ctx, `SELECT `+jobCols+` FROM jobs WHERE tenant_id = ? AND id = ?`,
		tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return j, err
}

func (r jobs) List(ctx context.Context, tenantID string, p store.Page) ([]*store.Job, int, error) {
	var total int
	if err := r.s.queryRow(ctx, `SELECT COUNT(*) FROM jobs WHERE tenant_id = ?`, tenantID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.s.query(ctx, `SELECT `+jobListCols+` FROM jobs WHERE tenant_id = ?
 ORDER BY created_at DESC, id`+r.s.d.byteOrder+` DESC`+pageClause(p), tenantID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*store.Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, j)
	}
	return out, total, rows.Err()
}

func (r jobs) CountActive(ctx context.Context, tenantID string, t store.JobType) (int, error) {
	var n int
	err := r.s.queryRow(ctx, `SELECT COUNT(*) FROM jobs WHERE tenant_id = ? AND type = ? AND status IN ('pending', 'processing')`,
		tenantID, string(t)).Scan(&n)
	return n, err
}

// lockRead is the row-lock suffix for Claim's look at the queue inside a
// transaction: a plain read on MySQL would keep seeing the transaction's
// snapshot, and Claim would look at the same stale job again and again.
func (r jobs) lockRead() string {
	if r.s.tx != nil {
		return r.s.d.forUpdate
	}
	return ""
}

// Claim looks for the oldest claimable job and takes it with one UPDATE that
// repeats the conditions and the attempt count it saw, so of any number of
// workers racing for a job exactly one UPDATE changes a row; the others look
// again.
func (r jobs) Claim(ctx context.Context, owner string, now time.Time, lease time.Duration) (*store.Job, error) {
	for {
		var tenantID, id string
		var attempts int
		err := r.s.queryRow(ctx, `SELECT tenant_id, id, attempts FROM jobs WHERE `+claimable+`
 ORDER BY created_at, tenant_id`+r.s.d.byteOrder+`, id`+r.s.d.byteOrder+` LIMIT 1`+r.lockRead(),
			micros(now), micros(now), store.JobMaxAttempts).Scan(&tenantID, &id, &attempts)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		res, err := r.s.write(ctx, nil, `UPDATE jobs SET status = 'processing', lease_owner = ?, lease_until = ?, attempts = attempts + 1,
 first_claimed_at = CASE WHEN first_claimed_at = 0 THEN ? ELSE first_claimed_at END, updated_at = ?
 WHERE tenant_id = ? AND id = ? AND attempts = ? AND `+claimable,
			owner, micros(now.Add(lease)), micros(now), micros(now), tenantID, id, attempts, micros(now), micros(now), store.JobMaxAttempts)
		if err != nil {
			return nil, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			continue // another worker was first
		}
		j, err := scanJob(r.s.queryRow(ctx, `SELECT `+jobCols+` FROM jobs WHERE tenant_id = ? AND id = ?`, tenantID, id))
		if errors.Is(err, sql.ErrNoRows) {
			continue // swept right after the claim
		}
		return j, err
	}
}

// leased is the WHERE condition of a job owner holds the lease of; it takes
// (tenant_id, id, owner).
const leased = `tenant_id = ? AND id = ? AND status = 'processing' AND lease_owner = ?`

// expectLease maps "no row changed" to ErrConflict.
func expectLease(res sql.Result) error {
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrConflict
	}
	return nil
}

func (r jobs) Renew(ctx context.Context, tenantID, id, owner string, until time.Time) error {
	res, err := r.s.write(ctx, nil, `UPDATE jobs SET lease_until = ? WHERE `+leased, micros(until), tenantID, id, owner)
	if err != nil {
		return err
	}
	return expectLease(res)
}

func (r jobs) Checkpoint(ctx context.Context, tenantID, id, owner string, progress int, sum store.JobSummary, errs []store.JobError) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		res, err := tx.exec(ctx, `UPDATE jobs SET progress = ?, summary_failed = ?, summary_updated = ?, summary_inserted = ?, summary_total = ?
 WHERE `+leased, progress, sum.Failed, sum.Updated, sum.Inserted, sum.Total, tenantID, id, owner)
		if err != nil {
			return err
		}
		if err := expectLease(res); err != nil {
			return err
		}
		for _, e := range errs {
			user, err := toJSON(e.User)
			if err != nil {
				return err
			}
			items, err := toJSON(e.Errors)
			if err != nil {
				return err
			}
			if _, err := tx.exec(ctx, `INSERT INTO job_errors (tenant_id, job_id, idx, user_data, errors) VALUES (?,?,?,?,?)`,
				tenantID, id, e.Index, user, items); err != nil {
				return tx.conflict(err)
			}
		}
		return nil
	})
}

func (r jobs) Finish(ctx context.Context, tenantID, id, owner string, st store.JobStatus, details string, at time.Time) error {
	if st != store.JobCompleted && st != store.JobFailed {
		return fmt.Errorf("%w: job status %q is not final", store.ErrInvalid, st)
	}
	res, err := r.s.write(ctx, nil, `UPDATE jobs SET status = ?, status_details = ?, updated_at = ?, lease_owner = '', lease_until = 0, input = NULL
 WHERE `+leased, string(st), details, micros(at), tenantID, id, owner)
	if err != nil {
		return err
	}
	return expectLease(res)
}

func (r jobs) exists(ctx context.Context, tenantID, id string) error {
	var one int
	err := r.s.queryRow(ctx, `SELECT 1 FROM jobs WHERE tenant_id = ? AND id = ?`, tenantID, id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}

func (r jobs) Errors(ctx context.Context, tenantID, id string) ([]store.JobError, error) {
	if err := r.exists(ctx, tenantID, id); err != nil {
		return nil, err
	}
	rows, err := r.s.query(ctx, `SELECT idx, user_data, errors FROM job_errors WHERE tenant_id = ? AND job_id = ? ORDER BY idx`, tenantID, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.JobError
	for rows.Next() {
		var e store.JobError
		var user, items string
		if err := rows.Scan(&e.Index, &user, &items); err != nil {
			return nil, err
		}
		if err := fromJSON(user, &e.User); err != nil {
			return nil, err
		}
		if err := fromJSON(items, &e.Errors); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (r jobs) AppendFile(ctx context.Context, tenantID, id, owner string, seq int, chunk []byte) error {
	if seq < 0 || len(chunk) > store.JobMaxChunk {
		return fmt.Errorf("%w: file chunk %d of %d bytes", store.ErrInvalid, seq, len(chunk))
	}
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		res, err := tx.exec(ctx, `UPDATE jobs SET file_size = file_size + ? WHERE `+leased, len(chunk), tenantID, id, owner)
		if err != nil {
			return err
		}
		if err := expectLease(res); err != nil {
			return err
		}
		if chunk == nil {
			chunk = []byte{}
		}
		_, err = tx.exec(ctx, `INSERT INTO job_files (tenant_id, job_id, seq, data) VALUES (?,?,?,?)`, tenantID, id, seq, chunk)
		return tx.conflict(err)
	})
}

// ReadFile reads one chunk at a time, so fn runs with no result set open
// (SQLite has a single connection, and fn may use the store).
func (r jobs) ReadFile(ctx context.Context, tenantID, id string, fn func(chunk []byte) error) error {
	if err := r.exists(ctx, tenantID, id); err != nil {
		return err
	}
	seq := int64(-1)
	for {
		var data []byte
		err := r.s.queryRow(ctx, `SELECT seq, data FROM job_files WHERE tenant_id = ? AND job_id = ? AND seq > ? ORDER BY seq LIMIT 1`,
			tenantID, id, seq).Scan(&seq, &data)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := fn(data); err != nil {
			return err
		}
	}
}

func (r jobs) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	var n int
	err := r.s.atomicRetry(ctx, r.s.sweep(), func(tx *Store) (err error) {
		fail := `UPDATE jobs SET status = 'failed', status_details = ?, updated_at = ?, lease_owner = '', lease_until = 0, input = NULL
 WHERE status = 'processing' AND `
		if _, err := tx.exec(ctx, fail+`first_claimed_at > 0 AND first_claimed_at < ?`,
			store.JobDetailTimedOut, micros(before), micros(before.Add(-store.JobMaxRuntime))); err != nil {
			return err
		}
		if _, err := tx.exec(ctx, fail+`attempts >= ? AND lease_until < ?`,
			store.JobDetailWorkerLost, micros(before), store.JobMaxAttempts, micros(before)); err != nil {
			return err
		}
		for _, table := range []string{"job_errors", "job_files"} {
			if _, err := tx.exec(ctx, `DELETE FROM `+table+` WHERE EXISTS (SELECT 1 FROM jobs j
 WHERE j.tenant_id = `+table+`.tenant_id AND j.id = `+table+`.job_id AND j.expires_at < ?)`, micros(before)); err != nil {
				return err
			}
		}
		n, err = affected(tx.exec(ctx, `DELETE FROM jobs WHERE expires_at < ?`, micros(before)))
		return err
	})
	return n, err
}

func scanJob(row scanner) (*store.Job, error) {
	var j store.Job
	var typ, status, params string
	var input []byte
	var lease, first, created, updated, expires int64
	if err := row.Scan(&j.TenantID, &j.ID, &typ, &status, &j.ConnectionID, &j.Connection, &j.ExternalID, &params, &input,
		&j.Progress, &j.Summary.Failed, &j.Summary.Updated, &j.Summary.Inserted, &j.Summary.Total, &j.StatusDetails,
		&j.Attempts, &j.LeaseOwner, &lease, &first, &created, &updated, &expires, &j.FileSize); err != nil {
		return nil, err
	}
	if err := fromJSON(params, &j.Params); err != nil {
		return nil, err
	}
	j.Type, j.Status = store.JobType(typ), store.JobStatus(status)
	if len(input) > 0 {
		j.Input = input
	}
	j.LeaseUntil, j.FirstClaimedAt = fromMicros(lease), fromMicros(first)
	j.CreatedAt, j.UpdatedAt, j.ExpiresAt = fromMicros(created), fromMicros(updated), fromMicros(expires)
	return &j, nil
}
