package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const actionJobCols = `tenant_id,id,trigger_id,status,sealed,attempts,next_at,lease_until,execution_ids,module_version_ids,created_at,updated_at`

func scanActionJob(row scanner) (*store.ActionJob, error) {
	var j store.ActionJob
	var next, lease, created, updated int64
	var executions, modules string
	if err := row.Scan(&j.TenantID, &j.ID, &j.Trigger, &j.Status, &j.Sealed, &j.Attempts, &next, &lease, &executions, &modules, &created, &updated); err != nil {
		return nil, err
	}
	if err := fromJSON(executions, &j.ExecutionIDs); err != nil {
		return nil, err
	}
	if err := fromJSON(modules, &j.ModuleVersionIDs); err != nil {
		return nil, err
	}
	j.NextAt, j.LeaseUntil, j.CreatedAt, j.UpdatedAt = fromMicros(next), fromMicros(lease), fromMicros(created), fromMicros(updated)
	return &j, nil
}
func jobTriggerValid(t string) bool {
	return t == "post-user-registration" || t == "post-change-password" || t == "custom-email-provider"
}
func jobStatusValid(s string) bool {
	return s == "pending" || s == "done" || s == "failed" || s == "dropped"
}
func (r actionsRepo) EnqueueJob(ctx context.Context, j *store.ActionJob) error {
	status := j.Status
	if status == "" {
		status = "pending"
	}
	if j.TenantID == "" || j.ID == "" || status != "pending" || !jobTriggerValid(j.Trigger) {
		return store.ErrInvalid
	}
	executions, err := toJSON(j.ExecutionIDs)
	if err != nil {
		return err
	}
	modules, err := toJSON(j.ModuleVersionIDs)
	if err != nil {
		return err
	}
	return r.atomic(ctx, j.TenantID, func(tx *Store) error {
		var n int
		if err := tx.queryRow(ctx, `SELECT COUNT(*) FROM action_jobs WHERE tenant_id=? AND id=?`, j.TenantID, j.ID).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return store.ErrConflict
		}
		if err := tx.queryRow(ctx, `SELECT COUNT(*) FROM action_jobs WHERE tenant_id=? AND status='pending'`, j.TenantID).Scan(&n); err != nil {
			return err
		}
		if n >= actionsrules.Inventory().Limits["job_pending_per_tenant"] {
			return store.ErrPrecondition
		}
		for _, id := range j.ModuleVersionIDs {
			if err := tx.queryRow(ctx, `SELECT COUNT(*) FROM action_module_versions WHERE tenant_id=? AND id=?`, j.TenantID, id).Scan(&n); err != nil {
				return err
			}
			if n == 0 {
				return store.ErrInvalid
			}
		}
		_, err := tx.exec(ctx, `INSERT INTO action_jobs (`+actionJobCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, j.TenantID, j.ID, j.Trigger, status, nonNil(j.Sealed), 0, micros(stampTime(j.NextAt)), int64(0), executions, modules, micros(stampTime(j.CreatedAt)), micros(stampTime(j.UpdatedAt)))
		return tx.conflict(err)
	})
}

// ClaimJobs locks only due job rows on server databases, skipping another
// worker's rows. SQLite's BEGIN IMMEDIATE serializes writers instead.
func (r actionsRepo) ClaimJobs(ctx context.Context, now time.Time, lease time.Duration, maxJobs int) ([]store.ActionJob, error) {
	if lease <= 0 || maxJobs < 0 {
		return nil, store.ErrInvalid
	}
	out := []store.ActionJob{}
	if maxJobs == 0 {
		return out, nil
	}
	err := r.s.atomicRetry(ctx, r.s.sweep(), func(tx *Store) error {
		out = []store.ActionJob{}
		lock := ""
		source := "action_jobs"
		if tx.d.name == "mysql" {
			// A filesort can lock every matching row before applying LIMIT,
			// starving a concurrent SKIP LOCKED claimant. Scan in queue order.
			source += " FORCE INDEX (action_jobs_due)"
		}
		if tx.d.name != "sqlite" {
			lock = " FOR UPDATE SKIP LOCKED"
		}
		rows, err := tx.query(ctx, `SELECT `+actionJobCols+` FROM `+source+` WHERE status='pending' AND next_at<=? AND lease_until<=? ORDER BY next_at,created_at,tenant_id`+tx.d.byteOrder+`,id`+tx.d.byteOrder+` LIMIT ?`+lock, micros(now), micros(now), maxJobs)
		if err != nil {
			return err
		}
		for rows.Next() {
			j, err := scanActionJob(rows)
			if err != nil {
				rows.Close()
				return err
			}
			out = append(out, *j)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		until := fromMicros(micros(now.Add(lease)))
		for i := range out {
			j := &out[i]
			if _, err = tx.exec(ctx, `UPDATE action_jobs SET lease_until=?,attempts=attempts+1,updated_at=? WHERE tenant_id=? AND id=?`, micros(until), micros(now), j.TenantID, j.ID); err != nil {
				return err
			}
			j.LeaseUntil = until
			j.Attempts++
			j.UpdatedAt = fromMicros(micros(now))
		}
		return nil
	})
	return out, err
}

// FinishJob is a lease compare-and-swap. Event bytes, trigger, attempts and
// immutable module pins are never replaced by a worker's supplied object.
func (r actionsRepo) FinishJob(ctx context.Context, j *store.ActionJob, leaseUntil time.Time) error {
	if !jobStatusValid(j.Status) {
		return store.ErrInvalid
	}
	executions, err := toJSON(j.ExecutionIDs)
	if err != nil {
		return err
	}
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		res, err := tx.exec(ctx, `UPDATE action_jobs SET status=?,next_at=?,execution_ids=?,lease_until=0,updated_at=? WHERE tenant_id=? AND id=? AND status='pending' AND lease_until<>0 AND lease_until=?`, j.Status, micros(j.NextAt), executions, micros(time.Now().UTC()), j.TenantID, j.ID, micros(leaseUntil))
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 1 {
			return nil
		}
		var one int
		err = tx.queryRow(ctx, `SELECT 1 FROM action_jobs WHERE tenant_id=? AND id=?`+tx.d.forUpdate, j.TenantID, j.ID).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		return store.ErrConflict
	})
}

// Purging joins the same tenant lock as enqueue/deploy/delete, so the last
// reference cannot disappear while a new pin is being installed.
func (r actionsRepo) PurgeJobs(ctx context.Context, before time.Time) (int, error) {
	n := 0
	err := r.s.atomicRetry(ctx, r.s.sweep(), func(tx *Store) error {
		n = 0
		rows, err := tx.query(ctx, `SELECT DISTINCT tenant_id`+tx.d.byteOrder+` FROM action_jobs WHERE status<>'pending' AND updated_at<? ORDER BY tenant_id`+tx.d.byteOrder, micros(before))
		if err != nil {
			return err
		}
		var tenants []string
		for rows.Next() {
			var tid string
			if err = rows.Scan(&tid); err != nil {
				rows.Close()
				return err
			}
			tenants = append(tenants, tid)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, tid := range tenants {
			if err = tx.lockActions(ctx, tid); errors.Is(err, store.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			rows, err = tx.query(ctx, `SELECT `+actionJobCols+` FROM action_jobs WHERE tenant_id=? AND status<>'pending' AND updated_at<?`+tx.d.forUpdate, tid, micros(before))
			if err != nil {
				return err
			}
			var jobs []store.ActionJob
			for rows.Next() {
				j, e := scanActionJob(rows)
				if e != nil {
					rows.Close()
					return e
				}
				jobs = append(jobs, *j)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			for _, j := range jobs {
				for _, id := range j.ExecutionIDs {
					if _, err = tx.exec(ctx, `DELETE FROM action_executions WHERE tenant_id=? AND id=?`, tid, id); err != nil {
						return err
					}
				}
				if _, err = tx.exec(ctx, `DELETE FROM action_jobs WHERE tenant_id=? AND id=?`, tid, j.ID); err != nil {
					return err
				}
				n++
			}
			if err = (actionsRepo{tx}).purgeModuleTombstones(ctx, tid); err != nil {
				return err
			}
		}
		return nil
	})
	return n, err
}
