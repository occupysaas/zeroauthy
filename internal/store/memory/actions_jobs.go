package memory

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func cloneActionJob(j *store.ActionJob) *store.ActionJob {
	c := *j
	c.Sealed = bytes.Clone(j.Sealed)
	c.ExecutionIDs = slices.Clone(j.ExecutionIDs)
	c.ModuleVersionIDs = slices.Clone(j.ModuleVersionIDs)
	return &c
}
func jobStatusValid(s string) bool {
	return s == "pending" || s == "done" || s == "failed" || s == "dropped"
}
func jobTriggerValid(s string) bool {
	return s == "post-user-registration" || s == "post-change-password" || s == "custom-email-provider"
}
func (r actionsRepo) EnqueueJob(_ context.Context, j *store.ActionJob) error {
	c := cloneActionJob(j)
	if c.Status == "" {
		c.Status = "pending"
	}
	if c.TenantID == "" || c.ID == "" || c.Status != "pending" || !jobTriggerValid(c.Trigger) {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	if r.s.tenants[c.TenantID] == nil {
		return store.ErrNotFound
	}
	if r.s.actionJobs[key{c.TenantID, c.ID}] != nil {
		return store.ErrConflict
	}
	n := 0
	for k, old := range r.s.actionJobs {
		if k.tenant == c.TenantID && old.Status == "pending" {
			n++
		}
	}
	if n >= actionsrules.Inventory().Limits["job_pending_per_tenant"] {
		return store.ErrPrecondition
	}
	for _, id := range c.ModuleVersionIDs {
		if r.s.moduleVersions[key{c.TenantID, id}] == nil {
			return store.ErrInvalid
		}
	}
	c.LeaseUntil = time.Time{}
	c.Attempts = 0
	c.CreatedAt = r.stamp(c.CreatedAt)
	c.UpdatedAt = r.stamp(c.UpdatedAt)
	c.NextAt = r.stamp(c.NextAt)
	r.s.actionJobs[key{c.TenantID, c.ID}] = c
	return nil
}
func (r actionsRepo) ClaimJobs(_ context.Context, now time.Time, lease time.Duration, maxJobs int) ([]store.ActionJob, error) {
	if lease <= 0 || maxJobs < 0 {
		return nil, store.ErrInvalid
	}
	out := []store.ActionJob{}
	if maxJobs == 0 {
		return out, nil
	}
	r.s.lock()
	defer r.s.unlock()
	due := []*store.ActionJob{}
	for _, j := range r.s.actionJobs {
		if j.Status == "pending" && !j.NextAt.After(now) && !j.LeaseUntil.After(now) {
			due = append(due, j)
		}
	}
	slices.SortFunc(due, func(a, b *store.ActionJob) int {
		if n := a.NextAt.Compare(b.NextAt); n != 0 {
			return n
		}
		if n := a.CreatedAt.Compare(b.CreatedAt); n != 0 {
			return n
		}
		if n := strings.Compare(a.TenantID, b.TenantID); n != 0 {
			return n
		}
		return strings.Compare(a.ID, b.ID)
	})
	for _, j := range due[:min(maxJobs, len(due))] {
		j.LeaseUntil = now.Add(lease)
		j.Attempts++
		j.UpdatedAt = now
		out = append(out, *cloneActionJob(j))
	}
	return out, nil
}
func (r actionsRepo) FinishJob(_ context.Context, j *store.ActionJob, leaseUntil time.Time) error {
	if !jobStatusValid(j.Status) {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	old := r.s.actionJobs[key{j.TenantID, j.ID}]
	if old == nil {
		return store.ErrNotFound
	}
	if old.Status != "pending" || old.LeaseUntil.IsZero() || !old.LeaseUntil.Equal(leaseUntil) {
		return store.ErrConflict
	}
	// Completion changes only worker-owned state; the sealed event and pins stay immutable.
	c := cloneActionJob(old)
	c.Status = j.Status
	c.NextAt = j.NextAt
	c.ExecutionIDs = slices.Clone(j.ExecutionIDs)
	c.LeaseUntil = time.Time{}
	c.UpdatedAt = r.s.now()
	r.s.actionJobs[key{j.TenantID, j.ID}] = c
	return nil
}
func (r actionsRepo) PurgeJobs(_ context.Context, before time.Time) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	n := 0
	for k, j := range r.s.actionJobs {
		if j.Status != "pending" && j.UpdatedAt.Before(before) {
			for _, id := range j.ExecutionIDs {
				delete(r.s.executions, key{k.tenant, id})
			}
			delete(r.s.actionJobs, k)
			n++
		}
	}
	r.s.purgeModuleTombstones()
	return n, nil
}
