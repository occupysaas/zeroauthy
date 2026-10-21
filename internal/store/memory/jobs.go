package memory

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type jobs struct{ s *Store }

// jobFile holds the chunks of one export file by sequence number.
type jobFile map[int][]byte

func cloneJob(j *store.Job) *store.Job {
	out := *j
	out.Params = cloneJSON(j.Params)
	out.Input = cloneOptBytes(j.Input)
	return &out
}

// cloneOptBytes copies b, mapping empty to nil like the SQL drivers.
func cloneOptBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return bytes.Clone(b)
}

func cloneJobErrors(errs []store.JobError) []store.JobError {
	if errs == nil {
		return nil
	}
	out := make([]store.JobError, len(errs))
	for i, e := range errs {
		out[i] = store.JobError{Index: e.Index, User: cloneJSONValue(e.User), Errors: slices.Clone(e.Errors)}
	}
	return out
}

func cloneJobFile(f jobFile) jobFile {
	out := make(jobFile, len(f))
	for seq, c := range f {
		out[seq] = bytes.Clone(c)
	}
	return out
}

// held returns the job when owner holds its lease. It is called with the
// lock held.
func (r jobs) held(tenantID, id, owner string) (*store.Job, error) {
	j, ok := r.s.jobs[key{tenantID, id}]
	if !ok || j.Status != store.JobProcessing || j.LeaseOwner != owner {
		return nil, store.ErrConflict
	}
	return j, nil
}

func (r jobs) Create(_ context.Context, j *store.Job) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{j.TenantID, j.ID}
	if _, ok := r.s.jobs[k]; ok {
		return store.ErrConflict
	}
	r.s.jobs[k] = cloneJob(j)
	return nil
}

func (r jobs) Get(_ context.Context, tenantID, id string) (*store.Job, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	j, ok := r.s.jobs[key{tenantID, id}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneJob(j), nil
}

func (r jobs) List(_ context.Context, tenantID string, p store.Page) ([]*store.Job, int, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var all []*store.Job
	for k, j := range r.s.jobs {
		if k.tenant == tenantID {
			c := cloneJob(j)
			c.Input = nil
			all = append(all, c)
		}
	}
	slices.SortFunc(all, func(a, b *store.Job) int {
		if c := b.CreatedAt.Compare(a.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(b.ID, a.ID)
	})
	total := len(all)
	if p.Offset > 0 {
		all = all[min(p.Offset, len(all)):]
	}
	if p.Limit > 0 && len(all) > p.Limit {
		all = all[:p.Limit]
	}
	return all, total, nil
}

func (r jobs) CountActive(_ context.Context, tenantID string, t store.JobType) (int, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	n := 0
	for k, j := range r.s.jobs {
		if k.tenant == tenantID && j.Type == t && (j.Status == store.JobPending || j.Status == store.JobProcessing) {
			n++
		}
	}
	return n, nil
}

func (r jobs) Claim(_ context.Context, owner string, now time.Time, lease time.Duration) (*store.Job, error) {
	r.s.lock()
	defer r.s.unlock()
	var best *store.Job
	for _, j := range r.s.jobs {
		ready := (j.Status == store.JobPending && !j.ExpiresAt.Before(now)) ||
			(j.Status == store.JobProcessing && j.LeaseUntil.Before(now) && j.Attempts < store.JobMaxAttempts)
		if !ready {
			continue
		}
		if best == nil || j.CreatedAt.Before(best.CreatedAt) ||
			(j.CreatedAt.Equal(best.CreatedAt) && (j.TenantID < best.TenantID || (j.TenantID == best.TenantID && j.ID < best.ID))) {
			best = j
		}
	}
	if best == nil {
		return nil, store.ErrNotFound
	}
	best.Status = store.JobProcessing
	best.LeaseOwner = owner
	best.LeaseUntil = now.Add(lease)
	best.Attempts++
	if best.FirstClaimedAt.IsZero() {
		best.FirstClaimedAt = now
	}
	best.UpdatedAt = now
	return cloneJob(best), nil
}

func (r jobs) Renew(_ context.Context, tenantID, id, owner string, until time.Time) error {
	r.s.lock()
	defer r.s.unlock()
	j, err := r.held(tenantID, id, owner)
	if err != nil {
		return err
	}
	j.LeaseUntil = until
	return nil
}

func (r jobs) Checkpoint(_ context.Context, tenantID, id, owner string, progress int, sum store.JobSummary, errs []store.JobError) error {
	r.s.lock()
	defer r.s.unlock()
	j, err := r.held(tenantID, id, owner)
	if err != nil {
		return err
	}
	k := key{tenantID, id}
	have := map[int]bool{}
	for _, e := range r.s.jobErrors[k] {
		have[e.Index] = true
	}
	for _, e := range errs {
		if have[e.Index] {
			return store.ErrConflict
		}
		have[e.Index] = true
	}
	j.Progress, j.Summary = progress, sum
	all := append(r.s.jobErrors[k], cloneJobErrors(errs)...)
	slices.SortFunc(all, func(a, b store.JobError) int { return a.Index - b.Index })
	r.s.jobErrors[k] = all
	return nil
}

func (r jobs) Finish(_ context.Context, tenantID, id, owner string, st store.JobStatus, details string, at time.Time) error {
	if st != store.JobCompleted && st != store.JobFailed {
		return fmt.Errorf("%w: job status %q is not final", store.ErrInvalid, st)
	}
	r.s.lock()
	defer r.s.unlock()
	j, err := r.held(tenantID, id, owner)
	if err != nil {
		return err
	}
	endJob(j, st, details, at)
	return nil
}

// endJob gives j its final state.
func endJob(j *store.Job, st store.JobStatus, details string, at time.Time) {
	j.Status, j.StatusDetails, j.UpdatedAt = st, details, at
	j.LeaseOwner, j.LeaseUntil, j.Input = "", time.Time{}, nil
}

func (r jobs) Errors(_ context.Context, tenantID, id string) ([]store.JobError, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	k := key{tenantID, id}
	if _, ok := r.s.jobs[k]; !ok {
		return nil, store.ErrNotFound
	}
	return cloneJobErrors(r.s.jobErrors[k]), nil
}

func (r jobs) AppendFile(_ context.Context, tenantID, id, owner string, seq int, chunk []byte) error {
	if seq < 0 || len(chunk) > store.JobMaxChunk {
		return fmt.Errorf("%w: file chunk %d of %d bytes", store.ErrInvalid, seq, len(chunk))
	}
	r.s.lock()
	defer r.s.unlock()
	j, err := r.held(tenantID, id, owner)
	if err != nil {
		return err
	}
	k := key{tenantID, id}
	if _, ok := r.s.jobFiles[k][seq]; ok {
		return store.ErrConflict
	}
	if r.s.jobFiles[k] == nil {
		r.s.jobFiles[k] = jobFile{}
	}
	r.s.jobFiles[k][seq] = bytes.Clone(chunk)
	j.FileSize += int64(len(chunk))
	return nil
}

func (r jobs) ReadFile(_ context.Context, tenantID, id string, fn func(chunk []byte) error) error {
	r.s.mu.RLock()
	k := key{tenantID, id}
	if _, ok := r.s.jobs[k]; !ok {
		r.s.mu.RUnlock()
		return store.ErrNotFound
	}
	file := cloneJobFile(r.s.jobFiles[k])
	r.s.mu.RUnlock()
	seqs := make([]int, 0, len(file))
	for seq := range file {
		seqs = append(seqs, seq)
	}
	slices.Sort(seqs)
	for _, seq := range seqs {
		if err := fn(file[seq]); err != nil {
			return err
		}
	}
	return nil
}

func (r jobs) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	n := 0
	for k, j := range r.s.jobs {
		if j.Status == store.JobProcessing {
			switch {
			case !j.FirstClaimedAt.IsZero() && j.FirstClaimedAt.Add(store.JobMaxRuntime).Before(before):
				endJob(j, store.JobFailed, store.JobDetailTimedOut, before)
			case j.Attempts >= store.JobMaxAttempts && j.LeaseUntil.Before(before):
				endJob(j, store.JobFailed, store.JobDetailWorkerLost, before)
			}
		}
		if j.ExpiresAt.Before(before) {
			delete(r.s.jobs, k)
			delete(r.s.jobErrors, k)
			delete(r.s.jobFiles, k)
			n++
		}
	}
	return n, nil
}
