package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const jobLabel = "action-job/v1"

// AsyncJob carries a canonical trigger event snapshot. Input must encode as a
// JSON object; callers construct it with the trigger event builder, without
// Action secrets (which are injected separately by the runner).
type AsyncJob struct {
	TenantID, Trigger string
	Input             any
}

type jobPayload struct {
	Units []continueUnit
	Input map[string]any
}

func asyncTrigger(trigger string) bool {
	return trigger == TriggerPostUserRegistration || trigger == TriggerPostChangePassword || trigger == TriggerCustomEmailProvider
}

// Enqueue snapshots the binding order, deployed Actions and immutable Modules
// through tx. It does no build extraction, secret opening or runner work. The
// caller owns the transaction that commits the accompanying user/email change.
func (e *Engine) Enqueue(ctx context.Context, tx store.Store, j AsyncJob) error {
	if j.TenantID == "" || !asyncTrigger(j.Trigger) {
		return store.ErrInvalid
	}
	bound, err := tx.Actions().Bindings(ctx, j.TenantID, j.Trigger)
	if err != nil {
		return err
	}
	return e.enqueueBound(ctx, tx, j, bound)
}

// enqueueBound snapshots bound, the trigger's bindings in order, into a job.
func (e *Engine) enqueueBound(ctx context.Context, tx store.Store, j AsyncJob, bound []store.BoundVersion) error {
	if len(bound) == 0 {
		return nil
	}
	raw, err := json.Marshal(j.Input)
	if err != nil {
		return fmt.Errorf("actions: encoding job event: %w", err)
	}
	var p jobPayload
	if err = json.Unmarshal(raw, &p.Input); err != nil || p.Input == nil {
		return ErrInvalidPayload
	}
	var ids []string
	for _, u := range pinned(bound) {
		versions, err := resolveModuleVersions(ctx, tx.Actions(), j.TenantID, u)
		if err != nil {
			return err
		}
		p.Units = append(p.Units, continueUnit{Name: u.name, ActionID: u.actionID, VersionKey: u.versionKey, Code: u.code, BuildID: u.buildID, Secrets: u.secrets, Modules: u.moduleRefs, ModuleVersions: versions})
		for _, v := range versions {
			ids = append(ids, v.ID)
		}
	}
	plain, err := json.Marshal(p)
	if err != nil {
		return err
	}
	now := e.now()
	job := &store.ActionJob{TenantID: j.TenantID, ID: "ajob_" + secrets.RandomString(24), Trigger: j.Trigger, Status: "pending", NextAt: now, CreatedAt: now, UpdatedAt: now, ModuleVersionIDs: ids}
	job.Sealed, err = keys.SealBound(e.Secrets, jobLabel, []string{job.TenantID, job.ID, job.Trigger}, plain)
	if err != nil {
		return err
	}
	return tx.Actions().EnqueueJob(ctx, job)
}

// RunJob performs one claimed attempt against its sealed snapshot. A nil result
// means the worker was canceled: it must leave the existing lease untouched.
// FinishJob's expected lease must still be supplied by the caller.
func (e *Engine) RunJob(ctx context.Context, j *store.ActionJob) *store.ActionJob {
	if j == nil || ctx.Err() != nil {
		return nil
	}
	next := *j
	next.ExecutionIDs = append([]string{}, j.ExecutionIDs...)
	if j.Status != "pending" {
		return &next
	}
	var result *Result
	var runErr error
	var f *flow
	// An envelope that does not open or decode can never succeed: it is
	// failed at once and never retried.
	corrupt := false
	plain, err := keys.OpenBound(e.Secrets, jobLabel, []string{j.TenantID, j.ID, j.Trigger}, j.Sealed)
	var p jobPayload
	if err != nil || !asyncTrigger(j.Trigger) || json.Unmarshal(plain, &p) != nil || len(p.Units) == 0 || p.Input == nil {
		runErr, corrupt = errors.New("actions: invalid job envelope"), true
	} else {
		f = &flow{jobID: j.ID, jobAttempt: j.Attempts, tenantID: j.TenantID, trigger: j.Trigger, handler: handlerFor(j.Trigger), acc: newAccum(j.Trigger, nil, nil, false), cache: e.caches.get(j.TenantID, j.Trigger)}
		for _, u := range p.Units {
			if u.ActionID == "" || u.VersionKey == "" || u.BuildID == "" || len(u.Modules) != len(u.ModuleVersions) {
				runErr, corrupt = errors.New("actions: invalid job snapshot"), true
				break
			}
			f.units = append(f.units, unit{name: u.Name, actionID: u.ActionID, versionKey: u.VersionKey, code: u.Code, buildID: u.BuildID, secrets: u.Secrets, moduleRefs: u.Modules, moduleVersions: u.ModuleVersions})
		}
		if runErr == nil {
			f.event = func() map[string]any { return p.Input }
			result, runErr = e.run(ctx, f, nil)
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	var executionID string
	if result != nil {
		executionID = result.ExecutionID
	}
	if runErr != nil {
		var flowErr *ErrFlow
		if errors.As(runErr, &flowErr) {
			executionID = flowErr.ExecutionID
		} else {
			executionID = newExecutionID()
			now := e.now()
			ex := &store.Execution{TenantID: j.TenantID, ID: executionID, Trigger: j.Trigger, Status: "final", CreatedAt: now, UpdatedAt: now, Results: []store.ExecutionResult{{JobID: j.ID, JobAttempt: j.Attempts, StartedAt: now, EndedAt: now, ErrorID: "internal_error", ErrorMsg: runErr.Error()}}}
			if err := e.Store.Actions().CreateExecution(ctx, ex); err != nil {
				e.log().Warn("actions: recording a failed job execution", "tenant", j.TenantID, "execution_id", executionID, "error", err)
			}
		}
		e.log().Warn("actions job failed", "tenant", j.TenantID, "job_id", j.ID, "execution_id", executionID, "error", runErr)
	}
	next.ExecutionIDs = append(next.ExecutionIDs, executionID)
	next.Status = "done"
	next.LeaseUntil = time.Time{}
	next.UpdatedAt = e.now()
	if corrupt {
		next.Status = "failed"
		return &next
	}
	// A drop recorded by any Action is terminal, even when a later Action
	// failed or asked to retry.
	if f.dropped != nil {
		e.log().Info("actions email outcome", "tenant", j.TenantID, "job_id", j.ID, "execution_id", executionID, "outcome", f.dropped.Kind, "reason", f.dropped.Reason)
		next.Status = "dropped"
		return &next
	}
	retry := runErr != nil
	if result != nil && result.Notification != nil {
		outcome := result.Notification
		e.log().Info("actions email outcome", "tenant", j.TenantID, "job_id", j.ID, "execution_id", executionID, "outcome", outcome.Kind, "reason", outcome.Reason)
		retry = outcome.Kind == "retry"
	}
	if retry {
		next.Status = "failed"
		// A retry reruns every pinned Action; one that already completed
		// (and may have delivered the email) must not run again.
		completed := slices.Contains(f.outcomes, "ok")
		if completed && j.Trigger == TriggerCustomEmailProvider {
			e.log().Warn("actions email not retried: an Action in the flow already completed", "tenant", j.TenantID, "job_id", j.ID, "execution_id", executionID)
		}
		if j.Trigger == TriggerCustomEmailProvider && j.Attempts <= 5 && !completed {
			delays := [...]time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute}
			next.Status = "pending"
			next.NextAt = e.now().Add(delays[max(j.Attempts, 1)-1])
		}
	}
	return &next
}

// Worker runs claimed jobs without holding any storage transaction across Node,
// dependency extraction or network I/O. Each goroutine owns only one lease.
type Worker struct {
	Engine      *Engine
	Store       store.Store
	Workers     int
	Poll, Lease time.Duration
}

func (w *Worker) Run(ctx context.Context) {
	workers := w.Workers
	if workers <= 0 {
		workers = 2
	}
	poll := w.Poll
	if poll <= 0 {
		poll = time.Second
	}
	lease := w.Lease
	if lease <= 0 {
		lease = time.Minute
	}
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			timer := time.NewTimer(0)
			defer timer.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
				}
				jobs, err := w.Store.Actions().ClaimJobs(ctx, w.Engine.now(), lease, 1)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					w.Engine.log().Warn("actions: claiming jobs", "error", err)
				}
				for i := range jobs {
					job := &jobs[i]
					next := w.Engine.RunJob(ctx, job)
					if next == nil || ctx.Err() != nil {
						return
					}
					if err := w.Store.Actions().FinishJob(ctx, next, job.LeaseUntil); err != nil {
						w.Engine.log().Warn("actions: finishing job", "tenant", job.TenantID, "job_id", job.ID, "error", err)
					}
				}
				// Drain a backlog promptly; polling only delays empty or failed claims.
				delay := poll
				if err == nil && len(jobs) > 0 {
					delay = 0
				}
				timer.Reset(delay)
			}
		}()
	}
	wg.Wait()
}

// PurgeJobs removes terminal jobs and their execution records after ten days.
func PurgeJobs(ctx context.Context, st store.Store, now time.Time) (int, error) {
	return st.Actions().PurgeJobs(ctx, now.Add(-10*24*time.Hour))
}
