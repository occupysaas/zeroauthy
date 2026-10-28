// Package jobs runs Management API jobs (imports, exports, verification
// emails): a pool of workers claims jobs from the store with a lease,
// renews the lease while the job runs, and finishes the job.
//
// A job whose worker stops (its lease runs out) is claimed once more by
// another worker; the store fails it when that worker stops too.
package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// FailedDetails is the status_details of a job whose processor failed. The
// error itself goes to the log, not to the job.
const FailedDetails = "The job failed. See the server log."

// DefaultPoll is how often an idle worker looks for a job when nothing
// wakes it.
const DefaultPoll = 2 * time.Second

// finishTimeout bounds the write that finishes a job once the process is
// shutting down.
const finishTimeout = 10 * time.Second

// Lease is a worker's claim on a job.
type Lease interface {
	// Owner is the name every store write for the job must carry.
	Owner() string
	// Renew extends the lease by the runner's lease duration. It returns
	// store.ErrConflict once another worker holds the job.
	Renew(ctx context.Context) error
	// Lost reports whether the lease is known to be lost. The context the
	// processor runs with is cancelled when it is.
	Lost() bool
}

// Processor runs jobs of one type. It returns the final status
// (store.JobCompleted or store.JobFailed) and status_details; an error
// that is not a lost lease fails the job with FailedDetails. A processor
// stops when ctx is cancelled (shutdown or a lost lease).
type Processor interface {
	Run(ctx context.Context, st store.Store, j *store.Job, lease Lease) (store.JobStatus, string, error)
}

// Runner is a pool of workers.
type Runner struct {
	Store      store.Store
	Processors map[store.JobType]Processor
	// Workers is how many jobs run at once; 0 runs none.
	Workers int
	// LeaseFor is how long a claim lasts; workers renew it every third.
	LeaseFor time.Duration
	// Poll is how often an idle worker looks for a job; default
	// DefaultPoll.
	Poll time.Duration
	Log  *slog.Logger
	Now  func() time.Time
	// Sweeps are housekeeping tasks (expired-record purges) run at start
	// and every Every while the workers run. Every replica with workers runs
	// them; each must be safe to run concurrently with itself.
	Sweeps []Sweep

	once   sync.Once
	wakeUp chan struct{}
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (r *Runner) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

func (r *Runner) poll() time.Duration {
	if r.Poll > 0 {
		return r.Poll
	}
	return DefaultPoll
}

func (r *Runner) wake() chan struct{} {
	r.once.Do(func() { r.wakeUp = make(chan struct{}, 1) })
	return r.wakeUp
}

// Notify wakes an idle worker at once. The create handlers call it after
// storing a job; a nil Runner ignores it.
func (r *Runner) Notify() {
	if r == nil {
		return
	}
	select {
	case r.wake() <- struct{}{}:
	default:
	}
}

// Sweep is a periodic housekeeping task. Its errors are logged.
type Sweep struct {
	Name  string
	Every time.Duration
	Run   func(ctx context.Context, st store.Store, now time.Time) error
}

func (r *Runner) sweep(ctx context.Context, s Sweep) {
	every := s.Every
	if every <= 0 {
		every = time.Hour
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := s.Run(ctx, r.Store, r.now()); err != nil && ctx.Err() == nil {
			r.log().Warn("jobs: sweep failed", "sweep", s.Name, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Run starts the workers and the sweeps, and returns when ctx is cancelled
// and they have stopped. Without workers it runs nothing.
func (r *Runner) Run(ctx context.Context) {
	var wg sync.WaitGroup
	if r.Workers > 0 {
		for _, s := range r.Sweeps {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r.sweep(ctx, s)
			}()
		}
	}
	for range r.Workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.work(ctx, "worker-"+secrets.RandomHex(8))
		}()
	}
	wg.Wait()
}

func (r *Runner) work(ctx context.Context, owner string) {
	for ctx.Err() == nil {
		j, err := r.Store.Jobs().Claim(ctx, owner, r.now(), r.LeaseFor)
		switch {
		case err == nil:
			r.process(ctx, owner, j)
			continue
		case !errors.Is(err, store.ErrNotFound) && ctx.Err() == nil:
			r.log().Error("jobs: claim a job", "err", err)
		}
		t := time.NewTimer(r.poll())
		select {
		case <-ctx.Done():
		case <-t.C:
		case <-r.wake():
		}
		t.Stop()
	}
}

// lease implements Lease for one claim.
type lease struct {
	r     *Runner
	j     *store.Job
	owner string
	lost  atomic.Bool
}

func (l *lease) Owner() string { return l.owner }
func (l *lease) Lost() bool    { return l.lost.Load() }

func (l *lease) Renew(ctx context.Context) error {
	err := l.r.Store.Jobs().Renew(ctx, l.j.TenantID, l.j.ID, l.owner, l.r.now().Add(l.r.LeaseFor))
	if errors.Is(err, store.ErrConflict) {
		l.lost.Store(true)
	}
	return err
}

// process runs one claimed job and finishes it.
func (r *Runner) process(ctx context.Context, owner string, j *store.Job) {
	l := &lease{r: r, j: j, owner: owner}
	jobCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var renewer sync.WaitGroup
	renewer.Add(1)
	go func() {
		defer renewer.Done()
		t := time.NewTicker(max(r.LeaseFor/3, time.Millisecond))
		defer t.Stop()
		for {
			select {
			case <-jobCtx.Done():
				return
			case <-t.C:
				if err := l.Renew(jobCtx); errors.Is(err, store.ErrConflict) {
					cancel()
					return
				} else if err != nil && jobCtx.Err() == nil {
					r.log().Error("jobs: renew a lease", "err", err, "tenant", j.TenantID, "job", j.ID)
				}
			}
		}
	}()

	status, details, err := r.run(jobCtx, j, l)
	cancel()
	renewer.Wait()

	switch {
	case l.Lost():
		r.log().Warn("jobs: lost the lease of a job", "tenant", j.TenantID, "job", j.ID)
		return
	case ctx.Err() != nil && (err != nil || (status != store.JobCompleted && status != store.JobFailed)):
		// Shutting down and the processor did not finish: leave the job
		// for the next claim.
		return
	case err != nil:
		r.log().Error("jobs: a job failed", "err", err, "tenant", j.TenantID, "job", j.ID, "type", j.Type)
		status, details = store.JobFailed, FailedDetails
	case status != store.JobCompleted && status != store.JobFailed:
		r.log().Error("jobs: a processor returned a status that is not final", "status", status, "tenant", j.TenantID, "job", j.ID)
		status, details = store.JobFailed, FailedDetails
	}
	fctx, fcancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer fcancel()
	if err := r.Store.Jobs().Finish(fctx, j.TenantID, j.ID, owner, status, details, r.now()); err != nil {
		if errors.Is(err, store.ErrConflict) {
			r.log().Warn("jobs: lost the lease of a job", "tenant", j.TenantID, "job", j.ID)
			return
		}
		r.log().Error("jobs: finish a job", "err", err, "tenant", j.TenantID, "job", j.ID)
	}
}

// run calls the job's processor, turning a panic into an error.
func (r *Runner) run(ctx context.Context, j *store.Job, l Lease) (status store.JobStatus, details string, err error) {
	p, ok := r.Processors[j.Type]
	if !ok {
		return "", "", fmt.Errorf("no processor for job type %q", j.Type)
	}
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("processor panic: %v", v)
		}
	}()
	return p.Run(ctx, r.Store, j, l)
}
