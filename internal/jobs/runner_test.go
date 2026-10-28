package jobs

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type procFunc func(ctx context.Context, st store.Store, j *store.Job, l Lease) (store.JobStatus, string, error)

func (f procFunc) Run(ctx context.Context, st store.Store, j *store.Job, l Lease) (store.JobStatus, string, error) {
	return f(ctx, st, j, l)
}

func addJob(t *testing.T, st store.Store, id string, params map[string]any) {
	t.Helper()
	now := time.Now().UTC()
	err := st.Jobs().Create(context.Background(), &store.Job{
		TenantID: "t1", ID: id, Type: store.JobVerificationEmail, Status: store.JobPending,
		Params: params, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func getJob(t *testing.T, st store.Store, id string) *store.Job {
	t.Helper()
	j, err := st.Jobs().Get(context.Background(), "t1", id)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// start runs r until the test ends or stop is called.
func start(t *testing.T, r *Runner) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	var once sync.Once
	stop = func() { once.Do(func() { cancel(); <-done }) }
	t.Cleanup(stop)
	return stop
}

func newRunner(st store.Store, p Processor, workers int) *Runner {
	return &Runner{
		Store: st, Processors: map[store.JobType]Processor{store.JobVerificationEmail: p},
		Workers: workers, LeaseFor: time.Second, Poll: 5 * time.Millisecond,
	}
}

func TestRunnerCompletesAJob(t *testing.T) {
	st := memory.New()
	addJob(t, st, "job_a", nil)
	start(t, newRunner(st, procFunc(func(context.Context, store.Store, *store.Job, Lease) (store.JobStatus, string, error) {
		return store.JobCompleted, "", nil
	}), 1))
	waitFor(t, "completion", func() bool { return getJob(t, st, "job_a").Status == store.JobCompleted })
	if j := getJob(t, st, "job_a"); j.LeaseOwner != "" || j.Attempts != 1 {
		t.Errorf("job = %+v, want its lease cleared after one attempt", j)
	}
}

func TestRunnerFailsAJobGenerically(t *testing.T) {
	for name, f := range map[string]procFunc{
		"error": func(context.Context, store.Store, *store.Job, Lease) (store.JobStatus, string, error) {
			return "", "", errors.New("smtp password is hunter2")
		},
		"panic": func(context.Context, store.Store, *store.Job, Lease) (store.JobStatus, string, error) {
			panic("boom")
		},
		"not final": func(context.Context, store.Store, *store.Job, Lease) (store.JobStatus, string, error) {
			return store.JobProcessing, "", nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			st := memory.New()
			addJob(t, st, "job_a", nil)
			start(t, newRunner(st, f, 1))
			waitFor(t, "failure", func() bool { return getJob(t, st, "job_a").Status == store.JobFailed })
			if d := getJob(t, st, "job_a").StatusDetails; d != FailedDetails {
				t.Errorf("status_details = %q, want the generic text", d)
			}
		})
	}
}

func TestRunnerKeepsTheLeaseOfALongJob(t *testing.T) {
	st := memory.New()
	addJob(t, st, "job_a", nil)
	r := newRunner(st, procFunc(func(ctx context.Context, _ store.Store, _ *store.Job, _ Lease) (store.JobStatus, string, error) {
		time.Sleep(450 * time.Millisecond) // several leases
		return store.JobCompleted, "", nil
	}), 2)
	r.LeaseFor = 120 * time.Millisecond
	start(t, r)
	waitFor(t, "completion", func() bool { return getJob(t, st, "job_a").Status == store.JobCompleted })
	if n := getJob(t, st, "job_a").Attempts; n != 1 {
		t.Errorf("attempts = %d, want 1: the renewed lease must keep the other worker away", n)
	}
}

// TestJobLeaseRetryOnce: a worker that stops mid-job loses the job to a
// second runner once the lease ends; when that one stops too the job is
// not claimed again and the sweeper fails it.
func TestJobLeaseRetryOnce(t *testing.T) {
	st := memory.New()
	addJob(t, st, "job_a", nil)
	var runs atomic.Int32
	block := procFunc(func(ctx context.Context, _ store.Store, _ *store.Job, _ Lease) (store.JobStatus, string, error) {
		runs.Add(1)
		<-ctx.Done()
		return "", "", ctx.Err()
	})
	const lease = 100 * time.Millisecond
	for attempt := 1; attempt <= 3; attempt++ {
		r := newRunner(st, block, 1)
		r.LeaseFor = lease
		stop := start(t, r)
		if attempt < 3 {
			waitFor(t, "a claim", func() bool { return int(runs.Load()) == attempt })
		} else {
			time.Sleep(4 * lease) // a third runner finds nothing to claim
		}
		stop()
		time.Sleep(2 * lease)
	}
	if n := runs.Load(); n != 2 {
		t.Errorf("the processor ran %d times, want 2", n)
	}
	j := getJob(t, st, "job_a")
	if j.Status != store.JobProcessing || j.Attempts != 2 {
		t.Fatalf("job = %s after %d attempts, want processing after 2: a stopped worker must not finish it", j.Status, j.Attempts)
	}
	if _, err := st.Jobs().DeleteExpired(context.Background(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if j := getJob(t, st, "job_a"); j.Status != store.JobFailed || j.StatusDetails != store.JobDetailWorkerLost {
		t.Errorf("job = %s %q, want failed with the worker-lost details", j.Status, j.StatusDetails)
	}
}

func TestRunnersNeverRunAJobTwice(t *testing.T) {
	st := memory.New()
	const n = 40
	for i := range n {
		addJob(t, st, "job_"+string(rune('A'+i/26))+string(rune('a'+i%26)), nil)
	}
	var mu sync.Mutex
	seen := map[string]int{}
	p := procFunc(func(_ context.Context, _ store.Store, j *store.Job, _ Lease) (store.JobStatus, string, error) {
		mu.Lock()
		seen[j.ID]++
		mu.Unlock()
		time.Sleep(time.Millisecond)
		return store.JobCompleted, "", nil
	})
	start(t, newRunner(st, p, 4))
	start(t, newRunner(st, p, 4))
	waitFor(t, "all jobs", func() bool {
		jobs, _, err := st.Jobs().List(context.Background(), "t1", store.Page{Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		done := 0
		for _, j := range jobs {
			if j.Status == store.JobCompleted {
				done++
			}
		}
		return done == n
	})
	mu.Lock()
	defer mu.Unlock()
	for id, c := range seen {
		if c != 1 {
			t.Errorf("job %s ran %d times", id, c)
		}
	}
	if len(seen) != n {
		t.Errorf("%d jobs ran, want %d", len(seen), n)
	}
}

func TestNotifyWakesAnIdleWorker(t *testing.T) {
	st := memory.New()
	r := newRunner(st, procFunc(func(context.Context, store.Store, *store.Job, Lease) (store.JobStatus, string, error) {
		return store.JobCompleted, "", nil
	}), 1)
	r.Poll = time.Hour
	start(t, r)
	time.Sleep(50 * time.Millisecond) // the worker is idle
	addJob(t, st, "job_a", nil)
	r.Notify()
	waitFor(t, "completion without polling", func() bool { return getJob(t, st, "job_a").Status == store.JobCompleted })
}

func TestZeroWorkersRunNothing(t *testing.T) {
	st := memory.New()
	addJob(t, st, "job_a", nil)
	r := newRunner(st, nil, 0)
	done := make(chan struct{})
	go func() { r.Run(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run with no workers did not return")
	}
	if getJob(t, st, "job_a").Status != store.JobPending {
		t.Error("the job was claimed")
	}
	var nilRunner *Runner
	nilRunner.Notify() // must not panic
}

// A worker whose lease another owner took stops its processor and never
// finishes the job.
func TestRenewalConflictCancelsAndNeverFinishes(t *testing.T) {
	st := memory.New()
	addJob(t, st, "job_a", nil)
	finishes := &finishCounter{Store: st}
	cancelled := make(chan struct{})
	started := make(chan struct{})
	r := newRunner(finishes, procFunc(func(ctx context.Context, _ store.Store, _ *store.Job, l Lease) (store.JobStatus, string, error) {
		close(started)
		<-ctx.Done()
		close(cancelled)
		// Returns a "success" even though it lost the job.
		return store.JobCompleted, "", nil
	}), 1)
	r.LeaseFor = 90 * time.Millisecond
	start(t, r)
	<-started
	// Another owner takes the job once the lease is made to look expired.
	if err := st.Jobs().Renew(context.Background(), "t1", "job_a", getJob(t, st, "job_a").LeaseOwner, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Jobs().Claim(context.Background(), "thief", time.Now().UTC(), time.Hour); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("the processor's context was not cancelled after the lease was lost")
	}
	time.Sleep(100 * time.Millisecond)
	if n := finishes.n.Load(); n != 0 {
		t.Errorf("Finish was called %d times after the lease was lost", n)
	}
	if j := getJob(t, st, "job_a"); j.Status != store.JobProcessing || j.LeaseOwner != "thief" {
		t.Errorf("job = %s owned by %q, want processing under the thief", j.Status, j.LeaseOwner)
	}
}

// A processor that returns without a final status once the runner's
// context is cancelled leaves the job for a retry.
func TestShutdownWithoutFinalStatusLeavesTheJob(t *testing.T) {
	st := memory.New()
	addJob(t, st, "job_a", nil)
	started := make(chan struct{})
	r := newRunner(st, procFunc(func(ctx context.Context, _ store.Store, _ *store.Job, _ Lease) (store.JobStatus, string, error) {
		close(started)
		<-ctx.Done()
		return "", "", nil
	}), 1)
	stop := start(t, r)
	<-started
	stop()
	if j := getJob(t, st, "job_a"); j.Status != store.JobProcessing {
		t.Errorf("job = %s, want processing (left for a retry)", j.Status)
	}
}

type finishCounter struct {
	store.Store
	n atomic.Int32
}

func (f *finishCounter) Jobs() store.Jobs { return finishJobs{f.Store.Jobs(), &f.n} }

type finishJobs struct {
	store.Jobs
	n *atomic.Int32
}

func (f finishJobs) Finish(ctx context.Context, tenantID, id, owner string, st store.JobStatus, details string, at time.Time) error {
	f.n.Add(1)
	return f.Jobs.Finish(ctx, tenantID, id, owner, st, details, at)
}

// TestSweepsRunPeriodically: housekeeping sweeps (such as the Actions
// execution purge) run at start and every interval while workers run, and
// stop with Run; a process without workers runs none.
func TestSweepsRunPeriodically(t *testing.T) {
	st := memory.New()
	var runs atomic.Int32
	sweep := Sweep{Name: "count", Every: 20 * time.Millisecond, Run: func(ctx context.Context, st store.Store, now time.Time) error {
		runs.Add(1)
		return errors.New("logged, not fatal")
	}}
	r := newRunner(st, nil, 1)
	r.Sweeps = []Sweep{sweep}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for runs.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if runs.Load() < 3 {
		t.Fatalf("sweep ran %d times", runs.Load())
	}
	after := runs.Load()
	time.Sleep(60 * time.Millisecond)
	if runs.Load() != after {
		t.Fatal("sweep kept running after Run returned")
	}

	idle := newRunner(st, nil, 0)
	idle.Sweeps = []Sweep{sweep}
	runs.Store(0)
	idle.Run(context.Background())
	if runs.Load() != 0 {
		t.Fatal("a process without workers ran a sweep")
	}
}
