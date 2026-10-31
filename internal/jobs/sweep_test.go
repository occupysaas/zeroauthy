package jobs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type oldSweepJobs struct {
	store.Jobs
	calls *int
}

func (s oldSweepJobs) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	*s.calls++
	return s.Jobs.DeleteExpired(ctx, before)
}

type failedSweepJobs struct{ store.Jobs }

func (s failedSweepJobs) DeleteExpiredResult(context.Context, time.Time, int) (int, []store.JobOutcome, bool, error) {
	return 0, []store.JobOutcome{{TenantID: "t", ID: "job", Type: store.JobUsersImport, Status: store.JobFailed}}, false, errors.New("rollback")
}

func TestSweepExpiredOldRepositoryAndFailure(t *testing.T) {
	st := memory.New()
	capture := &outcomeRecorder{}
	ctx := logs.WithRecorder(context.Background(), capture)
	now := time.Now().UTC()
	if err := st.Jobs().Create(ctx, &store.Job{TenantID: "t", ID: "job", Type: store.JobUsersImport, Status: store.JobProcessing, FirstClaimedAt: now.Add(-store.JobMaxRuntime - time.Minute), ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := SweepExpired(ctx, failedSweepJobs{st.Jobs()}, now); err == nil {
		t.Fatal("expected rollback")
	}
	if len(capture.events) != 0 {
		t.Fatalf("failed write emitted=%+v", capture.events)
	}
	calls := 0
	if _, err := SweepExpired(ctx, oldSweepJobs{st.Jobs(), &calls}, now); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(capture.events) != 0 {
		t.Fatal(calls, capture.events)
	}
	j, err := st.Jobs().Get(ctx, "t", "job")
	if err != nil || j.Status != store.JobFailed {
		t.Fatal(j, err)
	}
}

func TestRunnerSweepUsesRecorder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := memory.New()
	now := time.Now().UTC()
	if err := st.Jobs().Create(ctx, &store.Job{TenantID: "t", ID: "job", Type: store.JobUsersImport, Status: store.JobProcessing, Attempts: store.JobMaxAttempts, LeaseUntil: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	capture := &outcomeRecorder{}
	r := &Runner{Store: st, Recorder: capture, Now: func() time.Time { return now }}
	r.sweep(ctx, Sweep{Run: func(ctx context.Context, st store.Store, now time.Time) error {
		_, err := SweepExpired(ctx, st.Jobs(), now)
		cancel()
		return err
	}})
	if len(capture.events) != 1 || capture.events[0].Type != "fui" || capture.events[0].TenantID != "t" {
		t.Fatalf("runner sweep events=%+v", capture.events)
	}
}
