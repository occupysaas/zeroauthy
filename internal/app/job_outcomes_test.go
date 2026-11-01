package app

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type sweepOutcomeRecorder struct {
	t      *testing.T
	st     store.Store
	events []logs.Event
}

func (r *sweepOutcomeRecorder) Record(ctx context.Context, event logs.Event) {
	// This read would deadlock with a recording call made under the memory
	// transaction lock. It also verifies the visible business state first.
	j, err := r.st.Jobs().Get(ctx, event.TenantID, event.Details["job_id"].(string))
	if err != nil || j.Status != store.JobFailed {
		r.t.Errorf("event before successful write: %+v %v", j, err)
	}
	r.events = append(r.events, event)
}

func TestSweepRecordsAbandonedImportsAfterWrite(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	now := time.Now().UTC()
	for _, tid := range []string{"a", "b"} {
		if err := st.Tenants().Create(ctx, &store.Tenant{ID: tid, Name: tid}); err != nil {
			t.Fatal(err)
		}
		for i := range store.JobSweepBatch + 1 {
			j := &store.Job{TenantID: tid, ID: fmt.Sprintf("job_%d", i), Type: store.JobUsersImport, Status: store.JobProcessing,
				FirstClaimedAt: now.Add(-store.JobMaxRuntime - time.Minute), LeaseUntil: now.Add(time.Hour), ExpiresAt: now.Add(time.Hour), Input: []byte(`{"password":"import-secret"}`)}
			if i%2 == 1 {
				j.FirstClaimedAt = now
				j.LeaseUntil = now.Add(-time.Second)
				j.Attempts = store.JobMaxAttempts
			}
			if err := st.Jobs().Create(ctx, j); err != nil {
				t.Fatal(err)
			}
		}
	}
	recorder := &sweepOutcomeRecorder{t: t, st: st}
	ctx = logs.WithRecorder(ctx, recorder)
	for range 2 {
		if n, err := sweep(ctx, st, now); err != nil || n != 0 {
			t.Fatal(n, err)
		}
	}
	if len(recorder.events) != 2*(store.JobSweepBatch+1) {
		t.Fatalf("sweep outcomes=%d", len(recorder.events))
	}
	seen := map[string]bool{}
	for _, event := range recorder.events {
		key := event.TenantID + "/" + event.Details["job_id"].(string)
		if seen[key] || event.Type != "fui" || len(event.Details) != 1 {
			t.Fatalf("unsafe/duplicate event=%+v", event)
		}
		seen[key] = true
	}
}
