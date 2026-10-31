package storetest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// JobSweepOutcomes verifies actual bounded atomic writes, without hydrating
// imported users. The same assertions exercise native and real gRPC stores.
func JobSweepOutcomes(t *testing.T, factory Factory) {
	ctx := context.Background()
	t.Run("BoundedAndCascade", func(t *testing.T) {
		st := open(t, factory)
		writer, ok := st.Jobs().(store.JobsOutcomeWriter)
		if !ok {
			t.Fatal("atomic job sweep outcome report missing")
		}
		before := jt(store.JobMaxRuntime + time.Hour)
		for _, tid := range []string{"ten_a", "ten_b"} {
			mustNoErr(t, st.Tenants().Create(ctx, &store.Tenant{ID: tid, Name: tid}))
			for i := range 3 {
				j := newJob(tid, fmt.Sprintf("job_%d", i), store.JobUsersImport)
				j.Status = store.JobProcessing
				j.Input = []byte(`[{"password":"private-import-password","custom_password_hash":{"hash":"private-hash"}}]`)
				if i == 1 {
					j.FirstClaimedAt = before
					j.Attempts = store.JobMaxAttempts
				}
				if i == 2 {
					j.Type = store.JobUsersExport
					j.ExpiresAt = before.Add(-time.Second)
				}
				mustNoErr(t, st.Jobs().Create(ctx, j))
				mustNoErr(t, st.Jobs().Checkpoint(ctx, tid, j.ID, j.LeaseOwner, 1, store.JobSummary{}, []store.JobError{jobErr(0)}))
				mustNoErr(t, st.Jobs().AppendFile(ctx, tid, j.ID, j.LeaseOwner, 0, []byte("private file")))
			}
		}
		seen := map[string]bool{}
		deleted := 0
		for calls := 0; ; calls++ {
			if calls > 6 {
				t.Fatal("batch did not drain")
			}
			n, outcomes, more, err := writer.DeleteExpiredResult(ctx, before, 2)
			mustNoErr(t, err)
			deleted += n
			if len(outcomes) > 2 {
				t.Fatalf("unbounded report: %d", len(outcomes))
			}
			for _, outcome := range outcomes {
				key := outcome.TenantID + "/" + outcome.ID
				if seen[key] {
					t.Fatalf("duplicate outcome: %+v", outcome)
				}
				seen[key] = true
				if outcome.Status != store.JobFailed || !outcome.UpdatedAt.Equal(before) {
					t.Fatalf("outcome=%+v", outcome)
				}
			}
			if !more {
				break
			}
		}
		if len(seen) != 6 || deleted != 2 {
			t.Fatalf("outcomes=%v deleted=%d", seen, deleted)
		}
		for _, tid := range []string{"ten_a", "ten_b"} {
			for i, detail := range []string{store.JobDetailTimedOut, store.JobDetailWorkerLost} {
				j, err := st.Jobs().Get(ctx, tid, fmt.Sprintf("job_%d", i))
				mustNoErr(t, err)
				if j.Status != store.JobFailed || j.StatusDetails != detail || len(j.Input) != 0 || j.LeaseOwner != "" {
					t.Fatalf("failed job=%+v", j)
				}
			}
			if _, err := st.Jobs().Get(ctx, tid, "job_2"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("expired job=%v", err)
			}
			if _, err := st.Jobs().Errors(ctx, tid, "job_2"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("expired errors=%v", err)
			}
			if err := st.Jobs().ReadFile(ctx, tid, "job_2", func([]byte) error { t.Error("expired chunk"); return nil }); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("expired file=%v", err)
			}
		}
		n, outcomes, more, err := writer.DeleteExpiredResult(ctx, before, 2)
		mustNoErr(t, err)
		if n != 0 || len(outcomes) != 0 || more {
			t.Fatalf("noop=%d %+v %v", n, outcomes, more)
		}
		_, _, _, err = writer.DeleteExpiredResult(ctx, before, store.JobSweepBatch+1)
		if !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("unbounded limit=%v", err)
		}
	})
	t.Run("RollbackAndRace", func(t *testing.T) {
		st := open(t, factory)
		if _, ok := st.Jobs().(store.JobsOutcomeWriter); !ok {
			t.Fatal("atomic job sweep outcome report missing")
		}
		mustNoErr(t, st.Tenants().Create(ctx, &store.Tenant{ID: "ten_a", Name: "ten_a"}))
		j := newJob("ten_a", "job", store.JobUsersImport)
		j.Status = store.JobProcessing
		mustNoErr(t, st.Jobs().Create(ctx, j))
		before := jt(store.JobMaxRuntime + time.Hour)
		abort := errors.New("rollback sweep")
		err := st.WithTx(ctx, func(tx store.Store) error {
			_, outcomes, _, err := tx.Jobs().(store.JobsOutcomeWriter).DeleteExpiredResult(ctx, before, 1)
			if err != nil {
				return err
			}
			if len(outcomes) != 1 {
				t.Fatalf("tx outcomes=%+v", outcomes)
			}
			return abort
		})
		if !errors.Is(err, abort) {
			t.Fatal(err)
		}
		got, err := st.Jobs().Get(ctx, "ten_a", "job")
		mustNoErr(t, err)
		if got.Status != store.JobProcessing || len(got.Input) == 0 {
			t.Fatalf("rollback=%+v", got)
		}
		var wg sync.WaitGroup
		results := make(chan []store.JobOutcome, 2)
		errs := make(chan error, 2)
		for range 2 {
			wg.Go(func() {
				_, outcomes, _, err := st.Jobs().(store.JobsOutcomeWriter).DeleteExpiredResult(ctx, before, 1)
				results <- outcomes
				errs <- err
			})
		}
		wg.Wait()
		close(results)
		close(errs)
		for err := range errs {
			mustNoErr(t, err)
		}
		count := 0
		for outcomes := range results {
			count += len(outcomes)
		}
		if count != 1 {
			t.Fatalf("racing sweep reports=%d", count)
		}
	})
}
