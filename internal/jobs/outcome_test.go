package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type outcomeRecorder struct{ events []logs.Event }

func (r *outcomeRecorder) Record(_ context.Context, e logs.Event) { r.events = append(r.events, e) }
func TestImportJobOutcomeLogged(t *testing.T) {
	for _, status := range []store.JobStatus{store.JobCompleted, store.JobFailed} {
		t.Run(string(status), func(t *testing.T) {
			st := memory.New()
			ctx := context.Background()
			now := time.Now().UTC()
			j := &store.Job{TenantID: "t1", ID: "import", Type: store.JobUsersImport, Status: store.JobPending, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}
			if err := st.Jobs().Create(ctx, j); err != nil {
				t.Fatal(err)
			}
			j, err := st.Jobs().Claim(ctx, "owner", now, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			capture := &outcomeRecorder{}
			r := &Runner{Store: st, LeaseFor: time.Minute, Recorder: capture, Processors: map[store.JobType]Processor{store.JobUsersImport: procFunc(func(context.Context, store.Store, *store.Job, Lease) (store.JobStatus, string, error) {
				return status, "", nil
			})}}
			r.process(ctx, "owner", j)
			want := "sui"
			if status == store.JobFailed {
				want = "fui"
			}
			if len(capture.events) != 1 || capture.events[0].Type != want || capture.events[0].TenantID != "t1" {
				t.Fatalf("events=%+v", capture.events)
			}
			// A stale completion must never emit another event.
			r.process(ctx, "owner", j)
			if len(capture.events) != 1 {
				t.Fatalf("stale events=%+v", capture.events)
			}
		})
	}
}
