package grpcstore

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/jobs"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sync/atomic"
	"testing"
	"time"
)

func TestJobSweepOutcomes(t *testing.T) {
	for name, open := range map[string]func(*testing.T) *Client{"memory": inProcess, "sqlite": inProcessSQLite} {
		t.Run(name, func(t *testing.T) { storetest.JobSweepOutcomes(t, func(t *testing.T) store.Store { return open(t) }) })
	}
}

// An older plugin ignores the additive request field. The same simulation
// can lose the response after committing: neither case may replay the write.
type legacyJobOutcomePlugin struct {
	*Server
	calls        atomic.Int32
	loseResponse bool
}

func (p *legacyJobOutcomePlugin) JobsDeleteExpired(ctx context.Context, q *storev1.DeleteExpiredRequest) (*storev1.CountResult, error) {
	p.calls.Add(1)
	q.JobOutcomeLimit = 0
	r, err := p.Server.JobsDeleteExpired(ctx, q)
	if p.loseResponse {
		return nil, status.Error(codes.Unavailable, "response lost after commit")
	}
	return r, err
}

type jobOutcomeCapture struct{ events []logs.Event }

func (c *jobOutcomeCapture) Record(_ context.Context, e logs.Event) { c.events = append(c.events, e) }

func TestJobSweepOldPluginAndLostResponseNeverReplay(t *testing.T) {
	for _, lose := range []bool{false, true} {
		t.Run(map[bool]string{false: "old response", true: "lost response"}[lose], func(t *testing.T) {
			backing := memory.New()
			plugin := &legacyJobOutcomePlugin{Server: NewServer(backing), loseResponse: lose}
			client := serveWith(t, plugin)
			defer client.Close()
			defer plugin.Close()
			now := time.Now().UTC()
			ctx := context.Background()
			if err := backing.Jobs().Create(ctx, &store.Job{TenantID: "t", ID: "job", Type: store.JobUsersImport, Status: store.JobProcessing, FirstClaimedAt: now.Add(-store.JobMaxRuntime - time.Minute), ExpiresAt: now.Add(time.Hour), Input: []byte("private import")}); err != nil {
				t.Fatal(err)
			}
			capture := &jobOutcomeCapture{}
			_, err := jobs.SweepExpired(logs.WithRecorder(ctx, capture), client.Jobs(), now)
			if (err != nil) != lose {
				t.Fatalf("err=%v", err)
			}
			if plugin.calls.Load() != 1 || len(capture.events) != 0 {
				t.Fatalf("replay/guessed event: calls=%d events=%+v", plugin.calls.Load(), capture.events)
			}
			j, err := backing.Jobs().Get(ctx, "t", "job")
			if err != nil || j.Status != store.JobFailed || len(j.Input) != 0 {
				t.Fatalf("business cleanup=%+v %v", j, err)
			}
		})
	}
}

func TestJobSweepPreJobsPlugin(t *testing.T) {
	client := serveWith(t, &storev1.UnimplementedStoreServiceServer{})
	defer client.Close()
	n, outcomes, more, err := client.Jobs().(store.JobsOutcomeWriter).DeleteExpiredResult(context.Background(), time.Now(), store.JobSweepBatch)
	if err != nil || n != 0 || len(outcomes) != 0 || more {
		t.Fatal(n, outcomes, more, err)
	}
}
