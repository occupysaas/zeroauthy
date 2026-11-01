package grpcstore

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/eventstream"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"strings"
	"testing"
	"time"
)

func TestActionJobReadCancel(t *testing.T) {
	s := inProcess(t)
	defer s.Close()
	storetest.TestActionJobReadCancel(t, s)
}

func TestActionJobReadCancelOldPlugin(t *testing.T) {
	c := serveWith(t, storev1.UnimplementedStoreServiceServer{})
	if _, err := c.Actions().GetJob(t.Context(), "t", "j"); !errors.Is(err, store.ErrActionsUnavailable) {
		t.Fatal(err)
	}
	if err := c.Actions().CancelJob(t.Context(), "t", "j"); !errors.Is(err, store.ErrActionsUnavailable) {
		t.Fatal(err)
	}
}

type oldActionJobPlugin struct {
	*Server
	missing string
}

func (p oldActionJobPlugin) ActionsGetJob(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	if p.missing == "GetJob" {
		return nil, status.Error(codes.Unimplemented, "RPC_SECRET_SENTINEL")
	}
	return p.Server.ActionsGetJob(ctx, q)
}
func (p oldActionJobPlugin) ActionsCancelJob(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	if p.missing == "CancelJob" {
		return nil, status.Error(codes.Unimplemented, "RPC_SECRET_SENTINEL")
	}
	return p.Server.ActionsCancelJob(ctx, q)
}
func TestActionJobReadCancelOldPluginPreservesActions(t *testing.T) {
	for _, missing := range []string{"GetJob", "CancelJob"} {
		t.Run(missing, func(t *testing.T) {
			c := serveWith(t, oldActionJobPlugin{Server: NewServer(memory.New()), missing: missing})
			defer c.Close()
			if err := c.CheckActionsSupport(t.Context()); err != nil {
				t.Fatal("prior Actions capability rejected", err)
			}
			if err := c.Tenants().Create(t.Context(), &store.Tenant{ID: "old", Name: "old"}); err != nil {
				t.Fatal(err)
			}
			if err := c.Actions().EnqueueJob(t.Context(), &store.ActionJob{TenantID: "old", ID: "prior", Trigger: "post-change-password", NextAt: time.Now()}); err != nil {
				t.Fatal("prior job enqueue", err)
			}
			err := eventstream.NewActionRunner(&actions.Engine{Store: c}).RunEventStream(t.Context(), "old", "act_event", []byte(`{"id":"evt_old"}`))
			if err == nil || !strings.Contains(err.Error(), "unavailable") || strings.Contains(err.Error(), "RPC_SECRET_SENTINEL") {
				t.Fatal("destination did not fail closed safely", err)
			}
			jobs, err := c.Actions().ClaimJobs(t.Context(), time.Now(), time.Minute, 10)
			if err != nil || len(jobs) != 1 || jobs[0].ID != "prior" {
				t.Fatalf("orphan job or prior feature broken %+v %v", jobs, err)
			}
		})
	}
}
