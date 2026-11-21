package actions

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/logout"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
)

type logoutJobProcessor struct{ calls int }

func (p *logoutJobProcessor) Deliver(_ context.Context, j *store.ActionJob) *store.ActionJob {
	p.calls++
	out := *j
	out.Status = "done"
	return &out
}
func (p *logoutJobProcessor) Finished(context.Context, *store.ActionJob) {}
func TestBackchannelJobDispatch(t *testing.T) {
	p := &logoutJobProcessor{}
	engine := &Engine{BackchannelLogout: p}
	next := engine.RunJob(t.Context(), &store.ActionJob{TenantID: "t", ID: "job", Trigger: logout.JobKind, Status: "pending"})
	if next == nil || next.Status != "done" || p.calls != 1 {
		t.Fatal("logout job did not dispatch to its processor")
	}
}
