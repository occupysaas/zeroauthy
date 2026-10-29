package actions_test

import (
	"context"
	"errors"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
	"time"
)

func TestCustomEmailProvider(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	u := h.user("t1")
	renderer, err := email.NewRenderer()
	if err != nil {
		t.Fatal(err)
	}
	svc := &email.Service{Store: h.st, Actions: h.eng, Renderer: renderer, DefaultFrom: "from@example.test"}
	if err := h.st.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "t1", Name: "custom", Enabled: true}, 0); err != nil {
		t.Fatal(err)
	}
	if err := h.st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: "t1", Name: "verify_email", Fields: map[string]any{"subject": "Verify {{ user.email }}", "body": "<p>Verify {{ user.email }}</p>"}}, 0); err != nil {
		t.Fatal(err)
	}
	event := email.Event{TenantID: "t1", UserID: u.UserID, Template: "verify_email", Language: "de"}
	if err := svc.Send(ctx, event); !errors.Is(err, email.ErrProviderConfiguration) {
		t.Fatalf("unbound: %v", err)
	}
	if js, _ := h.st.Actions().ClaimJobs(ctx, h.clock(), time.Minute, 1); len(js) != 0 {
		t.Fatal("unbound queued")
	}
	a := h.action("t1", actions.TriggerCustomEmailProvider, "mail", `exports.onExecuteCustomEmailProvider=(e)=>{if(e.notification.from!=='from@example.test'||e.notification.to!==e.user.email||e.notification.subject!=='Verify '+e.user.email||e.notification.html!=='<p>Verify '+e.user.email+'</p>'||e.notification.locale!=='de'||e.notification.message_type!=='verify_email')throw Error('bad rendered event')}`, nil, false)
	h.bind("t1", a.Trigger, a)
	if err := svc.Send(ctx, event); err != nil {
		t.Fatal(err)
	}
	j := claimJob(t, h)
	n := finishJob(t, h, &j)
	if n.Status != "done" {
		t.Fatalf("rendered delivery: %+v", n)
	}
	for _, tc := range []struct{ code, status string }{{"", "sent"}, {"a.notification.retry('again')", "retry"}, {"a.notification.drop('done')", "drop"}, {"throw Error('failure')", "failed"}} {
		h.redeploy(a, `exports.onExecuteCustomEmailProvider=(e,a)=>{if(e.notification.message_type!=='try_provider_configuration_email')throw Error('bad test type');`+tc.code+`}`)
		h.bind("t1", a.Trigger, a)
		out, err := svc.SendTestOutcome(ctx, "t1", "verify_email", "operator@example.test")
		if out == nil || out.Status != tc.status || out.ExecutionID == "" {
			t.Fatalf("immediate: %+v %v", out, err)
		}
		if js, _ := h.st.Actions().ClaimJobs(ctx, h.clock().Add(time.Hour), time.Minute, 1); len(js) != 0 {
			t.Fatal("test send queued")
		}
	}
	// Real pending cap must propagate through the email provider boundary.
	for i := 0; i < actionsrules.Inventory().Limits["job_pending_per_tenant"]; i++ {
		if err := h.st.Actions().EnqueueJob(ctx, &store.ActionJob{TenantID: "t1", ID: fmt.Sprintf("cap-%d", i), Trigger: actions.TriggerCustomEmailProvider, Status: "pending", NextAt: h.clock()}); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.Send(ctx, event); !errors.Is(err, email.ErrProviderConfiguration) {
		t.Fatalf("pending cap: %v", err)
	}
}
