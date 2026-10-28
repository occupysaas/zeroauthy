package email

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
	"time"
)

type customQueue struct {
	inputs  []actions.EmailInput
	now     []actions.EmailInput
	outcome actions.EmailOutcome
	err     error
}

func (q *customQueue) EnqueueEmail(_ context.Context, _ store.Store, in actions.EmailInput) error {
	q.inputs = append(q.inputs, in)
	return q.err
}
func (q *customQueue) RunEmailNow(_ context.Context, in actions.EmailInput) (actions.EmailOutcome, error) {
	q.now = append(q.now, in)
	return q.outcome, q.err
}
func TestCustomEmailProvider(t *testing.T) {
	ctx, st, _, fallback, factory, s := emailServiceFixture(t)
	p := &store.EmailProvider{TenantID: "tenant-a", Name: "custom", Enabled: true, DefaultFrom: "sender@example.test"}
	if err := st.EmailProviders().Put(ctx, p, 0); err != nil {
		t.Fatal(err)
	}
	q := &customQueue{}
	s.Actions = q
	msg := Message{To: "u@example.test", Subject: "Verify", HTML: "<p>Verify</p>", Text: "Verify"}
	if err := s.SendMessage(ctx, "tenant-a", msg); err != nil {
		t.Fatal(err)
	}
	if len(q.inputs) != 1 || q.inputs[0].Message.HTML != msg.HTML || q.inputs[0].Message.From != p.DefaultFrom || len(fallback.messages) != 0 || len(factory.calls) != 0 {
		t.Fatalf("custom delivery: %+v", q.inputs)
	}
	q.err = store.ErrConflict
	if err := s.SendMessage(ctx, "tenant-a", msg); !errors.Is(err, ErrProviderConfiguration) {
		t.Fatalf("queue failure: %v", err)
	}
	q.err = nil
	s.Actions = nil
	if err := s.SendMessage(ctx, "tenant-a", msg); !errors.Is(err, ErrProviderConfiguration) {
		t.Fatalf("missing engine: %v", err)
	}
	p, _ = st.EmailProviders().Get(ctx, "tenant-a")
	p.Enabled = false
	if err := st.EmailProviders().Put(ctx, p, p.Revision); err != nil {
		t.Fatal(err)
	}
	if err := s.SendMessage(ctx, "tenant-a", msg); err != nil {
		t.Fatal(err)
	}
	if len(fallback.messages) != 1 {
		t.Fatal("disabled custom did not fall back")
	}
}

func TestCustomEmailProviderTestSend(t *testing.T) {
	ctx, st, _, _, _, s := emailServiceFixture(t)
	if err := st.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "tenant-a", Name: "custom", Enabled: true}, 0); err != nil {
		t.Fatal(err)
	}
	if err := st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: "tenant-a", Name: "verify_email", Fields: map[string]any{"body": "<p>Verify</p>", "subject": "Verify"}}, 0); err != nil {
		t.Fatal(err)
	}
	s.Actions = &actions.Engine{Store: st}
	out, err := s.SendTestOutcome(ctx, "tenant-a", "verify_email", "operator@example.test")
	if out != nil || !errors.Is(err, ErrProviderConfiguration) {
		t.Fatalf("unbound test send outcome=%+v err=%v", out, err)
	}
	if err := s.SendTest(ctx, "tenant-a", "verify_email", "operator@example.test"); !errors.Is(err, ErrProviderConfiguration) {
		t.Fatalf("unbound error-only API: %v", err)
	}
	if jobs, _ := st.Actions().ClaimJobs(ctx, s.clock(), time.Minute, 1); len(jobs) != 0 {
		t.Fatal("unbound test queued")
	}
	for _, status := range []string{"sent", "retry", "drop", "failed"} {
		q := &customQueue{outcome: actions.EmailOutcome{Status: status, Reason: "reason", ExecutionID: "execution"}}
		s.Actions = q
		out, err := s.SendTestOutcome(ctx, "tenant-a", "verify_email", "operator@example.test")
		if err != nil || out.Status != status || out.ExecutionID != "execution" || len(q.inputs) != 0 || len(q.now) != 1 || q.now[0].Message.Type != "try_provider_configuration_email" {
			t.Fatalf("outcome %+v %v queue %+v", out, err, q)
		}
	}
}
