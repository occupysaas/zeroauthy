package mgmt_test

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/url"
	"strings"
	"testing"
)

type enrollmentQueue struct{ inputs []actions.EmailInput }

func (q *enrollmentQueue) EnqueueEmail(_ context.Context, _ store.Store, in actions.EmailInput) error {
	q.inputs = append(q.inputs, in)
	return nil
}
func (q *enrollmentQueue) RunEmailNow(context.Context, actions.EmailInput) (actions.EmailOutcome, error) {
	return actions.EmailOutcome{}, nil
}
func TestEnrollmentTicketTenantCustomProviderAndTemplate(t *testing.T) {
	e, uid := mfaUser(t)
	renderer, err := email.NewRenderer()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err = e.st.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: e.tn.ID, Name: "custom", Enabled: true, DefaultFrom: "sender@example.test"}, 0); err != nil {
		t.Fatal(err)
	}
	if err = e.st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: e.tn.ID, Name: "enrollment_email", Fields: map[string]any{"subject": "Enrollment invitation", "body": "<p>{{ url }}</p>"}}, 0); err != nil {
		t.Fatal(err)
	}
	q := &enrollmentQueue{}
	e.h.EmailService = &email.Service{Store: e.st, Wrapper: e.w, Renderer: renderer, Actions: q}
	r, out := mfaCall(t, e.clientsEnv, "CreateGuardianEnrollmentTicket", "", "", map[string]any{"user_id": uid, "factor": "otp", "send_mail": true, "email": "invitation@example.test", "email_locale": "fr", "allow_multiple_enrollments": true}, "")
	if r.Code != 200 {
		t.Fatalf("%d %s", r.Code, r.Body)
	}
	ticketURL := out.(map[string]any)["ticket_url"].(string)
	if len(q.inputs) != 1 || !strings.Contains(q.inputs[0].Message.HTML, ticketURL) || q.inputs[0].Message.Subject != "Enrollment invitation" || q.inputs[0].Message.To != "invitation@example.test" || q.inputs[0].Message.Type != "enrollment_email" {
		t.Fatalf("tenant provider/template: %+v", q.inputs)
	}
	parsed, _ := url.Parse(ticketURL)
	raw := parsed.Query().Get("ticket")
	ticket, err := e.st.MFA().ConsumeTicket(ctx, e.tn.ID, secrets.HashToken(raw), now)
	if err != nil || ticket.UserID != uid || ticket.Factor != "otp" || !ticket.AllowMultiple || ticket.ExpiresAt.Sub(now) < 7*24*60*60*1e9 {
		t.Fatal(ticket, err)
	}
	if _, err = e.st.MFA().ConsumeTicket(ctx, e.tn.ID, secrets.HashToken(raw), now); err == nil {
		t.Fatal("ticket replay")
	}
}
