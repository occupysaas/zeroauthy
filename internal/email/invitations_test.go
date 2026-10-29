package email

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func invitationFixture(t *testing.T) (*Service, *actions.Engine, *store.OrganizationInvitation, *recordingMailer, *time.Time) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	st := memory.New()
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{8}, 32))
	mail := &recordingMailer{}
	renderer, _ := NewRenderer()
	for _, err := range []error{st.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "tenant"}), st.Organizations().Create(ctx, &store.Organization{TenantID: "t", ID: "org_1234567890123456", Name: "org"}, nil), st.Clients().Create(ctx, &store.Client{TenantID: "t", ClientID: "c", Name: "App"})} {
		if err != nil {
			t.Fatal(err)
		}
	}
	in := &store.OrganizationInvitation{TenantID: "t", OrganizationID: "org_1234567890123456", ID: "uinv_i", ClientID: "c", InviteeEmail: "invitee@example.test", ExpiresAt: now.Add(30 * 24 * time.Hour)}
	if _, err := orglogin.IssueInvitationTicket(w, in, "https://app.example/login", "org"); err != nil {
		t.Fatal(err)
	}
	if err := st.OrganizationsII().CreateInvitation(ctx, in); err != nil {
		t.Fatal(err)
	}
	s := &Service{Store: st, Wrapper: w, Renderer: renderer, Fallback: mail, DefaultFrom: "sender@example.test", Now: func() time.Time { return now }}
	e := &actions.Engine{Store: st, Secrets: w, Now: func() time.Time { return now }, InvitationEmail: s}
	return s, e, in, mail, &now
}
func enqueueInvitation(t *testing.T, e *actions.Engine) *store.ActionJob {
	t.Helper()
	ctx := context.Background()
	err := e.Store.WithTx(ctx, func(tx store.Store) error {
		return e.EnqueueInvitation(ctx, tx, actions.InvitationDelivery{TenantID: "t", OrganizationID: "org_1234567890123456", InvitationID: "uinv_i", ClientID: "c", InviterName: "A <script>", OrganizationDisplayName: "Team & Co", ApplicationName: "Frozen App", TenantName: "tenant", Language: "fr", NotificationHost: "login.example.test"})
	})
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := e.Store.Actions().ClaimJobs(ctx, e.Now(), time.Minute, 1)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim: %v %v", jobs, err)
	}
	return &jobs[0]
}
func TestInvitationEmailLifecycle(t *testing.T) {
	s, e, in, mail, _ := invitationFixture(t)
	job := enqueueInvitation(t, e)
	next := e.RunJob(context.Background(), job)
	if next == nil || next.Status != "done" || len(mail.messages) != 1 {
		t.Fatalf("delivery: %v, %d", next, len(mail.messages))
	}
	msg := mail.messages[0]
	if strings.Contains(msg.HTML, "<script>") || !strings.Contains(msg.HTML, "A &lt;script&gt;") || !strings.Contains(msg.Text, "Frozen App") || msg.Locale != "fr" {
		t.Fatalf("unsafe/missing frozen context: %+v", msg)
	}
	ticket, _ := orglogin.OpenInvitationTicket(s.Wrapper, in)
	if !strings.Contains(msg.Text, ticket.URL) {
		t.Fatal("URL changed")
	}
	if !strings.Contains(msg.Subject, "invitation") {
		t.Fatal("missing localized subject")
	}
	t.Run("stored override frozen", func(t *testing.T) {
		s, e, _, m, _ := invitationFixture(t)
		ctx := context.Background()
		tmpl := &store.EmailTemplate{TenantID: "t", Name: "user_invitation", Fields: map[string]any{"enabled": true, "body": "<p>{{ inviter.name | escape }} {{ application.name }} {{ url }}</p>", "subject": "Stored {{ organization.display_name }}", "urlLifetimeInSeconds": float64(60)}}
		if err := s.Store.EmailTemplates().Put(ctx, tmpl, 0); err != nil {
			t.Fatal(err)
		}
		j := enqueueInvitation(t, e)
		if n := e.RunJob(ctx, j); n.Status != "done" || len(m.messages) != 1 || !strings.HasPrefix(m.messages[0].Subject, "Stored Team") {
			t.Fatalf("stored: %v %v", n, m.messages)
		}
	})
	t.Run("disabled", func(t *testing.T) {
		s, e, _, m, _ := invitationFixture(t)
		ctx := context.Background()
		if err := s.Store.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: "t", Name: "user_invitation", Fields: map[string]any{"enabled": false}}, 0); err != nil {
			t.Fatal(err)
		}
		j := enqueueInvitation(t, e)
		if n := e.RunJob(ctx, j); n.Status != "done" || len(m.messages) != 0 {
			t.Fatalf("disabled: %v", n)
		}
	})
}
func TestInvitationEmailRetrySameTicket(t *testing.T) {
	s, e, in, m, now := invitationFixture(t)
	m.err = errors.New("provider unavailable")
	j := enqueueInvitation(t, e)
	n := e.RunJob(context.Background(), j)
	if n == nil || n.Status != "pending" {
		t.Fatalf("retry: %v", n)
	}
	if err := e.Store.Actions().FinishJob(context.Background(), n, j.LeaseUntil); err != nil {
		t.Fatal(err)
	}
	*now = n.NextAt
	m.err = nil
	jobs, err := e.Store.Actions().ClaimJobs(context.Background(), *now, time.Minute, 1)
	if err != nil || len(jobs) != 1 {
		t.Fatal(err)
	}
	if n = e.RunJob(context.Background(), &jobs[0]); n.Status != "done" {
		t.Fatal(n)
	}
	if len(m.messages) != 2 || m.messages[0].Text != m.messages[1].Text {
		t.Fatal("retry changed message")
	}
	got, err := s.Store.OrganizationsII().GetInvitation(context.Background(), "t", "org_1234567890123456", in.ID)
	if err != nil || !got.ExpiresAt.Equal(in.ExpiresAt) {
		t.Fatal("invitation changed")
	}
}
func TestInvitationEmailRestartAfterSend(t *testing.T) {
	_, e, _, m, now := invitationFixture(t)
	j := enqueueInvitation(t, e)
	if n := e.RunJob(context.Background(), j); n.Status != "done" {
		t.Fatal(n)
	}
	*now = now.Add(2 * time.Minute)
	jobs, _ := e.Store.Actions().ClaimJobs(context.Background(), *now, time.Minute, 1)
	if len(jobs) != 1 {
		t.Fatal("lease not recovered")
	}
	restarted := &actions.Engine{Store: e.Store, Secrets: e.Secrets, Now: e.Now, InvitationEmail: e.InvitationEmail}
	if n := restarted.RunJob(context.Background(), &jobs[0]); n.Status != "done" {
		t.Fatal(n)
	}
	if len(m.messages) != 2 || m.messages[0].Text != m.messages[1].Text {
		t.Fatal("restart changed ticket")
	}
}
func TestInvitationEmailInactiveNoSend(t *testing.T) {
	for _, kind := range []string{"expired", "deleted", "consumed"} {
		t.Run(kind, func(t *testing.T) {
			s, e, in, m, now := invitationFixture(t)
			j := enqueueInvitation(t, e)
			ctx := context.Background()
			switch kind {
			case "expired":
				*now = in.ExpiresAt
			case "deleted":
				if err := s.Store.OrganizationsII().DeleteInvitation(ctx, "t", "org_1234567890123456", in.ID); err != nil {
					t.Fatal(err)
				}
			case "consumed":
				if err := s.Store.Users().Create(ctx, &store.User{TenantID: "t", UserID: "u"}); err != nil {
					t.Fatal(err)
				}
				if err := s.Store.WithTx(ctx, func(tx store.Store) error {
					_, err := tx.OrganizationsII().ConsumeInvitation(ctx, "t", "org_1234567890123456", in.ID, "tx", "u", *now)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			if n := e.RunJob(ctx, j); n.Status != "done" || len(m.messages) != 0 {
				t.Fatalf("inactive sent: %v", n)
			}
		})
	}
}

func TestInvitationEmailProviderFailureFrozenSelection(t *testing.T) {
	s, e, in, fallback, now := invitationFixture(t)
	ctx := context.Background()
	factory := &recordingFactory{sendErr: errors.New("transport unavailable")}
	s.Providers = factory
	p := &store.EmailProvider{TenantID: "t", Name: "sendgrid", Enabled: true, DefaultFrom: "provider@example.test", SealedCredentials: providerSecret(t, s.Wrapper, "t", "sendgrid", "original-key")}
	if err := s.Store.EmailProviders().Put(ctx, p, 0); err != nil {
		t.Fatal(err)
	}
	j := enqueueInvitation(t, e)
	p, err := s.Store.EmailProviders().Get(ctx, "t")
	if err != nil {
		t.Fatal(err)
	}
	p.SealedCredentials = providerSecret(t, s.Wrapper, "t", "sendgrid", "replacement-key")
	if err = s.Store.EmailProviders().Put(ctx, p, p.Revision); err != nil {
		t.Fatal(err)
	}
	n := e.RunJob(ctx, j)
	if n.Status != "pending" || len(fallback.messages) != 0 {
		t.Fatal("provider failure must retry without fallback")
	}
	if err = s.Store.Actions().FinishJob(ctx, n, j.LeaseUntil); err != nil {
		t.Fatal(err)
	}
	*now = n.NextAt
	factory.sendErr = nil
	js, err := s.Store.Actions().ClaimJobs(ctx, *now, time.Minute, 1)
	if err != nil || len(js) != 1 {
		t.Fatal(err)
	}
	if n = e.RunJob(ctx, &js[0]); n.Status != "done" {
		t.Fatal(n.Status)
	}
	calls := factory.snapshot()
	if len(calls) != 2 || calls[0].message.Text != calls[1].message.Text || calls[1].config.Credentials["api_key"] != "original-key" {
		t.Fatal("provider selection or message changed")
	}
	active, err := s.Store.OrganizationsII().GetInvitation(ctx, "t", in.OrganizationID, in.ID)
	if err != nil || active.TicketHash != in.TicketHash || !active.ExpiresAt.Equal(in.ExpiresAt) {
		t.Fatal("provider failure invalidated invitation")
	}
}

func TestInvitationEmailDeletionDuringSendInvalidatesLink(t *testing.T) {
	s, e, in, _, _ := invitationFixture(t)
	ctx := context.Background()
	factory := &recordingFactory{entered: make(chan struct{}, 1), release: make(chan struct{})}
	s.Providers = factory
	if err := s.Store.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "t", Name: "sendgrid", Enabled: true, SealedCredentials: providerSecret(t, s.Wrapper, "t", "sendgrid", "key")}, 0); err != nil {
		t.Fatal(err)
	}
	j := enqueueInvitation(t, e)
	done := make(chan *store.ActionJob, 1)
	go func() { done <- e.RunJob(ctx, j) }()
	select {
	case <-factory.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("transport not reached")
	}
	err := s.Store.OrganizationsII().DeleteInvitation(ctx, "t", in.OrganizationID, in.ID)
	close(factory.release)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case n := <-done:
		if n.Status != "done" {
			t.Fatal(n.Status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("send did not complete")
	}
	if _, err := s.Store.OrganizationsII().FindInvitation(ctx, "t", in.TicketHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("deleted link still resolves")
	}
}

func TestInvitationEmailProviderSenderPrecedence(t *testing.T) {
	for _, tc := range []struct{ name, templateFrom, want string }{
		{"provider default", "", "provider@example.test"},
		{"stored template from", "template@example.test", "template@example.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, e, _, fallback, _ := invitationFixture(t)
			ctx := context.Background()
			factory := &recordingFactory{}
			s.Providers = factory
			if err := s.Store.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "t", Name: "sendgrid", Enabled: true, DefaultFrom: "provider@example.test", SealedCredentials: providerSecret(t, s.Wrapper, "t", "sendgrid", "key")}, 0); err != nil {
				t.Fatal(err)
			}
			if tc.templateFrom != "" {
				if err := s.Store.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: "t", Name: "user_invitation", Fields: map[string]any{"from": tc.templateFrom, "body": "<p>{{ url }}</p>", "subject": "Invitation"}}, 0); err != nil {
					t.Fatal(err)
				}
			}
			j := enqueueInvitation(t, e)
			if n := e.RunJob(ctx, j); n.Status != "done" {
				t.Fatal(n.Status)
			}
			calls := factory.snapshot()
			if len(calls) != 1 || len(fallback.messages) != 0 {
				t.Fatalf("provider calls %d fallback calls %d", len(calls), len(fallback.messages))
			}
			if calls[0].message.From != tc.want {
				t.Fatalf("From = %q, want %q", calls[0].message.From, tc.want)
			}
		})
	}
}
