package dbconn

import (
	"bytes"
	"context"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/email/providers"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type countedResetStore struct {
	store.Store
	creates int
}
type countedResetRepo struct {
	store.PasswordResetTickets
	owner *countedResetStore
}

func (s *countedResetStore) PasswordResetTickets() store.PasswordResetTickets {
	return countedResetRepo{PasswordResetTickets: s.Store.PasswordResetTickets(), owner: s}
}
func (r countedResetRepo) Create(ctx context.Context, t *store.PasswordResetTicket) error {
	r.owner.creates++
	return r.PasswordResetTickets.Create(ctx, t)
}

func TestResetEmailTemplateTicketPolicy(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tn, err := e.st.Tenants().Get(ctx, e.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	user, err := e.st.Users().FindByLogin(ctx, e.tenantID, "Username-Password-Authentication", "alice@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := e.st.Connections().GetByName(ctx, e.tenantID, "Username-Password-Authentication")
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{"body": "<a href=\"{{ url }}\">reset</a>", "subject": "Reset", "enabled": true, "syntax": "liquid", "urlLifetimeInSeconds": 3600, "resultUrl": "https://acme.example.test/after", "includeEmailInRedirect": true}
	if err = e.st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: e.tenantID, Name: "reset_email", Fields: fields}, 0); err != nil {
		t.Fatal(err)
	}
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{6}, 32))
	renderer, _ := email.NewRenderer()
	svc := &email.Service{Store: e.st, Wrapper: w, Renderer: renderer, Providers: &providers.Factory{}, Fallback: e.mail, DefaultFrom: "zeroauthy@example.test", Now: fixedNow}
	counted := &countedResetStore{Store: e.st}
	h := *e.h
	h.Store = counted
	h.Email = svc
	if err = h.StartReset(ctx, tenant.Resolved{Tenant: tn, Host: "acme.example.test"}, conn, user, "app", "en"); err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`ticket=([A-Za-z0-9]{43})`).FindStringSubmatch(e.mail.sent[0].HTML)
	if len(match) != 2 {
		t.Fatalf("reset email=%+v", e.mail.sent[0])
	}
	tk, err := e.st.PasswordResetTickets().GetByTokenHash(ctx, e.tenantID, secrets.HashToken(match[1]))
	if err != nil {
		t.Fatal(err)
	}
	if !tk.ExpiresAt.Equal(fixedNow().Add(time.Hour)) || tk.ResultURL != "https://acme.example.test/after" || !tk.IncludeEmailInRedirect || tk.ClientID != "app" {
		t.Fatalf("ticket policy=%+v", tk)
	}
	created := counted.creates
	current, _ := e.st.EmailTemplates().Get(ctx, e.tenantID, "reset_email")
	current.Fields["enabled"] = false
	if err = e.st.EmailTemplates().Put(ctx, current, current.Revision); err != nil {
		t.Fatal(err)
	}
	if err = h.StartReset(ctx, tenant.Resolved{Tenant: tn, Host: "acme.example.test"}, conn, user, "app", "en"); err != nil {
		t.Fatal(err)
	}
	if counted.creates != created || len(e.mail.sent) != 1 {
		t.Fatal("disabled reset template issued ticket or sent mail")
	}
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// A panic in a background send is recovered and logged without its value,
// which could hold the message; it must not crash the process.
func TestGoRunRecoversPanic(t *testing.T) {
	var out syncBuffer
	h := &Handlers{Log: slog.New(slog.NewTextHandler(&out, nil))} // Go is nil: the go statement
	h.goRun(func() { panic("send https://x.test/u/reset-password?ticket=SECRET") })
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), "level=ERROR") {
		if time.Now().After(deadline) {
			t.Fatal("panic was not logged")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if strings.Contains(out.String(), "SECRET") {
		t.Fatalf("log contains the panic value: %s", out.String())
	}
}
