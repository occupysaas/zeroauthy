package email

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/email/providers"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/sqlstore"
)

type sqlEmailTransport struct {
	mu       sync.Mutex
	messages []providers.Message
	failure  error
}

func (t *sqlEmailTransport) Send(_ context.Context, m providers.Message) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.messages = append(t.messages, m)
	return t.failure
}

type sqlEmailFactory struct {
	transport *sqlEmailTransport
	mu        sync.Mutex
	revisions []int64
	creds     []map[string]any
}

func (f *sqlEmailFactory) New(_ context.Context, _ string, rev int64, cfg providers.Config) (providers.Transport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revisions = append(f.revisions, rev)
	f.creds = append(f.creds, cfg.Credentials)
	return f.transport, nil
}

type sqlEmailFallback struct {
	mu       sync.Mutex
	messages []Message
}

func (f *sqlEmailFallback) Send(_ context.Context, m Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.messages = append(f.messages, m)
	return nil
}

func TestSQLTwoServerCurrentConfigClaimsRestartAndLegacyFallback(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "two-server-email.db")
	open := func() *sqlstore.Store {
		s, err := sqlstore.Open(ctx, "sqlite://"+path)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		return s
	}
	a, b := open(), open()
	defer a.Close()
	defer b.Close()
	if err := a.Tenants().Create(ctx, &store.Tenant{ID: "mail-tenant", Name: "mail-tenant", FriendlyName: "Mail tenant", DefaultAudience: "https://api.example.test"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Tenants().Create(ctx, &store.Tenant{ID: "legacy-tenant", Name: "legacy-tenant", FriendlyName: "Legacy tenant"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Users().Create(ctx, &store.User{TenantID: "mail-tenant", UserID: "auth0|welcome", Email: "welcome@example.test", EmailVerified: true}); err != nil {
		t.Fatal(err)
	}
	if err := a.Users().Create(ctx, &store.User{TenantID: "mail-tenant", UserID: "auth0|security", Email: "security@example.test", EmailVerified: true}); err != nil {
		t.Fatal(err)
	}
	if err := a.Users().Create(ctx, &store.User{TenantID: "mail-tenant", UserID: "auth0|failure", Email: "failure@example.test", EmailVerified: true}); err != nil {
		t.Fatal(err)
	}
	w, err := keys.NewLocalWrapper(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	seal := func(value string) []byte {
		raw, _ := json.Marshal(map[string]string{"api_key": value})
		sealed, e := keys.SealEmailProvider(w, "mail-tenant", "sendgrid", raw)
		if e != nil {
			t.Fatal(e)
		}
		return sealed
	}
	if err = a.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "mail-tenant", Name: "sendgrid", Enabled: true, DefaultFrom: "first@example.test", SealedCredentials: seal("first-private")}, 0); err != nil {
		t.Fatal(err)
	}
	for _, spec := range []struct{ name, body string }{{"welcome_email", "Welcome {{ user.email | escape }}"}, {"blocked_account", "Blocked {{ user.email | escape }}"}, {"stolen_credentials", "Breach {{ user.email | escape }}"}} {
		if err = a.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: "mail-tenant", Name: spec.name, Fields: map[string]any{"template": spec.name, "body": spec.body, "subject": "M21 {{ tenant.name }}", "enabled": true}}, 0); err != nil {
			t.Fatal(err)
		}
	}
	transport := &sqlEmailTransport{}
	factory := &sqlEmailFactory{transport: transport}
	fallback := &sqlEmailFallback{}
	renderer, _ := NewRenderer()
	service := func(st store.Store) *Service {
		return &Service{Store: st, Wrapper: w, Renderer: renderer, Providers: factory, Fallback: fallback, DefaultFrom: "legacy@example.test", Now: func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }}
	}
	serviceB := service(b)
	if err = serviceB.Welcome(ctx, "mail-tenant", "auth0|welcome", "", "en"); err != nil {
		t.Fatal(err)
	}
	if err = service(a).Welcome(ctx, "mail-tenant", "auth0|welcome", "", "en"); err != nil {
		t.Fatal(err)
	}
	if err = serviceB.Notify(ctx, "mail-tenant", "auth0|security", "blocked_account"); err != nil {
		t.Fatal(err)
	}
	if err = service(a).Notify(ctx, "mail-tenant", "auth0|security", "blocked_account"); err != nil {
		t.Fatal(err)
	}
	if err = serviceB.Notify(ctx, "mail-tenant", "auth0|security", "stolen_credentials"); err != nil {
		t.Fatal(err)
	}
	if len(transport.messages) != 3 {
		t.Fatalf("deduped welcome/protection sends = %d, want 3", len(transport.messages))
	}
	if len(factory.revisions) != 3 || factory.revisions[0] != 1 {
		t.Fatalf("first provider snapshots = %v", factory.revisions)
	}
	updated := &store.EmailProvider{TenantID: "mail-tenant", Name: "sendgrid", Enabled: true, DefaultFrom: "second@example.test", SealedCredentials: seal("second-private")}
	if err = a.EmailProviders().Put(ctx, updated, 1); err != nil {
		t.Fatal(err)
	}
	if err = serviceB.SendMessage(ctx, "mail-tenant", Message{To: "config@example.test", Subject: "current", Text: "current"}); err != nil {
		t.Fatal(err)
	}
	if got := factory.revisions[len(factory.revisions)-1]; got != 2 {
		t.Fatalf("second server saw stale provider revision %d", got)
	}
	if got := factory.creds[len(factory.creds)-1]["api_key"]; got != "second-private" {
		t.Fatalf("second server used stale credentials: %v", got)
	}

	// Test-send claims share the fixed window across server instances and remain consumed after the attempted send.
	now := time.Date(2026, 10, 25, 12, 3, 0, 0, time.UTC)
	start := now.Truncate(10 * time.Minute)
	end := start.Add(10 * time.Minute)
	for i := 0; i < 3; i++ {
		ok, e := a.EmailNotifications().Claim(ctx, "mail-tenant", "operator", "test", start.Format("200601021504"), now, end, 3)
		if e != nil || !ok {
			t.Fatalf("test claim %d = %v,%v", i, ok, e)
		}
	}
	if ok, e := b.EmailNotifications().Claim(ctx, "mail-tenant", "operator", "test", start.Format("200601021504"), now, end, 3); e != nil || ok {
		t.Fatalf("distributed fourth test claim = %v,%v", ok, e)
	}

	if err = serviceB.SendMessage(ctx, "legacy-tenant", Message{To: "old@example.test", Subject: "legacy", Text: "legacy"}); err != nil {
		t.Fatal(err)
	}
	if len(fallback.messages) != 1 || fallback.messages[0].To != "old@example.test" {
		t.Fatalf("legacy fallback changed: %+v", fallback.messages)
	}
	transport.failure = errors.New("fixture failure")
	failedTestWindow := start.Add(10 * time.Minute)
	claimed, err := a.EmailNotifications().Claim(ctx, "mail-tenant", "operator", "test", failedTestWindow.Format("200601021504"), now, failedTestWindow.Add(10*time.Minute), 3)
	if err != nil || !claimed {
		t.Fatalf("failed test-send claim = %v, %v", claimed, err)
	}
	if err = serviceB.SendTest(ctx, "mail-tenant", "welcome_email", "operator@example.test"); err == nil {
		t.Fatal("failed test-send delivery was hidden")
	}
	for i := 0; i < 2; i++ {
		claimed, err = b.EmailNotifications().Claim(ctx, "mail-tenant", "operator", "test", failedTestWindow.Format("200601021504"), now, failedTestWindow.Add(10*time.Minute), 3)
		if err != nil || !claimed {
			t.Fatalf("distributed test claim %d after failed send = %v, %v", i, claimed, err)
		}
	}
	claimed, err = a.EmailNotifications().Claim(ctx, "mail-tenant", "operator", "test", failedTestWindow.Format("200601021504"), now, failedTestWindow.Add(10*time.Minute), 3)
	if err != nil || claimed {
		t.Fatalf("failed test-send attempt was refunded from distributed limit: %v, %v", claimed, err)
	}
	if err = serviceB.Welcome(ctx, "mail-tenant", "auth0|failure", "", "en"); err == nil {
		t.Fatal("provider failure was hidden")
	}
	if err = service(a).Welcome(ctx, "mail-tenant", "auth0|failure", "", "en"); err != nil {
		t.Fatal(err)
	}
	if len(transport.messages) != 6 || len(fallback.messages) != 1 {
		t.Fatal("failed tenant provider retried or fell back")
	}
	if err = b.Close(); err != nil {
		t.Fatal(err)
	}
	b = open()
	defer b.Close()
	if ok, e := b.EmailNotifications().Claim(ctx, "mail-tenant", "operator", "test", start.Format("200601021504"), now, end, 3); e != nil || ok {
		t.Fatalf("claim lost after restart = %v,%v", ok, e)
	}
	if err = a.Tenants().Delete(ctx, "mail-tenant"); err != nil {
		t.Fatal(err)
	}
	if _, e := b.EmailProviders().Get(ctx, "mail-tenant"); !errors.Is(e, store.ErrNotFound) {
		t.Fatalf("tenant deletion kept provider: %v", e)
	}
	if _, e := b.EmailTemplates().Get(ctx, "mail-tenant", "welcome_email"); !errors.Is(e, store.ErrNotFound) {
		t.Fatalf("tenant deletion kept template: %v", e)
	}
	if err = service(b).SendMessage(ctx, "legacy-tenant", Message{To: "still-legacy@example.test", Subject: "legacy", Text: "legacy"}); err != nil {
		t.Fatal(err)
	}
	if len(fallback.messages) != 2 {
		t.Fatal("tenant deletion changed the unrelated legacy fallback")
	}
}
