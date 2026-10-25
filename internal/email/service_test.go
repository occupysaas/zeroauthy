package email

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/email/providers"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type recordingMailer struct {
	mu       sync.Mutex
	messages []Message
	err      error
}

func (m *recordingMailer) Send(_ context.Context, msg Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, msg)
	return m.err
}

type providerCall struct {
	tenant   string
	revision int64
	config   providers.Config
	message  providers.Message
}
type recordingFactory struct {
	mu      sync.Mutex
	calls   []providerCall
	sendErr error
	entered chan struct{}
	release chan struct{}
}

type failingRenderer struct{ err error }

func (r failingRenderer) Render(context.Context, RenderInput) (Rendered, error) {
	return Rendered{}, r.err
}

func (f *recordingFactory) New(_ context.Context, tenant string, revision int64, cfg providers.Config) (providers.Transport, error) {
	return recordingTransport{f: f, tenant: tenant, revision: revision, cfg: cfg}, nil
}

type recordingTransport struct {
	f        *recordingFactory
	tenant   string
	revision int64
	cfg      providers.Config
}

func (t recordingTransport) Send(_ context.Context, m providers.Message) error {
	t.f.mu.Lock()
	t.f.calls = append(t.f.calls, providerCall{tenant: t.tenant, revision: t.revision, config: t.cfg, message: m})
	entered, release, err := t.f.entered, t.f.release, t.f.sendErr
	t.f.mu.Unlock()
	if entered != nil {
		entered <- struct{}{}
	}
	if release != nil {
		<-release
	}
	return err
}
func (f *recordingFactory) snapshot() []providerCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]providerCall(nil), f.calls...)
}

type emailProvidersOverride struct {
	store.Store
	repo store.EmailProviders
}

func (s emailProvidersOverride) EmailProviders() store.EmailProviders { return s.repo }

type failingProviders struct{ err error }

func (p failingProviders) Get(context.Context, string) (*store.EmailProvider, error) {
	return nil, p.err
}
func (p failingProviders) Put(context.Context, *store.EmailProvider, int64) error { return p.err }
func (p failingProviders) Delete(context.Context, string, int64) error            { return p.err }

func providerSecret(t *testing.T, w keys.Wrapper, tenant, name, secret string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"api_key": secret})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := keys.SealEmailProvider(w, tenant, name, raw)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}
func emailServiceFixture(t *testing.T) (context.Context, *memory.Store, *keys.LocalWrapper, *recordingMailer, *recordingFactory, *Service) {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "tenant-a", Name: "tenant-a", FriendlyName: "Tenant A"}); err != nil {
		t.Fatal(err)
	}
	w, err := keys.NewLocalWrapper(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	fallback := &recordingMailer{}
	factory := &recordingFactory{}
	renderer, _ := NewRenderer()
	svc := &Service{Store: st, Wrapper: w, Renderer: renderer, Providers: factory, Fallback: fallback, DefaultFrom: "zeroauthy@example.test", Now: func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) }}
	return ctx, st, w, fallback, factory, svc
}

func TestTenantDeliverySelection(t *testing.T) {
	ctx, st, w, fallback, factory, svc := emailServiceFixture(t)
	legacy := Message{To: "user@example.test", Subject: "Legacy", Text: "localized default"}
	if err := svc.SendMessage(ctx, "tenant-a", legacy); err != nil {
		t.Fatal(err)
	}
	if err := st.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "tenant-a", Name: "sendgrid", Enabled: false, DefaultFrom: "provider@example.test", SealedCredentials: providerSecret(t, w, "tenant-a", "sendgrid", "disabled-secret")}, 0); err != nil {
		t.Fatal(err)
	}
	if err := svc.SendMessage(ctx, "tenant-a", legacy); err != nil {
		t.Fatal(err)
	}
	if err := st.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "tenant-a", Name: "sendgrid", Enabled: true, DefaultFrom: "provider@example.test", SealedCredentials: providerSecret(t, w, "tenant-a", "sendgrid", "active-secret")}, 1); err != nil {
		t.Fatal(err)
	}
	if err := svc.SendMessage(ctx, "tenant-a", legacy); err != nil {
		t.Fatal(err)
	}
	if len(fallback.messages) != 2 {
		t.Fatalf("fallback sends=%d, want absent+disabled only", len(fallback.messages))
	}
	calls := factory.snapshot()
	if len(calls) != 1 || calls[0].tenant != "tenant-a" || calls[0].config.Credentials["api_key"] != "active-secret" || calls[0].message.From != "provider@example.test" {
		t.Fatalf("provider calls=%+v", calls)
	}
	factory.mu.Lock()
	factory.sendErr = errors.New("provider rejected")
	factory.mu.Unlock()
	if err := svc.SendMessage(ctx, "tenant-a", legacy); err == nil {
		t.Fatal("broken enabled provider succeeded")
	}
	if len(fallback.messages) != 2 {
		t.Fatal("enabled provider failure fell back")
	}
	if err := st.EmailProviders().Delete(ctx, "tenant-a", 2); err != nil {
		t.Fatal(err)
	}
	if err := svc.SendMessage(ctx, "tenant-a", legacy); err != nil {
		t.Fatal(err)
	}
	if len(fallback.messages) != 3 {
		t.Fatal("deleted provider did not restore legacy fallback")
	}
	if err := st.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "tenant-a", Name: "sendgrid", Enabled: true, DefaultFrom: "provider@example.test", SealedCredentials: []byte("SENTINEL_BAD_CIPHERTEXT")}, 0); err != nil {
		t.Fatal(err)
	}
	err := svc.SendMessage(ctx, "tenant-a", legacy)
	if err == nil || strings.Contains(err.Error(), "SENTINEL_BAD_CIPHERTEXT") {
		t.Fatalf("decrypt error=%v", err)
	}
	if len(fallback.messages) != 3 {
		t.Fatal("decrypt failure fell back")
	}
	if policy, err := svc.Resolve(ctx, "tenant-a", "verify_email"); err != nil || policy.Template != nil || !policy.Enabled {
		t.Fatalf("absent legacy template policy=%+v,%v", policy, err)
	}
	verify := VerifyEmailMessage(i18n.Default(), "https://tenant.example.test/verify")
	verify.To = legacy.To
	if err := (&Sender{Mailer: fallback}).SendVerifyEmail(ctx, VerifyEmail{To: verify.To, L: i18n.Default(), Link: "https://tenant.example.test/verify"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fallback.messages[len(fallback.messages)-1].Text, "verify") {
		t.Fatal("no-record legacy content was not preserved")
	}
	broken := emailProvidersOverride{Store: st, repo: failingProviders{err: errors.New("store unavailable")}}
	svc.Store = broken
	if err := svc.SendMessage(ctx, "tenant-a", legacy); err == nil || len(fallback.messages) != 4 {
		t.Fatalf("provider repository failure=%v fallback=%d", err, len(fallback.messages))
	}
}

func TestTenantProviderIsolation(t *testing.T) {
	ctx, st, w, _, factory, svc := emailServiceFixture(t)
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "tenant-b", Name: "tenant-b"}); err != nil {
		t.Fatal(err)
	}
	for tenant, secret := range map[string]string{"tenant-a": "alpha-secret", "tenant-b": "beta-secret"} {
		if err := st.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: tenant, Name: "sendgrid", Enabled: true, DefaultFrom: tenant + "@example.test", SealedCredentials: providerSecret(t, w, tenant, "sendgrid", secret)}, 0); err != nil {
			t.Fatal(err)
		}
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		if err := svc.SendMessage(ctx, tenant, Message{To: "user@example.test", Subject: "tenant", Text: "body"}); err != nil {
			t.Fatal(err)
		}
	}
	calls := factory.snapshot()
	if len(calls) != 2 || calls[0].tenant != "tenant-a" || calls[0].config.Credentials["api_key"] != "alpha-secret" || calls[1].tenant != "tenant-b" || calls[1].config.Credentials["api_key"] != "beta-secret" {
		t.Fatalf("tenant providers crossed boundaries: %+v", calls)
	}
}

func TestRenderedHeaders(t *testing.T) {
	ctx, st, _, fallback, factory, svc := emailServiceFixture(t)
	if err := st.Users().Create(ctx, &store.User{TenantID: "tenant-a", UserID: "user-a", Email: "user@example.test", EmailVerified: true, Name: "A"}); err != nil {
		t.Fatal(err)
	}
	if err := st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: "tenant-a", Name: "verify_email", Fields: map[string]any{"template": "verify_email", "body": "<p>Hello {{ user.name }}</p>", "subject": "Hi {{ user.name }}", "from": "safe@example.test", "enabled": true}}, 0); err != nil {
		t.Fatal(err)
	}
	if err := svc.Send(ctx, Event{TenantID: "tenant-a", UserID: "user-a", Template: "verify_email", URL: "https://tenant.example.test/ticket"}); err != nil {
		t.Fatal(err)
	}
	if len(fallback.messages) != 1 || fallback.messages[0].From != "safe@example.test" || !strings.Contains(fallback.messages[0].Text, "Hello A") {
		t.Fatalf("rendered fallback=%+v", fallback.messages)
	}
	if err := svc.Send(ctx, Event{TenantID: "tenant-a", UserID: "user-a", Template: "verify_email", Variables: map[string]any{"unsupported": make(chan int)}}); !errors.Is(err, ErrRenderSyntax) {
		t.Fatalf("unsupported render context=%v", err)
	}
	if len(fallback.messages) != 1 {
		t.Fatal("renderer failure sent a message")
	}
	svc.Renderer = failingRenderer{err: ErrRenderCapacity}
	if err := svc.Send(ctx, Event{TenantID: "tenant-a", UserID: "user-a", Template: "verify_email"}); !errors.Is(err, ErrRenderCapacity) {
		t.Fatalf("capacity error=%v", err)
	}
	if len(fallback.messages) != 1 {
		t.Fatal("render capacity failure sent a message")
	}
	renderer, _ := NewRenderer()
	svc.Renderer = renderer
	if err := st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: "tenant-a", Name: "verify_email", Fields: map[string]any{"template": "verify_email", "body": "Bad", "subject": "OK\r\nBcc: evil@example.test", "enabled": true}}, 1); err != nil {
		t.Fatal(err)
	}
	if err := svc.Send(ctx, Event{TenantID: "tenant-a", UserID: "user-a", Template: "verify_email"}); !errors.Is(err, ErrHeaderInjection) {
		t.Fatalf("header injection=%v", err)
	}
	if len(fallback.messages) != 1 || len(factory.snapshot()) != 0 {
		t.Fatal("invalid headers reached a transport")
	}
}

func TestProviderSnapshot(t *testing.T) {
	ctx, st, w, _, factory, svc := emailServiceFixture(t)
	p := &store.EmailProvider{TenantID: "tenant-a", Name: "sendgrid", Enabled: true, DefaultFrom: "provider@example.test", SealedCredentials: providerSecret(t, w, "tenant-a", "sendgrid", "first-secret")}
	if err := st.EmailProviders().Put(ctx, p, 0); err != nil {
		t.Fatal(err)
	}
	factory.entered = make(chan struct{}, 1)
	factory.release = make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- svc.SendMessage(ctx, "tenant-a", Message{To: "user@example.test", Subject: "snapshot", Text: "body"})
	}()
	<-factory.entered
	if err := st.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "tenant-a", Name: "sendgrid", Enabled: true, DefaultFrom: "next@example.test", SealedCredentials: providerSecret(t, w, "tenant-a", "sendgrid", "second-secret")}, 1); err != nil {
		t.Fatal(err)
	}
	close(factory.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	factory.mu.Lock()
	factory.entered = nil
	factory.release = nil
	factory.mu.Unlock()
	if err := svc.SendMessage(ctx, "tenant-a", Message{To: "user@example.test", Subject: "next", Text: "body"}); err != nil {
		t.Fatal(err)
	}
	calls := factory.snapshot()
	if len(calls) != 2 || calls[0].config.Credentials["api_key"] != "first-secret" || calls[1].config.Credentials["api_key"] != "second-secret" || calls[0].message.From != "provider@example.test" || calls[1].message.From != "next@example.test" {
		t.Fatalf("provider snapshots=%+v", calls)
	}
}
