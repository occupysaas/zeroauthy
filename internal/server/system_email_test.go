package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/oauth"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/system"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type testEmailMailer struct {
	mu       sync.Mutex
	messages []email.Message
	err      error
}

func (m *testEmailMailer) Send(_ context.Context, msg email.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, msg)
	return m.err
}

func tenantOperatorToken(t *testing.T, st store.Store, emailAddress string, grants []string) (string, string) {
	t.Helper()
	ctx := context.Background()
	if _, err := system.CreateOperator(ctx, st, emailAddress); err != nil {
		t.Fatal(err)
	}
	sys, _ := st.Tenants().GetByName(ctx, tenant.SystemName)
	u, err := st.Users().FindByLogin(ctx, sys.ID, system.OperatorsConnection, emailAddress)
	if err != nil {
		t.Fatal(err)
	}
	user, err := st.Users().Get(ctx, sys.ID, u.UserID)
	if err != nil {
		t.Fatal(err)
	}
	user.EmailVerified = true
	if err = st.Users().Update(ctx, user); err != nil {
		t.Fatal(err)
	}
	return mintTargetOperator(t, st, u.UserID, grants), u.UserID
}

func mintTargetOperator(t *testing.T, st store.Store, userID string, grants []string) string {
	t.Helper()
	ctx := context.Background()
	sys, _ := st.Tenants().GetByName(ctx, tenant.SystemName)
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{5}, 32))
	m := &oauth.Minter{Keys: keys.NewManager(st.SigningKeys(), w)}
	token, err := m.AccessToken(ctx, oauth.AccessTokenParams{TenantID: sys.ID, Issuer: "https://" + mgmtSystemHost + "/", Subject: userID, Audience: []string{tenant.OperatorAudience}, ClientID: system.ConsoleClientID, Scopes: []string{"openid"}, Lifetime: time.Hour, Operator: grants})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestSystemEmailPreviewAndOperatorTest(t *testing.T) {
	mailer := &testEmailMailer{}
	h, st := newMgmtEnvWith(t, func(d *Deps) {
		r, _ := email.NewRenderer()
		d.EmailService = &email.Service{Store: d.Store, Renderer: r, Fallback: mailer, DefaultFrom: "zeroauthy@example.test"}
	})
	ctx := context.Background()
	acme, _ := st.Tenants().GetByName(ctx, "acme")
	if err := st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: acme.ID, Name: "verify_email", Fields: map[string]any{"template": "verify_email", "body": "<p>{{ user.email | escape }} {{ url }}</p>", "subject": "Verify {{ tenant.name }}", "enabled": true, "resultUrl": "https://real.example.test/callback"}}, 0); err != nil {
		t.Fatal(err)
	}
	token, userID := tenantOperatorToken(t, st, "email-op@example.test", []string{"*"})
	if err := st.Operators().Upsert(ctx, &store.Operator{TenantID: mustSystemID(t, st), UserID: userID, Tenants: []string{"acme"}}); err != nil {
		t.Fatal(err)
	}
	base := "https://" + mgmtSystemHost + "/api/system/tenants/acme/emails/"
	rec, out := sendRaw(h, "POST", base+"preview", token, map[string]any{"template": "verify_email"})
	preview, _ := out.(map[string]any)
	if rec.Code != http.StatusOK || !strings.Contains(preview["html"].(string), "preview@example.invalid") || preview["resultUrl"] != "https://example.invalid/verify_email" {
		t.Fatalf("preview=%d %s", rec.Code, rec.Body)
	}
	rec, _ = sendRaw(h, "POST", base+"preview", token, map[string]any{"template": "verify_email", "overrides": map[string]any{"body": "Hello {{ user.email }}"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("override preview=%d %s", rec.Code, rec.Body)
	}
	rec, _ = sendRaw(h, "POST", base+"preview", token, map[string]any{"template": "verify_email", "to": "attacker@example.test"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("arbitrary preview recipient=%d", rec.Code)
	}
	rec, _ = sendRaw(h, "POST", base+"preview", token, map[string]any{"template": "verify_email", "overrides": map[string]any{"body": strings.Repeat("x", 17<<10)}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized preview override=%d", rec.Code)
	}
	if err := st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: acme.ID, Name: "reset_email", Fields: map[string]any{"body": "Disabled", "subject": "Disabled", "enabled": false}}, 0); err != nil {
		t.Fatal(err)
	}
	if rec, _ = sendRaw(h, "POST", base+"preview", token, map[string]any{"template": "reset_email"}); rec.Code != http.StatusNotFound {
		t.Fatalf("disabled template preview=%d", rec.Code)
	}
	rec, _ = sendRaw(h, "POST", base+"test", token, map[string]any{"template": "verify_email", "to": "attacker@example.test"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("arbitrary test recipient=%d", rec.Code)
	}
	systemID := mustSystemID(t, st)
	operator, _ := st.Users().Get(ctx, systemID, userID)
	operator.EmailVerified = false
	if err := st.Users().Update(ctx, operator); err != nil {
		t.Fatal(err)
	}
	if rec, _ = sendRaw(h, "POST", base+"test", token, map[string]any{"template": "verify_email"}); rec.Code != http.StatusForbidden {
		t.Fatalf("unverified operator test=%d", rec.Code)
	}
	operator.EmailVerified = true
	if err := st.Users().Update(ctx, operator); err != nil {
		t.Fatal(err)
	}
	rec, _ = sendRaw(h, "POST", base+"test", token, map[string]any{"template": "verify_email"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("test send=%d %s", rec.Code, rec.Body)
	}
	mailer.mu.Lock()
	msgs := append([]email.Message(nil), mailer.messages...)
	mailer.mu.Unlock()
	if len(msgs) != 1 || msgs[0].To != "email-op@example.test" || !strings.Contains(msgs[0].HTML, "https://example.invalid/verify_email") {
		t.Fatalf("test message=%+v", msgs)
	}
	if rec, _ = sendRaw(h, "POST", base+"test", token, map[string]any{"template": "verify_email", "overrides": map[string]any{"body": "UNSAVED"}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("test accepted unsaved template=%d", rec.Code)
	}
	mailer.err = errors.New("provider failure")
	for i, want := range []int{http.StatusBadGateway, http.StatusBadGateway, http.StatusTooManyRequests} {
		got, _ := sendRaw(h, "POST", base+"test", token, map[string]any{"template": "verify_email"})
		if got.Code != want {
			t.Fatalf("test failure attempt %d=%d want %d", i+1, got.Code, want)
		}
	}
	if rec, _ = sendRaw(h, "POST", "https://acme.example.test/api/system/tenants/acme/emails/preview", token, map[string]any{"template": "verify_email"}); rec.Code != http.StatusNotFound {
		t.Fatalf("tenant host=%d", rec.Code)
	}
	if err := st.Operators().Upsert(ctx, &store.Operator{TenantID: mustSystemID(t, st), UserID: userID, Tenants: []string{"*"}}); err != nil {
		t.Fatal(err)
	}
	if rec, _ = sendRaw(h, "POST", "https://"+mgmtSystemHost+"/api/system/tenants/system/emails/preview", token, map[string]any{"template": "verify_email"}); rec.Code != http.StatusForbidden {
		t.Fatalf("reserved tenant=%d %s", rec.Code, rec.Body)
	}
	if rec, _ = sendRaw(h, "GET", "https://"+mgmtSystemHost+"/api/system/tenants", token, nil); rec.Code != http.StatusOK {
		t.Fatalf("existing system API changed=%d", rec.Code)
	}
}

func TestSystemEmailPreviewTargetGrantAndLimits(t *testing.T) {
	h, st := newMgmtEnv(t)
	ctx := context.Background()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "globex-id", Name: "globex", Domains: []string{"globex.example.test"}}); err != nil {
		t.Fatal(err)
	}
	_, userID := tenantOperatorToken(t, st, "grants@example.test", []string{"*"})
	sysID := mustSystemID(t, st)
	if err := st.Operators().Upsert(ctx, &store.Operator{TenantID: sysID, UserID: userID, Tenants: []string{"acme"}}); err != nil {
		t.Fatal(err)
	}
	limited := mintTargetOperator(t, st, userID, []string{"acme"})
	if rec, _ := sendRaw(h, "POST", "https://"+mgmtSystemHost+"/api/system/tenants/acme/emails/preview", limited, map[string]any{"template": "verify_email"}); rec.Code != http.StatusNotFound {
		t.Fatalf("missing template=%d", rec.Code)
	}
	if rec, _ := sendRaw(h, "POST", "https://"+mgmtSystemHost+"/api/system/tenants/globex/emails/preview", limited, map[string]any{"template": "verify_email"}); rec.Code != http.StatusForbidden {
		t.Fatalf("persisted target grant=%d", rec.Code)
	}
	otherGrant := mintTargetOperator(t, st, userID, []string{"globex"})
	if rec, _ := sendRaw(h, "POST", "https://"+mgmtSystemHost+"/api/system/tenants/acme/emails/preview", otherGrant, map[string]any{"template": "verify_email"}); rec.Code != http.StatusForbidden {
		t.Fatalf("signed target grant=%d", rec.Code)
	}
	// Fill the preview allowance for one operator and target in this minute.
	acme, _ := st.Tenants().GetByName(ctx, "acme")
	if err := st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: acme.ID, Name: "verify_email", Fields: map[string]any{"body": "Preview", "subject": "Preview", "enabled": true}}, 0); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 31; i++ {
		rec, _ := sendRaw(h, "POST", "https://"+mgmtSystemHost+"/api/system/tenants/acme/emails/preview", limited, map[string]any{"template": "verify_email"})
		want := http.StatusOK
		if i == 30 {
			want = http.StatusTooManyRequests
		}
		if rec.Code != want {
			t.Fatalf("preview %d=%d want %d", i+1, rec.Code, want)
		}
	}
	admin := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	// A tenant's M2M token never reaches the system API: its issuer is not
	// the system host's (401), and it carries no operator claim (403).
	if rec, _ := sendRaw(h, "POST", "https://"+mgmtSystemHost+"/api/system/tenants/acme/emails/preview", admin, map[string]any{"template": "verify_email"}); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("M2M preview=%d", rec.Code)
	}
	// A tenant's M2M token never reaches the system API: its issuer is not
	// the system host's (401), and it carries no operator claim (403).
	if rec, _ := sendRaw(h, "POST", "https://"+mgmtSystemHost+"/api/system/tenants/acme/emails/test", admin, map[string]any{"template": "verify_email"}); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("M2M test=%d", rec.Code)
	}
	for i, want := range []int{http.StatusNoContent, http.StatusNoContent, http.StatusNoContent, http.StatusTooManyRequests} {
		rec, _ := sendRaw(h, "POST", "https://"+mgmtSystemHost+"/api/system/tenants/acme/emails/test", limited, map[string]any{"template": "verify_email"})
		if rec.Code != want {
			t.Fatalf("test rate %d=%d want %d", i+1, rec.Code, want)
		}
	}
}

func mustSystemID(t *testing.T, st store.Store) string {
	t.Helper()
	sys, err := st.Tenants().GetByName(context.Background(), tenant.SystemName)
	if err != nil {
		t.Fatal(err)
	}
	return sys.ID
}
