package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestBrandingPreviewAuthAndNoSideEffects(t *testing.T) {
	h, st := newMgmtEnvWith(t, func(d *Deps) { d.Store = previewReadOnlyStore{d.Store} })
	ctx := context.Background()
	target, _ := st.Tenants().GetByName(ctx, "acme")
	source := `<html><head>{% auth0:head %}</head><body><p>Preview wrapper</p>{% auth0:widget %}</body></html>`
	config, err := st.HostedLogins().Get(ctx, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	config.Template = &source
	if err := st.HostedLogins().Put(ctx, config, config.Revision); err != nil {
		t.Fatal(err)
	}
	before, err := st.HostedLogins().Get(ctx, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	token, userID := tenantOperatorToken(t, st, "branding-op@example.test", []string{"acme"})
	sysID := mustSystemID(t, st)
	if err := st.Operators().Upsert(ctx, &store.Operator{TenantID: sysID, UserID: userID, Tenants: []string{"acme"}}); err != nil {
		t.Fatal(err)
	}
	base := "https://" + mgmtSystemHost + "/api/system/tenants/acme/branding/preview"
	rec, out := sendRaw(h, "POST", base, token, map[string]any{"screen": "login", "language": "en"})
	body, _ := out.(map[string]any)
	html, _ := body["html"].(string)
	if rec.Code != http.StatusOK || !strings.Contains(html, "Preview wrapper") || !strings.Contains(html, "script-src &#39;none&#39;") {
		t.Fatalf("preview=%d %s", rec.Code, rec.Body.String())
	}
	after, err := st.HostedLogins().Get(ctx, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision != before.Revision {
		t.Fatal("preview mutated config")
	}
	if _, err := st.AuthTransactions().Get(ctx, target.ID, "preview-state"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("preview created transaction")
	}
	rec, _ = sendRaw(h, "POST", base, token, map[string]any{"screen": "login", "overrides": map[string]any{"template": "<script>private</script>"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unsafe override=%d", rec.Code)
	}
	for _, tc := range []struct {
		name    string
		payload any
	}{
		{"unsupported screen", map[string]any{"screen": "not-a-screen"}},
		{"unsupported language", map[string]any{"screen": "login", "language": "not_a_language!"}},
		{"unknown property", map[string]any{"screen": "login", "tenant": "other"}},
		{"unknown override", map[string]any{"screen": "login", "overrides": map[string]any{"unknown": true}}},
		{"body limit", map[string]any{"screen": "login", "overrides": map[string]any{"template": strings.Repeat("x", 2<<20)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, _ := sendRaw(h, "POST", base, token, tc.payload)
			if rec.Code != 400 {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
			}
		})
	}
	// A persisted wildcard cannot expand a narrower signed grant.
	if err := st.Operators().Upsert(ctx, &store.Operator{TenantID: sysID, UserID: userID, Tenants: []string{"*"}}); err != nil {
		t.Fatal(err)
	}
	rec, _ = sendRaw(h, "POST", strings.Replace(base, "/acme/", "/system/", 1), token, map[string]any{"screen": "login"})
	if rec.Code != 403 {
		t.Fatalf("signed target grant=%d", rec.Code)
	}
	wildcard, _ := operatorToken(t, st, "branding-wildcard@example.test")
	rec, _ = sendRaw(h, "POST", strings.Replace(base, "/acme/", "/system/", 1), wildcard, map[string]any{"screen": "login"})
	if rec.Code != 403 {
		t.Fatalf("reserved target=%d", rec.Code)
	}
	rec, _ = sendRaw(h, "POST", strings.Replace(base, mgmtSystemHost, "acme.example.test", 1), token, map[string]any{"screen": "login"})
	if rec.Code != 404 {
		t.Fatalf("non-system host=%d", rec.Code)
	}
	m2m := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	rec, _ = sendRaw(h, "POST", base, m2m, map[string]any{"screen": "login"})
	if rec.Code != 401 && rec.Code != 403 {
		t.Fatalf("M2M=%d", rec.Code)
	}

	if err := st.Operators().Upsert(ctx, &store.Operator{TenantID: sysID, UserID: userID, Tenants: []string{"other"}}); err != nil {
		t.Fatal(err)
	}
	rec, _ = sendRaw(h, "POST", base, token, map[string]any{"screen": "login"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("revoked target grant=%d", rec.Code)
	}
}

// These repositories must never even be requested by a preview operation.
// Authentication uses bearer tokens; preview has no session/ticket dependency.
type previewReadOnlyStore struct{ store.Store }

func (s previewReadOnlyStore) AuthTransactions() store.AuthTransactions {
	panic("preview accessed authentication state")
}
func (s previewReadOnlyStore) Sessions() store.Sessions { panic("preview accessed sessions") }
func (s previewReadOnlyStore) PasswordResetTickets() store.PasswordResetTickets {
	panic("preview accessed reset tickets")
}
func (s previewReadOnlyStore) EmailVerificationTickets() store.EmailVerificationTickets {
	panic("preview accessed verification tickets")
}
func (s previewReadOnlyStore) HostedLogins() store.HostedLogins {
	return previewReadOnlyConfig{s.Store.HostedLogins()}
}

type previewReadOnlyConfig struct{ store.HostedLogins }

func (s previewReadOnlyConfig) Put(context.Context, *store.HostedLoginConfig, int64) error {
	panic("preview wrote configuration")
}
