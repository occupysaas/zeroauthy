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
	previewTheme := strings.Repeat("2", 32)
	rec, _ = sendRaw(h, "POST", base, token, map[string]any{"screen": "login", "overrides": map[string]any{"themes": map[string]any{previewTheme: map[string]any{"colors": map[string]any{"primary_button": "#654321"}}}, "default_theme_id": previewTheme}})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "#654321") {
		t.Fatalf("unsaved theme preview=%d %s", rec.Code, rec.Body)
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

func TestCustomTextLanguageIdentity(t *testing.T) {
	h, st := newMgmtEnv(t)
	ctx := context.Background()
	token, _ := operatorToken(t, st, "language-op@example.test")
	base := "https://acme.example.test/api/v2/prompts/login/custom-text/"
	for _, item := range []struct{ language, title string }{{"en", "First"}, {"EN", "Replacement"}} {
		rec, _ := sendRaw(h, "PUT", base+item.language, token, map[string]any{"login": map[string]any{"title": item.title}})
		if rec.Code != 200 {
			t.Fatalf("PUT %s=%d %s", item.language, rec.Code, rec.Body)
		}
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	config, _ := st.HostedLogins().Get(ctx, tn.ID)
	if len(config.CustomText["login"]) != 1 {
		t.Errorf("case-equivalent language records: %v", config.CustomText["login"])
	}
	for _, language := range []string{"en", "EN"} {
		rec, _ := sendRaw(h, "GET", base+language, token, nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Replacement") {
			t.Errorf("GET %s=%d %s", language, rec.Code, rec.Body)
		}
	}
	rec, _ := sendRaw(h, "PUT", base+"en", token, map[string]any{})
	if rec.Code != 200 {
		t.Fatal(rec.Body)
	}
	for _, language := range []string{"en", "EN"} {
		rec, _ := sendRaw(h, "GET", base+language, token, nil)
		if strings.TrimSpace(rec.Body.String()) != "{}" {
			t.Errorf("clear left %s override: %s", language, rec.Body)
		}
	}
}

func TestBrandingPreviewDraftKeepsOtherResources(t *testing.T) {
	h, st := newMgmtEnv(t)
	ctx := context.Background()
	token, _ := operatorToken(t, st, "preview-draft-op@example.test")
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	tn.EnabledLocales = []string{"en", "fr"}
	if err := st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	config, _ := st.HostedLogins().Get(ctx, tn.ID)
	config.CustomText = store.CustomText{"login": {"en": {"login": {"title": "Saved English"}}, "fr": {"login": {"title": "Saved French"}}}, "signup": {"en": {"signup": {"title": "Saved signup"}}}}
	config.Partials = map[string]map[string]map[string]string{"signup": {"signup": {"form-footer-start": "<p>Saved signup partial</p>"}}}
	if err := st.HostedLogins().Put(ctx, config, config.Revision); err != nil {
		t.Fatal(err)
	}
	overrides := map[string]any{"custom_text": map[string]any{"login": map[string]any{"en": map[string]any{"login": map[string]any{"title": "Draft English"}}}}, "partials": map[string]any{"login": map[string]any{"login": map[string]any{"form-footer-start": "<p>Draft footer</p>"}}}}
	for _, item := range []struct{ screen, language, want string }{{"login", "fr", "Saved French"}, {"signup", "en", "Saved signup partial"}} {
		rec, _ := sendRaw(h, "POST", "https://"+mgmtSystemHost+"/api/system/tenants/acme/branding/preview", token, map[string]any{"screen": item.screen, "language": item.language, "overrides": overrides})
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), item.want) {
			t.Errorf("preview lost %s: status=%d %s", item.want, rec.Code, rec.Body)
		}
	}
}
