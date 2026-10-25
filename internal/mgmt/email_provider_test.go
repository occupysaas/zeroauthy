package mgmt_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func TestProviderSecretPatch(t *testing.T) {
	e := newClientsEnv(t)
	secret := "SENTINEL_EMAIL_SECRET"
	create, _ := e.call(t, e.tn, m2mCaller("create:email_provider"), "POST", "/api/v2/emails/provider", map[string]any{"name": "sendgrid", "enabled": true, "credentials": map[string]any{"api_key": secret}}, e.h.CreateEmailProvider)
	if create.Code != http.StatusCreated || strings.Contains(create.Body.String(), secret) {
		t.Fatalf("create: %d %s", create.Code, create.Body)
	}
	patch, _ := e.call(t, e.tn, m2mCaller("update:email_provider"), "PATCH", "/api/v2/emails/provider", map[string]any{"enabled": false}, e.h.PatchEmailProvider)
	if patch.Code != http.StatusOK || strings.Contains(patch.Body.String(), secret) {
		t.Fatalf("patch: %d %s", patch.Code, patch.Body)
	}
	p, err := e.st.EmailProviders().Get(t.Context(), e.tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := keys.OpenEmailProvider(e.w, e.tn.ID, p.Name, p.SealedCredentials)
	if err != nil {
		t.Fatal(err)
	}
	var creds map[string]any
	if json.Unmarshal(plain, &creds) != nil || creds["api_key"] != secret {
		t.Fatalf("omitted secret was not preserved: %v", creds)
	}
	replacement := "SENTINEL_REPLACEMENT_SECRET"
	patch, _ = e.call(t, e.tn, m2mCaller("update:email_provider"), "PATCH", "/api/v2/emails/provider", map[string]any{"credentials": map[string]any{"api_key": replacement}}, e.h.PatchEmailProvider)
	if patch.Code != http.StatusOK || strings.Contains(patch.Body.String(), replacement) {
		t.Fatalf("replace secret: %d %s", patch.Code, patch.Body)
	}
	p, _ = e.st.EmailProviders().Get(t.Context(), e.tn.ID)
	plain, _ = keys.OpenEmailProvider(e.w, e.tn.ID, p.Name, p.SealedCredentials)
	_ = json.Unmarshal(plain, &creds)
	if creds["api_key"] != replacement {
		t.Fatalf("secret was not replaced: %v", creds)
	}
	bad, _ := e.call(t, e.tn, m2mCaller("update:email_provider"), "PATCH", "/api/v2/emails/provider", map[string]any{"credentials": map[string]any{"api_key": "********"}}, e.h.PatchEmailProvider)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("masked secret: %d %s", bad.Code, bad.Body)
	}
	change, _ := e.call(t, e.tn, m2mCaller("update:email_provider"), "PATCH", "/api/v2/emails/provider", map[string]any{"name": "resend", "credentials": map[string]any{"api_key": "new-key"}}, e.h.PatchEmailProvider)
	if change.Code != http.StatusOK {
		t.Fatalf("kind switch: %d %s", change.Code, change.Body)
	}
	p, _ = e.st.EmailProviders().Get(t.Context(), e.tn.ID)
	plain, _ = keys.OpenEmailProvider(e.w, e.tn.ID, p.Name, p.SealedCredentials)
	_ = json.Unmarshal(plain, &creds)
	if p.Name != "resend" || creds["api_key"] != "new-key" || len(creds) != 1 {
		t.Fatalf("old kind credentials survived: %s %v", p.Name, creds)
	}
}

type conflictProviderStore struct {
	store.Store
	repo *conflictProviderRepo
}

func (s conflictProviderStore) EmailProviders() store.EmailProviders { return s.repo }

type conflictProviderRepo struct {
	store.EmailProviders
	writes int
}

func (r *conflictProviderRepo) Put(context.Context, *store.EmailProvider, int64) error {
	r.writes++
	return store.ErrConflict
}

func TestProviderPatchConflictRetriesAreBounded(t *testing.T) {
	e := newClientsEnv(t)
	created, _ := e.call(t, e.tn, m2mCaller("create:email_provider"), "POST", "/api/v2/emails/provider", map[string]any{"name": "sendgrid", "enabled": true, "credentials": map[string]any{"api_key": "keep"}}, e.h.CreateEmailProvider)
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body)
	}
	before, _ := e.st.EmailProviders().Get(t.Context(), e.tn.ID)
	repo := &conflictProviderRepo{EmailProviders: e.st.EmailProviders()}
	oldStore := e.h.Store
	e.h.Store = conflictProviderStore{Store: e.st, repo: repo}
	t.Cleanup(func() { e.h.Store = oldStore })
	req := httptest.NewRequest("PATCH", "https://login.acme.test/api/v2/emails/provider", strings.NewReader(`{"enabled":false}`))
	req.Header.Set("Content-Type", "application/json")
	ctx := tenant.WithResolved(req.Context(), tenant.Resolved{Tenant: e.tn, Host: "login.acme.test"})
	req = req.WithContext(mgmt.WithCaller(ctx, m2mCaller("update:email_provider")))
	rec := httptest.NewRecorder()
	e.h.PatchEmailProvider(rec, req)
	if rec.Code != http.StatusConflict || repo.writes != 3 {
		t.Fatalf("conflicts=%d response=%d %s", repo.writes, rec.Code, rec.Body)
	}
	after, _ := e.st.EmailProviders().Get(t.Context(), e.tn.ID)
	if after.Revision != before.Revision || after.Enabled != before.Enabled {
		t.Fatal("conflicted update partially changed provider")
	}
}
