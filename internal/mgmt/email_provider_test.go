package mgmt_test

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/emailrules"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
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

func TestEmailProviderPublicCredentials(t *testing.T) {
	e := newClientsEnv(t)
	const route = "/api/v2/emails/provider"
	secret := secrets.RandomString(32)
	want := map[string]any{"smtp_host": "mail.example.test", "smtp_port": float64(465), "smtp_user": "mailer"}
	input := maps.Clone(want)
	input["smtp_pass"] = secret
	create, _ := e.call(t, e.tn, m2mCaller("create:email_provider"), "POST", route, map[string]any{"name": "smtp", "credentials": input}, e.h.CreateEmailProvider)
	if create.Code != 201 || strings.Contains(create.Body.String(), secret) {
		t.Fatal("invalid create response", create.Code)
	}
	patch, _ := e.call(t, e.tn, m2mCaller("update:email_provider"), "PATCH", route, map[string]any{"credentials": map[string]any{"smtp_port": 587}}, e.h.PatchEmailProvider)
	if patch.Code != 200 {
		t.Fatal("partial update failed", patch.Code)
	}
	want["smtp_port"] = float64(587)
	p, err := e.st.EmailProviders().Get(t.Context(), e.tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.PublicConfig, want) {
		t.Error("public storage did not contain exactly the SMTP endpoint fields")
	}
	plain, err := keys.OpenEmailProvider(e.w, e.tn.ID, "smtp", p.SealedCredentials)
	if err != nil {
		t.Fatal(err)
	}
	var sealed map[string]any
	if json.Unmarshal(plain, &sealed) != nil || len(sealed) != 1 || sealed["smtp_pass"] != secret {
		t.Error("sealed credentials did not contain only the unchanged password")
	}
	// The normal GET can be served from public config without a decryptor.
	e.h.Wrapper = nil
	get, out := e.call(t, e.tn, m2mCaller("read:email_provider"), "GET", route, nil, e.h.GetEmailProvider)
	if get.Code != 200 || strings.Contains(get.Body.String(), secret) || !reflect.DeepEqual(out.(map[string]any)["credentials"], want) {
		t.Error("GET did not return exactly the public credentials")
	}
}

func TestEmailProviderFields(t *testing.T) {
	e := newClientsEnv(t)
	const route = "/api/v2/emails/provider"
	secret := secrets.RandomString(32)
	legacy := map[string]any{"api_key": secret, "api_user": "mailer"}
	b, _ := json.Marshal(legacy)
	cipher, err := keys.SealEmailProvider(e.w, e.tn.ID, "sendgrid", b)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.EmailProviders().Put(t.Context(), &store.EmailProvider{TenantID: e.tn.ID, Name: "sendgrid", Enabled: true, SealedCredentials: cipher}, 0); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		query string
		want  map[string]any
	}{
		{"?fields=credentials", map[string]any{"credentials": map[string]any{"api_user": "mailer"}}},
		{"?fields=credentials&include_fields=false", map[string]any{"name": "sendgrid", "enabled": true}},
		{"?fields=api_key,sealed_credentials", map[string]any{}},
	} {
		rec, got := e.call(t, e.tn, m2mCaller("read:email_provider"), "GET", route+tc.query, nil, e.h.GetEmailProvider)
		if rec.Code != 200 || !reflect.DeepEqual(got, tc.want) || strings.Contains(rec.Body.String(), secret) {
			t.Errorf("incorrect legacy projection for %s (status %d)", tc.query, rec.Code)
		}
	}
	rec, _ := e.call(t, e.tn, m2mCaller("read:email_provider"), "GET", route+"?include_fields=wrong", nil, e.h.GetEmailProvider)
	if rec.Code != 400 {
		t.Errorf("invalid include_fields status %d", rec.Code)
	}
}

func TestEmailProviderNullableRegion(t *testing.T) {
	e := newClientsEnv(t)
	const route = "/api/v2/emails/provider"
	create, _ := e.call(t, e.tn, m2mCaller("create:email_provider"), "POST", route, map[string]any{"name": "mailgun", "credentials": map[string]any{"domain": "mail.example.test", "region": "eu", "api_key": secrets.RandomString(32)}}, e.h.CreateEmailProvider)
	if create.Code != 201 {
		t.Fatal("create", create.Code)
	}
	get, obj := e.call(t, e.tn, m2mCaller("read:email_provider"), "GET", route, nil, e.h.GetEmailProvider)
	want := map[string]any{"region": "eu"}
	if get.Code != 200 || !reflect.DeepEqual(obj.(map[string]any)["credentials"], want) {
		t.Fatal("incorrect public Mailgun credentials")
	}
	patch, out := e.call(t, e.tn, m2mCaller("update:email_provider"), "PATCH", route, map[string]any{"credentials": map[string]any{"region": nil}}, e.h.PatchEmailProvider)
	if patch.Code != 200 {
		t.Fatal("clear region", patch.Code)
	}
	view := out.(map[string]any)
	if _, ok := view["credentials"]; ok || !reflect.DeepEqual(view["settings"], map[string]any{"domain": "mail.example.test"}) {
		t.Fatal("clearing region retained stale public credential or lost the domain")
	}
}

func TestEmailProviderLegacySettingsProjection(t *testing.T) {
	e := newClientsEnv(t)
	secret := secrets.RandomString(32)
	b, _ := json.Marshal(map[string]any{"api_key": secret, "region": "eu"})
	cipher, err := keys.SealEmailProvider(e.w, e.tn.ID, "sparkpost", b)
	if err != nil {
		t.Fatal(err)
	}
	repo := e.st.EmailProviders()
	if err := repo.Put(t.Context(), &store.EmailProvider{TenantID: e.tn.ID, Name: "sparkpost", Enabled: true, SealedCredentials: cipher}, 0); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"legacy", "migrated"} {
		if stage == "migrated" {
			if err := emailrules.BackfillProvider(t.Context(), repo, e.w, e.tn.ID); err != nil {
				t.Fatal(err)
			}
		}
		settings := map[string]any{"region": "eu"}
		for _, tc := range []struct {
			query string
			want  map[string]any
		}{
			{"?fields=settings", map[string]any{"settings": settings}},
			{"?fields=credentials&include_fields=false", map[string]any{"name": "sparkpost", "enabled": true, "settings": settings}},
		} {
			rec, got := e.call(t, e.tn, m2mCaller("read:email_provider"), "GET", "/api/v2/emails/provider"+tc.query, nil, e.h.GetEmailProvider)
			if rec.Code != 200 || !reflect.DeepEqual(got, tc.want) || strings.Contains(rec.Body.String(), secret) {
				t.Errorf("%s projection dropped or changed settings for %s (status %d)", stage, tc.query, rec.Code)
			}
		}
	}
}
