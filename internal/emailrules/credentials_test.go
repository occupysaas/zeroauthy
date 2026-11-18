package emailrules

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// Publish a real competing edit between the migration's read and CAS write.
type providerEditDuringBackfill struct {
	store.EmailProviders
	edit *store.EmailProvider
}

func (r *providerEditDuringBackfill) Put(ctx context.Context, p *store.EmailProvider, revision int64) error {
	if r.edit != nil {
		if err := r.EmailProviders.Put(ctx, r.edit, revision); err != nil {
			return err
		}
		r.edit = nil
	}
	return r.EmailProviders.Put(ctx, p, revision)
}

func TestEmailProviderBackfillConcurrentEdit(t *testing.T) {
	ctx := t.Context()
	st := memory.New()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "tenant", Name: "tenant"}); err != nil {
		t.Fatal(err)
	}
	w, err := keys.NewLocalWrapper([]byte(secrets.RandomString(32)))
	if err != nil {
		t.Fatal(err)
	}
	newKey := secrets.RandomString(32)
	legacy := func(region, key string) *store.EmailProvider {
		b, err := json.Marshal(map[string]any{"region": region, "api_key": key})
		if err != nil {
			t.Fatal(err)
		}
		cipher, err := keys.SealEmailProvider(w, "tenant", "sparkpost", b)
		if err != nil {
			t.Fatal(err)
		}
		return &store.EmailProvider{TenantID: "tenant", Name: "sparkpost", SealedCredentials: cipher}
	}
	if err := st.EmailProviders().Put(ctx, legacy("", secrets.RandomString(32)), 0); err != nil {
		t.Fatal(err)
	}
	repo := &providerEditDuringBackfill{EmailProviders: st.EmailProviders(), edit: legacy("eu", newKey)}
	if err := BackfillProvider(ctx, repo, w, "tenant"); err != nil {
		t.Fatal(err)
	}
	p, err := repo.Get(ctx, "tenant")
	if err != nil {
		t.Fatal(err)
	}
	b, err := keys.OpenEmailProvider(w, "tenant", "sparkpost", p.SealedCredentials)
	if err != nil {
		t.Fatal(err)
	}
	var private map[string]any
	if p.Revision != 3 || p.PublicConfig["region"] != "eu" || json.Unmarshal(b, &private) != nil || len(private) != 1 || private["api_key"] != newKey {
		t.Fatal("migration lost the concurrent update")
	}
}

func TestEmailProviderMalformedLegacyField(t *testing.T) {
	ctx := t.Context()
	st := memory.New()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "tenant", Name: "tenant"}); err != nil {
		t.Fatal(err)
	}
	w, err := keys.NewLocalWrapper([]byte(secrets.RandomString(32)))
	if err != nil {
		t.Fatal(err)
	}
	private := secrets.RandomString(32)
	b, _ := json.Marshal(map[string]any{"smtp_host": map[string]any{"value": private}})
	cipher, err := keys.SealEmailProvider(w, "tenant", "smtp", b)
	if err != nil {
		t.Fatal(err)
	}
	p := &store.EmailProvider{TenantID: "tenant", Name: "smtp", SealedCredentials: cipher}
	if err := st.EmailProviders().Put(ctx, p, 0); err != nil {
		t.Fatal(err)
	}
	if err := LegacyPublicConfig(w, "tenant", p); !errors.Is(err, ErrInvalidProvider) {
		t.Fatal("legacy read accepted a nested credential")
	}
	if err := BackfillProvider(ctx, st.EmailProviders(), w, "tenant"); !errors.Is(err, ErrInvalidProvider) {
		t.Fatal("backfill accepted a nested credential")
	}
	p, err = st.EmailProviders().Get(ctx, "tenant")
	if err != nil {
		t.Fatal(err)
	}
	if p.Revision != 1 || len(p.PublicConfig) != 0 || !bytes.Equal(p.SealedCredentials, cipher) {
		t.Fatal("malformed row partially migrated")
	}
	p.PublicConfig = map[string]any{"api_user": map[string]any{"value": private}}
	if err := st.EmailProviders().Put(ctx, p, p.Revision); !errors.Is(err, store.ErrInvalid) {
		t.Fatal("store accepted a non-string public username")
	}
}

func TestEmailProviderBackfillWithoutEnvelope(t *testing.T) {
	ctx := t.Context()
	st := memory.New()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "tenant", Name: "tenant"}); err != nil {
		t.Fatal(err)
	}
	repo := st.EmailProviders()
	if err := repo.Put(ctx, &store.EmailProvider{TenantID: "tenant", Name: "smtp", PublicConfig: map[string]any{"smtp_host": "mail.example.test"}}, 0); err != nil {
		t.Fatal(err)
	}
	if err := BackfillProvider(ctx, repo, nil, "tenant"); err != nil {
		t.Fatal("missing envelope must not be replaced during migration")
	}
	p, err := repo.Get(ctx, "tenant")
	if err != nil {
		t.Fatal(err)
	}
	if p.Revision != 1 || len(p.SealedCredentials) != 0 {
		t.Fatal("backfill silently repaired a provider without an authenticated envelope")
	}
}

func TestEmailProviderStoredPortProjection(t *testing.T) {
	for _, tc := range []struct {
		stored any
		want   int
	}{{int64(65535), 65535}, {"00001", 1}} {
		row := store.EmailProvider{Name: "smtp", PublicConfig: map[string]any{"smtp_port": tc.stored}}
		b, err := json.Marshal(ProjectProvider(&row))
		if err != nil {
			t.Fatal(err)
		}
		var view struct {
			Credentials struct {
				Port int `json:"smtp_port"`
			} `json:"credentials"`
		}
		if err := json.Unmarshal(b, &view); err != nil {
			t.Fatal(err)
		}
		if view.Credentials.Port != tc.want {
			t.Errorf("stored port %v projected as %d, want %d", tc.stored, view.Credentials.Port, tc.want)
		}
	}
	for _, port := range []any{int64(65536), "0", "587.5", 1.5} {
		if _, err := publicCredentials(map[string]any{"smtp_port": port}); !errors.Is(err, ErrInvalidProvider) {
			t.Errorf("accepted invalid port %v", port)
		}
	}
	if err := ValidateProvider(rawProvider(map[string]any{"name": "smtp", "credentials": map[string]any{"smtp_host": "mail.example.test", "smtp_port": "587"}}), nil); !errors.Is(err, ErrInvalidProvider) {
		t.Fatal("accepted string port on the management write endpoint")
	}
}
