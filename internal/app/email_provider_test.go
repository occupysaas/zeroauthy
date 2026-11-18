package app

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/storage"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func TestEmailProviderMigrationIdempotent(t *testing.T) {
	ctx := t.Context()
	cfg := sqliteConfig(t, true)
	master := []byte(secrets.RandomString(32))
	cfg.Security.MasterKey = base64.StdEncoding.EncodeToString(master)
	w, err := keys.NewLocalWrapper(master)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	a, err := New(ctx, cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	secret := secrets.RandomString(32)
	for _, id := range []string{"alpha", "beta"} {
		if err := a.store.Tenants().Create(ctx, &store.Tenant{ID: id, Name: id}); err != nil {
			t.Fatal(err)
		}
		creds := map[string]any{"smtp_host": "mail.example.test", "smtp_user": "mailer", "smtp_port": 587, "smtp_pass": secret}
		var public map[string]any
		if id == "beta" {
			delete(creds, "smtp_port")
			public = map[string]any{"smtp_port": "0587"}
		}
		plain, _ := json.Marshal(creds)
		b, err := keys.SealEmailProvider(w, id, "smtp", plain)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.store.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: id, Name: "smtp", Enabled: true, PublicConfig: public, SealedCredentials: b}, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", strings.TrimPrefix(cfg.Storage.DSN, "sqlite://"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.ExecContext(ctx, `CREATE TRIGGER interrupt_backfill BEFORE UPDATE ON email_providers WHEN NEW.tenant_id='beta' BEGIN SELECT RAISE(ABORT, 'interrupted'); END`); err != nil {
		t.Fatal(err)
	}
	a, err = New(ctx, cfg, log)
	if err == nil {
		a.Close()
		t.Fatal("startup did not attempt the legacy backfill")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(logs.String(), secret) {
		t.Fatal("credential in startup error or log")
	}
	st, err := storage.Open(ctx, cfg.Storage.DSN)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	check := func(id string, migrated bool) *store.EmailProvider {
		t.Helper()
		p, err := st.EmailProviders().Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		b, err := keys.OpenEmailProvider(w, id, "smtp", p.SealedCredentials)
		if err != nil {
			t.Fatal(err)
		}
		var creds map[string]any
		if json.Unmarshal(b, &creds) != nil || creds["smtp_pass"] != secret {
			t.Fatal("lost sealed password")
		}
		host := "mail.example.test"
		if migrated {
			if p.Revision != 2 || len(creds) != 1 || p.PublicConfig["smtp_host"] != host || p.PublicConfig["smtp_port"] != float64(587) || len(p.PublicConfig) != 3 {
				t.Fatalf("incomplete migrated row: %s", id)
			}
		} else if p.Revision != 1 || creds["smtp_host"] != host || p.PublicConfig["smtp_port"] != "0587" || len(p.PublicConfig) != 1 {
			t.Fatalf("partial update on interruption: %s", id)
		}
		// The GET must return a JSON number even while this row is still legacy.
		req := httptest.NewRequest("GET", "/api/v2/emails/provider?fields=credentials", nil)
		req = req.WithContext(tenant.WithResolved(ctx, tenant.Resolved{Tenant: &store.Tenant{ID: id, Name: id}}))
		rec := httptest.NewRecorder()
		(&mgmt.Handlers{Store: st, Wrapper: w}).GetEmailProvider(rec, req)
		var view struct {
			Credentials struct {
				Port int `json:"smtp_port"`
			} `json:"credentials"`
		}
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &view) != nil || view.Credentials.Port != 587 {
			t.Fatalf("GET port for %s did not return the integer 587 (status %d)", id, rec.Code)
		}
		// Invitation delivery validates the transport using either row encoding.
		engine := actions.Engine{Store: st, Secrets: w}
		if err := st.WithTx(ctx, func(tx store.Store) error {
			return engine.EnqueueInvitation(ctx, tx, actions.InvitationDelivery{TenantID: id, OrganizationID: "o", InvitationID: "i", ClientID: "c"})
		}); err != nil {
			t.Fatal(err)
		}
		return p
	}
	first := check("alpha", true)
	check("beta", false)
	if _, err := db.ExecContext(ctx, "DROP TRIGGER interrupt_backfill"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		a, err = New(ctx, cfg, log)
		if err != nil {
			t.Fatal(err)
		}
		if err = a.Close(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(check("alpha", true).SealedCredentials, first.SealedCredentials) {
			t.Fatal("restart rewrote a migrated row")
		}
		check("beta", true)
	}
}
