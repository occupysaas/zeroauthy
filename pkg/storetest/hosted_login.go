package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func testHostedLogin(t *testing.T, newStore Factory) {
	ctx := context.Background()
	s := open(t, newStore)
	mustNoErr(t, s.Tenants().Create(ctx, newTenant("hosted")))
	repo := s.HostedLogins()
	if _, err := repo.Get(ctx, "ten_hosted"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing config=%v", err)
	}
	config := &store.HostedLoginConfig{TenantID: "ten_hosted", Branding: map[string]any{"colors": map[string]any{"primary": "#112233"}}}
	mustNoErr(t, repo.Put(ctx, config, 0))
	config.Branding["colors"].(map[string]any)["primary"] = "#000000"
	got, err := repo.Get(ctx, "ten_hosted")
	mustNoErr(t, err)
	if got.Revision != 1 || got.Branding["colors"].(map[string]any)["primary"] != "#112233" {
		t.Fatalf("create/copy %#v", got)
	}
	got.Branding["colors"].(map[string]any)["primary"] = "#ffffff"
	again, err := repo.Get(ctx, "ten_hosted")
	mustNoErr(t, err)
	if again.Branding["colors"].(map[string]any)["primary"] != "#112233" {
		t.Fatal("Get leaked mutable map")
	}
	if err := repo.Put(ctx, got, 0); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale revision=%v", err)
	}
	mustNoErr(t, repo.Put(ctx, got, 1))
	newer, err := repo.Get(ctx, "ten_hosted")
	mustNoErr(t, err)
	if newer.Revision != 2 {
		t.Fatalf("revision=%d", newer.Revision)
	}
	if err := s.WithTx(ctx, func(tx store.Store) error {
		c, e := tx.HostedLogins().Get(ctx, "ten_hosted")
		if e != nil {
			return e
		}
		c.DefaultThemeID = "x"
		if e = tx.HostedLogins().Put(ctx, c, 2); e != nil {
			return e
		}
		return errors.New("rollback")
	}); err == nil {
		t.Fatal("rollback missing error")
	}
	after, err := repo.Get(ctx, "ten_hosted")
	mustNoErr(t, err)
	if after.Revision != 2 || after.DefaultThemeID != "" {
		t.Fatal("rollback committed hosted config")
	}
	mustNoErr(t, s.Tenants().Delete(ctx, "ten_hosted"))
	if _, err := repo.Get(ctx, "ten_hosted"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cascade failed: %v", err)
	}
}

func testHostedTransition(t *testing.T, newStore Factory) {
	ctx := context.Background()
	s := open(t, newStore)
	mustNoErr(t, s.Tenants().Create(ctx, newTenant("hostedstate")))
	expiry := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	original := &store.AuthTransaction{TenantID: "ten_hostedstate", ID: "txn-1", CookieHash: "cookie", CSRFToken: "csrf", ClientID: "client", Params: map[string]string{"redirect_uri": "https://app.test/callback"}, ExpiresAt: expiry, CreatedAt: expiry.Add(-time.Hour)}
	mustNoErr(t, s.AuthTransactions().Create(ctx, original))
	next := store.HostedLoginState{Step: "password", Identifier: "ada@example.test", ConnectionID: "db", PromptFields: map[string]string{"ulp-team": "blue"}, FormFields: map[string]string{"ulp-team": "text"}}
	mustNoErr(t, s.AuthTransactions().CompareAndSwapHosted(ctx, original.TenantID, original.ID, 0, next, expiry.Add(-time.Minute)))
	got, err := s.AuthTransactions().Get(ctx, original.TenantID, original.ID)
	mustNoErr(t, err)
	if got.HostedState.Step != "password" || got.HostedState.Revision != 1 || got.Params["redirect_uri"] != original.Params["redirect_uri"] || !got.ExpiresAt.Equal(expiry) {
		t.Fatalf("transition mutated auth transaction: %#v", got)
	}
	got.HostedState.PromptFields["ulp-team"] = "red"
	got.HostedState.FormFields["ulp-team"] = "password"
	fresh, err := s.AuthTransactions().Get(ctx, original.TenantID, original.ID)
	mustNoErr(t, err)
	if fresh.HostedState.PromptFields["ulp-team"] != "blue" || fresh.HostedState.FormFields["ulp-team"] != "text" {
		t.Fatal("hosted state leaked mutable map")
	}
	if err := s.AuthTransactions().CompareAndSwapHosted(ctx, original.TenantID, original.ID, 0, next, expiry.Add(-time.Minute)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale transition=%v", err)
	}
	if err := s.AuthTransactions().CompareAndSwapHosted(ctx, original.TenantID, original.ID, 1, next, expiry); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired boundary=%v", err)
	}
}
