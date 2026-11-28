package oidc

import (
	"context"
	"encoding/json"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
)

func TestUserinfoCustomClaims(t *testing.T) {
	e := newUserinfoEnv(t)
	ctx := context.Background()
	s := &store.LoginSession{TenantID: "ten_a", ID: "sid", TokenHash: "hash", UserID: "auth0|1", ExpiresAt: uiNow.AddDate(0, 0, 1), IdleExpiresAt: uiNow.AddDate(0, 0, 1), UserinfoClaims: map[string]string{"app": `{"https://app.test/claim":"first","private_claim":true,"sub":"evil","email":"evil"}`}}
	if err := e.st.Sessions().Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	raw := e.token(t, "ten_a", map[string]any{"sid": "sid", "azp": "app"})
	check := func(want string) {
		t.Helper()
		rec := e.call("GET", "Bearer "+raw)
		var b map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &b)
		if rec.Code != 200 || b["https://app.test/claim"] != want || b["sub"] != "auth0|1" || b["email"] != "alice@acme.test" {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
	}
	check("first")
	if _, err := store.SetSessionClaims(ctx, e.st, "ten_a", "sid", "app", `{"https://app.test/claim":"latest"}`); err != nil {
		t.Fatal(err)
	}
	check("latest")
}
func TestUserinfoClaimsPerClient(t *testing.T) {
	e := newUserinfoEnv(t)
	s := &store.LoginSession{TenantID: "ten_a", ID: "sid", TokenHash: "hash", UserID: "auth0|1", UserinfoClaims: map[string]string{"app": `{"https://app.test/claim":true}`}}
	if err := e.st.Sessions().Create(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	for _, c := range []map[string]any{{"sid": "sid", "azp": "other"}, {"sid": "sid", "azp": "app", "sub": "auth0|blocked"}, {"azp": "app"}} {
		rec := e.call("GET", "Bearer "+e.token(t, "ten_a", c))
		var b map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &b)
		if _, ok := b["https://app.test/claim"]; ok {
			t.Fatalf("leaked claims: %s", rec.Body.String())
		}
	}
}
func TestUserinfoNoSession(t *testing.T) { TestUserinfoClaimsPerClient(t) }

func TestUserinfoExpiredSessionHasNoClaims(t *testing.T) {
	e := newUserinfoEnv(t)
	s := &store.LoginSession{TenantID: "ten_a", ID: "expired", TokenHash: "expired-hash", UserID: "auth0|1", ExpiresAt: uiNow, IdleExpiresAt: uiNow, UserinfoClaims: map[string]string{"app": `{"urn:old":true}`}}
	if err := e.st.Sessions().Create(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	rec := e.call("GET", "Bearer "+e.token(t, "ten_a", map[string]any{"sid": s.ID, "azp": "app"}))
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if _, ok := body["urn:old"]; ok {
		t.Fatal("expired unswept session exposes stale claims")
	}
}
