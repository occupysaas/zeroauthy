package server

import (
	"context"
	"reflect"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestPasskeyPrerequisitesRoute(t *testing.T) {
	h, st := newMgmtEnv(t)
	ctx := context.Background()
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	c := &store.Connection{ID: "con_Passkeys", TenantID: tn.ID, Name: "passkeys", Strategy: store.StrategyDatabase,
		Extra: map[string]any{"authentication_methods": map[string]any{"passkey": map[string]any{"enabled": true}}}}
	if err := st.Connections().Create(ctx, c); err != nil {
		t.Fatal(err)
	}
	cfg := &store.HostedLoginConfig{TenantID: tn.ID, Prompts: map[string]any{"universal_login_experience": "new", "identifier_first": false}}
	old, err := st.HostedLogins().Get(ctx, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.HostedLogins().Put(ctx, cfg, old.Revision); err != nil {
		t.Fatal(err)
	}
	op, _ := operatorToken(t, st, "passkeys@example.test")
	base := "https://" + mgmtSystemHost + "/api/system/tenants/"
	path := base + "acme/connections/" + c.ID + "/passkey-prerequisites"
	rec, out := sendRaw(h, "GET", path, op, nil)
	want := map[string]any{"effective": false, "unmet": []any{"identifier_first"}}
	if rec.Code != 200 || !reflect.DeepEqual(out, want) {
		t.Fatalf("prerequisites = %d %s", rec.Code, rec.Body)
	}
	for _, target := range []string{base + "system/connections/" + c.ID + "/passkey-prerequisites", base + "missing/connections/" + c.ID + "/passkey-prerequisites", "https://acme.example.test/api/system/tenants/acme/connections/" + c.ID + "/passkey-prerequisites"} {
		if rec, _ := sendRaw(h, "GET", target, op, nil); rec.Code != 404 {
			t.Errorf("foreign/missing/tenant host = %d %s", rec.Code, rec.Body)
		}
	}
	admin := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	if rec, _ := sendRaw(h, "GET", path, admin, nil); rec.Code != 401 && rec.Code != 403 {
		t.Errorf("non-operator = %d", rec.Code)
	}
	old, _ = st.HostedLogins().Get(ctx, tn.ID)
	if err := st.HostedLogins().Put(ctx, &store.HostedLoginConfig{TenantID: tn.ID, Prompts: map[string]any{"universal_login_experience": "new", "identifier_first": true}}, old.Revision); err != nil {
		t.Fatal(err)
	}
	rec, out = sendRaw(h, "GET", path, op, nil)
	if rec.Code != 200 || !reflect.DeepEqual(out, map[string]any{"effective": true, "unmet": []any{}}) {
		t.Fatalf("effective = %d %s", rec.Code, rec.Body)
	}
	limited, userID := tenantOperatorToken(t, st, "limited-passkeys@example.test", []string{"*"})
	if err := st.Operators().Upsert(ctx, &store.Operator{TenantID: mustSystemID(t, st), UserID: userID, Tenants: []string{"acme"}}); err != nil {
		t.Fatal(err)
	}
	if rec, _ := sendRaw(h, "GET", path, limited, nil); rec.Code != 200 {
		t.Fatalf("tenant operator = %d %s", rec.Code, rec.Body)
	}
	otherGrant := mintTargetOperator(t, st, userID, []string{"system"})
	if rec, _ := sendRaw(h, "GET", path, otherGrant, nil); rec.Code != 403 {
		t.Fatalf("signed target grant = %d %s", rec.Code, rec.Body)
	}
	if err := st.Operators().Upsert(ctx, &store.Operator{TenantID: mustSystemID(t, st), UserID: userID, Tenants: []string{"system"}}); err != nil {
		t.Fatal(err)
	}
	if rec, _ := sendRaw(h, "GET", path, limited, nil); rec.Code != 403 {
		t.Fatalf("stored target grant = %d %s", rec.Code, rec.Body)
	}
}
