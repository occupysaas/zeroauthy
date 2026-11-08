package server

import (
	"context"
	"encoding/json"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
)

func TestRoamingUVSettingRoute(t *testing.T) {
	h, st := newMgmtEnv(t)
	op, _ := operatorToken(t, st, "roaming@example.test")
	path := "https://" + mgmtSystemHost + "/api/system/tenants/acme/guardian/factors/webauthn-roaming/settings"
	rec, out := sendRaw(h, "GET", path, op, nil)
	if rec.Code != 200 || out.(map[string]any)["user_verification"] != "discouraged" {
		t.Fatalf("default %d %s", rec.Code, rec.Body)
	}
	for _, uv := range []string{"preferred", "required", "discouraged"} {
		rec, _ = sendRaw(h, "PUT", path, op, map[string]any{"user_verification": uv})
		if rec.Code != 200 {
			t.Fatalf("PUT %d %s", rec.Code, rec.Body)
		}
		rec, out = sendRaw(h, "GET", path, op, nil)
		if rec.Code != 200 || out.(map[string]any)["user_verification"] != uv {
			t.Fatalf("GET %d %s", rec.Code, rec.Body)
		}
	}
	for _, body := range []any{map[string]any{"user_verification": "never"}, map[string]any{}, map[string]any{"user_verification": "required", "extra": true}} {
		rec, _ = sendRaw(h, "PUT", path, op, body)
		if rec.Code != 400 {
			t.Fatalf("invalid %d %s", rec.Code, rec.Body)
		}
	}
	tn, _ := st.Tenants().GetByName(context.Background(), "acme")
	g, _ := st.MFA().GetGuardian(context.Background(), tn.ID)
	var saved map[string]string
	if json.Unmarshal(g.Stored["webauthn-roaming/settings"], &saved) != nil || saved["user_verification"] != "discouraged" {
		t.Fatalf("stored %+v", g.Stored)
	}
	admin := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	rec, _ = sendRaw(h, "PUT", path, admin, map[string]any{"user_verification": "required"})
	if rec.Code != 401 && rec.Code != 403 {
		t.Fatalf("non-operator %d", rec.Code)
	}
	rec, _ = sendRaw(h, "GET", "https://"+mgmtSystemHost+"/api/v2/guardian/factors/webauthn-roaming/settings", op, nil)
	if rec.Code != 404 {
		t.Fatalf("v2 %d", rec.Code)
	}
	limited, uid := tenantOperatorToken(t, st, "limited-roaming@example.test", []string{"*"})
	if err := st.Operators().Upsert(context.Background(), &store.Operator{TenantID: mustSystemID(t, st), UserID: uid, Tenants: []string{"system"}}); err != nil {
		t.Fatal(err)
	}
	rec, _ = sendRaw(h, "PUT", path, limited, map[string]any{"user_verification": "required"})
	if rec.Code != 403 {
		t.Fatalf("target operator %d %s", rec.Code, rec.Body)
	}
}
