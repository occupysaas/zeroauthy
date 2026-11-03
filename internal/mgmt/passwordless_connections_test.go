package mgmt_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestPasswordlessConnectionCreateHTTP(t *testing.T) {
	e := newUsersEnv(t)
	rec, out := e.do(t, m2mCaller("create:connections"), "POST", "/api/v2/connections",
		map[string]any{"name": "email", "strategy": "email", "options": map[string]any{"email": map[string]any{"from": "a@acme.test"}}}, e.h.CreateConnection)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	m := out.(map[string]any)
	opts := m["options"].(map[string]any)
	if m["strategy"] != "email" || opts["brute_force_protection"] != true || opts["totp"].(map[string]any)["time_step"] != float64(180) {
		t.Fatalf("view = %v", m)
	}
	for _, k := range []string{"password_options", "validation", "requires_username", "import_mode", "enabledDatabaseCustomization", "mfa", "authentication_methods"} {
		if _, ok := opts[k]; ok {
			t.Errorf("database option %q in passwordless view", k)
		}
	}
	// A second connection of the same strategy conflicts.
	rec, _ = e.do(t, m2mCaller("create:connections"), "POST", "/api/v2/connections",
		map[string]any{"name": "email", "strategy": "email"}, e.h.CreateConnection)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate = %d %s", rec.Code, rec.Body)
	}
	rec, _ = e.do(t, m2mCaller("create:connections"), "POST", "/api/v2/connections",
		map[string]any{"name": "login-code", "strategy": "email"}, e.h.CreateConnection)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), `must be named \"email\"`) {
		t.Fatalf("name = %d %s", rec.Code, rec.Body)
	}
}

func TestSMSConnectionSecretsSealed(t *testing.T) {
	e := newUsersEnv(t)
	tok := strings.Repeat("T", 32) + "SECRETTOKEN"
	sid := "AC" + strings.Repeat("b", 32)
	rec, out := e.do(t, m2mCaller("create:connections"), "POST", "/api/v2/connections", map[string]any{
		"name": "sms", "strategy": "sms",
		"options": map[string]any{
			"from": "+15555550100", "twilio_sid": sid, "twilio_token": tok,
			"gateway_authentication": map[string]any{"audience": "aud", "method": "bearer", "secret": "GATEWAYSECRET"},
		},
	}, e.h.CreateConnection)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "SECRETTOKEN") || strings.Contains(rec.Body.String(), "GATEWAYSECRET") {
		t.Fatalf("secret returned on create: %s", rec.Body)
	}
	id := out.(map[string]any)["id"].(string)
	stored, err := e.st.Connections().Get(t.Context(), e.tn.ID, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := stored.Extra["twilio_token"]; ok {
		t.Fatal("twilio_token stored in plaintext Extra")
	}
	if strings.Contains(string(stored.ConfigurationSealed), "SECRETTOKEN") || len(stored.ConfigurationSealed) == 0 {
		t.Fatal("credentials not sealed")
	}
	open := func(b []byte) (map[string]string, error) {
		return keys.OpenConnectionConfig(e.w, stored.TenantID, stored.ID, b)
	}
	get := func() string {
		rec, _ := e.do(t, m2mCaller("read:connections"), "GET", "/api/v2/connections/"+id, nil, func(w http.ResponseWriter, r *http.Request) {
			e.h.GetConnection(w, r, id, mgmtapi.GetConnectionParams{})
		})
		if rec.Code != 200 {
			t.Fatalf("get = %d %s", rec.Code, rec.Body)
		}
		return rec.Body.String()
	}
	if body := get(); strings.Contains(body, "SECRETTOKEN") || strings.Contains(body, "GATEWAYSECRET") || strings.Contains(body, "configuration") || !strings.Contains(body, sid) {
		t.Fatalf("get = %s", body)
	}
	got, err := connrules.PasswordlessOf(*stored, open)
	if err != nil || got.SMS.TwilioToken != tok || got.SMS.GatewayAuth.Secret != "GATEWAYSECRET" {
		t.Fatalf("PasswordlessOf = %+v, %v", got.SMS, err)
	}

	// PATCH without the secrets keeps them.
	patch := func(opts map[string]any) (int, string) {
		rec, _ := e.do(t, m2mCaller("update:connections"), "PATCH", "/api/v2/connections/"+id, map[string]any{"options": opts},
			func(w http.ResponseWriter, r *http.Request) { e.h.UpdateConnection(w, r, id) })
		return rec.Code, rec.Body.String()
	}
	if code, body := patch(map[string]any{"from": "+15555550199", "twilio_sid": sid,
		"gateway_authentication": map[string]any{"audience": "aud2", "method": "bearer"}}); code != 200 || strings.Contains(body, "SECRET") {
		t.Fatalf("patch = %d %s", code, body)
	}
	stored, _ = e.st.Connections().Get(t.Context(), e.tn.ID, id)
	got, err = connrules.PasswordlessOf(*stored, open)
	if err != nil || got.SMS.From != "+15555550199" || got.SMS.TwilioToken != tok || got.SMS.GatewayAuth.Secret != "GATEWAYSECRET" || got.SMS.GatewayAuth.Audience != "aud2" {
		t.Fatalf("after patch = %+v %+v, %v", got.SMS, got.SMS.GatewayAuth, err)
	}
	// A new token replaces it; null for the gateway removes its secret.
	newTok := strings.Repeat("N", 40)
	if code, body := patch(map[string]any{"twilio_token": newTok, "gateway_authentication": nil}); code != 200 {
		t.Fatalf("patch = %d %s", code, body)
	}
	stored, _ = e.st.Connections().Get(t.Context(), e.tn.ID, id)
	got, _ = connrules.PasswordlessOf(*stored, open)
	if got.SMS.TwilioToken != newTok || got.SMS.GatewayAuth != nil {
		t.Fatalf("after replace = %+v", got.SMS)
	}
	if code, body := patch(map[string]any{"twilio_token": "short"}); code != 400 || strings.Contains(body, "short") {
		t.Fatalf("invalid token = %d %s", code, body)
	}
	if code, body := patch(map[string]any{"provider": "sms_gateway", "gateway_url": "https://10.0.0.1/send"}); code != 400 || !strings.Contains(body, "gateway_url") {
		t.Fatalf("private gateway = %d %s", code, body)
	}
	var _ store.Connection
}
