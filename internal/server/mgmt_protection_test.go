package server

import (
	"context"
	"encoding/json"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func protectionEnv(t *testing.T) (http.Handler, string, string) {
	t.Helper()
	seedText := strings.Replace(mgmtSeed, `"delete:connections"]`, `"delete:connections", "read:attack_protection", "update:attack_protection", "read:users", "update:users", "read:anomaly_blocks", "delete:anomaly_blocks"]`, 1)
	h, _ := newMgmtEnvSeed(t, seedText, nil) // memory-only fixture
	return h, clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret"), m2mToken(t, h, "acme.example.test", acmeMgmtAPI)
}
func TestProtectionAPIContracts(t *testing.T) {
	h, token, reader := protectionEnv(t)
	for _, feature := range []string{"brute-force-protection", "suspicious-ip-throttling", "breached-password-detection", "bot-detection", "captcha"} {
		target := "https://acme.example.test/api/v2/attack-protection/" + feature
		for _, method := range []string{"GET", "PATCH"} {
			for _, auth := range []string{"", reader} {
				rec, _ := sendJSON(h, method, target, auth, map[string]any{})
				want := 403
				if auth == "" {
					want = 401
				}
				if rec.Code != want {
					t.Errorf("%s %s auth: %d %s", method, feature, rec.Code, rec.Body)
				}
			}
			rec, body := sendJSON(h, method, target, token, map[string]any{})
			if feature == "brute-force-protection" && body["max_attempts"] != float64(10) {
				t.Errorf("wrong default: %v", body)
			}
			if feature == "breached-password-detection" && body["enabled"] != false {
				t.Errorf("local breach default must be off: %v", body)
			}
			if feature == "captcha" && (strings.Contains(rec.Body.String(), `"secret"`) || strings.Contains(rec.Body.String(), `"api_key"`)) {
				t.Fatal("CAPTCHA response has credential fields")
			}
			if rec.Code != 200 {
				t.Errorf("%s %s success: %d %s", method, feature, rec.Code, rec.Body)
			}
		}
		rec, _ := sendJSON(h, "PATCH", target, token, map[string]any{"unknown": true})
		if rec.Code != 400 {
			t.Errorf("%s validation: %d", feature, rec.Code)
		}
	}
	for _, path := range []string{"user-blocks?identifier=unknown@example.test", "user-blocks/auth0%7Cunknown", "anomaly/blocks/ips/192.0.2.1"} {
		for _, method := range []string{"GET", "DELETE"} {
			target := "https://acme.example.test/api/v2/" + path
			for _, auth := range []string{"", reader} {
				rec, _ := sendJSON(h, method, target, auth, nil)
				want := 403
				if auth == "" {
					want = 401
				}
				if rec.Code != want {
					t.Errorf("%s %s auth: %d", method, path, rec.Code)
				}
			}
			rec, _ := sendJSON(h, method, target, token, nil)
			want := 204
			if strings.Contains(path, "auth0") || method == "GET" && strings.Contains(path, "anomaly") {
				want = 404
			} else if method == "GET" {
				want = 200
			}
			if rec.Code != want {
				t.Errorf("%s %s: %d %s", method, path, rec.Code, rec.Body)
			}
		}
	}
	for _, path := range []string{"user-blocks", "user-blocks?identifier=x&consider_brute_force_enablement=wat", "user-blocks/malformed", "anomaly/blocks/ips/invalid"} {
		rec, _ := sendJSON(h, "GET", "https://acme.example.test/api/v2/"+path, token, nil)
		if rec.Code != 400 {
			t.Errorf("%s: %d %s", path, rec.Code, rec.Body)
		}
	}
}

func TestProtectionCheckerCapability(t *testing.T) {
	h, st := newMgmtEnv(t)
	op, _ := operatorToken(t, st, "capability@example.test")
	rec, _ := sendJSON(h, "GET", "https://"+mgmtSystemHost+"/api/system/tenants", op, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"breached_password_checker":{"available":false}`) {
		t.Fatalf("capability absent: %d %s", rec.Code, rec.Body)
	}
	for _, secret := range []string{"file_path", "corpus", "api_key", "secret"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatal("capability exposed sensitive configuration")
		}
	}
	m2m := m2mToken(t, h, "acme.example.test", acmeMgmtAPI)
	rec, _ = sendJSON(h, "GET", "https://"+mgmtSystemHost+"/api/system/tenants", m2m, nil)
	if rec.Code != 401 && rec.Code != 403 {
		t.Fatalf("tenant M2M capability access: %d %s", rec.Code, rec.Body)
	}
}

func TestProtectionExactScopes(t *testing.T) {
	h, _, _ := protectionEnv(t)
	type operation struct{ method, path, scope string }
	ops := []operation{}
	for _, f := range []string{"brute-force-protection", "suspicious-ip-throttling", "breached-password-detection", "bot-detection", "captcha"} {
		ops = append(ops, operation{"GET", "attack-protection/" + f, "read:attack_protection"}, operation{"PATCH", "attack-protection/" + f, "update:attack_protection"})
	}
	for _, p := range []string{"user-blocks?identifier=nobody", "user-blocks/auth0%7Cnobody"} {
		ops = append(ops, operation{"GET", p, "read:users"}, operation{"DELETE", p, "update:users"})
	}
	ops = append(ops, operation{"GET", "anomaly/blocks/ips/192.0.2.1", "read:anomaly_blocks"}, operation{"DELETE", "anomaly/blocks/ips/192.0.2.1", "delete:anomaly_blocks"})
	for _, scope := range []string{"read:attack_protection", "update:attack_protection", "read:users", "update:users", "read:anomaly_blocks", "delete:anomaly_blocks"} {
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"admin"}, "client_secret": {"admin-s3cret"}, "audience": {acmeMgmtAPI}, "scope": {scope}}
		req := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var body map[string]any
		json.Unmarshal(rec.Body.Bytes(), &body)
		token, _ := body["access_token"].(string)
		if rec.Code != 200 || token == "" {
			t.Fatalf("scoped token: %d %s", rec.Code, rec.Body)
		}
		for _, op := range ops {
			rec, _ := sendJSON(h, op.method, "https://acme.example.test/api/v2/"+op.path, token, map[string]any{})
			if scope != op.scope && rec.Code != 403 {
				t.Errorf("%s authorized %s %s: %d", scope, op.method, op.path, rec.Code)
			}
			if scope == op.scope && (rec.Code == 401 || rec.Code == 403) {
				t.Errorf("%s refused: %d %s", scope, rec.Code, rec.Body)
			}
		}
	}
}

func TestProtectionBlockRouteSuccess(t *testing.T) {
	seedText := strings.Replace(mgmtSeed, `"delete:connections"]`, `"delete:connections", "read:users", "update:users", "read:anomaly_blocks", "delete:anomaly_blocks"]`, 1)
	h, st := newMgmtEnvSeed(t, seedText, nil)
	ctx := context.Background()
	tn, err := st.Tenants().GetByName(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Users().Create(ctx, &store.User{TenantID: tn.ID, UserID: "auth0|known", Email: "known@example.test"}); err != nil {
		t.Fatal(err)
	}
	token := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	for _, method := range []string{"GET", "DELETE"} {
		rec, _ := sendJSON(h, method, "https://acme.example.test/api/v2/user-blocks/auth0%7Cknown", token, nil)
		want := 200
		if method == "DELETE" {
			want = 204
		}
		if rec.Code != want {
			t.Fatalf("known user %s: %d %s", method, rec.Code, rec.Body)
		}
	}
	at := time.Now()
	a, err := st.Protection().Reserve(ctx, []store.ProtectionLimit{{Key: store.ProtectionKey{TenantID: tn.ID, Kind: store.ProtectionSuspiciousIPLogin, IP: "192.0.2.1"}, Algorithm: "token-bucket", Capacity: 1, Refill: time.Hour}}, at)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Protection().Complete(ctx, a.Receipt, "failure", at); err != nil {
		t.Fatal(err)
	}
	rec, _ := sendJSON(h, "GET", "https://acme.example.test/api/v2/anomaly/blocks/ips/::ffff:192.0.2.1", token, nil)
	if rec.Code != 200 || rec.Body.Len() != 0 {
		t.Fatalf("blocked IP: %d %s", rec.Code, rec.Body)
	}
	rec, _ = sendJSON(h, "DELETE", "https://acme.example.test/api/v2/anomaly/blocks/ips/192.0.2.1", token, nil)
	if rec.Code != 204 {
		t.Fatal(rec.Code)
	}
	rec, _ = sendJSON(h, "GET", "https://acme.example.test/api/v2/anomaly/blocks/ips/192.0.2.1", token, nil)
	if rec.Code != 404 {
		t.Fatal(rec.Code)
	}
}
