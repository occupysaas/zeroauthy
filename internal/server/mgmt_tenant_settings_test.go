package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/session"
)

const settingsURL = "https://acme.example.test/api/v2/tenants/settings"

func settingsEnv(t *testing.T) (http.Handler, string, string) {
	t.Helper()
	seedText := strings.Replace(mgmtSeed, `"delete:connections"]`, `"delete:connections", "read:tenant_settings", "update:tenant_settings"]`, 1)
	h, _ := newMgmtEnvSeed(t, seedText, nil) // memory.New, no database
	return h, clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret"), m2mToken(t, h, "acme.example.test", acmeMgmtAPI)
}

func TestTenantSettingsAPI(t *testing.T) {
	h, token, reader := settingsEnv(t)
	for _, method := range []string{"GET", "PATCH"} {
		rec, _ := sendJSON(h, method, settingsURL, "", map[string]any{"friendly_name": "new"})
		if rec.Code != 401 {
			t.Fatalf("missing auth: %d %s", rec.Code, rec.Body)
		}
		rec, _ = sendJSON(h, method, settingsURL, reader, map[string]any{"friendly_name": "new"})
		if rec.Code != 403 {
			t.Fatalf("missing scope: %d %s", rec.Code, rec.Body)
		}
	}
	rec, body := sendJSON(h, "GET", settingsURL, token, nil)
	if rec.Code != 200 || body["session_lifetime"] != float64(168) || body["ephemeral_session_lifetime"] != float64(72) {
		t.Fatalf("defaults: %d %s", rec.Code, rec.Body)
	}
	for _, raw := range []string{`{}`, `null`, `[]`, `{"unknown":true}`, `{"friendly_name":"must not persist","session_lifetime":0}`, `{"session_lifetime":null}`, `{"session_lifetime":1.5}`, `{"session_lifetime":1,"session_lifetime_in_minutes":60}`, `{"enabled_locales":[]}`, `{"flags":{"disable_impersonation":true}}`, `{"device_flow":{"unknown":true}}`, `{"default_audience":"unknown"}`, `{"default_directory":"unknown"}`} {
		req := httptest.NewRequest("PATCH", settingsURL, strings.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), `"invalid_body"`) {
			t.Errorf("%s: %d %s", raw, rec.Code, rec.Body)
		}
	}
	rec, body = sendJSON(h, "GET", settingsURL, token, nil)
	if body["friendly_name"] == "must not persist" {
		t.Fatal("partial patch persisted")
	}
	rec, body = sendJSON(h, "PATCH", settingsURL, token, map[string]any{"friendly_name": "New", "session_lifetime_in_minutes": 90, "enabled_locales": []string{"fr", "de"}, "device_flow": map[string]any{"charset": "digits"}})
	if rec.Code != 200 || body["session_lifetime"] != 1.5 {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body)
	}
	rec, body = sendJSON(h, "GET", settingsURL+"?fields=friendly_name&include_fields=true", token, nil)
	if rec.Code != 200 || len(body) != 1 || body["friendly_name"] != "New" {
		t.Fatalf("projection: %d %s", rec.Code, rec.Body)
	}
	rec, _ = sendJSON(h, "GET", settingsURL+"?include_fields=wat", token, nil)
	if rec.Code != 400 {
		t.Fatal("invalid query accepted")
	}
	// A token for acme cannot authorize settings on the reserved system tenant.
	rec, _ = sendJSON(h, "PATCH", "https://"+mgmtSystemHost+"/api/v2/tenants/settings", token, map[string]any{"friendly_name": "wrong"})
	if rec.Code != 401 && rec.Code != 403 {
		t.Fatalf("cross tenant: %d %s", rec.Code, rec.Body)
	}
}

func TestTenantSettingsConcurrentPatch(t *testing.T) {
	h, token, _ := settingsEnv(t)
	var wg sync.WaitGroup
	for _, patch := range []map[string]any{{"support_email": "help@example.test"}, {"support_url": "https://example.test/help"}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec, _ := sendJSON(h, "PATCH", settingsURL, token, patch)
			if rec.Code != 200 {
				t.Errorf("patch: %d %s", rec.Code, rec.Body)
			}
		}()
	}
	wg.Wait()
	rec, body := sendJSON(h, "GET", settingsURL, token, nil)
	if body["support_email"] != "help@example.test" || body["support_url"] != "https://example.test/help" {
		t.Fatalf("lost patch: %s", rec.Body)
	}
}

func TestTenantSettingsContract(t *testing.T) {
	h, token, reader := settingsEnv(t)
	c := newMgmtContract(t)
	c.do(h, "GET", settingsURL, token, nil)
	c.do(h, "GET", settingsURL+"?fields=session_cookie,enabled_locales", token, nil)
	c.do(h, "PATCH", settingsURL, token, map[string]any{"session_lifetime_in_minutes": 90, "session_cookie": map[string]any{"mode": "non-persistent"}, "support_email": "help@example.test", "flags": map[string]any{"enable_sso": false}, "sessions": map[string]any{"anonymous": map[string]any{"activate_cookie": false}}, "error_page": nil})
	c.do(h, "PATCH", settingsURL, token, map[string]any{"unknown": true})
	c.do(h, "GET", settingsURL, reader, nil)
}

func TestTenantSettingsLiveConsumers(t *testing.T) {
	seedText := strings.Replace(mgmtSeed, `"delete:connections"]`, `"delete:connections", "read:tenant_settings", "update:tenant_settings"]`, 1)
	seedText = strings.Replace(seedText, "    clients:\n", `    resource_servers:
      - {identifier: "https://one.test", skip_consent_for_verifiable_first_party_clients: true}
      - {identifier: "https://two.test", skip_consent_for_verifiable_first_party_clients: true}
    connections:
      - {name: One, enabled_clients: [password, spa]}
      - {name: Two, enabled_clients: [password, spa]}
    users:
      - {connection: One, email: one@example.test, password: "one password 12"}
      - {connection: Two, email: two@example.test, password: "two password 12"}
    clients:
      - {client_id: password, client_secret: password-secret, app_type: regular_web, grant_types: [authorization_code, password, "http://auth0.com/oauth/grant-type/password-realm"], callbacks: ["https://app.example.test/cb"]}
      - {client_id: spa, app_type: spa, grant_types: [authorization_code], callbacks: ["https://app.example.test/cb", "http://localhost:3000/cb"]}
      - {client_id: device, app_type: native, grant_types: ["urn:ietf:params:oauth:grant-type:device_code"]}
`, 1)
	h, st := newMgmtEnvSeed(t, seedText, nil)
	token := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	patch := func(body map[string]any) {
		t.Helper()
		rec, _ := sendJSON(h, "PATCH", settingsURL, token, body)
		if rec.Code != 200 {
			t.Fatalf("patch: %d %s", rec.Code, rec.Body)
		}
	}
	form := func(path string, values url.Values) (*httptest.ResponseRecorder, map[string]any) {
		t.Helper()
		req := httptest.NewRequest("POST", "https://acme.example.test"+path, strings.NewReader(values.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec, body
	}
	patch(map[string]any{"default_audience": "https://one.test", "default_directory": "One", "allowed_logout_urls": []string{"https://one.test/bye"}, "enabled_locales": []string{"fr", "de"}, "friendly_name": "Updated company", "support_email": "help@example.test", "device_flow": map[string]any{"charset": "digits", "mask": "***-***-***"}, "pushed_authorization_requests_supported": true, "skip_non_verifiable_callback_uri_confirmation_prompt": true})
	password := url.Values{"grant_type": {"password"}, "client_id": {"password"}, "client_secret": {"password-secret"}, "username": {"one@example.test"}, "password": {"one password 12"}, "scope": {"openid"}}
	checkToken := func(want string) {
		t.Helper()
		rec, body := form("/oauth/token", password)
		if rec.Code != 200 {
			t.Fatalf("password: %d %s", rec.Code, rec.Body)
		}
		parts := strings.Split(body["access_token"].(string), ".")
		claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
		if !strings.Contains(string(claims), want) {
			t.Fatalf("audience: %s", claims)
		}
	}
	checkToken("https://one.test")
	patch(map[string]any{"default_audience": "https://two.test", "default_directory": "Two", "allowed_logout_urls": []string{"https://two.test/bye"}})
	password.Set("username", "two@example.test")
	password.Set("password", "two password 12")
	checkToken("https://two.test")
	password.Set("grant_type", "http://auth0.com/oauth/grant-type/password-realm")
	password.Set("realm", "One")
	password.Set("username", "one@example.test")
	password.Set("password", "one password 12")
	password.Set("audience", "https://one.test")
	checkToken("https://one.test")
	for _, u := range []string{"https://one.test/bye", "https://two.test/bye"} {
		rec, _ := send(h, "GET", "https://acme.example.test/v2/logout?returnTo="+url.QueryEscape(u), nil)
		if u == "https://two.test/bye" {
			if rec.Code != 302 || rec.Header().Get("Location") != u {
				t.Fatalf("logout: %d %s", rec.Code, rec.Body)
			}
		} else if rec.Code != 400 {
			t.Fatalf("removed logout allowed: %d", rec.Code)
		}
	}
	rec, body := form("/oauth/device/code", url.Values{"client_id": {"device"}, "scope": {"openid"}})
	if rec.Code != 200 || !regexp.MustCompile(`^[0-9]{3}-[0-9]{3}-[0-9]{3}$`).MatchString(fmt.Sprint(body["user_code"])) {
		t.Fatalf("device: %d %s", rec.Code, rec.Body)
	}
	q := url.Values{"client_id": {"spa"}, "redirect_uri": {"https://app.example.test/cb"}, "response_type": {"code"}, "scope": {"openid"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	parQ := url.Values{}
	for k, v := range q {
		parQ[k] = append([]string(nil), v...)
	}
	parQ.Set("client_id", "password")
	parQ.Set("client_secret", "password-secret")
	rec, body = form("/oauth/par", parQ)
	if rec.Code != 201 {
		t.Fatalf("PAR enabled: %d %s", rec.Code, rec.Body)
	}
	patch(map[string]any{"pushed_authorization_requests_supported": false})
	rec, _ = form("/oauth/par", parQ)
	if rec.Code != 403 && rec.Code != 400 {
		t.Fatalf("PAR disabled: %d %s", rec.Code, rec.Body)
	}
	// A fresh hosted page uses the tenant's French default, not console English.
	req := httptest.NewRequest("GET", "https://acme.example.test/authorize?"+q.Encode(), nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "/u/login") {
		t.Fatalf("authorize: %d %s", rec.Code, loc)
	}
	if strings.HasPrefix(loc, "/") {
		loc = "https://acme.example.test" + loc
	}
	req = httptest.NewRequest("GET", loc, nil)
	for _, cookie := range rec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `lang="fr"`) || !strings.Contains(rec.Body.String(), "help@example.test") {
		t.Fatalf("hosted settings: %d %s", rec.Code, rec.Body)
	}

	// Existing sessions observe the confirmation setting on the next authorize.
	tn, err := st.Tenants().GetByName(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	user, err := st.Users().FindByLogin(context.Background(), tn.ID, "One", "one@example.test")
	if err != nil {
		t.Fatal(err)
	}
	cookies := httptest.NewRecorder()
	manager := session.Manager{Store: st}
	if _, err = manager.Start(context.Background(), cookies, httptest.NewRequest("GET", "https://acme.example.test", nil), tn, user.UserID, "One", time.Now()); err != nil {
		t.Fatal(err)
	}
	q.Set("redirect_uri", "http://localhost:3000/cb")
	for _, skip := range []bool{false, true} {
		patch(map[string]any{"skip_non_verifiable_callback_uri_confirmation_prompt": skip})
		req = httptest.NewRequest("GET", "https://acme.example.test/authorize?"+q.Encode(), nil)
		for _, cookie := range cookies.Result().Cookies() {
			req.AddCookie(cookie)
		}
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		location := rec.Header().Get("Location")
		if skip {
			if !strings.HasPrefix(location, "http://localhost:3000/cb?") || !strings.Contains(location, "code=") {
				t.Fatalf("skip confirmation: %d %s", rec.Code, location)
			}
		} else if !strings.Contains(location, "/u/consent") {
			t.Fatalf("confirmation missing: %d %s", rec.Code, location)
		}
	}
}
