package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/system"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const mgmtSeed = `
tenants:
  - name: acme
    domains: [acme.example.test, login.acme.test]
    clients:
      - {client_id: m2m, app_type: non_interactive, client_secret: s3cret, grant_types: [client_credentials]}
      - {client_id: admin, app_type: non_interactive, client_secret: admin-s3cret, grant_types: [client_credentials]}
    client_grants:
      - {client_id: m2m, audience: "https://acme.example.test/api/v2/", scopes: ["read:clients"]}
      - client_id: admin
        audience: "https://acme.example.test/api/v2/"
        scopes: ["read:clients", "create:clients", "update:clients", "delete:clients", "read:client_keys", "update:client_keys"]
`

const mgmtSystemHost = "admin.example.test"

func newMgmtServer(t *testing.T) http.Handler {
	t.Helper()
	h, _ := newMgmtEnv(t)
	return h
}

func newMgmtEnv(t *testing.T) (http.Handler, store.Store) {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	f, err := seed.Parse([]byte(mgmtSeed))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.CheckManagementAPI(""); err != nil {
		t.Fatal(err)
	}
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{5}, 32))
	if err := seed.Apply(ctx, st, f, nil, w); err != nil {
		t.Fatal(err)
	}
	if _, err := system.Ensure(ctx, st, system.Config{Host: mgmtSystemHost, Wrapper: w}); err != nil {
		t.Fatal(err)
	}
	km := keys.NewManager(st.SigningKeys(), w)
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	if err := km.Ensure(ctx, tn.ID); err != nil {
		t.Fatal(err)
	}
	return New(Deps{
		Store: st, Keys: km, Wrapper: w,
		Resolver: tenant.NewResolver(st.Tenants(), "", false),
		Sessions: &session.Manager{Store: st}, Mailer: discardMailer{},
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		UserThrottle: identity.NewThrottle(10, time.Minute, time.Minute),
		IPThrottle:   identity.NewThrottle(100, time.Minute, time.Minute),
		SystemHost:   mgmtSystemHost,
	}), st
}

func send(h http.Handler, method, target string, header map[string]string) (*httptest.ResponseRecorder, map[string]any) {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec, body
}

func m2mToken(t *testing.T, h http.Handler, host, aud string) string {
	t.Helper()
	return clientToken(t, h, host, aud, "m2m", "s3cret")
}

func clientToken(t *testing.T, h http.Handler, host, aud, id, secret string) string {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}, "audience": {aud}}
	req := httptest.NewRequest("POST", "https://"+host+"/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	tok, _ := body["access_token"].(string)
	if rec.Code != 200 || tok == "" {
		t.Fatalf("token: %d %s", rec.Code, rec.Body)
	}
	return tok
}

// A seeded client grant for the canonical identifier gives a token through
// the token endpoint, which /api/v2 accepts on every host of the tenant.
func TestManagementAPIMounted(t *testing.T) {
	h := newMgmtServer(t)
	tok := m2mToken(t, h, "login.acme.test", "https://acme.example.test/api/v2/")
	for _, host := range []string{"acme.example.test", "login.acme.test"} {
		rec, body := send(h, "GET", "https://"+host+"/api/v2/nothing-yet", map[string]string{"Authorization": "Bearer " + tok})
		if rec.Code != 404 || body["statusCode"] != float64(404) || body["error"] != "Not Found" {
			t.Errorf("%s with token: %d %v", host, rec.Code, body)
		}
		rec, body = send(h, "GET", "https://"+host+"/api/v2/nothing-yet", nil)
		if rec.Code != 401 || body["statusCode"] != float64(401) || body["errorCode"] != "invalid_token" {
			t.Errorf("%s without token: %d %v", host, rec.Code, body)
		}
	}
}

func TestSystemAPIOnlyOnSystemHost(t *testing.T) {
	h := newMgmtServer(t)
	tok := m2mToken(t, h, "acme.example.test", "https://acme.example.test/api/v2/")
	rec, _ := send(h, "GET", "https://acme.example.test/api/system/tenants", map[string]string{"Authorization": "Bearer " + tok})
	if rec.Code != 404 {
		t.Errorf("on a tenant host: %d %s", rec.Code, rec.Body)
	}
	rec, body := send(h, "GET", "https://"+mgmtSystemHost+"/api/system/tenants", nil)
	if rec.Code != 401 || body["errorCode"] != "invalid_token" {
		t.Errorf("system host, no token: %d %v", rec.Code, body)
	}
}

// Design §6: CORS on /api/v2 and /api/system allows only the system host's
// origin.
func TestManagementCORS(t *testing.T) {
	h := newMgmtServer(t)
	sysOrigin := "https://" + mgmtSystemHost
	for _, target := range []string{"https://acme.example.test/api/v2/clients", "https://" + mgmtSystemHost + "/api/system/tenants"} {
		rec, _ := send(h, "OPTIONS", target, map[string]string{"Origin": sysOrigin,
			"Access-Control-Request-Method": "PATCH", "Access-Control-Request-Headers": "authorization, content-type"})
		if rec.Code != 204 || rec.Header().Get("Access-Control-Allow-Origin") != sysOrigin ||
			!strings.Contains(rec.Header().Get("Access-Control-Allow-Methods"), "PATCH") ||
			!strings.Contains(strings.ToLower(rec.Header().Get("Access-Control-Allow-Headers")), "authorization") {
			t.Errorf("%s preflight from the system origin: %d %v", target, rec.Code, rec.Header())
		}
		rec, _ = send(h, "GET", target, map[string]string{"Origin": sysOrigin})
		if rec.Header().Get("Access-Control-Allow-Origin") != sysOrigin {
			t.Errorf("%s GET from the system origin: no ACAO (%d)", target, rec.Code)
		}
		for _, origin := range []string{"https://acme.example.test", "https://evil.test", "http://" + mgmtSystemHost, "null"} {
			rec, _ := send(h, "OPTIONS", target, map[string]string{"Origin": origin, "Access-Control-Request-Method": "GET"})
			if rec.Code != 403 || rec.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Errorf("%s preflight from %s: %d %v", target, origin, rec.Code, rec.Header())
			}
			rec, _ = send(h, "GET", target, map[string]string{"Origin": origin})
			if rec.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Errorf("%s GET from %s: ACAO set", target, origin)
			}
		}
	}
}

// Responses on the CORS-handled paths vary by Origin, with or without one,
// so a cache never serves one origin's answer to another.
func TestCORSVaryOrigin(t *testing.T) {
	srv := newMgmtServer(t)
	for _, target := range []string{"https://acme.example.test/api/v2/clients", "https://" + mgmtSystemHost + "/api/system/tenants", "https://acme.example.test/oauth/token"} {
		for _, origin := range []string{"", "https://evil.test", "https://" + mgmtSystemHost} {
			h := map[string]string{}
			if origin != "" {
				h["Origin"] = origin
			}
			method := "GET"
			if strings.HasSuffix(target, "/oauth/token") {
				method = "POST"
			}
			rec, _ := send(srv, method, target, h)
			if !strings.Contains(rec.Header().Get("Vary"), "Origin") {
				t.Errorf("%s from %q: Vary = %q", target, origin, rec.Header().Get("Vary"))
			}
		}
	}
}
