package main

import (
	"context"
	"encoding/json"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/server"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/storage"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Deferred database-backed HTTP integration: two independently constructed
// server handlers/SQL handles, then close/reopen one to model a server restart.
func TestM19TwoHTTPInstances(t *testing.T) {
	ctx := context.Background()
	dsn := "sqlite://" + filepath.Join(t.TempDir(), "http.db")
	open := func() store.Store {
		s, e := storage.Open(ctx, dsn)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	a := open()
	defer a.Close()
	if e := a.(storage.Migrator).Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	w, e := keys.NewLocalWrapper(make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	f, e := seed.Load("../seed.yaml")
	if e != nil {
		t.Fatal(e)
	}
	f.Mode = seed.ModeCreateOnly
	if e = f.CheckManagementAPI(""); e != nil {
		t.Fatal(e)
	}
	if e = seed.Apply(ctx, a, f, time.Now, w); e != nil {
		t.Fatal(e)
	}
	b := open()
	defer func() { b.Close() }()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if e = seed.InitializeProtection(ctx, a, config.Security{}, log); e != nil {
		t.Fatal(e)
	}
	mailDir := t.TempDir()
	mail, e := email.New(config.Email{Driver: "dir", Dir: mailDir}, log)
	if e != nil {
		t.Fatal(e)
	}
	build := func(st store.Store) http.Handler {
		km := keys.NewManager(st.SigningKeys(), w)
		all, e := st.Tenants().List(ctx)
		if e != nil {
			t.Fatal(e)
		}
		for _, tn := range all {
			if e = km.Ensure(ctx, tn.ID); e != nil {
				t.Fatal(e)
			}
		}
		return server.New(server.Deps{Store: st, Keys: km, Wrapper: w, Log: log, Mailer: mail, Resolver: tenant.NewResolver(st.Tenants(), "", false), Sessions: &session.Manager{Store: st}, SystemHost: "system.localhost:8443", Protection: &protection.Service{Store: st, Wrapper: w, Log: log, BreachChecker: protection.NewRangeChecker(rangeTransport{}), CaptchaVerifier: verifier{}}})
	}
	h1, h2 := build(a), build(b)
	request := func(h http.Handler, method, path, token string, body any) (int, map[string]any) {
		t.Helper()
		data, _ := json.Marshal(body)
		r := httptest.NewRequest(method, "https://localhost:8443"+path, strings.NewReader(string(data)))
		r.RemoteAddr = "192.0.2.19:1234"
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		out := map[string]any{}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	status, tokenBody := request(h1, "POST", "/oauth/token", "", map[string]any{"grant_type": "client_credentials", "client_id": "e2e-m17-admin", "client_secret": "e2e-m17-admin-secret-not-for-production", "audience": "https://localhost:8443/api/v2/"})
	if status != 200 {
		t.Fatal(status, tokenBody)
	}
	token := tokenBody["access_token"].(string)
	for path, patch := range map[string]any{"brute-force-protection": map[string]any{"enabled": true, "max_attempts": 2, "shields": []string{"block"}}, "suspicious-ip-throttling": map[string]any{"enabled": false}} {
		if status, out := request(h1, "PATCH", "/api/v2/attack-protection/"+path, token, patch); status != 200 {
			t.Fatal(status, out)
		}
	}
	login := func(h http.Handler, password string) (int, map[string]any) {
		return request(h, "POST", "/oauth/token", "", map[string]any{"grant_type": "http://auth0.com/oauth/grant-type/password-realm", "client_id": "e2e-node", "client_secret": "e2e-node-secret-not-for-production", "realm": "Username-Password-Authentication", "username": "alice@e2e.local", "password": password})
	}
	for _, h := range []http.Handler{h1, h2} {
		if status, out := login(h, "wrong"); status != 403 && status != 401 {
			t.Fatal(status, out)
		}
	}
	reset := func(h http.Handler) {
		status, out := request(h, "POST", "/dbconnections/change_password", "", map[string]any{"client_id": "e2e-node", "connection": "Username-Password-Authentication", "email": "reset-me@e2e.local"})
		if status != 200 {
			t.Fatal("reset request", status, out)
		}
	}
	for _, h := range []http.Handler{h1, h2, h1} {
		reset(h)
	}
	messages, err := os.ReadDir(mailDir)
	if err != nil || len(messages) != 3 {
		t.Fatalf("reset sends before restart: %d %v", len(messages), err)
	}
	if e = b.Close(); e != nil {
		t.Fatal(e)
	}
	b = open()
	h2 = build(b)
	reset(h2)
	messages, err = os.ReadDir(mailDir)
	if err != nil || len(messages) != 3 {
		t.Fatalf("restart forgot mail budget: %d %v", len(messages), err)
	}
	if status, out := login(h2, "Correct-Horse-Battery-9"); status == 200 {
		t.Fatal("restart forgot block", out)
	}
	path := "/api/v2/user-blocks?identifier=alice%40e2e.local"
	status, out := request(h2, "GET", path, token, nil)
	if status != 200 || len(out["blocked_for"].([]any)) != 1 {
		t.Fatal(status, out)
	}
	if status, out = request(h2, "DELETE", path, token, nil); status != 204 {
		t.Fatal(status, out)
	}
	if status, out = login(h1, "Correct-Horse-Battery-9"); status != 200 {
		t.Fatal("unblock not visible on other handler", status, out)
	}
}
