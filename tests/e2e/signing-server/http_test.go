package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/server"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/storage"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const httpSeed = `tenants:
  - name: m20
    domains: [m20.example.test]
    resource_servers:
      - {identifier: 'https://m20-api.test', name: API, allow_offline_access: true, scopes: [{value: 'read:things'}]}
    clients:
      - {client_id: admin, name: Admin, app_type: non_interactive, client_secret: admin-secret, grant_types: [client_credentials]}
      - {client_id: web, name: Web, app_type: regular_web, client_secret: web-secret, grant_types: ['http://auth0.com/oauth/grant-type/password-realm', refresh_token], allowed_logout_urls: ['https://app.test/bye']}
    client_grants:
      - {client_id: admin, audience: 'https://m20.example.test/api/v2/', scopes: ['read:signing_keys','create:signing_keys','update:signing_keys']}
    connections:
      - {name: Users, enabled_clients: [web]}
    users:
      - {connection: Users, email: user@m20.test, password: 'Testing-password-1234', email_verified: true}
`

func TestM20HTTPSharedStoreRefreshAndForgery(t *testing.T) {
	ctx := context.Background()
	dsn := "sqlite://" + filepath.Join(t.TempDir(), "http.db")
	a := openStore(t, ctx, dsn)
	defer a.Close()
	if err := a.(storage.Migrator).Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	w, err := keys.NewLocalWrapper(bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	f, err := seed.Parse([]byte(httpSeed))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.CheckManagementAPI(""); err != nil {
		t.Fatal(err)
	}
	if err = seed.Apply(ctx, a, f, time.Now, w); err != nil {
		t.Fatal(err)
	}
	tn, err := a.Tenants().GetByName(ctx, "m20")
	if err != nil {
		t.Fatal(err)
	}
	b := openStore(t, ctx, dsn)
	defer b.Close()
	makeServer := func(st store.Store) *httptest.Server {
		km := keys.NewManager(st.SigningKeys(), w)
		if err := km.Ensure(ctx, tn.ID); err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewTLSServer(server.New(server.Deps{Store: st, Keys: km, Wrapper: w, Resolver: tenant.NewResolver(st.Tenants(), "", false), Sessions: &session.Manager{Store: st}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}))
		t.Cleanup(srv.Close)
		return srv
	}
	sa, sb := makeServer(a), makeServer(b)
	request := func(srv *httptest.Server, method, path, token string, body any) (int, map[string]any) {
		t.Helper()
		var payload io.Reader
		if body != nil {
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			payload = bytes.NewReader(raw)
		}
		req, err := http.NewRequest(method, srv.URL+path, payload)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "m20.example.test"
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		client := srv.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	admin := func(srv *httptest.Server) string {
		t.Helper()
		status, out := request(srv, "POST", "/oauth/token", "", map[string]any{"grant_type": "client_credentials", "client_id": "admin", "client_secret": "admin-secret", "audience": "https://m20.example.test/api/v2/"})
		if status != 200 {
			t.Fatalf("admin token status=%d", status)
		}
		return out["access_token"].(string)
	}
	firstAdmin := admin(sa)
	status, userTokens := request(sa, "POST", "/oauth/token", "", map[string]any{"grant_type": "http://auth0.com/oauth/grant-type/password-realm", "realm": "Users", "client_id": "web", "client_secret": "web-secret", "username": "user@m20.test", "password": "Testing-password-1234", "audience": "https://m20-api.test", "scope": "openid offline_access read:things"})
	if status != 200 || userTokens["refresh_token"] == nil {
		t.Fatalf("user token status=%d refresh=%v", status, userTokens["refresh_token"] != nil)
	}
	access := userTokens["access_token"].(string)
	if status, _ = request(sb, "GET", "/userinfo", access, nil); status != 200 {
		t.Fatalf("cross-instance userinfo=%d", status)
	}
	oldKey := tokenKid(t, access)
	users, err := a.Users().FindByEmail(ctx, tn.ID, "user@m20.test")
	if err != nil || len(users) != 1 {
		t.Fatal("user missing")
	}
	sess := &store.LoginSession{ID: "m20-session", TenantID: tn.ID, UserID: users[0].UserID, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	if err = a.Sessions().Create(ctx, sess); err != nil {
		t.Fatal(err)
	}
	status, rotation := request(sa, "POST", "/api/v2/keys/signing/rotate", firstAdmin, map[string]any{})
	if status != 201 {
		t.Fatalf("HTTP rotation=%d", status)
	}
	if status, _ = request(sb, "GET", "/userinfo", access, nil); status != 200 {
		t.Fatalf("previous key lost before revoke=%d", status)
	}
	newAdmin := admin(sb)
	status, _ = request(sb, "PUT", "/api/v2/keys/signing/"+oldKey+"/revoke", newAdmin, map[string]any{})
	if status != 200 {
		t.Fatalf("HTTP revoke=%d", status)
	}
	if status, _ = request(sa, "GET", "/userinfo", access, nil); status != 401 {
		t.Fatalf("revoked userinfo=%d", status)
	}
	if status, _ = request(sa, "GET", "/api/v2/keys/signing", firstAdmin, nil); status != 401 {
		t.Fatalf("revoked management token=%d", status)
	}
	if _, err = a.Sessions().Get(ctx, tn.ID, sess.ID); err != nil {
		t.Fatalf("rotation deleted session: %v", err)
	}
	status, refreshed := request(sa, "POST", "/oauth/token", "", map[string]any{"grant_type": "refresh_token", "client_id": "web", "client_secret": "web-secret", "refresh_token": userTokens["refresh_token"]})
	if status != 200 {
		t.Fatalf("refresh after revoke=%d", status)
	}
	if tokenKid(t, refreshed["access_token"].(string)) != rotation["kid"] {
		t.Fatal("refresh did not use new current key")
	}
	if status, _ = request(sb, "GET", "/userinfo", refreshed["access_token"].(string), nil); status != 200 {
		t.Fatalf("refreshed userinfo=%d", status)
	}
	// A custom public key can verify a mathematical signature without becoming
	// trusted by the service's management, userinfo, or logout consumers.
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{Key: &private.PublicKey, KeyID: "attacker-custom", Algorithm: "RS256", Use: "sig"}
	status, _ = request(sb, "PUT", "/api/v2/keys/custom-signing", newAdmin, map[string]any{"keys": []jose.JSONWebKey{jwk}})
	if status != 200 {
		t.Fatalf("custom replace=%d", status)
	}
	forge := func(original string) string {
		parsed, err := jwt.ParseSigned(original, []jose.SignatureAlgorithm{jose.RS256})
		if err != nil {
			t.Fatal(err)
		}
		var claims map[string]any
		if err = parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
			t.Fatal(err)
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: private}, (&jose.SignerOptions{}).WithHeader("kid", jwk.KeyID))
		if err != nil {
			t.Fatal(err)
		}
		token, err := jwt.Signed(signer).Claims(claims).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		checked, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
		if err != nil {
			t.Fatal(err)
		}
		if err = checked.Claims(jwk.Key, &claims); err != nil {
			t.Fatalf("forgery signature invalid: %v", err)
		}
		return token
	}
	if status, _ = request(sa, "GET", "/api/v2/keys/signing", forge(newAdmin), nil); status != 401 {
		t.Fatalf("custom management forgery=%d", status)
	}
	if status, _ = request(sa, "GET", "/userinfo", forge(refreshed["access_token"].(string)), nil); status != 401 {
		t.Fatalf("custom userinfo forgery=%d", status)
	}
	if status, _ = request(sa, "GET", "/oidc/logout?id_token_hint="+url.QueryEscape(forge(refreshed["id_token"].(string)))+"&post_logout_redirect_uri="+url.QueryEscape("https://app.test/bye"), "", nil); status != 400 {
		t.Fatalf("custom logout forgery=%d", status)
	}
	c := openStore(t, ctx, dsn)
	defer c.Close()
	sc := makeServer(c)
	status, custom := request(sc, "GET", "/api/v2/keys/custom-signing", newAdmin, nil)
	if status != 200 || !strings.Contains(string(mustJSON(t, custom)), "attacker-custom") {
		t.Fatal("restart lost custom set")
	}
}
func tokenKid(t *testing.T, token string) string {
	t.Helper()
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Headers[0].KeyID
}
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
