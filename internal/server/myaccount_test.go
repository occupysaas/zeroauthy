package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

// myAccountSeed is flowSeed with a password-realm client for the My Account
// API (Plan 42a) and a machine client.
var myAccountSeed = strings.Replace(strings.Replace(flowSeed, "    clients:\n", `    clients:
      - {client_id: admin, app_type: non_interactive, client_secret: admin-s3cret, grant_types: [client_credentials]}
      - client_id: ropg
        app_type: regular_web
        client_secret: ropg-s3cret
        grant_types: ["http://auth0.com/oauth/grant-type/password-realm", refresh_token]
`, 1), "enabled_clients: [spa, tv, spa2]}\n", "enabled_clients: [spa, tv, spa2, ropg]}\n", 1)

var allMyAccountScopes = []string{"read:me:factors", "read:me:authentication_methods", "create:me:authentication_methods", "update:me:authentication_methods", "delete:me:authentication_methods"}

type myAccountEnv struct {
	*flowEnv
	tn        *store.Tenant
	canonical string
	alias     string
	km        *keys.Manager
	api       *store.ResourceServer
}

// newMyAccountEnv serves the flow tenant on its canonical host and a second
// alias, with the My Account API active and a user grant for ropg.
func newMyAccountEnv(t *testing.T) *myAccountEnv {
	t.Helper()
	ctx := context.Background()
	e := newFlowEnvSeed(t, myAccountSeed, nil)
	tn, _ := e.st.Tenants().GetByName(ctx, "flow")
	alias := "localhost:" + strconv.Itoa(e.srv.Listener.Addr().(*net.TCPAddr).Port)
	tn.Domains = append(tn.Domains, alias)
	if err := e.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	tn, _ = e.st.Tenants().GetByName(ctx, "flow")
	api, err := tenantsetup.MyAccountAPI(ctx, e.st, tn, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.ClientGrants().Create(ctx, &store.ClientGrant{TenantID: tn.ID, ID: "cgr_ma", ClientID: "ropg", Audience: api.Identifier, SubjectType: store.SubjectTypeUser, Scopes: allMyAccountScopes, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return &myAccountEnv{flowEnv: e, tn: tn, canonical: tn.CanonicalHost, alias: alias, km: keys.NewManager(e.st.SigningKeys(), e.w), api: api}
}

// on serves one request addressed to host.
func (e *myAccountEnv) on(host, method, path, token string, body any, header http.Header) *httptest.ResponseRecorder {
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, "https://"+host+path, strings.NewReader(string(b)))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, "https://"+host+path, nil)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range header {
		r.Header[k] = v
	}
	rec := httptest.NewRecorder()
	e.srv.Config.Handler.ServeHTTP(rec, r)
	return rec
}

// tokenFor runs the password-realm grant on host for audience.
func (e *myAccountEnv) tokenFor(host, audience string, scopes ...string) *httptest.ResponseRecorder {
	form := url.Values{"grant_type": {"http://auth0.com/oauth/grant-type/password-realm"}, "realm": {"Username-Password-Authentication"},
		"client_id": {"ropg"}, "client_secret": {"ropg-s3cret"}, "username": {"alice@flow.test"}, "password": {"alice password 1"},
		"audience": {audience}, "scope": {strings.Join(scopes, " ")}}
	r := httptest.NewRequest("POST", "https://"+host+"/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	e.srv.Config.Handler.ServeHTTP(rec, r)
	return rec
}

// token is a My Account access token issued on host.
func (e *myAccountEnv) token(t *testing.T, host string, scopes ...string) string {
	t.Helper()
	if len(scopes) == 0 {
		scopes = allMyAccountScopes
	}
	rec := e.tokenFor(host, "https://"+host+"/me/", scopes...)
	tok := decodeJSON(rec)
	if rec.Code != 200 || tok["access_token"] == nil {
		t.Fatalf("token on %s = %d %s", host, rec.Code, rec.Body)
	}
	return tok["access_token"].(string)
}

func problemOf(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	p := decodeJSON(rec)
	for _, k := range []string{"type", "status", "title", "detail"} {
		if p[k] == nil {
			t.Errorf("problem body %s lacks %s", rec.Body, k)
		}
	}
	if p["status"] != float64(rec.Code) {
		t.Errorf("problem status %v, response %d", p["status"], rec.Code)
	}
	return p
}

// Review Focus 2: each host has its own My Account audience.
func TestMyAccountAudiencePerHost(t *testing.T) {
	e := newMyAccountEnv(t)
	canonicalTok := e.token(t, e.canonical)
	aliasTok := e.token(t, e.alias)
	for _, c := range []struct {
		host, tok string
		ok        bool
	}{{e.canonical, canonicalTok, true}, {e.alias, aliasTok, true}, {e.alias, canonicalTok, false}, {e.canonical, aliasTok, false}} {
		rec := e.on(c.host, "GET", "/me/v1/factors", c.tok, nil, nil)
		if got := rec.Code != 401; got != c.ok {
			t.Errorf("%s with token from other host=%v: %d %s", c.host, !c.ok, rec.Code, rec.Body)
		}
		if !c.ok {
			problemOf(t, rec)
		}
	}
	// The canonical audience cannot be requested on another host.
	if rec := e.tokenFor(e.alias, "https://"+e.canonical+"/me/", allMyAccountScopes...); rec.Code == 200 {
		t.Fatalf("canonical audience on alias = %d %s", rec.Code, rec.Body)
	}
	// Without a client grant the user policy refuses the token.
	ctx := context.Background()
	if err := e.st.ClientGrants().Delete(ctx, e.tn.ID, "cgr_ma"); err != nil {
		t.Fatal(err)
	}
	if rec := e.tokenFor(e.canonical, "https://"+e.canonical+"/me/", allMyAccountScopes...); rec.Code == 200 {
		t.Fatalf("token without a client grant = %d %s", rec.Code, rec.Body)
	}
}

// Review Focus 3: client tokens are refused, at issuance and at the API.
func TestMyAccountRefusesClientTokens(t *testing.T) {
	ctx := context.Background()
	e := newMyAccountEnv(t)
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"admin"}, "client_secret": {"admin-s3cret"}, "audience": {"https://" + e.canonical + "/me/"}}
	r := httptest.NewRequest("POST", "https://"+e.canonical+"/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	e.srv.Config.Handler.ServeHTTP(rec, r)
	if rec.Code == 200 || decodeJSON(rec)["error"] != "access_denied" {
		t.Fatalf("client credentials = %d %s", rec.Code, rec.Body)
	}
	// A correctly signed client-credentials token whose subject names a user.
	users, err := e.st.Users().FindByEmail(ctx, e.tn.ID, "alice@flow.test")
	if err != nil || len(users) != 1 {
		t.Fatal(users, err)
	}
	u := users[0]
	now := time.Now()
	for _, claims := range []map[string]any{
		{"gty": "client-credentials", "sub": u.UserID, "azp": "admin"},
		{"gty": "client-credentials", "sub": "admin@clients", "azp": "admin"},
		{"sub": "admin@clients", "azp": "admin"},
	} {
		claims["iss"], claims["aud"], claims["exp"], claims["iat"], claims["scope"] = "https://"+e.canonical+"/", "https://"+e.canonical+"/me/", now.Add(time.Hour).Unix(), now.Unix(), strings.Join(allMyAccountScopes, " ")
		raw, err := e.km.SignWithType(ctx, e.tn.ID, claims, "at+jwt")
		if err != nil {
			t.Fatal(err)
		}
		if rec := e.on(e.canonical, "GET", "/me/v1/factors", raw, nil, nil); rec.Code != 401 {
			t.Errorf("client token %v = %d %s", claims, rec.Code, rec.Body)
		}
	}
}

// Every operation requires its own scope; a missing one is 403.
func TestMyAccountScopes(t *testing.T) {
	e := newMyAccountEnv(t)
	tok := e.token(t, e.canonical, "openid")
	for _, c := range []struct{ method, path string }{
		{"GET", "/me/v1/factors"},
		{"GET", "/me/v1/authentication-methods"},
		{"POST", "/me/v1/authentication-methods"},
		{"GET", "/me/v1/authentication-methods/totp%7Cdev_x"},
		{"PATCH", "/me/v1/authentication-methods/totp%7Cdev_x"},
		{"DELETE", "/me/v1/authentication-methods/totp%7Cdev_x"},
		{"POST", "/me/v1/authentication-methods/totp%7Cdev_x/verify"},
	} {
		var body any
		if c.method == "POST" || c.method == "PATCH" {
			body = map[string]any{}
		}
		rec := e.on(e.canonical, c.method, c.path, tok, body, nil)
		if rec.Code != 403 {
			t.Errorf("%s %s without scope = %d %s", c.method, c.path, rec.Code, rec.Body)
			continue
		}
		problemOf(t, rec)
	}
	if rec := e.on(e.canonical, "GET", "/me/v1/nothing", tok, nil, nil); rec.Code != 404 {
		t.Errorf("unknown route = %d", rec.Code)
	}
}

// Errors carry the ErrorResponse body and the correlation ID.
func TestProblemShape(t *testing.T) {
	e := newMyAccountEnv(t)
	rec := e.on(e.canonical, "GET", "/me/v1/factors", "", nil, http.Header{"X-Correlation-Id": {"corr-42"}})
	if rec.Code != 401 {
		t.Fatalf("no token = %d", rec.Code)
	}
	problemOf(t, rec)
	if got := rec.Header().Get("x-correlation-id"); got != "corr-42" {
		t.Errorf("x-correlation-id = %q", got)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content type %q", ct)
	}
	rec = e.on(e.canonical, "GET", "/me/v1/factors", "", nil, http.Header{"X-Correlation-Id": {strings.Repeat("x", 65)}})
	if got := rec.Header().Get("x-correlation-id"); got == "" || len(got) > 64 {
		t.Errorf("oversized correlation id echoed as %q", got)
	}
	// Deactivated: the API is gone.
	ctx := context.Background()
	if err := e.st.ResourceServers().Delete(ctx, e.tn.ID, e.api.ID); err != nil {
		t.Fatal(err)
	}
	if rec := e.on(e.canonical, "GET", "/me/v1/factors", "x", nil, nil); rec.Code != 404 {
		t.Errorf("inactive API = %d %s", rec.Code, rec.Body)
	}
}
