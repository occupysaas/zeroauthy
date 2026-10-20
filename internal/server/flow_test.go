package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const flowSeed = `
tenants:
  - name: flow
    domains: ["HOST"]
    resource_servers:
      - {identifier: "https://api.flow.test", skip_consent_for_verifiable_first_party_clients: true, name: API, allow_offline_access: true, scopes: [{value: "read:things"}]}
    client_grants:
      - {client_id: partner, audience: "https://api.flow.test", subject_type: user, scopes: ["read:things"]}
    clients:
      - client_id: partner
        app_type: regular_web
        client_secret: partner-secret
        is_first_party: false
        refresh_token: {rotation_type: rotating, expiration_type: expiring}
        grant_types: [authorization_code]
        callbacks: ["https://partner.flow.test/cb"]
      - client_id: spa
        app_type: spa
        grant_types: [authorization_code, refresh_token]
        callbacks: ["https://app.flow.test/cb"]
        allowed_logout_urls: ["https://app.flow.test/bye"]
        web_origins: ["https://app.flow.test"]
        allowed_origins: ["https://app.flow.test"]
      - {client_id: tv, name: "Flow TV", app_type: native, grant_types: ["urn:ietf:params:oauth:grant-type:device_code"]}
      - client_id: spa2
        app_type: spa
        grant_types: [authorization_code]
        callbacks: ["https://app2.flow.test/cb"]
        allowed_logout_urls: ["https://app2.flow.test/bye"]
    connections:
      - {name: Username-Password-Authentication, is_domain_connection: true, enabled_clients: [spa, tv, spa2]}
    users:
      - {connection: Username-Password-Authentication, email: alice@flow.test, password: "alice password 1", email_verified: true}
`

const (
	verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

type flowEnv struct {
	srv  *httptest.Server
	base string
	st   store.Store
	w    keys.Wrapper
}

func newFlowEnv(t *testing.T) *flowEnv {
	t.Helper()
	return newFlowEnvSeed(t, flowSeed, nil)
}

// newFlowEnvSeed is newFlowEnv with its own seed (HOST is replaced by the
// server's host) and adjust applied to the server's Deps.
func newFlowEnvSeed(t *testing.T, seedText string, adjust func(*Deps)) *flowEnv {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{8}, 32))
	km := keys.NewManager(st.SigningKeys(), w)
	d := Deps{
		Store: st, Keys: km, Wrapper: w, Resolver: tenant.NewResolver(st.Tenants(), "", false),
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Sessions:     &session.Manager{Store: st},
		Mailer:       discardMailer{},
		UserThrottle: identity.NewThrottle(10, time.Minute, time.Minute),
		IPThrottle:   identity.NewThrottle(100, time.Minute, time.Minute),
	}
	if adjust != nil {
		adjust(&d)
	}
	srv := httptest.NewTLSServer(New(d))
	t.Cleanup(srv.Close)
	host := srv.Listener.Addr().String()
	f, err := seed.Parse([]byte(strings.ReplaceAll(seedText, "HOST", host)))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.CheckManagementAPI(""); err != nil {
		t.Fatal(err)
	}
	if err := seed.Apply(ctx, st, f, nil, w); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "flow")
	if err := km.Ensure(ctx, tn.ID); err != nil {
		t.Fatal(err)
	}
	return &flowEnv{srv: srv, base: "https://" + host, st: st, w: w}
}

func (e *flowEnv) client(t *testing.T) *http.Client {
	jar, _ := cookiejar.New(nil)
	c := e.srv.Client()
	c.Jar = jar
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

func authorizeURL(base string, extra ...string) string {
	q := url.Values{
		"client_id": {"spa"}, "redirect_uri": {"https://app.flow.test/cb"}, "response_type": {"code"},
		"scope": {"openid email read:things"}, "audience": {"https://api.flow.test"}, "state": {"s1"}, "nonce": {"n1"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "auth0Client": {"eyJuYW1lIjoidGVzdCJ9"},
	}
	for i := 0; i+1 < len(extra); i += 2 {
		q.Set(extra[i], extra[i+1])
	}
	return base + "/authorize?" + q.Encode()
}

func mustDo(t *testing.T, c *http.Client, req *http.Request) (*http.Response, string) {
	t.Helper()
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func fetch(t *testing.T, c *http.Client, u string) (*http.Response, string) {
	req, _ := http.NewRequest("GET", u, nil)
	return mustDo(t, c, req)
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func TestEndToEndCodeFlow(t *testing.T) {
	e := newFlowEnv(t)
	c := e.client(t)

	// 1. /authorize without a session goes to the login page.
	resp, _ := fetch(t, c, authorizeURL(e.base))
	loginURL, _ := resp.Location()
	if resp.StatusCode != 302 || loginURL.Path != "/u/login" {
		t.Fatalf("authorize = %d %v", resp.StatusCode, loginURL)
	}
	// 2. Log in.
	_, page := fetch(t, c, loginURL.String())
	csrf := csrfRe.FindStringSubmatch(page)
	if csrf == nil {
		t.Fatalf("no csrf: %s", page)
	}
	form := url.Values{"state": {loginURL.Query().Get("state")}, "csrf": {csrf[1]}, "username": {"alice@flow.test"}, "password": {"alice password 1"}}
	req, _ := http.NewRequest("POST", e.base+"/u/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, body := mustDo(t, c, req)
	cb, _ := resp.Location()
	if resp.StatusCode != 302 || cb.Host != "app.flow.test" || cb.Query().Get("state") != "s1" {
		t.Fatalf("login = %d %v %s", resp.StatusCode, cb, body)
	}
	// 3. Exchange the code from the SPA's origin.
	tf := url.Values{"grant_type": {"authorization_code"}, "client_id": {"spa"}, "code": {cb.Query().Get("code")},
		"redirect_uri": {"https://app.flow.test/cb"}, "code_verifier": {verifier}}
	req, _ = http.NewRequest("POST", e.base+"/oauth/token", strings.NewReader(tf.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://app.flow.test")
	resp, body = mustDo(t, c, req)
	if resp.StatusCode != 200 || resp.Header.Get("Access-Control-Allow-Origin") != "https://app.flow.test" {
		t.Fatalf("token = %d %v %s", resp.StatusCode, resp.Header, body)
	}
	var tok map[string]any
	_ = json.Unmarshal([]byte(body), &tok)
	if tok["id_token"] == nil || tok["scope"] != "openid email read:things" {
		t.Fatalf("token body = %v", tok)
	}
	// 4. /userinfo with the access token.
	req, _ = http.NewRequest("GET", e.base+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok["access_token"].(string))
	resp, body = mustDo(t, c, req)
	if resp.StatusCode != 200 || !strings.Contains(body, `"email":"alice@flow.test"`) {
		t.Fatalf("userinfo = %d %s", resp.StatusCode, body)
	}
	// 5. Silent authentication with the session cookie.
	resp, body = fetch(t, c, authorizeURL(e.base, "prompt", "none", "response_mode", "web_message"))
	if resp.StatusCode != 200 || !strings.Contains(body, "authorization_response") || !strings.Contains(body, "code") || strings.Contains(body, "login_required") {
		t.Fatalf("silent auth = %d %s", resp.StatusCode, body)
	}
	// 6. Silent authentication without a session (review focus 5).
	resp, body = fetch(t, e.client(t), authorizeURL(e.base, "prompt", "none", "response_mode", "web_message"))
	if resp.StatusCode != 200 || !strings.Contains(body, "login_required") {
		t.Fatalf("silent auth without session = %d %s", resp.StatusCode, body)
	}
}

func TestCORS(t *testing.T) {
	e := newFlowEnv(t)
	c := e.client(t)
	preflight := func(path, origin string) *http.Response {
		req, _ := http.NewRequest("OPTIONS", e.base+path, nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "content-type, auth0-client")
		resp, _ := mustDo(t, c, req)
		return resp
	}
	for _, path := range []string{"/oauth/token", "/oauth/device/code", "/userinfo"} {
		resp := preflight(path, "https://app.flow.test")
		h := resp.Header
		if resp.StatusCode != 204 || h.Get("Access-Control-Allow-Origin") != "https://app.flow.test" ||
			!strings.Contains(h.Get("Access-Control-Allow-Methods"), "POST") ||
			h.Get("Access-Control-Allow-Headers") != "content-type, auth0-client" || !strings.Contains(h.Get("Vary"), "Origin") {
			t.Errorf("%s preflight = %d %v", path, resp.StatusCode, h)
		}
		resp = preflight(path, "https://evil.test")
		if resp.StatusCode != 403 || resp.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%s evil preflight = %d %v", path, resp.StatusCode, resp.Header)
		}
	}
	resp, _ := fetch(t, c, e.base+"/.well-known/jwks.json")
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("jwks ACAO = %q", resp.Header.Get("Access-Control-Allow-Origin"))
	}
}

// Origins are matched exactly: near-misses and unlisted origins get no
// Access-Control-* headers, and every response varies by Origin.
func TestCORSNegative(t *testing.T) {
	e := newFlowEnv(t)
	c := e.client(t)
	for _, origin := range []string{
		"https://evil.test", "http://app.flow.test", "https://app.flow.test:8443",
		"https://app.flow.test/", "https://sub.app.flow.test", "https://APP.flow.test", "null",
	} {
		for _, method := range []string{"OPTIONS", "POST"} {
			req, _ := http.NewRequest(method, e.base+"/oauth/token", strings.NewReader("grant_type=x"))
			req.Header.Set("Origin", origin)
			req.Header.Set("Access-Control-Request-Method", "POST")
			resp, _ := mustDo(t, c, req)
			for k := range resp.Header {
				if strings.HasPrefix(k, "Access-Control-") {
					t.Errorf("%s from %q: got %s", method, origin, k)
				}
			}
			if method == "OPTIONS" && resp.StatusCode != 403 {
				t.Errorf("preflight from %q = %d", origin, resp.StatusCode)
			}
			if !strings.Contains(resp.Header.Get("Vary"), "Origin") {
				t.Errorf("%s from %q: Vary = %q", method, origin, resp.Header.Get("Vary"))
			}
		}
	}
	// A request without an Origin gets no CORS headers either.
	req, _ := http.NewRequest("POST", e.base+"/oauth/token", strings.NewReader("grant_type=x"))
	resp, _ := mustDo(t, c, req)
	if resp.Header.Get("Access-Control-Allow-Origin") != "" || !strings.Contains(resp.Header.Get("Vary"), "Origin") {
		t.Errorf("no-origin response headers = %v", resp.Header)
	}
	// Paths outside the CORS set never get the allow header.
	req, _ = http.NewRequest("GET", e.base+"/authorize", nil)
	req.Header.Set("Origin", "https://app.flow.test")
	resp, _ = mustDo(t, c, req)
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("/authorize ACAO = %q", resp.Header.Get("Access-Control-Allow-Origin"))
	}
}

// postForm posts a form from the SPA's origin and decodes a JSON reply.
func (e *flowEnv) postForm(t *testing.T, c *http.Client, path string, form url.Values) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("POST", e.base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://app.flow.test")
	resp, body := mustDo(t, c, req)
	var out map[string]any
	_ = json.Unmarshal([]byte(body), &out)
	return resp, out
}

// codeFlow runs /authorize (logging in if needed) and exchanges the code.
func (e *flowEnv) codeFlow(t *testing.T, c *http.Client, extra ...string) map[string]any {
	t.Helper()
	resp, _ := fetch(t, c, authorizeURL(e.base, extra...))
	loc, _ := resp.Location()
	if loc != nil && loc.Path == "/u/login" {
		_, page := fetch(t, c, loc.String())
		csrf := csrfRe.FindStringSubmatch(page)
		if csrf == nil {
			t.Fatalf("no csrf: %s", page)
		}
		form := url.Values{"state": {loc.Query().Get("state")}, "csrf": {csrf[1]}, "username": {"alice@flow.test"}, "password": {"alice password 1"}}
		req, _ := http.NewRequest("POST", e.base+"/u/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, _ = mustDo(t, c, req)
		loc, _ = resp.Location()
	}
	if loc == nil || loc.Host != "app.flow.test" || loc.Query().Get("code") == "" {
		t.Fatalf("authorize ended at %v (status %d)", loc, resp.StatusCode)
	}
	resp, tok := e.postForm(t, c, "/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"spa"},
		"code": {loc.Query().Get("code")}, "redirect_uri": {"https://app.flow.test/cb"}, "code_verifier": {verifier}})
	if resp.StatusCode != 200 {
		t.Fatalf("code exchange = %d %v", resp.StatusCode, tok)
	}
	return tok
}

func TestEndToEndRefreshAndLogout(t *testing.T) {
	e := newFlowEnv(t)
	c := e.client(t)
	refresh := func(token string) (*http.Response, map[string]any) {
		return e.postForm(t, c, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"spa"}, "refresh_token": {token}})
	}

	// 1. offline_access yields a refresh token.
	tok := e.codeFlow(t, c, "scope", "openid offline_access read:things")
	first, _ := tok["refresh_token"].(string)
	if first == "" || tok["scope"] != "openid offline_access read:things" {
		t.Fatalf("token response = %v", tok)
	}
	// 2. Refreshing rotates, cross-origin, with an ID token.
	resp, body := refresh(first)
	second, _ := body["refresh_token"].(string)
	if resp.StatusCode != 200 || second == "" || second == first || body["id_token"] == nil ||
		resp.Header.Get("Access-Control-Allow-Origin") != "https://app.flow.test" {
		t.Fatalf("refresh = %d %v %v", resp.StatusCode, resp.Header, body)
	}
	// 3. Reusing the rotated token revokes the family.
	if resp, body := refresh(first); resp.StatusCode != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("reuse = %d %v", resp.StatusCode, body)
	}
	if resp, body := refresh(second); resp.StatusCode != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("successor after reuse = %d %v", resp.StatusCode, body)
	}
	// 4. The session still works: a new login gives a new family, which
	//    /oauth/revoke ends.
	tok = e.codeFlow(t, c, "scope", "openid offline_access")
	third := tok["refresh_token"].(string)
	if resp, body := e.postForm(t, c, "/oauth/revoke", url.Values{"client_id": {"spa"}, "token": {third}}); resp.StatusCode != 200 {
		t.Fatalf("revoke = %d %v", resp.StatusCode, body)
	}
	if resp, _ := refresh(third); resp.StatusCode != 400 {
		t.Fatalf("refresh after revoke = %d", resp.StatusCode)
	}
	// 5. /v2/logout ends the session and returns to the app.
	resp, _ = fetch(t, c, e.base+"/v2/logout?"+url.Values{"client_id": {"spa"}, "returnTo": {"https://app.flow.test/bye"}}.Encode())
	if loc, _ := resp.Location(); resp.StatusCode != 302 || loc.String() != "https://app.flow.test/bye" {
		t.Fatalf("logout = %d %v", resp.StatusCode, loc)
	}
	// 6. Silent authentication now reports login_required.
	resp, page := fetch(t, c, authorizeURL(e.base, "prompt", "none", "response_mode", "web_message"))
	if resp.StatusCode != 200 || !strings.Contains(page, "login_required") {
		t.Fatalf("silent auth after logout = %d %s", resp.StatusCode, page)
	}
	// 7. Discovery advertises the new endpoints.
	_, doc := fetch(t, c, e.base+"/.well-known/openid-configuration")
	for _, want := range []string{`"end_session_endpoint":"` + e.base + `/oidc/logout"`, `"revocation_endpoint":"` + e.base + `/oauth/revoke"`, `"refresh_token"`, `"offline_access"`} {
		if !strings.Contains(doc, want) {
			t.Errorf("discovery lacks %s", want)
		}
	}
}

func TestEndToEndConsentFlow(t *testing.T) {
	e := newFlowEnv(t)
	c := e.client(t)
	post := func(path string, form url.Values) (*http.Response, string) {
		req, _ := http.NewRequest("POST", e.base+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return mustDo(t, c, req)
	}
	q := url.Values{"client_id": {"partner"}, "redirect_uri": {"https://partner.flow.test/cb"}, "response_type": {"code"},
		"scope": {"openid read:things"}, "audience": {"https://api.flow.test"}, "state": {"p1"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}}

	resp, _ := fetch(t, c, e.base+"/authorize?"+q.Encode())
	loc, _ := resp.Location()
	if loc == nil || loc.Path != "/u/login" {
		t.Fatalf("authorize = %d %v", resp.StatusCode, loc)
	}
	_, page := fetch(t, c, loc.String())
	csrf := csrfRe.FindStringSubmatch(page)
	if csrf == nil {
		t.Fatalf("no csrf: %s", page)
	}
	resp, body := post("/u/login", url.Values{"state": {loc.Query().Get("state")}, "csrf": {csrf[1]}, "username": {"alice@flow.test"}, "password": {"alice password 1"}})
	loc, _ = resp.Location()
	if loc == nil || loc.Path != "/u/consent" {
		t.Fatalf("login = %d %v %s", resp.StatusCode, loc, body)
	}
	resp, page = fetch(t, c, loc.String())
	csrf = csrfRe.FindStringSubmatch(page)
	if resp.StatusCode != 200 || csrf == nil || !strings.Contains(page, "read:things") {
		t.Fatalf("consent page = %d %s", resp.StatusCode, page)
	}
	resp, body = post("/u/consent", url.Values{"state": {loc.Query().Get("state")}, "csrf": {csrf[1]}, "action": {"accept"}})
	cb, _ := resp.Location()
	if cb == nil || cb.Host != "partner.flow.test" || cb.Query().Get("code") == "" || cb.Query().Get("state") != "p1" {
		t.Fatalf("accept = %d %v %s", resp.StatusCode, cb, body)
	}
	resp, body = post("/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"partner"}, "client_secret": {"partner-secret"},
		"code": {cb.Query().Get("code")}, "redirect_uri": {"https://partner.flow.test/cb"}, "code_verifier": {verifier}})
	var tok map[string]any
	_ = json.Unmarshal([]byte(body), &tok)
	if resp.StatusCode != 200 || tok["scope"] != "read:things" || tok["id_token"] != nil {
		t.Fatalf("token = %d %s", resp.StatusCode, body)
	}
}

// The device flow over HTTP: the code request, the browser pages (with a
// real cookie jar, so the Path=/ transaction cookies must reach /activate
// and /device/confirmation) and the token poll.
func TestEndToEndDeviceFlow(t *testing.T) {
	e := newFlowEnv(t)
	c := e.client(t)
	resp, dev := e.postForm(t, c, "/oauth/device/code", url.Values{"client_id": {"tv"}, "scope": {"openid"}})
	if resp.StatusCode != 200 {
		t.Fatalf("device code = %d %v", resp.StatusCode, dev)
	}
	complete, _ := dev["verification_uri_complete"].(string)
	u, err := url.Parse(complete)
	if err != nil || u.Path != "/activate" {
		t.Fatalf("verification_uri_complete = %q", complete)
	}
	resp, _ = fetch(t, c, e.base+u.RequestURI())
	loc, _ := resp.Location()
	if resp.StatusCode != 302 || loc == nil || loc.Path != "/device/confirmation" {
		t.Fatalf("activate = %d %v", resp.StatusCode, loc)
	}
	resp, body := fetch(t, c, loc.String())
	if resp.StatusCode != 200 || !strings.Contains(body, dev["user_code"].(string)) {
		t.Fatalf("confirmation = %d\n%s", resp.StatusCode, body)
	}
	post := func(path string, form url.Values) (*http.Response, string) {
		req, _ := http.NewRequest("POST", e.base+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return mustDo(t, c, req)
	}
	resp, _ = post("/device/confirmation", url.Values{"state": {loc.Query().Get("state")}, "csrf": {csrfRe.FindStringSubmatch(body)[1]}, "action": {"confirm"}})
	loc, _ = resp.Location()
	if resp.StatusCode != 302 || loc == nil || loc.Path != "/u/login" {
		t.Fatalf("confirm = %d %v", resp.StatusCode, loc)
	}
	_, body = fetch(t, c, e.base+loc.RequestURI())
	resp, _ = post("/u/login", url.Values{"state": {loc.Query().Get("state")}, "csrf": {csrfRe.FindStringSubmatch(body)[1]}, "username": {"alice@flow.test"}, "password": {"alice password 1"}})
	loc, _ = resp.Location()
	if resp.StatusCode != 302 || loc == nil || loc.Path != "/device/success" {
		t.Fatalf("login = %d %v", resp.StatusCode, loc)
	}
	if resp, body = fetch(t, c, e.base+"/device/success"); resp.StatusCode != 200 {
		t.Fatalf("success page = %d\n%s", resp.StatusCode, body)
	}
	resp, tok := e.postForm(t, c, "/oauth/token", url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "client_id": {"tv"}, "device_code": {dev["device_code"].(string)}})
	if resp.StatusCode != 200 || tok["id_token"] == nil || tok["access_token"] == nil {
		t.Fatalf("token = %d %v", resp.StatusCode, tok)
	}
}

// OIDF oidcc-ensure-post-request-succeeds: /authorize accepts POST with a
// form-encoded body (OpenID Connect Core §3.1.2.1) and behaves as GET.
func TestEndToEndAuthorizePost(t *testing.T) {
	e := newFlowEnv(t)
	c := e.client(t)
	post := func(form string) (*http.Response, string) {
		req, _ := http.NewRequest("POST", e.base+"/authorize", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return mustDo(t, c, req)
	}
	params := func(extra ...string) string {
		u, _ := url.Parse(authorizeURL(e.base, extra...))
		return u.RawQuery
	}

	// Without a session: to the login page, then back with the code.
	resp, body := post(params())
	loginURL, _ := resp.Location()
	if resp.StatusCode != 302 || loginURL == nil || loginURL.Path != "/u/login" {
		t.Fatalf("POST /authorize = %d %v %s", resp.StatusCode, loginURL, body)
	}
	_, page := fetch(t, c, loginURL.String())
	csrf := csrfRe.FindStringSubmatch(page)
	if csrf == nil {
		t.Fatalf("no csrf: %s", page)
	}
	form := url.Values{"state": {loginURL.Query().Get("state")}, "csrf": {csrf[1]}, "username": {"alice@flow.test"}, "password": {"alice password 1"}}
	req, _ := http.NewRequest("POST", e.base+"/u/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, body = mustDo(t, c, req)
	cb, _ := resp.Location()
	if resp.StatusCode != 302 || cb.Host != "app.flow.test" || cb.Query().Get("state") != "s1" || cb.Query().Get("code") == "" {
		t.Fatalf("login = %d %v %s", resp.StatusCode, cb, body)
	}

	// With the session: the code is issued at once, in the requested mode.
	resp, body = post(params("response_mode", "form_post"))
	if resp.StatusCode != 200 || !strings.Contains(body, `action="https://app.flow.test/cb"`) || !strings.Contains(body, `name="code"`) {
		t.Fatalf("POST /authorize with session = %d %s", resp.StatusCode, body)
	}

	// Errors are delivered as for GET.
	resp, _ = post(params("response_type", "token"))
	if loc, _ := resp.Location(); resp.StatusCode != 302 || loc == nil || loc.Query().Get("error") != "unsupported_response_type" || loc.Query().Get("state") != "s1" {
		t.Fatalf("POST error = %d %v", resp.StatusCode, loc)
	}
	resp, body = post(params() + "&client_id=other")
	if resp.StatusCode != 400 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") || !strings.Contains(body, `"invalid_request"`) {
		t.Fatalf("repeated client_id = %d %v %s", resp.StatusCode, resp.Header, body)
	}
}
