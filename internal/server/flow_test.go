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
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const flowSeed = `
tenants:
  - name: flow
    domains: ["HOST"]
    resource_servers:
      - {identifier: "https://api.flow.test", name: API, scopes: [{value: "read:things"}]}
    clients:
      - client_id: spa
        app_type: spa
        grant_types: [authorization_code]
        callbacks: ["https://app.flow.test/cb"]
        web_origins: ["https://app.flow.test"]
        allowed_origins: ["https://app.flow.test"]
    connections:
      - {name: Username-Password-Authentication, enabled_clients: [spa]}
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
}

func newFlowEnv(t *testing.T) *flowEnv {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{8}, 32))
	km := keys.NewManager(st.SigningKeys(), w)
	srv := httptest.NewTLSServer(New(Deps{
		Store: st, Keys: km, Resolver: tenant.NewResolver(st.Tenants(), "", false),
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Sessions:     &session.Manager{Store: st},
		UserThrottle: identity.NewThrottle(10, time.Minute, time.Minute),
		IPThrottle:   identity.NewThrottle(100, time.Minute, time.Minute),
	}))
	t.Cleanup(srv.Close)
	host := srv.Listener.Addr().String()
	f, err := seed.Parse([]byte(strings.Replace(flowSeed, "HOST", host, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Apply(ctx, st, f, nil); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "flow")
	if err := km.Ensure(ctx, tn.ID); err != nil {
		t.Fatal(err)
	}
	return &flowEnv{srv: srv, base: "https://" + host}
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
	for _, path := range []string{"/oauth/token", "/userinfo"} {
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
