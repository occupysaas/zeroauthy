package passwordless

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func (e *testEnv) handlers() *Handlers {
	now := e.svc.Now
	sessions := &session.Manager{Store: e.st, Now: now}
	return &Handlers{Service: e.svc, Sessions: sessions, Authz: &authz.Handlers{Store: e.st, Sessions: sessions, Now: now, Wrapper: e.svc.Wrapper}}
}

func (e *testEnv) serve(h *Handlers, method, target string, form url.Values) *httptest.ResponseRecorder {
	e.t.Helper()
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	tn, _ := e.st.Tenants().Get(e.ctx, tid)
	req = req.WithContext(tenant.WithResolved(req.Context(), tenant.Resolved{Tenant: tn, Host: "acme.example.test"}))
	rec := httptest.NewRecorder()
	if method == "POST" {
		h.VerifyRedirectConfirm(rec, req)
	} else {
		h.VerifyRedirect(rec, req)
	}
	return rec
}

var formField = regexp.MustCompile(`name="(verification_code|state_token)" value="([^"]+)"`)

// Review Focus 2 end to end: GETs (a scanner) render the confirmation page
// and never consume the link; the user's POST signs in once.
func TestLinkVerifyRedirectFlow(t *testing.T) {
	e := newTestEnv(t)
	h := e.handlers()
	params := url.Values{"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}, "redirect_uri": {"https://app.test/cb"}, "response_type": {"code"}, "scope": {"openid"}, "state": {"s1"}}
	if _, err := e.start(StartInput{Connection: "email", Email: "ada@example.test", AuthParams: params}); err != nil {
		t.Fatal(err)
	}
	link := e.mail.last(t).Link
	var page string
	for i := 0; i < 2; i++ {
		rec := e.serve(h, "GET", link, nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), `action="/passwordless/verify_redirect"`) {
			t.Fatalf("GET %d = %d %s", i, rec.Code, rec.Body.String())
		}
		page = rec.Body.String()
	}
	form := url.Values{}
	for _, m := range formField.FindAllStringSubmatch(page, -1) {
		form.Set(m[1], strings.ReplaceAll(m[2], "&#43;", "+"))
	}
	if form.Get("state_token") == "" || form.Get("verification_code") == "" {
		t.Fatalf("form fields = %v", form)
	}
	rec := e.serve(h, "POST", "https://acme.example.test/passwordless/verify_redirect", form)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != 302 || loc == nil || loc.Host != "app.test" || loc.Query().Get("code") == "" || loc.Query().Get("state") != "s1" {
		t.Fatalf("POST = %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	// A second use fails with access_denied at the redirect.
	rec = e.serve(h, "POST", "https://acme.example.test/passwordless/verify_redirect", form)
	loc, _ = url.Parse(rec.Header().Get("Location"))
	if rec.Code != 302 || loc.Query().Get("error") != "access_denied" {
		t.Fatalf("reuse = %d %s", rec.Code, rec.Header().Get("Location"))
	}
	// A tampered state token renders the expired-form page.
	form.Set("state_token", "AAAA")
	if rec := e.serve(h, "POST", "https://acme.example.test/passwordless/verify_redirect", form); rec.Code != 400 {
		t.Fatalf("tampered state = %d", rec.Code)
	}
}

func TestCodeVerifyRedirect(t *testing.T) {
	e := newTestEnv(t)
	h := e.handlers()
	code := e.emailCode("ada@example.test")
	q := url.Values{"client_id": {"cli"}, "connection": {"email"}, "email": {"ada@example.test"}, "verification_code": {"000000"}, "code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"},
		"redirect_uri": {"https://app.test/cb"}, "response_type": {"code"}, "scope": {"openid"}, "state": {"s2"}}
	rec := e.serve(h, "GET", "https://acme.example.test/passwordless/verify_redirect?"+q.Encode(), nil)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != 302 || loc.Query().Get("error") != "access_denied" || len(e.rec.of("f")) != 1 {
		t.Fatalf("wrong code = %d %s", rec.Code, rec.Header().Get("Location"))
	}
	q.Set("verification_code", code)
	rec = e.serve(h, "GET", "https://acme.example.test/passwordless/verify_redirect?"+q.Encode(), nil)
	loc, _ = url.Parse(rec.Header().Get("Location"))
	if rec.Code != 302 || loc.Query().Get("code") == "" || loc.Query().Get("state") != "s2" {
		t.Fatalf("code = %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	// A redirect_uri that is not a callback gets the error page, not a redirect.
	q.Set("redirect_uri", "https://evil.test/cb")
	if rec := e.serve(h, "GET", "https://acme.example.test/passwordless/verify_redirect?"+q.Encode(), nil); rec.Code != 400 {
		t.Fatalf("bad redirect = %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if rec := e.serve(h, "GET", "https://acme.example.test/passwordless/verify_redirect?client_id=cli", nil); rec.Code != 400 {
		t.Fatalf("missing params = %d", rec.Code)
	}
}
