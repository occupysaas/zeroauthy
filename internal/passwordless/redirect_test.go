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
	if e.jar == nil {
		e.jar = map[string]*http.Cookie{}
	}
	return e.serveIn(e.jar, h, method, target, form)
}

// serveIn serves one request from the browser whose cookies are jar.
func (e *testEnv) serveIn(jar map[string]*http.Cookie, h *Handlers, method, target string, form url.Values) *httptest.ResponseRecorder {
	e.t.Helper()
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	for _, c := range jar {
		req.AddCookie(c)
	}
	tn, _ := e.st.Tenants().Get(e.ctx, tid)
	req = req.WithContext(tenant.WithResolved(req.Context(), tenant.Resolved{Tenant: tn, Host: "acme.example.test"}))
	rec := httptest.NewRecorder()
	if method == "POST" {
		h.VerifyRedirectConfirm(rec, req)
	} else {
		h.VerifyRedirect(rec, req)
	}
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(jar, c.Name)
		} else {
			jar[c.Name] = c
		}
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

func confirmFields(t *testing.T, body string) url.Values {
	t.Helper()
	form := url.Values{}
	for _, m := range formField.FindAllStringSubmatch(body, -1) {
		form.Set(m[1], strings.ReplaceAll(m[2], "&#43;", "+"))
	}
	if form.Get("state_token") == "" || form.Get("verification_code") == "" {
		t.Fatalf("no confirmation form: %s", body)
	}
	return form
}

// A typed code is not verified by the GET (login CSRF): the GET renders the
// confirmation page and the browser that rendered it posts the code.
func TestCodeVerifyRedirect(t *testing.T) {
	e := newTestEnv(t)
	h := e.handlers()
	code := e.emailCode("ada@example.test")
	q := url.Values{"client_id": {"cli"}, "connection": {"email"}, "email": {"ada@example.test"}, "verification_code": {"000000"}, "code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"},
		"redirect_uri": {"https://app.test/cb"}, "response_type": {"code"}, "scope": {"openid"}, "state": {"s2"}}
	page := e.serve(h, "GET", "https://acme.example.test/passwordless/verify_redirect?"+q.Encode(), nil)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "ada@example.test") || len(e.rec.of("f")) != 0 {
		t.Fatalf("typed code GET = %d %s", page.Code, page.Body.String())
	}
	rec := e.serve(h, "POST", "https://acme.example.test/passwordless/verify_redirect", confirmFields(t, page.Body.String()))
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != 302 || loc.Query().Get("error") != "access_denied" || len(e.rec.of("f")) != 1 {
		t.Fatalf("wrong code = %d %s", rec.Code, rec.Header().Get("Location"))
	}
	q.Set("verification_code", code)
	page = e.serve(h, "GET", "https://acme.example.test/passwordless/verify_redirect?"+q.Encode(), nil)
	rec = e.serve(h, "POST", "https://acme.example.test/passwordless/verify_redirect", confirmFields(t, page.Body.String()))
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

// Login CSRF: an attacker renders the confirmation form for their own link
// or code and makes the victim's browser post it. The form is bound to the
// browser that rendered it, so the victim's post is refused and nothing is
// consumed; posting without the binding cookie is refused too.
func TestVerifyRedirectConfirmCrossBrowserRefused(t *testing.T) {
	for _, kind := range []string{"link", "code"} {
		t.Run(kind, func(t *testing.T) {
			e := newTestEnv(t)
			h := e.handlers()
			var target string
			if kind == "link" {
				params := url.Values{"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}, "redirect_uri": {"https://app.test/cb"}, "response_type": {"code"}, "scope": {"openid"}, "state": {"s1"}}
				if _, err := e.start(StartInput{Connection: "email", Email: "mallory@example.test", AuthParams: params}); err != nil {
					t.Fatal(err)
				}
				target = e.mail.last(t).Link
			} else {
				code := e.emailCode("mallory@example.test")
				target = "https://acme.example.test/passwordless/verify_redirect?" + url.Values{"client_id": {"cli"}, "connection": {"email"}, "email": {"mallory@example.test"}, "verification_code": {code},
					"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}, "redirect_uri": {"https://app.test/cb"}, "response_type": {"code"}, "scope": {"openid"}, "state": {"s1"}}.Encode()
			}
			attacker, victim := map[string]*http.Cookie{}, map[string]*http.Cookie{}
			page := e.serveIn(attacker, h, "GET", target, nil)
			if page.Code != 200 {
				t.Fatalf("attacker GET = %d %s", page.Code, page.Body.String())
			}
			form := confirmFields(t, page.Body.String())
			for name, jar := range map[string]map[string]*http.Cookie{"victim": victim, "no cookie": {}} {
				rec := e.serveIn(jar, h, "POST", "https://acme.example.test/passwordless/verify_redirect", form)
				if rec.Code != 400 || rec.Header().Get("Location") != "" || jar[session.CookieName] != nil {
					t.Fatalf("%s POST = %d %s", name, rec.Code, rec.Header().Get("Location"))
				}
			}
			// The victim's own (unrelated) binding cookie does not help either.
			e.serveIn(victim, h, "GET", target, nil)
			if rec := e.serveIn(victim, h, "POST", "https://acme.example.test/passwordless/verify_redirect", form); rec.Code != 400 {
				t.Fatalf("victim with own cookie POST = %d %s", rec.Code, rec.Header().Get("Location"))
			}
			// Nothing was consumed: the rendering browser still signs in.
			rec := e.serveIn(attacker, h, "POST", "https://acme.example.test/passwordless/verify_redirect", form)
			loc, _ := url.Parse(rec.Header().Get("Location"))
			if rec.Code != 302 || loc.Query().Get("code") == "" {
				t.Fatalf("same browser POST = %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
			}
		})
	}
}
