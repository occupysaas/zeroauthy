package login

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const aliceLogin = "alice@acme.test"

func partnerQ(client, redirect string) url.Values {
	return url.Values{
		"client_id": {client}, "redirect_uri": {redirect}, "response_type": {"code"},
		"scope": {"read:things"}, "audience": {"https://api.acme.test"}, "state": {"st"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
}

// signedIn returns a browser with a session for alice.
func (e *env) signedIn(t *testing.T) *browser {
	t.Helper()
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {aliceLogin}, "password": {"alice password 1"}})
	if rec.Code != 302 || b.cookies[session.CookieName] == nil {
		t.Fatalf("sign in = %d %s", rec.Code, rec.Body)
	}
	return b
}

// toConsent runs /authorize and returns the consent state and CSRF token.
func (b *browser) toConsent(t *testing.T, q url.Values) (string, string) {
	t.Helper()
	rec := b.do(t, "GET", "/authorize?"+q.Encode(), nil)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Path != "/u/consent" {
		t.Fatalf("authorize -> %s (%d)", loc, rec.Code)
	}
	state := loc.Query().Get("state")
	page := b.do(t, "GET", loc.RequestURI(), nil)
	if page.Code != 200 {
		t.Fatalf("consent page = %d %s", page.Code, page.Body)
	}
	m := csrfField.FindStringSubmatch(page.Body.String())
	if m == nil {
		t.Fatalf("no csrf: %s", page.Body)
	}
	return state, m[1]
}

func (e *env) grants(t *testing.T, client string) ([]string, error) {
	t.Helper()
	tn := mustTenant(t, e, "acme")
	u, err := e.st.Users().FindByLogin(context.Background(), tn.ID, "Username-Password-Authentication", aliceLogin)
	if err != nil {
		t.Fatal(err)
	}
	g, err := e.st.UserGrants().Find(context.Background(), tn.ID, client, u.UserID, "https://api.acme.test")
	if err != nil {
		return nil, err
	}
	return g.Scopes, nil
}

func TestConsentAcceptIssuesCodeAndRemembers(t *testing.T) {
	e := newEnv(t)
	b := e.signedIn(t)
	q := partnerQ("partner", "https://partner.example/cb")
	state, csrf := b.toConsent(t, q)
	page := b.do(t, "GET", "/u/consent?state="+state, nil)
	if !strings.Contains(page.Body.String(), "read:things") {
		t.Fatalf("page lacks scope: %s", page.Body)
	}
	rec := b.do(t, "POST", "/u/consent", url.Values{"state": {state}, "csrf": {csrf}, "action": {"accept"}})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != 302 || loc.Host != "partner.example" || loc.Query().Get("code") == "" {
		t.Fatalf("accept = %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	got, err := e.grants(t, "partner")
	if err != nil || len(got) != 1 || got[0] != "read:things" {
		t.Fatalf("grant = %v, %v", got, err)
	}
	rec = b.do(t, "GET", "/authorize?"+q.Encode(), nil)
	loc, _ = url.Parse(rec.Header().Get("Location"))
	if loc.Host != "partner.example" || loc.Query().Get("code") == "" {
		t.Fatalf("second authorize -> %s", loc)
	}
}

func TestConsentDeclineProtected(t *testing.T) {
	e := newEnv(t)
	b := e.signedIn(t)
	state, csrf := b.toConsent(t, partnerQ("partner", "https://partner.example/cb"))
	rec := b.do(t, "POST", "/u/consent", url.Values{"state": {state}, "csrf": {csrf}, "action": {"decline"}})
	if rec.Code != 400 || rec.Header().Get("Location") != "" {
		t.Fatalf("decline = %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if _, err := e.grants(t, "partner"); err == nil {
		t.Fatal("grant stored on decline")
	}
}

func TestConsentDeclineAllowAlways(t *testing.T) {
	e := newEnv(t)
	b := e.signedIn(t)
	q := partnerQ("partner-open", "https://open.example/cb")
	state, csrf := b.toConsent(t, q)
	rec := b.do(t, "POST", "/u/consent", url.Values{"state": {state}, "csrf": {csrf}, "action": {"decline"}})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != 302 || loc.Query().Get("error") != "access_denied" || loc.Query().Get("state") != "st" {
		t.Fatalf("decline = %d %s", rec.Code, loc)
	}
}

func TestConsentWrongCSRF(t *testing.T) {
	e := newEnv(t)
	b := e.signedIn(t)
	state, _ := b.toConsent(t, partnerQ("partner", "https://partner.example/cb"))
	rec := b.do(t, "POST", "/u/consent", url.Values{"state": {state}, "csrf": {"nope"}, "action": {"accept"}})
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "expired") {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestConsentWithoutSessionFails(t *testing.T) {
	e := newEnv(t)
	b := e.signedIn(t)
	state, csrf := b.toConsent(t, partnerQ("partner", "https://partner.example/cb"))
	delete(b.cookies, session.CookieName)
	rec := b.do(t, "POST", "/u/consent", url.Values{"state": {state}, "csrf": {csrf}, "action": {"accept"}})
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "expired") || rec.Header().Get("Location") != "" {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestConsentWrongCookie(t *testing.T) {
	e := newEnv(t)
	b := e.signedIn(t)
	state, csrf := b.toConsent(t, partnerQ("partner", "https://partner.example/cb"))
	c := *b.cookies["za_txn_"+state]
	c.Value = "other"
	b.cookies["za_txn_"+state] = &c
	rec := b.do(t, "POST", "/u/consent", url.Values{"state": {state}, "csrf": {csrf}, "action": {"accept"}})
	if rec.Code != 400 {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestNoConfirmationRightAfterLogin(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	q := url.Values{"client_id": {"local"}, "redirect_uri": {"http://localhost:5000/cb"}, "response_type": {"code"},
		"scope": {"openid"}, "state": {"st"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	rec := b.do(t, "GET", "/authorize?"+q.Encode(), nil)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Path != "/u/login" {
		t.Fatalf("authorize -> %s", loc)
	}
	state := loc.Query().Get("state")
	page := b.do(t, "GET", loc.RequestURI(), nil)
	csrf := csrfField.FindStringSubmatch(page.Body.String())[1]
	rec = b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {aliceLogin}, "password": {"alice password 1"}})
	loc, _ = url.Parse(rec.Header().Get("Location"))
	if rec.Code != 302 || loc.Host != "localhost:5000" || loc.Query().Get("code") == "" {
		t.Fatalf("login = %d %s", rec.Code, loc)
	}
}

func TestConfirmationAcceptStoresNoGrant(t *testing.T) {
	e := newEnv(t)
	b := e.signedIn(t)
	q := url.Values{"client_id": {"local"}, "redirect_uri": {"http://localhost:5000/cb"}, "response_type": {"code"},
		"scope": {"openid"}, "state": {"st"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	state, csrf := b.toConsent(t, q)
	page := b.do(t, "GET", "/u/consent?state="+state, nil)
	if strings.Contains(page.Body.String(), "<ul") || !strings.Contains(page.Body.String(), "localhost") {
		t.Fatalf("confirmation page: %s", page.Body)
	}
	rec := b.do(t, "POST", "/u/consent", url.Values{"state": {state}, "csrf": {csrf}, "action": {"accept"}})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != 302 || loc.Query().Get("code") == "" {
		t.Fatalf("accept = %d %s", rec.Code, loc)
	}
	if _, err := e.grants(t, "local"); err != store.ErrNotFound {
		t.Fatalf("grant err = %v", err)
	}
}

func TestConsentWithoutValidActionIs400(t *testing.T) {
	for _, action := range []string{"", "maybe"} {
		e := newEnv(t)
		b := e.signedIn(t)
		state, csrf := b.toConsent(t, partnerQ("partner", "https://partner.example/cb"))
		form := url.Values{"state": {state}, "csrf": {csrf}}
		if action != "" {
			form.Set("action", action)
		}
		rec := b.do(t, "POST", "/u/consent", form)
		if rec.Code != 400 || rec.Header().Get("Location") != "" {
			t.Fatalf("action %q: got %d %s", action, rec.Code, rec.Body)
		}
	}
}
