package login

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/adhub"
	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/protectionrules"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// fakeAD is the connector: accounts by sign-in name.
type fakeAD struct {
	mu        sync.Mutex
	passwords []string
	accounts  map[string]struct {
		password string
		err      error
		profile  string
	}
	down bool
}

func (f *fakeAD) Authenticate(_ context.Context, conn *store.Connection, username, password string) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.passwords = append(f.passwords, password)
	if f.down {
		return nil, adhub.ErrUnavailable
	}
	a, ok := f.accounts[username]
	if !ok {
		return nil, adhub.ErrWrongCredentials
	}
	if a.err != nil {
		return nil, a.err
	}
	if a.password != password {
		return nil, adhub.ErrWrongCredentials
	}
	return json.RawMessage(a.profile), nil
}

const adPassword = "Corp-Directory-Passw0rd-7f3a"

func newADEnv(t *testing.T) (*socialEnv, *fakeAD) {
	t.Helper()
	s := newSocialEnv(t)
	ad := &fakeAD{accounts: map[string]struct {
		password string
		err      error
		profile  string
	}{
		"jdoe": {password: adPassword, profile: `{"id":"5f1c2a","displayName":"John Doe","name":{"givenName":"John","familyName":"Doe"},"nickname":"jdoe",` +
			`"emails":[{"value":"JDoe@corp.example"}],"groups":["users","administrators"],"dn":"cn=jdoe,ou=users,dc=corp","sAMAccountName":"jdoe"}`},
		"disabled": {err: adhub.ErrAccountBlocked},
		"expired":  {err: adhub.ErrPasswordChangeRequired},
	}}
	s.h.AD = ad
	spec := connrules.Spec{Name: "corp-ad", Strategy: "ad", EnabledClients: []string{"spa", "social-only"},
		Options: connrules.Options{Extra: map[string]any{"domain_aliases": []any{"corp.example"}, "tenant_domain": "corp.example"}}}
	connrules.CreateDefaults(&spec)
	c := &store.Connection{TenantID: s.tenant.ID, ID: "con_ad", CreatedAt: fixedNow(), Origin: store.OriginAPI}
	connrules.Apply(&spec, c)
	c.FederationRevision = 1
	if err := s.st.Connections().Create(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	return s, ad
}

// beginAD opens the login page of client (social-only has no database, so
// its page is the ad connection's form).
func beginAD(t *testing.T, s *socialEnv, b *browser, client string, extra ...string) (string, string, string) {
	t.Helper()
	loc, _ := url.Parse(s.authorizeTo(t, b, client, extra...))
	page := b.do(t, "GET", loc.RequestURI(), nil)
	if page.Code != 200 {
		t.Fatalf("login page: %d %s", page.Code, page.Body)
	}
	state := loc.Query().Get("state")
	return page.Body.String(), state, csrfFrom(t, page.Body.String())
}

func TestADLogin(t *testing.T) {
	s, ad := newADEnv(t)
	b := s.browser("acme.example.test")
	page, state, csrf := beginAD(t, s, b, "social-only")
	if !strings.Contains(page, `name="password"`) || strings.Contains(page, "/u/signup?") || strings.Contains(page, "/u/reset-password/request") {
		t.Fatalf("ad login page must be a password form without sign-up or reset links: %s", page)
	}
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"jdoe"}, "password": {adPassword}})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != 302 || loc.Host != "only.acme.test" || loc.Query().Get("code") == "" || b.cookies[session.CookieName] == nil {
		t.Fatalf("ad login = %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	u, err := s.st.Users().Get(context.Background(), s.tenant.ID, "ad|corp-ad|5f1c2a")
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "jdoe@corp.example" || u.EmailVerified || u.Name != "John Doe" || u.GivenName != "John" || u.FamilyName != "Doe" || u.Nickname != "jdoe" {
		t.Fatalf("profile %+v", u)
	}
	id := u.Identities[0]
	groups, _ := id.ProviderData["groups"].([]any)
	if id.Provider != "ad" || id.Connection != "corp-ad" || id.UserID != "corp-ad|5f1c2a" || len(groups) != 2 || id.ProviderData["ad_username"] != "jdoe" ||
		id.ProviderData["password"] != nil {
		t.Fatalf("identity %+v", id)
	}
	assertSessionMethods(t, b, "pwd")
	// A second login synchronizes the same user.
	b2 := s.browser("acme.example.test")
	_, state, csrf = beginAD(t, s, b2, "social-only")
	if rec := b2.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"jdoe"}, "password": {adPassword}}); rec.Code != 302 {
		t.Fatalf("second login: %d", rec.Code)
	}
	if len(ad.passwords) != 2 {
		t.Fatalf("connector calls %d", len(ad.passwords))
	}
}

// Each connector error class maps to its login error (LR38a-9); nothing
// falls back when no connector is online.
func TestADLoginErrors(t *testing.T) {
	s, ad := newADEnv(t)
	for name, tc := range map[string]struct {
		user, password string
		down           bool
		code           int
		text           string
	}{
		"wrong password":   {"jdoe", "wrong", false, 401, "Incorrect"},
		"unknown user":     {"nobody", "x", false, 401, "Incorrect"},
		"account disabled": {"disabled", "x", false, 403, "blocked"},
		"password expired": {"expired", "x", false, 403, "password"},
		"no connector":     {"jdoe", adPassword, true, 503, "not available right now"},
	} {
		ad.down = tc.down
		b := s.browser("acme.example.test")
		_, state, csrf := beginAD(t, s, b, "social-only")
		rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {tc.user}, "password": {tc.password}})
		if rec.Code != tc.code || !strings.Contains(rec.Body.String(), tc.text) || b.cookies[session.CookieName] != nil {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}

// Failed ad logins count against brute-force protection by connection and
// username, before the connector is asked.
func TestADLoginBruteForce(t *testing.T) {
	s, ad := newADEnv(t)
	tn := mustTenant(t, s.env, "acme")
	tn.ProtectionSettings = protectionrules.Defaults()
	tn.ProtectionSettings.BruteForce.MaxAttempts = 3
	tn.ProtectionSettingsInitialized = true
	if err := s.st.Tenants().Update(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	b := s.browser("acme.example.test")
	_, state, csrf := beginAD(t, s, b, "social-only")
	for range 3 {
		if rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"jdoe"}, "password": {"wrong"}}); rec.Code != 401 {
			t.Fatalf("wrong password: %d", rec.Code)
		}
	}
	calls := len(ad.passwords)
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"jdoe"}, "password": {adPassword}})
	if rec.Code != 429 || len(ad.passwords) != calls {
		t.Fatalf("blocked login reached the connector or passed: %d (%d calls)", rec.Code, len(ad.passwords)-calls)
	}
}

// TestADLoginNoSecretsInLogs is Review Focus 3: the password never reaches
// the server log over a full login and a failed one.
func TestADLoginNoSecretsInLogs(t *testing.T) {
	s, _ := newADEnv(t)
	for _, pw := range []string{adPassword, "Wrong-" + adPassword} {
		b := s.browser("acme.example.test")
		_, state, csrf := beginAD(t, s, b, "social-only")
		b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"jdoe"}, "password": {pw}})
	}
	if out := s.logs.String(); strings.Contains(out, adPassword) || out == "" {
		t.Fatalf("password logged (or no log captured): %d bytes", len(out))
	}
}

// An application with a database uses the ad connection when asked by name
// or found by home realm discovery.
func TestADLoginSelection(t *testing.T) {
	s, _ := newADEnv(t)
	b := s.browser("acme.example.test")
	page, state, csrf := beginAD(t, s, b, "spa", "connection", "corp-ad")
	if strings.Contains(page, "/u/signup?") {
		t.Fatal("sign-up offered for the ad connection")
	}
	if rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"jdoe"}, "password": {adPassword}}); rec.Code != 302 {
		t.Fatalf("connection=corp-ad: %d %s", rec.Code, rec.Body)
	}
	// Identifier first: corp.example is the ad connection's domain alias.
	enableIdentifier(t, s.env)
	b = s.browser("acme.example.test")
	page, state, csrf = beginAD(t, s, b, "spa")
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page)}, "username": {"jdoe@corp.example"}})
	if rec.Code != 303 || !strings.HasPrefix(rec.Header().Get("Location"), "/u/login/password") {
		t.Fatalf("home realm discovery: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	pw := b.do(t, "GET", rec.Header().Get("Location"), nil)
	if pw.Code != 200 {
		t.Fatalf("password stage: %d %s", pw.Code, pw.Body)
	}
	s.h.AD.(*fakeAD).accounts["jdoe@corp.example"] = s.h.AD.(*fakeAD).accounts["jdoe"]
	rec = b.do(t, "POST", "/u/login/password", url.Values{"state": {state}, "csrf": {csrfFrom(t, pw.Body.String())}, "password": {adPassword}})
	if rec.Code != 302 {
		t.Fatalf("password stage login: %d %s", rec.Code, rec.Body)
	}
}

func csrfFrom(t *testing.T, body string) string {
	t.Helper()
	m := csrfField.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no csrf on page: %s", body)
	}
	return m[1]
}
