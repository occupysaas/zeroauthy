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

	"github.com/zeroauthy/zeroauthy/internal/dbconn"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// aliasEnv is the flow tenant with a second public alias served by the same
// handler. Canonical is the test server's host (first seeded domain).
type aliasEnv struct {
	*flowEnv
	alias string
	tn    *store.Tenant
}

func newAliasEnv(t *testing.T) *aliasEnv {
	t.Helper()
	ctx := context.Background()
	e := newFlowEnv(t)
	tn, _ := e.st.Tenants().GetByName(ctx, "flow")
	alias := "localhost:" + strconv.Itoa(e.srv.Listener.Addr().(*net.TCPAddr).Port)
	tn.Domains = append(tn.Domains, alias)
	tn.PushedAuthorizationRequestsSupported = true
	if err := e.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	tn, _ = e.st.Tenants().GetByName(ctx, "flow")
	if tn.CanonicalHost != strings.TrimPrefix(e.base, "https://") {
		t.Fatalf("canonical = %q", tn.CanonicalHost)
	}
	return &aliasEnv{flowEnv: e, alias: alias, tn: tn}
}

// on serves a request addressed to host in-process.
func (e *aliasEnv) on(host, method, path string, form url.Values, header http.Header) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, "https://"+host+path, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range header {
		r.Header[k] = v
	}
	rec := httptest.NewRecorder()
	e.srv.Config.Handler.ServeHTTP(rec, r)
	return rec
}

// code runs /authorize and login on the canonical host and returns the
// unexchanged code.
func (e *aliasEnv) code(t *testing.T, c *http.Client, extra ...string) string {
	t.Helper()
	resp, _ := fetch(t, c, authorizeURL(e.base, extra...))
	loc, _ := resp.Location()
	if loc != nil && loc.Path == "/u/login" {
		_, page := fetch(t, c, loc.String())
		csrf := csrfRe.FindStringSubmatch(page)
		form := url.Values{"hosted_revision": {hostedRevision(page)}, "state": {loc.Query().Get("state")}, "csrf": {csrf[1]}, "username": {"alice@flow.test"}, "password": {"alice password 1"}}
		req, _ := http.NewRequest("POST", e.base+"/u/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, _ = mustDo(t, c, req)
		loc, _ = resp.Location()
	}
	if loc == nil || loc.Query().Get("code") == "" {
		t.Fatalf("no code: %v", loc)
	}
	return loc.Query().Get("code")
}

func decodeJSON(rec *httptest.ResponseRecorder) map[string]any {
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}

func TestDomainOriginBindings(t *testing.T) {
	ctx := context.Background()
	e := newAliasEnv(t)
	c := e.client(t)
	canonical := strings.TrimPrefix(e.base, "https://")
	exchange := func(host, code string) *httptest.ResponseRecorder {
		return e.on(host, "POST", "/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"spa"},
			"code": {code}, "redirect_uri": {"https://app.flow.test/cb"}, "code_verifier": {verifier}}, nil)
	}

	// Authorization code: the alias is refused without consuming the code.
	code := e.code(t, c, "scope", "openid offline_access read:things")
	if rec := exchange(e.alias, code); rec.Code != 400 || decodeJSON(rec)["error"] != "invalid_grant" {
		t.Fatalf("code on alias = %d %s", rec.Code, rec.Body)
	}
	rec := exchange(canonical, code)
	tok := decodeJSON(rec)
	if rec.Code != 200 || tok["refresh_token"] == nil {
		t.Fatalf("code on its origin = %d %s", rec.Code, rec.Body)
	}
	ac, _ := e.st.AuthCodes().Get(ctx, e.tn.ID, secrets.HashToken(code))
	if ac == nil || ac.Origin != e.base {
		t.Fatalf("code origin = %+v", ac)
	}

	// Refresh token: refused on the alias without rotation; revocation on
	// the alias is a no-op.
	refresh := tok["refresh_token"].(string)
	refreshOn := func(host string) *httptest.ResponseRecorder {
		return e.on(host, "POST", "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"spa"}, "refresh_token": {refresh}}, nil)
	}
	if rec := refreshOn(e.alias); rec.Code != 400 || decodeJSON(rec)["error"] != "invalid_grant" {
		t.Fatalf("refresh on alias = %d %s", rec.Code, rec.Body)
	}
	if rec := e.on(e.alias, "POST", "/oauth/revoke", url.Values{"client_id": {"spa"}, "token": {refresh}}, nil); rec.Code != 200 {
		t.Fatalf("revoke on alias = %d", rec.Code)
	}
	rec = refreshOn(canonical)
	if rec.Code != 200 {
		t.Fatalf("refresh on its origin after alias attempts = %d %s", rec.Code, rec.Body)
	}

	// Discovery, issuer and userinfo follow the serving host; the Management
	// API audience does not.
	for _, host := range []string{canonical, e.alias} {
		doc := decodeJSON(e.on(host, "GET", "/.well-known/openid-configuration", nil, nil))
		if doc["issuer"] != "https://"+host+"/" {
			t.Errorf("%s issuer = %v", host, doc["issuer"])
		}
	}
	apis, _ := e.st.ResourceServers().List(ctx, e.tn.ID)
	for _, a := range apis {
		if a.IsSystem && a.Identifier != e.base+"/api/v2/" {
			t.Errorf("management audience = %s", a.Identifier)
		}
	}

	// Device code: polling on the alias does not touch the grant.
	dev := decodeJSON(e.on(canonical, "POST", "/oauth/device/code", url.Values{"client_id": {"tv"}, "scope": {"openid"}}, nil))
	devCode, _ := dev["device_code"].(string)
	poll := func(host string) map[string]any {
		return decodeJSON(e.on(host, "POST", "/oauth/token", url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "client_id": {"tv"}, "device_code": {devCode}}, nil))
	}
	if got := poll(e.alias); got["error"] != "invalid_grant" {
		t.Fatalf("device on alias = %v", got)
	}
	if got := poll(canonical); got["error"] != "authorization_pending" {
		t.Fatalf("device on its origin = %v", got)
	}
	if rec := e.on(e.alias, "GET", "/activate?user_code="+url.QueryEscape(dev["user_code"].(string)), nil, nil); strings.Contains(rec.Body.String(), "Flow TV") {
		t.Fatal("activation page on the alias shows the device grant")
	}

	// PAR: a request URI from the canonical origin is not consumed by the alias.
	partner, _ := e.st.Clients().Get(ctx, e.tn.ID, "partner")
	partner.IsFirstParty = true
	if err := e.st.Clients().Update(ctx, partner); err != nil {
		t.Fatal(err)
	}
	par := decodeJSON(e.on(canonical, "POST", "/oauth/par", url.Values{"client_id": {"partner"}, "client_secret": {"partner-secret"}, "redirect_uri": {"https://partner.flow.test/cb"}, "response_type": {"code"},
		"scope": {"openid"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"p1"}}, nil))
	requestURI, _ := par["request_uri"].(string)
	if requestURI == "" {
		t.Fatalf("par = %v", par)
	}
	at := func(host string) *httptest.ResponseRecorder {
		return e.on(host, "GET", "/authorize?"+url.Values{"client_id": {"partner"}, "request_uri": {requestURI}}.Encode(), nil, nil)
	}
	if rec := at(e.alias); rec.Code == http.StatusFound && strings.Contains(rec.Header().Get("Location"), "/u/login") {
		t.Fatalf("PAR on alias started a login: %s", rec.Header().Get("Location"))
	}
	if rec := at(canonical); rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/u/login") {
		t.Fatalf("PAR on its origin = %d %s", rec.Code, rec.Header().Get("Location"))
	}

	// Reset tickets: a ticket for the alias works only there; a legacy
	// ticket without origin means canonical, never its first presenter.
	users, _ := e.st.Users().FindByEmail(ctx, e.tn.ID, "alice@flow.test")
	user := users[0]
	issue := func(origin string) string {
		raw, err := dbconn.IssueResetTicket(ctx, e.st, store.PasswordResetTicket{Origin: origin, TenantID: e.tn.ID, UserID: user.UserID, Connection: "Username-Password-Authentication"},
			dbconn.TicketTokenLength, time.Now(), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	valid := func(host, raw string) bool {
		rec := e.on(host, "GET", "/u/reset-password?ticket="+url.QueryEscape(raw), nil, nil)
		return rec.Code == 200 && strings.Contains(rec.Body.String(), `name="password"`)
	}
	aliasTicket := issue("https://" + e.alias)
	if valid(canonical, aliasTicket) || !valid(e.alias, aliasTicket) {
		t.Error("reset ticket not bound to its origin")
	}
	legacy := issue("")
	if valid(e.alias, legacy) || !valid(canonical, legacy) {
		t.Error("legacy reset ticket not bound to canonical")
	}
}
