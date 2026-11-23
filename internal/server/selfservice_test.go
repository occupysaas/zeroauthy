package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/scim"
	"github.com/zeroauthy/zeroauthy/internal/selfservice"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func throwawayCertPEM(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "assistant test idp"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// assistantBrowser keeps the assistant cookie like a browser.
type assistantBrowser struct {
	t      *testing.T
	h      http.Handler
	cookie *http.Cookie
}

func (b *assistantBrowser) do(method, target string, form url.Values, origin string) (*httptest.ResponseRecorder, string) {
	b.t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, "https://acme.example.test"+target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if b.cookie != nil {
		req.AddCookie(b.cookie)
	}
	rec := httptest.NewRecorder()
	b.h.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.Name == "za_self_service" {
			if c.MaxAge < 0 {
				b.cookie = nil
			} else {
				b.cookie = c
			}
		}
	}
	return rec, rec.Body.String()
}

var csrfField = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (b *assistantBrowser) post(form url.Values) (*httptest.ResponseRecorder, string) {
	b.t.Helper()
	_, page := b.do("GET", selfservice.Path, nil, "")
	m := csrfField.FindStringSubmatch(page)
	if m == nil {
		b.t.Fatalf("no CSRF token on the page: %s", page)
	}
	form.Set("csrf", m[1])
	return b.do("POST", selfservice.Path, form, "https://acme.example.test")
}

type assistantEnv struct {
	a     *orgAPI
	st    store.Store
	tn    *store.Tenant
	cert  string
	pid   string
	appID string
}

func newAssistantEnv(t *testing.T) *assistantEnv {
	t.Helper()
	a, st := newSelfServiceManagement(t)
	ctx := context.Background()
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	app := &store.Client{TenantID: tn.ID, ClientID: "partner-app", Name: "Partner app", AppType: "spa", Callbacks: []string{"https://app.example.test/callback"},
		GrantTypes: []string{"authorization_code"}, TokenEndpointAuthMethod: "none"}
	if err := st.Clients().Create(ctx, app); err != nil {
		t.Fatal(err)
	}
	code, out, raw := a.call("POST", "/self-service-profiles", a.admin, map[string]any{"name": "Partners", "allowed_strategies": []string{"samlp", "oidc"},
		"branding": map[string]any{"colors": map[string]any{"primary": "#0a7"}}})
	if code != 201 {
		t.Fatalf("profile %d %s", code, raw)
	}
	pid := out["id"].(string)
	if code, _, raw := a.call("PUT", "/self-service-profiles/"+pid+"/custom-text/en/get-started", a.admin, map[string]any{"introduction": `<script>alert(1)</script><b>Welcome</b> <a href="javascript:x()">x</a>`}); code != 200 {
		t.Fatalf("text %d %s", code, raw)
	}
	return &assistantEnv{a: a, st: st, tn: tn, cert: throwawayCertPEM(t), pid: pid, appID: app.ClientID}
}

func (e *assistantEnv) ticket(t *testing.T, body map[string]any) string {
	t.Helper()
	code, out, raw := e.a.call("POST", "/self-service-profiles/"+e.pid+"/sso-ticket", e.a.admin, body)
	if code != 201 {
		t.Fatalf("ticket %d %s", code, raw)
	}
	u, _ := url.Parse(out["ticket"].(string))
	if u.Path != selfservice.Path {
		t.Fatalf("ticket URL %s", u)
	}
	return u.Query().Get("ticket")
}

func (e *assistantEnv) open(t *testing.T, token string) *assistantBrowser {
	t.Helper()
	b := &assistantBrowser{t: t, h: e.a.h}
	rec, _ := b.do("GET", selfservice.Path+"?ticket="+url.QueryEscape(token), nil, "")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != selfservice.Path || b.cookie == nil {
		t.Fatalf("open %d %v", rec.Code, rec.Header())
	}
	c := b.cookie
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/self-service" {
		t.Fatalf("cookie attributes %+v", c)
	}
	return b
}

// TestAssistantFlow: a create ticket's customer configures SAML, gets the
// ticket's applications, organizations-free, one allowed domain, a SCIM
// token, and finishing ends the ticket.
func TestAssistantFlow(t *testing.T) {
	e := newAssistantEnv(t)
	ctx := context.Background()
	token := e.ticket(t, map[string]any{"connection_config": map[string]any{"name": "partner-saml", "display_name": "Partner"},
		"enabled_clients":       []string{e.appID},
		"domain_aliases_config": map[string]any{"domain_verification": "optional", "pending_domains": []string{"partner.example.test"}},
		"provisioning_config":   map[string]any{"scopes": []string{"get:users", "post:users"}}})
	b := e.open(t, token)
	rec, page := b.do("GET", selfservice.Path, nil, "")
	if rec.Code != 200 || !strings.Contains(page, "<b>Welcome</b>") || strings.Contains(page, "<script>") || strings.Contains(page, "javascript:") {
		t.Fatalf("page %d %s", rec.Code, page)
	}
	if !strings.Contains(page, "urn:auth0:acme:partner-saml") || !strings.Contains(page, "https://acme.example.test/login/callback?connection=partner-saml") {
		t.Fatal("service provider values missing")
	}
	// no-referrer would make browsers send Origin: null on the assistant's
	// own form posts, which the origin check refuses.
	if rp := rec.Header().Get("Referrer-Policy"); rp != "same-origin" {
		t.Fatalf("Referrer-Policy %q", rp)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("CSP %q", csp)
	}
	// CSRF and origin.
	if rec, _ := b.do("POST", selfservice.Path, url.Values{"action": {"configure"}, "strategy": {"samlp"}}, "https://acme.example.test"); rec.Code != 403 {
		t.Fatalf("no CSRF %d", rec.Code)
	}
	_, page = b.do("GET", selfservice.Path, nil, "")
	csrf := csrfField.FindStringSubmatch(page)[1]
	if rec, _ := b.do("POST", selfservice.Path, url.Values{"csrf": {csrf}, "action": {"configure"}, "strategy": {"samlp"}}, "https://evil.example.test"); rec.Code != 403 {
		t.Fatalf("cross-origin %d", rec.Code)
	}
	if rec, _ := b.post(url.Values{"action": {"configure"}, "strategy": {"okta"}, "okta_domain": {"x.okta.test"}, "client_id": {"c"}, "client_secret": {"s"}}); rec.Code != 400 {
		t.Fatalf("strategy outside the profile %d", rec.Code)
	}
	rec, page = b.post(url.Values{"action": {"configure"}, "strategy": {"samlp"}, "sign_in_url": {"https://idp.partner.example.test/sso"}, "signing_cert": {e.cert},
		"domains": {"partner.example.test", "gmail.com"}, "name": {"hijack"}, "enabled_clients": {"admin"}})
	if rec.Code != 200 {
		t.Fatalf("configure %d %s", rec.Code, page)
	}
	conn, err := e.st.Connections().GetByName(ctx, e.tn.ID, "partner-saml")
	if err != nil {
		t.Fatalf("connection not created: %v", err)
	}
	if conn.Strategy != "samlp" || len(conn.EnabledClients) != 1 || conn.EnabledClients[0] != e.appID {
		t.Fatalf("connection %+v", conn)
	}
	if aliases, _ := conn.Extra["domain_aliases"].([]any); len(aliases) != 1 || aliases[0] != "partner.example.test" {
		t.Fatalf("domain aliases %v", conn.Extra["domain_aliases"])
	}
	if _, err := e.st.Connections().GetByName(ctx, e.tn.ID, "hijack"); err == nil {
		t.Fatal("a form field named the connection")
	}
	tk, _ := e.st.SelfService().GetTicketByHash(ctx, e.tn.ID, scim.HashToken(token))
	if tk.ConnectionID != conn.ID {
		t.Fatalf("ticket bound to %q", tk.ConnectionID)
	}
	if !strings.Contains(page, "client_id=partner-app") || !strings.Contains(page, "connection=partner-saml") {
		t.Fatal("no test sign-in link")
	}
	// SCIM token with the ticket's scopes.
	rec, page = b.post(url.Values{"action": {"scim"}})
	m := regexp.MustCompile(`id="scim-token">([^<]+)<`).FindStringSubmatch(page)
	if rec.Code != 200 || m == nil {
		t.Fatalf("scim %d %s", rec.Code, page)
	}
	toks, _ := e.st.Directory().ListSCIMTokens(ctx, e.tn.ID, conn.ID)
	if len(toks) != 1 || strings.Join(toks[0].Scopes, " ") != "get:users post:users" || toks[0].Hash != scim.HashToken(m[1]) {
		t.Fatalf("scim token %+v", toks)
	}
	// Finish ends the ticket.
	if rec, page := b.post(url.Values{"action": {"finish"}}); rec.Code != 200 || !strings.Contains(page, "Setup is complete") {
		t.Fatalf("finish %d %s", rec.Code, page)
	}
	b2 := &assistantBrowser{t: t, h: e.a.h}
	if rec, _ := b2.do("GET", selfservice.Path+"?ticket="+url.QueryEscape(token), nil, ""); rec.Code != 404 {
		t.Fatalf("used ticket opened again: %d", rec.Code)
	}
}

// TestAssistantScope is Plan 37c Review Focus 4: a ticket changes only its
// one connection, within the profile's strategies, with only the ticket's
// applications, and nothing once revoked, expired or used.
func TestAssistantScope(t *testing.T) {
	e := newAssistantEnv(t)
	ctx := context.Background()
	token := e.ticket(t, map[string]any{"connection_config": map[string]any{"name": "scoped-saml"}})
	b := e.open(t, token)
	saml := url.Values{"action": {"configure"}, "strategy": {"samlp"}, "sign_in_url": {"https://idp.scoped.example.test/sso"}, "signing_cert": {e.cert}}
	if rec, page := b.post(saml); rec.Code != 200 {
		t.Fatalf("configure %d %s", rec.Code, page)
	}
	first, err := e.st.Connections().GetByName(ctx, e.tn.ID, "scoped-saml")
	if err != nil {
		t.Fatal(err)
	}
	if len(first.EnabledClients) != 0 {
		t.Fatalf("clients beyond the ticket: %v", first.EnabledClients)
	}
	// A second save edits the same connection; the strategy is fixed.
	saml.Set("sign_in_url", "https://idp2.scoped.example.test/sso")
	if rec, page := b.post(saml); rec.Code != 200 {
		t.Fatalf("reconfigure %d %s", rec.Code, regexp.MustCompile(`class="error"[^>]*>[^<]*`).FindString(page))
	}
	again, _ := e.st.Connections().GetByName(ctx, e.tn.ID, "scoped-saml")
	if again.ID != first.ID || again.Extra["signInEndpoint"] != "https://idp2.scoped.example.test/sso" {
		t.Fatalf("reconfigured %+v", again.Extra)
	}
	list, _, _ := e.st.Connections().List(ctx, e.tn.ID, store.ConnectionFilter{}, store.Page{})
	if len(list) != 2 { // the database connection and this one
		t.Fatalf("connections %d", len(list))
	}
	if rec, _ := b.post(url.Values{"action": {"configure"}, "strategy": {"oidc"}, "discovery_url": {"https://idp.example.test/.well-known/openid-configuration"}, "client_id": {"c"}}); rec.Code != 400 {
		t.Fatalf("strategy change %d", rec.Code)
	}
	// No SCIM without provisioning_config.
	if rec, _ := b.post(url.Values{"action": {"scim"}}); rec.Code != 403 {
		t.Fatalf("scim without provisioning %d", rec.Code)
	}
	// An edit ticket without sso cannot change the connection.
	edit := e.ticket(t, map[string]any{"connection_id": first.ID, "enabled_features": map[string]any{"sso": false}})
	be := e.open(t, edit)
	saml.Set("sign_in_url", "https://evil.example.test/sso")
	if rec, _ := be.post(saml); rec.Code != 403 {
		t.Fatalf("edit without sso %d", rec.Code)
	}
	// Revoked and expired tickets open nothing.
	revoked := e.ticket(t, map[string]any{"connection_config": map[string]any{"name": "revoked-saml"}})
	if code, _, _ := e.a.call("POST", "/self-service-profiles/"+e.pid+"/sso-ticket/"+revoked+"/revoke", e.a.admin, nil); code != 202 {
		t.Fatal("revoke")
	}
	if rec, _ := (&assistantBrowser{t: t, h: e.a.h}).do("GET", selfservice.Path+"?ticket="+url.QueryEscape(revoked), nil, ""); rec.Code != 404 {
		t.Fatalf("revoked ticket %d", rec.Code)
	}
	// A browser already holding the revoked ticket's cookie is refused too.
	held := e.ticket(t, map[string]any{"connection_config": map[string]any{"name": "held-saml"}})
	bh := e.open(t, held)
	e.a.call("POST", "/self-service-profiles/"+e.pid+"/sso-ticket/"+held+"/revoke", e.a.admin, nil)
	if rec, _ := bh.do("GET", selfservice.Path, nil, ""); rec.Code != 404 {
		t.Fatalf("revoked cookie %d", rec.Code)
	}
	if rec, _ := (&assistantBrowser{t: t, h: e.a.h}).do("GET", selfservice.Path+"?ticket=not-a-ticket", nil, ""); rec.Code != 404 {
		t.Fatalf("unknown ticket %d", rec.Code)
	}
}
