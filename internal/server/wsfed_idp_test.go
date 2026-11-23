package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/samlcore"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// wsfedEnv is the flow environment with a WS-Fed relying party application
// (Plan 37b): the wsfed add-on, callbacks and a realm alias.
func wsfedEnv(t *testing.T) (*flowEnv, *store.Tenant) {
	t.Helper()
	e := newFlowEnv(t)
	tn, err := e.st.Tenants().GetByName(t.Context(), "flow")
	if err != nil {
		t.Fatal(err)
	}
	c := &store.Client{TenantID: tn.ID, ClientID: "wsfed-rp", Name: "WS-Fed RP", AppType: store.AppTypeRegularWeb, IsFirstParty: true,
		Callbacks: []string{"https://rp.flow.test/", "https://rp.flow.test/other"}, ClientAliases: []string{"urn:rp:portal"},
		Addons: &store.ClientAddons{WSFed: []byte(`{}`)}}
	if err := e.st.Clients().Create(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	conn, err := e.st.Connections().GetByName(t.Context(), tn.ID, "Username-Password-Authentication")
	if err != nil {
		t.Fatal(err)
	}
	conn.EnabledClients = append(conn.EnabledClients, "wsfed-rp")
	if err := e.st.Connections().Update(t.Context(), conn); err != nil {
		t.Fatal(err)
	}
	return e, tn
}

func wsfedURL(base, path string, q url.Values) string { return base + path + "?" + q.Encode() }

// wsfedToken checks the auto-posted sign-in response and verifies its token.
func wsfedToken(t *testing.T, e *flowEnv, tid, page, wantReply, wantCtx string) *samlcore.WSFedToken {
	t.Helper()
	action, fields := postedResponse(t, page)
	if action != wantReply || fields.Get("wa") != "wsignin1.0" || fields.Get("wctx") != wantCtx {
		t.Fatalf("posted to %s with wa=%q wctx=%q", action, fields.Get("wa"), fields.Get("wctx"))
	}
	tok, err := samlcore.VerifyWSFedToken([]byte(fields.Get("wresult")), samlcore.Trust{Certs: tenantCerts(t, e, tid)})
	if err != nil {
		t.Fatalf("wresult does not verify with the tenant certificate: %v", err)
	}
	doc, err := samlcore.Parse([]byte(fields.Get("wresult")))
	if err != nil {
		t.Fatal(err)
	}
	if got := doc.Root().SelectAttrValue("Context", ""); got != wantCtx {
		t.Fatalf("RSTR Context %q, want %q", got, wantCtx)
	}
	return tok
}

func TestWSFedSignIn(t *testing.T) {
	e, tn := wsfedEnv(t)
	c := e.client(t)
	resp, page := e.follow(t, c, wsfedURL(e.base, "/wsfed/wsfed-rp", url.Values{"wa": {"wsignin1.0"}, "wtrealm": {"urn:rp:portal"},
		"wreply": {"https://rp.flow.test/"}, "wctx": {"rm=0&id=passive&ru=%2f_layouts"}}))
	if resp.StatusCode != 200 {
		t.Fatalf("sign-in ended with %d", resp.StatusCode)
	}
	tok := wsfedToken(t, e, tn.ID, page, "https://rp.flow.test/", "rm=0&id=passive&ru=%2f_layouts")
	if tok.Version != "1.1" {
		t.Fatalf("token version %s, want SAML 1.1", tok.Version)
	}
	if err := tok.Check(samlcore.WSFedExpect{Now: time.Now(), Skew: time.Minute, Audience: "urn:rp:portal"}); err != nil {
		t.Fatalf("token conditions: %v", err)
	}
	if got := tok.NotOnOrAfter.Sub(tok.NotBefore); got != 8*time.Hour {
		t.Fatalf("lifetime %v, want node-wsfed's 8 hours", got)
	}
	users, err := e.st.Users().FindByEmail(t.Context(), tn.ID, "alice@flow.test")
	if err != nil || len(users) != 1 {
		t.Fatalf("user lookup: %v", err)
	}
	if tok.NameID != users[0].UserID || tok.Attributes[samlcore.ClaimEmail][0] != "alice@flow.test" ||
		tok.Attributes[samlcore.ClaimNameIdentifier][0] != users[0].UserID || tok.Issuer != "urn:"+strings.TrimPrefix(e.base, "https://") {
		t.Fatalf("token subject %q attributes %v issuer %q", tok.NameID, tok.Attributes, tok.Issuer)
	}
	// The session is reused; wtrealm by client ID and the realm-only
	// endpoint both resolve the application.
	for _, u := range []string{
		wsfedURL(e.base, "/wsfed/wsfed-rp", url.Values{"wtrealm": {"wsfed-rp"}, "wreply": {"https://rp.flow.test/other"}}),
		wsfedURL(e.base, "/wsfed", url.Values{"wtrealm": {"urn:rp:portal"}, "wreply": {"https://rp.flow.test/other"}}),
		wsfedURL(e.base, "/wsfed", url.Values{"wtrealm": {"wsfed-rp"}, "wreply": {"https://rp.flow.test/other"}}),
	} {
		resp, page := e.follow(t, c, u)
		if resp.StatusCode != 200 || strings.Contains(page, `name="password"`) {
			t.Fatalf("%s: status %d, session not reused", u, resp.StatusCode)
		}
		wsfedToken(t, e, tn.ID, page, "https://rp.flow.test/other", "")
	}
}

// Without wtrealm the audience is wreply (node-wsfed); without wreply the
// response goes to the first callback.
func TestWSFedDefaults(t *testing.T) {
	e, tn := wsfedEnv(t)
	c := e.client(t)
	_, page := e.follow(t, c, wsfedURL(e.base, "/wsfed/wsfed-rp", url.Values{"wreply": {"https://rp.flow.test/other"}}))
	tok := wsfedToken(t, e, tn.ID, page, "https://rp.flow.test/other", "")
	if strings.Join(tok.Audiences, ",") != "https://rp.flow.test/other" {
		t.Fatalf("audience %v, want wreply", tok.Audiences)
	}
	_, page = e.follow(t, c, e.base+"/wsfed/wsfed-rp")
	tok = wsfedToken(t, e, tn.ID, page, "https://rp.flow.test/", "")
	if strings.Join(tok.Audiences, ",") != "https://rp.flow.test/" {
		t.Fatalf("audience %v, want the first callback", tok.Audiences)
	}
}

// TestWReplyAllowlist is Plan 37b Review Focus 1: a wreply outside the
// application's callbacks gets an error page; no token is posted and no
// login starts.
func TestWReplyAllowlist(t *testing.T) {
	e, _ := wsfedEnv(t)
	c := e.client(t)
	for _, reply := range []string{"https://evil.flow.test/", "https://rp.flow.test/../evil", "https://rp.flow.test/?x=1",
		"https://rp.flow.test/#frag", "javascript:alert(1)", "//evil.flow.test/", "http://rp.flow.test/"} {
		for _, path := range []string{"/wsfed/wsfed-rp", "/wsfed"} {
			resp, page := fetch(t, c, wsfedURL(e.base, path, url.Values{"wtrealm": {"urn:rp:portal"}, "wreply": {reply}}))
			if resp.StatusCode != 400 || strings.Contains(page, "wresult") || resp.Header.Get("Location") != "" {
				t.Fatalf("%s wreply %s: status %d location %q", path, reply, resp.StatusCode, resp.Header.Get("Location"))
			}
		}
	}
}

func TestWSFedRealmResolution(t *testing.T) {
	e, tn := wsfedEnv(t)
	c := e.client(t)
	other := &store.Client{TenantID: tn.ID, ClientID: "plain", Name: "No add-on", AppType: store.AppTypeRegularWeb, IsFirstParty: true,
		Callbacks: []string{"https://rp.flow.test/"}, ClientAliases: []string{"urn:plain"}}
	if err := e.st.Clients().Create(t.Context(), other); err != nil {
		t.Fatal(err)
	}
	for name, u := range map[string]string{
		"unknown realm":           wsfedURL(e.base, "/wsfed", url.Values{"wtrealm": {"urn:unknown"}}),
		"no realm":                e.base + "/wsfed",
		"realm of another client": wsfedURL(e.base, "/wsfed/wsfed-rp", url.Values{"wtrealm": {"urn:plain"}}),
		"unregistered realm":      wsfedURL(e.base, "/wsfed/wsfed-rp", url.Values{"wtrealm": {"urn:other"}}),
		"client without add-on":   e.base + "/wsfed/plain",
		"alias without add-on":    wsfedURL(e.base, "/wsfed", url.Values{"wtrealm": {"urn:plain"}}),
		"unknown client":          e.base + "/wsfed/nobody",
		"unknown action":          wsfedURL(e.base, "/wsfed/wsfed-rp", url.Values{"wa": {"wattr1.0"}}),
		"long wctx":               wsfedURL(e.base, "/wsfed/wsfed-rp", url.Values{"wctx": {strings.Repeat("a", 2049)}}),
	} {
		resp, page := fetch(t, c, u)
		if resp.StatusCode < 400 || resp.StatusCode >= 500 || strings.Contains(page, "wresult") || resp.Header.Get("Location") != "" {
			t.Errorf("%s: status %d location %q", name, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
}

// whr names the connection; wfresh=0 forces authentication again.
func TestWSFedConnectionHintAndFresh(t *testing.T) {
	e, tn := wsfedEnv(t)
	c := e.client(t)
	resp, page := fetch(t, c, wsfedURL(e.base, "/wsfed/wsfed-rp", url.Values{"whr": {"no-such-connection"}}))
	if resp.StatusCode != 400 || strings.Contains(page, "wresult") {
		t.Fatalf("unknown whr connection: status %d", resp.StatusCode)
	}
	resp, page = e.follow(t, c, wsfedURL(e.base, "/wsfed/wsfed-rp", url.Values{"whr": {"Username-Password-Authentication"}}))
	if resp.StatusCode != 200 {
		t.Fatalf("whr sign-in %d", resp.StatusCode)
	}
	wsfedToken(t, e, tn.ID, page, "https://rp.flow.test/", "")
	resp, _ = fetch(t, c, wsfedURL(e.base, "/wsfed/wsfed-rp", url.Values{"wfresh": {"0"}}))
	if loc, _ := resp.Location(); resp.StatusCode != http.StatusFound || loc == nil || loc.Path != "/u/login" {
		t.Fatalf("wfresh=0 with a session: status %d location %v, want the login page", resp.StatusCode, loc)
	}
}

// The binding is server-only: a client cannot smuggle one through /authorize.
func TestWSFedBindingNotInjectable(t *testing.T) {
	e, _ := wsfedEnv(t)
	c := e.client(t)
	resp, page := fetch(t, c, e.base+"/authorize?"+url.Values{"client_id": {"wsfed-rp"}, "redirect_uri": {"https://rp.flow.test/"},
		"response_type": {"code"}, "scope": {"openid"}, "saml": {`wsfed:{"reply":"https://evil.flow.test/","aud":"x"}`}}.Encode())
	if strings.Contains(page, "wresult") || strings.Contains(resp.Header.Get("Location"), "evil") {
		t.Fatal("WS-Fed binding accepted from request parameters")
	}
}

func TestWSFedMetadata(t *testing.T) {
	e, tn := wsfedEnv(t)
	c := e.client(t)
	certs := tenantCerts(t, e, tn.ID)
	for path, endpoint := range map[string]string{
		"/wsfed/FederationMetadata/2007-06/FederationMetadata.xml":          e.base + "/wsfed",
		"/wsfed/wsfed-rp/FederationMetadata/2007-06/FederationMetadata.xml": e.base + "/wsfed/wsfed-rp",
	} {
		resp, body := fetch(t, c, e.base+path)
		if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/xml") {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		doc, err := samlcore.Parse([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		root := doc.Root()
		if root.Tag != "EntityDescriptor" || root.SelectAttrValue("entityID", "") != "urn:"+strings.TrimPrefix(e.base, "https://") {
			t.Fatalf("%s: root %s %v", path, root.Tag, root.Attr)
		}
		role := root.FindElement("RoleDescriptor")
		if role == nil || role.SelectAttrValue("xsi:type", "") != "fed:SecurityTokenServiceType" ||
			role.SelectAttrValue("protocolSupportEnumeration", "") != "http://docs.oasis-open.org/wsfed/federation/200706" {
			t.Fatalf("%s: role descriptor", path)
		}
		if addr := role.FindElement("PassiveRequestorEndpoint/EndpointReference/Address"); addr == nil || addr.Text() != endpoint {
			t.Fatalf("%s: passive requestor endpoint", path)
		}
		x509s := role.FindElements("KeyDescriptor/KeyInfo/X509Data/X509Certificate")
		if len(x509s) == 0 || len(x509s) != len(certs) {
			t.Fatalf("%s: %d signing certificates, want %d", path, len(x509s), len(certs))
		}
		if len(role.FindElements("TokenTypesOffered/TokenType")) != 2 || len(role.FindElements("ClaimTypesOffered/ClaimType")) != 5 {
			t.Fatalf("%s: token or claim types", path)
		}
	}
	for _, path := range []string{"/wsfed/nobody/FederationMetadata/2007-06/FederationMetadata.xml"} {
		if resp, _ := fetch(t, c, e.base+path); resp.StatusCode != 404 {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
	}
}

func wsfedSignedIn(t *testing.T, e *flowEnv) *http.Client {
	t.Helper()
	c := e.client(t)
	if resp, page := e.follow(t, c, e.base+"/wsfed/wsfed-rp"); resp.StatusCode != 200 || !strings.Contains(page, "wresult") {
		t.Fatalf("sign-in %d", resp.StatusCode)
	}
	return c
}

func wsfedNeedsLogin(t *testing.T, e *flowEnv, c *http.Client) bool {
	t.Helper()
	resp, _ := fetch(t, c, e.base+"/wsfed/wsfed-rp")
	loc, _ := resp.Location()
	return resp.StatusCode == http.StatusFound && loc != nil && loc.Path == "/u/login"
}

// wsignout1.0 ends the session and returns to wreply, which must be an
// allowed logout URL (the /v2/logout rule).
func TestWSFedSignOut(t *testing.T) {
	e, tn := wsfedEnv(t)
	rp, _ := e.st.Clients().Get(t.Context(), tn.ID, "wsfed-rp")
	rp.AllowedLogoutURLs = []string{"https://rp.flow.test/signed-out"}
	if err := e.st.Clients().Update(t.Context(), rp); err != nil {
		t.Fatal(err)
	}
	c := wsfedSignedIn(t, e)
	resp, _ := fetch(t, c, wsfedURL(e.base, "/wsfed/wsfed-rp", url.Values{"wa": {"wsignout1.0"}, "wreply": {"https://evil.flow.test/"}}))
	for i := 0; i < 3 && resp.StatusCode == http.StatusFound; i++ {
		loc, _ := resp.Location()
		if !strings.HasPrefix(loc.String(), e.base) {
			t.Fatalf("redirected to %s", loc)
		}
		resp, _ = fetch(t, c, loc.String())
	}
	if resp.StatusCode != 400 || wsfedNeedsLogin(t, e, c) {
		t.Fatalf("disallowed wreply: status %d; the session must survive", resp.StatusCode)
	}
	resp, _ = fetch(t, c, wsfedURL(e.base, "/wsfed/wsfed-rp", url.Values{"wa": {"wsignout1.0"}, "wreply": {"https://rp.flow.test/signed-out"}}))
	var final string
	for i := 0; i < 3 && resp.StatusCode == http.StatusFound; i++ {
		loc, _ := resp.Location()
		if !strings.HasPrefix(loc.String(), e.base) {
			final = loc.String()
			break
		}
		resp, _ = fetch(t, c, loc.String())
	}
	if final != "https://rp.flow.test/signed-out" {
		t.Fatalf("sign-out ended at %q (status %d)", final, resp.StatusCode)
	}
	if !wsfedNeedsLogin(t, e, c) {
		t.Fatal("session survived wsignout1.0")
	}
}

// wsignoutcleanup1.0 ends the session and answers without redirecting.
func TestWSFedSignOutCleanup(t *testing.T) {
	e, _ := wsfedEnv(t)
	c := wsfedSignedIn(t, e)
	resp, _ := fetch(t, c, wsfedURL(e.base, "/wsfed/wsfed-rp", url.Values{"wa": {"wsignoutcleanup1.0"}}))
	if resp.StatusCode != 200 || resp.Header.Get("Location") != "" {
		t.Fatalf("cleanup: status %d location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if !wsfedNeedsLogin(t, e, c) {
		t.Fatal("session survived wsignoutcleanup1.0")
	}
}
