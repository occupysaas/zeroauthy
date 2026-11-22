package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"html"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/samlcore"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var (
	formActionRe = regexp.MustCompile(`<form[^>]*action="([^"]+)"`)
	hiddenRe     = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)"`)
)

// samlEnv is the flow environment with a SAML service-provider application.
func samlEnv(t *testing.T, addon *store.SAMLAddon) (*flowEnv, *store.Tenant) {
	t.Helper()
	e := newFlowEnv(t)
	tn, err := e.st.Tenants().GetByName(t.Context(), "flow")
	if err != nil {
		t.Fatal(err)
	}
	c := &store.Client{TenantID: tn.ID, ClientID: "saml-sp", Name: "SAML SP", AppType: store.AppTypeRegularWeb, IsFirstParty: true,
		Callbacks: []string{"https://sp.flow.test/acs"}, Addons: &store.ClientAddons{SAMLP: addon}}
	if err := e.st.Clients().Create(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	conn, err := e.st.Connections().GetByName(t.Context(), tn.ID, "Username-Password-Authentication")
	if err != nil {
		t.Fatal(err)
	}
	conn.EnabledClients = append(conn.EnabledClients, "saml-sp")
	if err := e.st.Connections().Update(t.Context(), conn); err != nil {
		t.Fatal(err)
	}
	return e, tn
}

func samlRequestURL(t *testing.T, base, acs, id, relay string) string {
	t.Helper()
	req, err := samlcore.BuildAuthnRequest(samlcore.AuthnRequest{ID: id, IssueInstant: time.Now(), Issuer: "urn:sp", Destination: base + "/samlp/saml-sp", ACSURL: acs, ProtocolBinding: samlcore.BindingPOST}, "")
	if err != nil {
		t.Fatal(err)
	}
	u, err := samlcore.EncodeRedirect(base+"/samlp/saml-sp", samlcore.ParamRequest, req, relay, nil)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// follow fetches u and follows same-origin redirects, logging in on the
// hosted login page, until a page is returned.
func (e *flowEnv) follow(t *testing.T, c *http.Client, u string) (*http.Response, string) {
	t.Helper()
	resp, body := fetch(t, c, u)
	for i := 0; i < 10 && resp.StatusCode == http.StatusFound; i++ {
		loc, _ := resp.Location()
		if loc.Path == "/u/login" {
			_, page := fetch(t, c, loc.String())
			csrf := csrfRe.FindStringSubmatch(page)
			if csrf == nil {
				t.Fatalf("no csrf on login page")
			}
			form := url.Values{"hosted_revision": {hostedRevision(page)}, "state": {loc.Query().Get("state")}, "csrf": {csrf[1]}, "username": {"alice@flow.test"}, "password": {"alice password 1"}}
			req, _ := http.NewRequest("POST", e.base+"/u/login", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, body = mustDo(t, c, req)
			continue
		}
		if !strings.HasPrefix(loc.String(), e.base) && loc.Host != "" {
			t.Fatalf("redirected off the tenant to %s", loc)
		}
		resp, body = fetch(t, c, e.base+loc.RequestURI())
	}
	return resp, body
}

func tenantCerts(t *testing.T, e *flowEnv, tid string) []*x509.Certificate {
	t.Helper()
	ks, err := e.st.SigningKeys().List(t.Context(), tid)
	if err != nil {
		t.Fatal(err)
	}
	var out []*x509.Certificate
	for _, k := range ks {
		if len(k.CertificateDER) > 0 {
			cert, err := x509.ParseCertificate(k.CertificateDER)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, cert)
		}
	}
	return out
}

// postedResponse extracts the auto-posted form's action and fields.
func postedResponse(t *testing.T, page string) (string, url.Values) {
	t.Helper()
	m := formActionRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no auto-post form in page: %.400s", page)
	}
	fields := url.Values{}
	for _, f := range hiddenRe.FindAllStringSubmatch(page, -1) {
		fields.Set(html.UnescapeString(f[1]), html.UnescapeString(f[2]))
	}
	return html.UnescapeString(m[1]), fields
}

func TestSAMLIdPSSO(t *testing.T) {
	e, tn := samlEnv(t, &store.SAMLAddon{})
	c := e.client(t)
	resp, page := e.follow(t, c, samlRequestURL(t, e.base, "https://sp.flow.test/acs", "_req1", "relay-1"))
	if resp.StatusCode != 200 {
		t.Fatalf("SSO ended with %d", resp.StatusCode)
	}
	action, fields := postedResponse(t, page)
	if action != "https://sp.flow.test/acs" || fields.Get("RelayState") != "relay-1" {
		t.Fatalf("posted to %s with RelayState %q", action, fields.Get("RelayState"))
	}
	doc, err := samlcore.DecodePOST(fields.Get("SAMLResponse"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := samlcore.VerifyResponse(doc, samlcore.Trust{Certs: tenantCerts(t, e, tn.ID)}, nil)
	if err != nil {
		t.Fatalf("response does not verify with the tenant certificate: %v", err)
	}
	env, _ := samlcore.ParseResponseEnvelope(v.Response)
	a, err := samlcore.ParseAssertion(v.Assertion)
	if err != nil {
		t.Fatal(err)
	}
	if env.StatusCode != samlcore.StatusSuccess || env.InResponseTo != "_req1" || env.Destination != "https://sp.flow.test/acs" {
		t.Fatalf("envelope %+v", env)
	}
	if err := a.Check(samlcore.Expect{Now: time.Now(), Skew: 2 * time.Minute, Audience: "urn:sp", Recipient: "https://sp.flow.test/acs", InResponseTo: "_req1"}); err != nil {
		t.Fatalf("assertion conditions: %v", err)
	}
	user, err := e.st.Users().FindByEmail(t.Context(), tn.ID, "alice@flow.test")
	if err != nil || len(user) != 1 {
		t.Fatalf("user lookup: %v", err)
	}
	if a.NameID != user[0].UserID || a.Attributes[samlcore.ClaimEmail][0] != "alice@flow.test" || a.Issuer != "urn:"+strings.TrimPrefix(e.base, "https://") || env.Issuer != a.Issuer {
		t.Fatalf("assertion subject %q attributes %v issuer %q", a.NameID, a.Attributes, a.Issuer)
	}
	if a.SessionIndex == "" {
		t.Fatal("no SessionIndex")
	}
	// A second request in the same browser uses the session: no login page.
	resp, page = e.follow(t, c, samlRequestURL(t, e.base, "https://sp.flow.test/acs", "_req2", ""))
	if resp.StatusCode != 200 || strings.Contains(page, `name="password"`) {
		t.Fatal("second SAML request did not reuse the session")
	}
	if _, fields := postedResponse(t, page); fields.Get("SAMLResponse") == "" {
		t.Fatal("no second response")
	}
}

// TestIdPACSAllowlist is Plan 37a Review Focus 4: an AuthnRequest naming an
// ACS outside the application's callbacks (and add-on recipient) gets an
// error page; nothing is posted and no login starts.
func TestIdPACSAllowlist(t *testing.T) {
	e, _ := samlEnv(t, &store.SAMLAddon{Recipient: "https://sp.flow.test/other-acs"})
	c := e.client(t)
	for _, acs := range []string{"https://evil.flow.test/acs", "https://sp.flow.test/acs/../evil", "https://sp.flow.test/acs?x=1"} {
		resp, page := fetch(t, c, samlRequestURL(t, e.base, acs, "_bad", "r"))
		if resp.StatusCode != 400 || strings.Contains(page, "SAMLResponse") || resp.Header.Get("Location") != "" {
			t.Fatalf("ACS %s: status %d location %q", acs, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	// The add-on recipient is allowed as well as the callbacks.
	resp, page := e.follow(t, c, samlRequestURL(t, e.base, "https://sp.flow.test/other-acs", "_ok", ""))
	if action, _ := postedResponse(t, page); resp.StatusCode != 200 || action != "https://sp.flow.test/other-acs" {
		t.Fatalf("recipient ACS: %d %s", resp.StatusCode, action)
	}
}

// An application without the add-on, or an unknown one, cannot be used.
func TestSAMLIdPRequiresAddon(t *testing.T) {
	e, tn := samlEnv(t, &store.SAMLAddon{})
	c, _ := e.st.Clients().Get(t.Context(), tn.ID, "saml-sp")
	c.Addons = nil
	if err := e.st.Clients().Update(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{samlRequestURL(t, e.base, "https://sp.flow.test/acs", "_x", ""), strings.Replace(samlRequestURL(t, e.base, "https://sp.flow.test/acs", "_x", ""), "/samlp/saml-sp", "/samlp/nope", 1)} {
		resp, page := fetch(t, e.client(t), u)
		if resp.StatusCode != http.StatusNotFound || strings.Contains(page, "SAMLResponse") {
			t.Fatalf("%s: status %d", u, resp.StatusCode)
		}
	}
}

func spIdentity(t *testing.T) (*rsa.PrivateKey, *x509.Certificate, string) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "sp"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func signedRequestURL(t *testing.T, base string, signer *samlcore.Signer, mutate func(*samlcore.AuthnRequest)) string {
	t.Helper()
	ar := samlcore.AuthnRequest{ID: "_signed", IssueInstant: time.Now(), Issuer: "urn:sp", Destination: base + "/samlp/saml-sp", ACSURL: "https://sp.flow.test/acs", ProtocolBinding: samlcore.BindingPOST}
	if mutate != nil {
		mutate(&ar)
	}
	req, err := samlcore.BuildAuthnRequest(ar, "")
	if err != nil {
		t.Fatal(err)
	}
	u, err := samlcore.EncodeRedirect(base+"/samlp/saml-sp", samlcore.ParamRequest, req, "", signer)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// With signingCert on the add-on, AuthnRequests must be signed by that key.
func TestSAMLIdPRequestSignature(t *testing.T) {
	key, cert, certPEM := spIdentity(t)
	e, _ := samlEnv(t, &store.SAMLAddon{SigningCert: certPEM})
	otherKey, otherCert, _ := spIdentity(t)
	for name, signer := range map[string]*samlcore.Signer{"unsigned": nil, "wrong key": {Key: otherKey, Cert: otherCert}} {
		resp, page := fetch(t, e.client(t), signedRequestURL(t, e.base, signer, nil))
		if resp.StatusCode != 400 || strings.Contains(page, "SAMLResponse") {
			t.Fatalf("%s request: status %d", name, resp.StatusCode)
		}
	}
	resp, _ := fetch(t, e.client(t), signedRequestURL(t, e.base, &samlcore.Signer{Key: key, Cert: cert}, nil))
	if loc, _ := resp.Location(); resp.StatusCode != 302 || loc.Path != "/u/login" {
		t.Fatalf("signed request: %d", resp.StatusCode)
	}
	// A request addressed to another IdP endpoint is refused.
	resp, _ = fetch(t, e.client(t), signedRequestURL(t, e.base, &samlcore.Signer{Key: key, Cert: cert}, func(a *samlcore.AuthnRequest) { a.Destination = "https://idp.other.test/sso" }))
	if resp.StatusCode != 400 {
		t.Fatalf("foreign Destination: %d", resp.StatusCode)
	}
}

func TestSAMLIdPSignResponse(t *testing.T) {
	yes := true
	e, tn := samlEnv(t, &store.SAMLAddon{SignResponse: &yes, Audience: "urn:configured"})
	_, page := e.follow(t, e.client(t), samlRequestURL(t, e.base, "https://sp.flow.test/acs", "_r", ""))
	_, fields := postedResponse(t, page)
	doc, err := samlcore.DecodePOST(fields.Get("SAMLResponse"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := samlcore.VerifyResponse(doc, samlcore.Trust{Certs: tenantCerts(t, e, tn.ID)}, nil)
	if err != nil || !v.ResponseSigned || !v.AssertionSigned {
		t.Fatalf("signed response: %+v %v", v, err)
	}
	a, _ := samlcore.ParseAssertion(v.Assertion)
	if len(a.Audiences) != 1 || a.Audiences[0] != "urn:configured" {
		t.Fatalf("configured audience: %v", a.Audiences)
	}
}

// IsPassive without a session answers the SP with a SAML error, not a page.
func TestSAMLIdPPassiveWithoutSession(t *testing.T) {
	e, tn := samlEnv(t, &store.SAMLAddon{})
	req, _ := samlcore.BuildAuthnRequest(samlcore.AuthnRequest{ID: "_p", IssueInstant: time.Now(), Issuer: "urn:sp", ACSURL: "https://sp.flow.test/acs"}, "")
	req.CreateAttr("IsPassive", "true")
	u, _ := samlcore.EncodeRedirect(e.base+"/samlp/saml-sp", samlcore.ParamRequest, req, "rs", nil)
	resp, page := e.follow(t, e.client(t), u)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	action, fields := postedResponse(t, page)
	doc, err := samlcore.DecodePOST(fields.Get("SAMLResponse"))
	if err != nil || action != "https://sp.flow.test/acs" || fields.Get("RelayState") != "rs" {
		t.Fatalf("error response delivery: %s %v", action, err)
	}
	env, _ := samlcore.ParseResponseEnvelope(doc.Root())
	if env.StatusCode != samlcore.StatusAuthnFail || env.InResponseTo != "_p" || len(doc.Root().ChildElements()) > 0 && doc.FindElement("//Assertion") != nil {
		t.Fatalf("error envelope %+v", env)
	}
	_ = tn
}

// The SAML binding is server-only: a za_saml parameter on /authorize is
// ignored and the request completes as an ordinary code flow.
func TestSAMLBindingNotInjectable(t *testing.T) {
	e, _ := samlEnv(t, &store.SAMLAddon{})
	tok := e.codeFlow(t, e.client(t), "za_saml", `{"acs":"https://evil.flow.test/acs","aud":"urn:evil"}`)
	if tok["access_token"] == nil {
		t.Fatal("code flow with an injected za_saml did not complete normally")
	}
}

func TestSAMLIdPMetadata(t *testing.T) {
	e, tn := samlEnv(t, &store.SAMLAddon{})
	resp, body := fetch(t, e.client(t), e.base+"/samlp/metadata/saml-sp")
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "xml") {
		t.Fatalf("metadata: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	md, err := samlcore.ParseMetadata([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if md.EntityID != "urn:"+strings.TrimPrefix(e.base, "https://") || md.IdP == nil {
		t.Fatalf("entity %+v", md)
	}
	if md.IdP.SSOLocation(samlcore.BindingRedirect) != e.base+"/samlp/saml-sp" || md.IdP.SSOLocation(samlcore.BindingPOST) != e.base+"/samlp/saml-sp" ||
		md.IdP.SLOLocation(samlcore.BindingRedirect) != e.base+"/samlp/saml-sp/logout" {
		t.Fatalf("endpoints %+v", md.IdP)
	}
	want := tenantCerts(t, e, tn.ID)
	if len(md.IdP.SigningCerts) == 0 || len(md.IdP.SigningCerts) > len(want) {
		t.Fatalf("certificates: %d of %d", len(md.IdP.SigningCerts), len(want))
	}
	if resp, _ := fetch(t, e.client(t), e.base+"/samlp/metadata/nope"); resp.StatusCode != 404 {
		t.Fatalf("unknown application metadata: %d", resp.StatusCode)
	}
}

// IdP-initiated SSO: no AuthnRequest; the unsolicited response goes to the
// add-on recipient with no InResponseTo.
func TestSAMLIdPInitiated(t *testing.T) {
	e, tn := samlEnv(t, &store.SAMLAddon{Recipient: "https://sp.flow.test/acs"})
	resp, page := e.follow(t, e.client(t), e.base+"/samlp/saml-sp?RelayState=deep-link")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	action, fields := postedResponse(t, page)
	doc, err := samlcore.DecodePOST(fields.Get("SAMLResponse"))
	if err != nil || action != "https://sp.flow.test/acs" || fields.Get("RelayState") != "deep-link" {
		t.Fatalf("delivery %s %v", action, err)
	}
	v, err := samlcore.VerifyResponse(doc, samlcore.Trust{Certs: tenantCerts(t, e, tn.ID)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := samlcore.ParseAssertion(v.Assertion)
	env, _ := samlcore.ParseResponseEnvelope(v.Response)
	if a.InResponseTo != "" || env.InResponseTo != "" {
		t.Fatal("unsolicited response answers a request")
	}
	if err := a.Check(samlcore.Expect{Now: time.Now(), Skew: time.Minute, Audience: "https://sp.flow.test/acs", Recipient: "https://sp.flow.test/acs", AllowUnsolicited: true}); err != nil {
		t.Fatal(err)
	}
}
