package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/samlcore"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// fixtureIdP is a SAML identity provider built on samlcore.
type fixtureIdP struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
	pem  string
}

func newFixtureIdP(t *testing.T) fixtureIdP {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "idp"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return fixtureIdP{key: key, cert: cert, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

// response builds a signed Response for the given request (inResponseTo ""
// = unsolicited).
func (idp fixtureIdP) response(t *testing.T, id, inResponseTo, audience, acs, nameID string, attrs map[string]string) string {
	t.Helper()
	now := time.Now()
	var as []samlcore.Attribute
	for k, v := range attrs {
		as = append(as, samlcore.Attribute{Name: k, Values: []string{v}})
	}
	a := samlcore.BuildAssertion(samlcore.AssertionSpec{ID: id, IssueInstant: now, Issuer: "https://idp.saml.test", NameID: nameID, Audience: audience,
		Recipient: acs, InResponseTo: inResponseTo, NotBefore: now, NotOnOrAfter: now.Add(5 * time.Minute), AuthnInstant: now, Attributes: as})
	signed, err := samlcore.Signer{Key: idp.key, Cert: idp.cert}.SignEnveloped(a)
	if err != nil {
		t.Fatal(err)
	}
	resp := samlcore.BuildResponse(samlcore.ResponseSpec{ID: "_resp" + id, InResponseTo: inResponseTo, Destination: acs, Issuer: "https://idp.saml.test", IssueInstant: now}, signed)
	return samlcore.EncodePOST(resp)
}

func samlConnEnv(t *testing.T, extra map[string]any) (*flowEnv, *store.Tenant, fixtureIdP) {
	t.Helper()
	e := newFlowEnvSeed(t, flowSeed, func(d *Deps) {
		d.Federation = &federation.FlowService{Service: federation.Service{Wrapper: d.Wrapper}, Store: d.Store,
			Providers: federation.NewProviders(federation.NetworkPolicy{}, time.Now)}
	})
	tn, err := e.st.Tenants().GetByName(t.Context(), "flow")
	if err != nil {
		t.Fatal(err)
	}
	idp := newFixtureIdP(t)
	opts := map[string]any{"signInEndpoint": "https://idp.saml.test/sso", "signingCert": idp.pem}
	for k, v := range extra {
		opts[k] = v
	}
	conn := &store.Connection{TenantID: tn.ID, ID: "con_saml0123456789ab", Name: "corp-saml", Strategy: "samlp", Extra: opts, EnabledClients: []string{"spa"}, FederationRevision: 1}
	if err := e.st.Connections().Create(t.Context(), conn); err != nil {
		t.Fatal(err)
	}
	return e, tn, idp
}

// startSAML follows /authorize?connection=corp-saml to the IdP and returns
// the decoded AuthnRequest and RelayState.
func startSAML(t *testing.T, e *flowEnv, c *http.Client) (*samlcore.AuthnRequest, string) {
	t.Helper()
	resp, _ := fetch(t, c, authorizeURL(e.base, "connection", "corp-saml"))
	for i := 0; i < 5 && (resp.StatusCode == 302 || resp.StatusCode == 303); i++ {
		loc, _ := resp.Location()
		if loc.Host == "idp.saml.test" {
			msg, err := samlcore.DecodeRedirect(loc.RawQuery)
			if err != nil {
				t.Fatal(err)
			}
			ar, err := samlcore.ParseAuthnRequest(msg.Doc.Root())
			if err != nil {
				t.Fatal(err)
			}
			return ar, msg.RelayState
		}
		resp, _ = fetch(t, c, e.base+loc.RequestURI())
	}
	t.Fatalf("authorize did not reach the IdP (status %d)", resp.StatusCode)
	return nil, ""
}

func postACS(t *testing.T, e *flowEnv, c *http.Client, samlResponse, relay string) *http.Response {
	t.Helper()
	form := url.Values{"SAMLResponse": {samlResponse}}
	if relay != "" {
		form.Set("RelayState", relay)
	}
	req, _ := http.NewRequest("POST", e.base+"/login/callback?connection=corp-saml", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, _ := mustDo(t, c, req)
	return resp
}

func TestSAMLSPLogin(t *testing.T) {
	e, tn, idp := samlConnEnv(t, map[string]any{"fieldsMap": map[string]any{"email": "mail"}})
	acs := e.base + "/login/callback?connection=corp-saml"
	// Note: e.client returns one shared *http.Client with a fresh jar, so
	// each browser is used to the end before the next starts.
	ar, relay := startSAML(t, e, e.client(t))
	if ar.ACSURL != acs || ar.Issuer != "urn:auth0:flow:corp-saml" || ar.Destination != "https://idp.saml.test/sso" || relay == "" || !strings.HasPrefix(ar.ID, "_") {
		t.Fatalf("AuthnRequest %+v relay %q", ar, relay)
	}
	other := newFixtureIdP(t)
	for name, build := range map[string]func(id string) string{
		"foreign key": func(id string) string {
			return other.response(t, "_bad1", id, "urn:auth0:flow:corp-saml", acs, "jdoe", nil)
		},
		"wrong audience": func(id string) string { return idp.response(t, "_bad2", id, "urn:other", acs, "jdoe", nil) },
		"wrong request": func(string) string {
			return idp.response(t, "_bad3", "_someone-else", "urn:auth0:flow:corp-saml", acs, "jdoe", nil)
		},
		"wrong recipient": func(id string) string {
			return idp.response(t, "_bad4", id, "urn:auth0:flow:corp-saml", "https://evil.test/acs", "jdoe", nil)
		},
	} {
		c := e.client(t)
		ar, relay := startSAML(t, e, c)
		resp := postACS(t, e, c, build(ar.ID), relay)
		if loc, _ := resp.Location(); loc != nil && loc.Query().Get("code") != "" {
			t.Fatalf("%s: login completed", name)
		}
	}
	c := e.client(t)
	ar, relay = startSAML(t, e, c)
	resp := postACS(t, e, c, idp.response(t, "_good", ar.ID, "urn:auth0:flow:corp-saml", acs, "jdoe", map[string]string{"mail": "jdoe@corp.test"}), relay)
	for i := 0; i < 5 && resp.StatusCode/100 == 3; i++ {
		loc, _ := resp.Location()
		if loc.Host == "app.flow.test" {
			break
		}
		resp, _ = fetch(t, c, e.base+loc.RequestURI())
	}
	if loc, _ := resp.Location(); loc == nil || loc.Host != "app.flow.test" || loc.Query().Get("code") == "" {
		t.Fatalf("SAML login did not complete: %d %v", resp.StatusCode, loc)
	}
	users, err := e.st.Users().FindByEmail(t.Context(), tn.ID, "jdoe@corp.test")
	if err != nil || len(users) != 1 || users[0].UserID != "samlp|corp-saml|jdoe" {
		t.Fatalf("provisioned user %+v %v", users, err)
	}
}

// TestACSReplay is Plan 37a Review Focus 2: the same assertion posted twice
// is refused the second time (store-backed, so across replicas).
func TestACSReplay(t *testing.T) {
	e, _, idp := samlConnEnv(t, map[string]any{"idpinitiated": map[string]any{"enabled": true, "client_id": "spa", "client_protocol": "oidc",
		"client_authorizequery": "redirect_uri=https%3A%2F%2Fapp.flow.test%2Fcb&response_type=code&scope=openid&code_challenge=" + challenge + "&code_challenge_method=S256"}})
	raw := idp.response(t, "_replayed", "", "urn:auth0:flow:corp-saml", e.base+"/login/callback?connection=corp-saml", "jdoe", nil)
	first := postACS(t, e, e.client(t), raw, "")
	if first.StatusCode != 302 && first.StatusCode != 303 {
		t.Fatalf("first post: %d", first.StatusCode)
	}
	second := postACS(t, e, e.client(t), raw, "")
	if loc, _ := second.Location(); second.StatusCode/100 == 3 && loc != nil && strings.Contains(loc.Path, "/authorize") {
		t.Fatalf("replayed assertion accepted: %d %v", second.StatusCode, loc)
	}
}

// TestIdPInitiatedPolicy is Plan 37a Review Focus 3: an unsolicited response
// is refused unless IdP-initiated login is enabled, and then lands only on
// the configured application.
func TestIdPInitiatedPolicy(t *testing.T) {
	e, _, idp := samlConnEnv(t, nil)
	acs := e.base + "/login/callback?connection=corp-saml"
	resp := postACS(t, e, e.client(t), idp.response(t, "_u1", "", "urn:auth0:flow:corp-saml", acs, "jdoe", nil), "https://evil.test/")
	if resp.StatusCode/100 == 3 {
		loc, _ := resp.Location()
		t.Fatalf("unsolicited response accepted while disabled: %v", loc)
	}
	// Configured but disabled: still refused.
	e3, _, idp3 := samlConnEnv(t, map[string]any{"idpinitiated": map[string]any{"enabled": false, "client_id": "spa", "client_protocol": "oidc",
		"client_authorizequery": "redirect_uri=https%3A%2F%2Fapp.flow.test%2Fcb&response_type=code&scope=openid"}})
	resp = postACS(t, e3, e3.client(t), idp3.response(t, "_u3", "", "urn:auth0:flow:corp-saml", e3.base+"/login/callback?connection=corp-saml", "jdoe", nil), "")
	if resp.StatusCode/100 == 3 {
		loc, _ := resp.Location()
		t.Fatalf("unsolicited response accepted with idpinitiated.enabled false: %v", loc)
	}
	e2, _, idp2 := samlConnEnv(t, map[string]any{"idpinitiated": map[string]any{"enabled": true, "client_id": "spa", "client_protocol": "oidc",
		"client_authorizequery": "redirect_uri=https%3A%2F%2Fapp.flow.test%2Fcb&response_type=code&scope=openid&code_challenge=" + challenge + "&code_challenge_method=S256"}})
	c := e2.client(t)
	resp = postACS(t, e2, c, idp2.response(t, "_u2", "", "urn:auth0:flow:corp-saml", e2.base+"/login/callback?connection=corp-saml", "jdoe", nil), "https://evil.test/")
	loc, _ := resp.Location()
	if resp.StatusCode/100 != 3 || loc == nil || loc.Path != "/authorize" || loc.Query().Get("client_id") != "spa" || loc.Query().Get("redirect_uri") != "https://app.flow.test/cb" {
		t.Fatalf("IdP-initiated landing: %d %v", resp.StatusCode, loc)
	}
	// The session lets /authorize finish with a code for the configured app.
	resp, _ = fetch(t, c, e2.base+loc.RequestURI())
	if loc, _ := resp.Location(); loc == nil || loc.Host != "app.flow.test" || loc.Query().Get("code") == "" {
		t.Fatalf("after IdP-initiated login: %d %v", resp.StatusCode, loc)
	}
}
