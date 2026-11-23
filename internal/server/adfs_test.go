package server

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/samlcore"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const adfsEndpoint = "https://adfs.flow.test/adfs/ls/"

// adfsMetadataXML is federation metadata for a fixture WS-Fed IdP.
func adfsMetadataXML(idp fixtureIdP) string {
	return `<EntityDescriptor entityID="http://adfs.flow.test/adfs/services/trust" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` +
		`<RoleDescriptor xsi:type="fed:SecurityTokenServiceType" protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706">` +
		`<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` + base64.StdEncoding.EncodeToString(idp.cert.Raw) + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor>` +
		`<fed:PassiveRequestorEndpoint><EndpointReference xmlns="http://www.w3.org/2005/08/addressing"><Address>` + adfsEndpoint + `</Address></EndpointReference></fed:PassiveRequestorEndpoint>` +
		`</RoleDescriptor></EntityDescriptor>`
}

func adfsConnEnv(t *testing.T, extra map[string]any) (*flowEnv, *store.Tenant, fixtureIdP) {
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
	opts := map[string]any{"fedMetadataXml": adfsMetadataXML(idp)}
	for k, v := range extra {
		opts[k] = v
	}
	conn := &store.Connection{TenantID: tn.ID, ID: "con_adfs0123456789ab", Name: "corp-adfs", Strategy: "adfs", Extra: opts, EnabledClients: []string{"spa"}, FederationRevision: 1}
	if err := e.st.Connections().Create(t.Context(), conn); err != nil {
		t.Fatal(err)
	}
	return e, tn, idp
}

// adfsToken is a fixture IdP wresult: a signed SAML 1.1 (or 2.0) token.
type adfsToken struct {
	id, audience, nameID string
	attrs                map[string]string
	saml2                bool
	notBefore, notAfter  time.Time
	unsigned             bool
}

func (idp fixtureIdP) wresult(t *testing.T, tok adfsToken) string {
	t.Helper()
	now := time.Now()
	if tok.notBefore.IsZero() {
		tok.notBefore, tok.notAfter = now.Add(-time.Minute), now.Add(time.Hour)
	}
	if tok.id == "" {
		tok.id = "_" + secrets.RandomString(24)
	}
	var as []samlcore.Attribute
	for k, v := range tok.attrs {
		as = append(as, samlcore.Attribute{Name: k, Values: []string{v}})
	}
	signer := samlcore.Signer{Key: idp.key, Cert: idp.cert}
	var signed = samlcore.BuildAssertion11(samlcore.Assertion11Spec{ID: tok.id, Issuer: "http://adfs.flow.test/adfs/services/trust", NameID: tok.nameID,
		Audience: tok.audience, IssueInstant: now, NotBefore: tok.notBefore, NotOnOrAfter: tok.notAfter, AuthnInstant: now, Attributes: as})
	var err error
	switch {
	case tok.saml2:
		signed = samlcore.BuildAssertion(samlcore.AssertionSpec{ID: tok.id, IssueInstant: now, Issuer: "http://adfs.flow.test/adfs/services/trust", NameID: tok.nameID,
			Audience: tok.audience, Recipient: "", NotBefore: tok.notBefore, NotOnOrAfter: tok.notAfter, AuthnInstant: now, Attributes: as})
		if !tok.unsigned {
			signed, err = signer.SignEnveloped(signed)
		}
	case !tok.unsigned:
		signed, err = signer.SignEnveloped11(signed)
	}
	if err != nil {
		t.Fatal(err)
	}
	raw, err := samlcore.BuildRSTR("", signed)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// startADFS follows /authorize?connection=corp-adfs to the IdP and returns
// the sign-in request's query.
func startADFS(t *testing.T, e *flowEnv, c *http.Client) url.Values {
	t.Helper()
	resp, _ := fetch(t, c, authorizeURL(e.base, "connection", "corp-adfs"))
	for i := 0; i < 5 && (resp.StatusCode == 302 || resp.StatusCode == 303); i++ {
		loc, _ := resp.Location()
		if loc.Host == "adfs.flow.test" {
			if loc.Path != "/adfs/ls/" {
				t.Fatalf("sign-in endpoint %s", loc)
			}
			return loc.Query()
		}
		resp, _ = fetch(t, c, e.base+loc.RequestURI())
	}
	t.Fatalf("authorize did not reach ADFS (status %d)", resp.StatusCode)
	return nil
}

func postWResult(t *testing.T, e *flowEnv, c *http.Client, wresult, wctx string) *http.Response {
	t.Helper()
	form := url.Values{"wa": {"wsignin1.0"}, "wresult": {wresult}, "wctx": {wctx}}
	req, _ := http.NewRequest("POST", e.base+"/login/callback", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, _ := mustDo(t, c, req)
	return resp
}

// completed follows the callback's redirects and reports whether the
// application received a code.
func completed(t *testing.T, e *flowEnv, c *http.Client, resp *http.Response) bool {
	t.Helper()
	for i := 0; i < 5 && resp.StatusCode/100 == 3; i++ {
		loc, _ := resp.Location()
		if loc.Host == "app.flow.test" {
			return loc.Query().Get("code") != ""
		}
		resp, _ = fetch(t, c, e.base+loc.RequestURI())
	}
	return false
}

const claimUPN = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"

func TestADFSLogin(t *testing.T) {
	e, tn, idp := adfsConnEnv(t, nil)
	c := e.client(t)
	q := startADFS(t, e, c)
	if q.Get("wa") != "wsignin1.0" || q.Get("wtrealm") != "urn:auth0:flow:corp-adfs" || q.Get("wreply") != e.base+"/login/callback" || q.Get("wctx") == "" {
		t.Fatalf("sign-in request %v", q)
	}
	raw := idp.wresult(t, adfsToken{audience: "urn:auth0:flow:corp-adfs", nameID: "jdoe@corp.test",
		attrs: map[string]string{samlcore.ClaimEmail: "jdoe@corp.test", samlcore.ClaimGivenName: "J", samlcore.ClaimSurname: "Doe"}})
	if !completed(t, e, c, postWResult(t, e, c, raw, q.Get("wctx"))) {
		t.Fatal("SAML 1.1 login did not complete")
	}
	users, err := e.st.Users().FindByEmail(t.Context(), tn.ID, "jdoe@corp.test")
	if err != nil || len(users) != 1 || users[0].UserID != "adfs|corp-adfs|jdoe@corp.test" || users[0].EmailVerified || users[0].GivenName != "J" {
		t.Fatalf("provisioned user %+v %v", users, err)
	}
	// A SAML 2.0 token in the RSTR is accepted too.
	c = e.client(t)
	q = startADFS(t, e, c)
	raw = idp.wresult(t, adfsToken{audience: "urn:auth0:flow:corp-adfs", nameID: "asmith", saml2: true, attrs: map[string]string{samlcore.ClaimEmail: "asmith@corp.test"}})
	if !completed(t, e, c, postWResult(t, e, c, raw, q.Get("wctx"))) {
		t.Fatal("SAML 2.0 login did not complete")
	}
	if u, err := e.st.Users().Get(t.Context(), tn.ID, "adfs|corp-adfs|asmith"); err != nil || u.Email != "asmith@corp.test" {
		t.Fatalf("SAML 2.0 user %+v %v", u, err)
	}
}

// TestADFSValidation is Plan 37b Review Focus 3: a token signed by a
// certificate whose thumbprint is not trusted, for another audience,
// outside its validity window, unsigned, or for another attempt is refused.
func TestADFSValidation(t *testing.T) {
	e, _, idp := adfsConnEnv(t, nil)
	other := newFixtureIdP(t)
	aud := "urn:auth0:flow:corp-adfs"
	now := time.Now()
	for name, build := range map[string]func() string{
		"unknown thumbprint": func() string { return other.wresult(t, adfsToken{audience: aud, nameID: "jdoe"}) },
		"wrong audience":     func() string { return idp.wresult(t, adfsToken{audience: "urn:auth0:flow:other", nameID: "jdoe"}) },
		"expired": func() string {
			return idp.wresult(t, adfsToken{audience: aud, nameID: "jdoe", notBefore: now.Add(-2 * time.Hour), notAfter: now.Add(-time.Hour)})
		},
		"not yet valid": func() string {
			return idp.wresult(t, adfsToken{audience: aud, nameID: "jdoe", notBefore: now.Add(time.Hour), notAfter: now.Add(2 * time.Hour)})
		},
		"unsigned": func() string { return idp.wresult(t, adfsToken{audience: aud, nameID: "jdoe", unsigned: true}) },
		"unsigned saml2": func() string {
			return idp.wresult(t, adfsToken{audience: aud, nameID: "jdoe", unsigned: true, saml2: true})
		},
		"no subject": func() string { return idp.wresult(t, adfsToken{audience: aud}) },
	} {
		c := e.client(t)
		q := startADFS(t, e, c)
		if completed(t, e, c, postWResult(t, e, c, build(), q.Get("wctx"))) {
			t.Errorf("%s: login completed", name)
		}
	}
	// A valid token without this browser's attempt is refused.
	c := e.client(t)
	_ = startADFS(t, e, c)
	if completed(t, e, c, postWResult(t, e, c, idp.wresult(t, adfsToken{audience: aud, nameID: "jdoe"}), "not-the-state")) {
		t.Error("token for an unknown wctx accepted")
	}
	if completed(t, e, e.client(t), postWResult(t, e, e.client(t), idp.wresult(t, adfsToken{audience: aud, nameID: "jdoe"}), "")) {
		t.Error("unsolicited token accepted")
	}
}

// The same token posted for a second attempt is refused (store-backed).
func TestADFSReplay(t *testing.T) {
	e, _, idp := adfsConnEnv(t, nil)
	raw := idp.wresult(t, adfsToken{id: "_replayed", audience: "urn:auth0:flow:corp-adfs", nameID: "jdoe"})
	c := e.client(t)
	q := startADFS(t, e, c)
	if !completed(t, e, c, postWResult(t, e, c, raw, q.Get("wctx"))) {
		t.Fatal("first post did not complete")
	}
	c = e.client(t)
	q = startADFS(t, e, c)
	if completed(t, e, c, postWResult(t, e, c, raw, q.Get("wctx"))) {
		t.Fatal("replayed token accepted")
	}
}

// user_id_attribute names the subject claim; should_trust_email_verified
// marks emails verified; entityId overrides wtrealm and the audience.
func TestADFSOptions(t *testing.T) {
	e, tn, idp := adfsConnEnv(t, map[string]any{"user_id_attribute": claimUPN, "should_trust_email_verified_connection": "always_set_emails_as_verified",
		"entityId": "urn:custom:rp"})
	c := e.client(t)
	q := startADFS(t, e, c)
	if q.Get("wtrealm") != "urn:custom:rp" {
		t.Fatalf("wtrealm %s", q.Get("wtrealm"))
	}
	raw := idp.wresult(t, adfsToken{audience: "urn:custom:rp", nameID: "ignored", attrs: map[string]string{claimUPN: "jdoe@corp.local", samlcore.ClaimEmail: "jdoe@corp.test"}})
	if !completed(t, e, c, postWResult(t, e, c, raw, q.Get("wctx"))) {
		t.Fatal("login did not complete")
	}
	u, err := e.st.Users().Get(t.Context(), tn.ID, "adfs|corp-adfs|jdoe@corp.local")
	if err != nil || !u.EmailVerified {
		t.Fatalf("user %+v %v", u, err)
	}
}

// Logout after an ADFS login signs out at ADFS (wa=wsignout1.0).
func TestADFSSignOut(t *testing.T) {
	e, _, idp := adfsConnEnv(t, nil)
	c := e.client(t)
	q := startADFS(t, e, c)
	if !completed(t, e, c, postWResult(t, e, c, idp.wresult(t, adfsToken{audience: "urn:auth0:flow:corp-adfs", nameID: "jdoe"}), q.Get("wctx"))) {
		t.Fatal("login did not complete")
	}
	resp, _ := fetch(t, c, e.base+"/v2/logout")
	loc, _ := resp.Location()
	if resp.StatusCode != http.StatusFound || loc == nil || loc.Host != "adfs.flow.test" || loc.Query().Get("wa") != "wsignout1.0" {
		t.Fatalf("logout: %d %v", resp.StatusCode, loc)
	}
}
