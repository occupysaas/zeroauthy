package samlcore

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/third_party/etree"
)

var w0 = time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)

func spec11() Assertion11Spec {
	return Assertion11Spec{ID: "_a11", Issuer: "urn:tenant.example.test", NameID: "auth0|123", Audience: "urn:sharepoint:portal",
		IssueInstant: w0, NotBefore: w0, NotOnOrAfter: w0.Add(8 * time.Hour), AuthnInstant: w0.Add(-time.Minute),
		Attributes: []Attribute{{Name: ClaimEmail, Values: []string{"jdoe@example.test"}}, {Name: ClaimGroups, Values: []string{"a", "b"}}, {Name: "plain", Values: []string{"x"}}}}
}

func TestBuildAssertion11Shape(t *testing.T) {
	a := roundTrip(t, BuildAssertion11(spec11()))
	if !inNS(a, NSAssertion11, "Assertion") || a.SelectAttrValue("MajorVersion", "") != "1" || a.SelectAttrValue("MinorVersion", "") != "1" ||
		a.SelectAttrValue("AssertionID", "") != "_a11" || a.SelectAttrValue("Issuer", "") != "urn:tenant.example.test" ||
		a.SelectAttrValue("IssueInstant", "") != "2026-11-22T10:00:00.000Z" {
		t.Fatalf("assertion attributes %v", a.Attr)
	}
	if got := tags(a.ChildElements()); strings.Join(got, ",") != "Conditions,AttributeStatement,AuthenticationStatement" {
		t.Fatalf("children %v", got)
	}
	cond := directChildren(a, NSAssertion11, "Conditions")[0]
	if cond.SelectAttrValue("NotBefore", "") != "2026-11-22T10:00:00.000Z" || cond.SelectAttrValue("NotOnOrAfter", "") != "2026-11-22T18:00:00.000Z" {
		t.Fatalf("conditions %v", cond.Attr)
	}
	aud := cond.FindElement("AudienceRestrictionCondition/Audience")
	if aud == nil || aud.Text() != "urn:sharepoint:portal" {
		t.Fatal("audience missing")
	}
	for _, path := range []string{"AttributeStatement/Subject", "AuthenticationStatement/Subject"} {
		subj := a.FindElement(path)
		nid := subj.FindElement("NameIdentifier")
		if nid == nil || nid.Text() != "auth0|123" || nid.SelectAttrValue("Format", "") != NameIDUnspecified {
			t.Fatalf("%s NameIdentifier", path)
		}
		if cm := subj.FindElement("SubjectConfirmation/ConfirmationMethod"); cm == nil || cm.Text() != ConfirmBearer11 {
			t.Fatalf("%s confirmation method", path)
		}
	}
	attrs := a.FindElements("AttributeStatement/Attribute")
	if len(attrs) != 3 {
		t.Fatalf("attributes %d", len(attrs))
	}
	if attrs[0].SelectAttrValue("AttributeNamespace", "") != "http://schemas.xmlsoap.org/ws/2005/05/identity/claims" ||
		attrs[0].SelectAttrValue("AttributeName", "") != "emailaddress" {
		t.Fatalf("namespace split %v", attrs[0].Attr)
	}
	if vals := attrs[1].FindElements("AttributeValue"); len(vals) != 2 || vals[1].Text() != "b" {
		t.Fatal("multi-valued attribute")
	}
	if attrs[2].SelectAttrValue("AttributeNamespace", "") != "" || attrs[2].SelectAttrValue("AttributeName", "") != "plain" {
		t.Fatalf("plain name %v", attrs[2].Attr)
	}
	st := a.FindElement("AuthenticationStatement")
	if st.SelectAttrValue("AuthenticationMethod", "") != AuthMethodPassword11 || st.SelectAttrValue("AuthenticationInstant", "") != "2026-11-22T09:59:00.000Z" {
		t.Fatalf("authentication statement %v", st.Attr)
	}
}

func signed11(t *testing.T, id testIdentity, s Assertion11Spec, alg, digest string) *etree.Element {
	t.Helper()
	el, err := Signer{Key: id.key, Cert: id.cert, Algorithm: alg, Digest: digest}.SignEnveloped11(BuildAssertion11(s))
	if err != nil {
		t.Fatal(err)
	}
	return el
}

func rstr(t *testing.T, token *etree.Element) []byte {
	t.Helper()
	raw, err := BuildRSTR("ctx", token)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(raw)
}

func TestSignAssertion11Verifies(t *testing.T) {
	idp := newIdentity(t, "idp", w0.Add(24*time.Hour))
	el := signed11(t, idp, spec11(), "", "")
	kids := el.ChildElements()
	if last := kids[len(kids)-1]; !inNS(last, NSDSig, "Signature") {
		t.Fatalf("signature must be the last child (SAML 1.1 schema), got %s", last.Tag)
	}
	tok, err := VerifyWSFedToken(rstr(t, el), Trust{Certs: idp.cert2()})
	if err != nil {
		t.Fatal(err)
	}
	if tok.Version != "1.1" || tok.ID != "_a11" || tok.Issuer != "urn:tenant.example.test" || tok.NameID != "auth0|123" ||
		strings.Join(tok.Audiences, ",") != "urn:sharepoint:portal" || !tok.Bearer ||
		strings.Join(tok.Attributes[ClaimGroups], ",") != "a,b" || tok.Attributes[ClaimEmail][0] != "jdoe@example.test" || tok.Attributes["plain"][0] != "x" ||
		!tok.NotOnOrAfter.Equal(w0.Add(8*time.Hour)) {
		t.Fatalf("token %+v", tok)
	}
	// By thumbprint, as ADFS connections trust certificates.
	s1, _ := Thumbprints(idp.cert)
	if _, err := VerifyWSFedToken(rstr(t, el), Trust{Thumbprints: []string{colons(s1)}}); err != nil {
		t.Fatalf("thumbprint trust: %v", err)
	}
	other := newIdentity(t, "other", w0.Add(24*time.Hour))
	if _, err := VerifyWSFedToken(rstr(t, el), Trust{Certs: other.cert2()}); !errors.Is(err, ErrSignature) {
		t.Fatalf("untrusted certificate: %v", err)
	}
	tampered := strings.Replace(string(rstr(t, el)), "jdoe@example.test", "admin@example.test", 1)
	if _, err := VerifyWSFedToken([]byte(tampered), Trust{Certs: idp.cert2()}); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered attribute: %v", err)
	}
	weak := signed11(t, idp, spec11(), AlgRSASHA1, DigestSHA1)
	if _, err := VerifyWSFedToken(rstr(t, weak), Trust{Certs: idp.cert2()}); !errors.Is(err, ErrWeakAlg) {
		t.Fatalf("SHA-1 without opt-in: %v", err)
	}
	if _, err := VerifyWSFedToken(rstr(t, weak), Trust{Certs: idp.cert2(), AllowSHA1: true}); err != nil {
		t.Fatalf("SHA-1 opted in: %v", err)
	}
}

func (id testIdentity) cert2() []*x509.Certificate { return []*x509.Certificate{id.cert} }

func TestBuildRSTR(t *testing.T) {
	idp := newIdentity(t, "idp", w0.Add(24*time.Hour))
	raw, err := BuildRSTR(`rm=0&id=<"x">`, signed11(t, idp, spec11(), "", ""))
	if err != nil {
		t.Fatal(err)
	}
	root := mustRoot(t, raw)
	if !inNS(root, NSTrust2005, "RequestSecurityTokenResponse") || root.SelectAttrValue("Context", "") != `rm=0&id=<"x">` {
		t.Fatalf("RSTR root %s %v", root.Tag, root.Attr)
	}
	tok := directChildren(root, NSTrust2005, "RequestedSecurityToken")
	if len(tok) != 1 || len(directChildren(tok[0], NSAssertion11, "Assertion")) != 1 {
		t.Fatal("RequestedSecurityToken must hold the assertion")
	}
	if raw, _ := BuildRSTR("", signed11(t, idp, spec11(), "", "")); strings.Contains(raw, "Context=") {
		t.Fatal("empty wctx must leave Context out")
	}
}

func TestVerifyWSFedTokenSAML2AndCollection(t *testing.T) {
	idp := newIdentity(t, "idp", w0.Add(24*time.Hour))
	a2, err := Signer{Key: idp.key, Cert: idp.cert}.SignEnveloped(mustRoot(t, assertionXML("_a2", "jdoe")))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := VerifyWSFedToken(rstr(t, a2), Trust{Certs: idp.cert2()})
	if err != nil || tok.Version != "2.0" || tok.NameID != "jdoe" || tok.Audiences[0] != "urn:sp" {
		t.Fatalf("SAML 2.0 token %+v %v", tok, err)
	}
	// WS-Trust 1.3 RSTR collection, as ADFS sends.
	inner := serialize(t, signed11(t, idp, spec11(), "", ""))
	coll := `<trust:RequestSecurityTokenResponseCollection xmlns:trust="` + NSTrust13 + `"><trust:RequestSecurityTokenResponse>` +
		`<trust:RequestedSecurityToken>` + stripDecl(inner) + `</trust:RequestedSecurityToken></trust:RequestSecurityTokenResponse></trust:RequestSecurityTokenResponseCollection>`
	if tok, err := VerifyWSFedToken([]byte(coll), Trust{Certs: idp.cert2()}); err != nil || tok.Version != "1.1" {
		t.Fatalf("collection %+v %v", tok, err)
	}
}

func stripDecl(s string) string {
	if i := strings.Index(s, "?>"); strings.HasPrefix(s, "<?xml") && i > 0 {
		return s[i+2:]
	}
	return s
}

func TestVerifyWSFedTokenWrapping(t *testing.T) {
	idp := newIdentity(t, "idp", w0.Add(24*time.Hour))
	good := stripDecl(serialize(t, signed11(t, idp, spec11(), "", "")))
	evilSpec := spec11()
	evilSpec.ID, evilSpec.NameID = "_evil", "admin"
	unsigned := stripDecl(serialize(t, BuildAssertion11(evilSpec)))
	wrap := func(inner string) []byte {
		return []byte(`<t:RequestSecurityTokenResponse xmlns:t="` + NSTrust2005 + `"><t:RequestedSecurityToken>` + inner + `</t:RequestedSecurityToken></t:RequestSecurityTokenResponse>`)
	}
	cases := map[string][]byte{
		"unsigned":          wrap(unsigned),
		"two tokens":        wrap(good + unsigned),
		"extra outside":     []byte(`<t:RequestSecurityTokenResponse xmlns:t="` + NSTrust2005 + `"><t:Extra>` + unsigned + `</t:Extra><t:RequestedSecurityToken>` + good + `</t:RequestedSecurityToken></t:RequestSecurityTokenResponse>`),
		"two RSTs":          []byte(`<t:RequestSecurityTokenResponse xmlns:t="` + NSTrust2005 + `"><t:RequestedSecurityToken>` + good + `</t:RequestedSecurityToken><t:RequestedSecurityToken>` + unsigned + `</t:RequestedSecurityToken></t:RequestSecurityTokenResponse>`),
		"nested in token":   wrap(strings.Replace(good, "</saml:Conditions>", "</saml:Conditions><saml:Advice>"+unsigned+"</saml:Advice>", 1)),
		"wrong root":        []byte(`<x xmlns="urn:x">` + good + `</x>`),
		"bare assertion":    []byte(good),
		"signed then moved": wrap(strings.Replace(good, `AssertionID="_a11"`, `AssertionID="_moved"`, 1)),
		"comment in nameid": wrap(strings.Replace(good, "auth0|123", "auth0|<!---->123", 1)),
	}
	for name, raw := range cases {
		tok, err := VerifyWSFedToken(raw, Trust{Certs: idp.cert2()})
		if err == nil && (name != "comment in nameid") {
			t.Errorf("%s accepted: %+v", name, tok)
		}
		if name == "comment in nameid" && err == nil && tok.NameID != "auth0|123" {
			t.Errorf("comment changed the NameID to %q", tok.NameID)
		}
	}
}

func TestWSFedTokenCheck(t *testing.T) {
	tok := &WSFedToken{Version: "1.1", Bearer: true, AudienceRestrictions: [][]string{{"urn:auth0:t:c"}}, NotBefore: w0, NotOnOrAfter: w0.Add(time.Hour)}
	ok := WSFedExpect{Now: w0.Add(time.Minute), Skew: 2 * time.Minute, Audience: "urn:auth0:t:c"}
	if err := tok.Check(ok); err != nil {
		t.Fatal(err)
	}
	for name, e := range map[string]WSFedExpect{
		"wrong audience": {Now: ok.Now, Skew: ok.Skew, Audience: "urn:other"},
		"expired":        {Now: w0.Add(time.Hour + 3*time.Minute), Skew: ok.Skew, Audience: ok.Audience},
		"not yet valid":  {Now: w0.Add(-3 * time.Minute), Skew: ok.Skew, Audience: ok.Audience},
	} {
		if err := tok.Check(e); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := (&WSFedToken{Bearer: true, AudienceRestrictions: [][]string{{"urn:auth0:t:c"}}}).Check(ok); err == nil {
		t.Error("token without NotOnOrAfter accepted")
	}
	if err := (&WSFedToken{AudienceRestrictions: [][]string{{"urn:auth0:t:c"}}, NotOnOrAfter: w0.Add(time.Hour)}).Check(ok); err == nil {
		t.Error("token without bearer confirmation accepted")
	}
	if err := (&WSFedToken{Bearer: true, NotOnOrAfter: w0.Add(time.Hour)}).Check(ok); err == nil {
		t.Error("token without audience restriction accepted")
	}
}
