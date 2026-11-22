package samlcore

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

func TestAuthnRequestTemplate(t *testing.T) {
	r := AuthnRequest{ID: "_req1", IssueInstant: t0, Issuer: `urn:auth0:acme:corp&"x"`, Destination: "https://idp.example.test/sso",
		ACSURL: "https://acme.example.test/login/callback?connection=corp", ProtocolBinding: BindingPOST}
	el, err := BuildAuthnRequest(r, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseAuthnRequest(roundTrip(t, el))
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "_req1" || got.Issuer != r.Issuer || got.ACSURL != r.ACSURL || got.Destination != r.Destination || got.ProtocolBinding != BindingPOST || !got.IssueInstant.Equal(t0) {
		t.Fatalf("default template round trip: %+v", got)
	}
	custom := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" @@AssertServiceURLAndDestination@@ ID="@@ID@@" IssueInstant="@@IssueInstant@@" ProtocolBinding="@@ProtocolBinding@@" Version="2.0" ForceAuthn="true"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">@@Issuer@@</saml:Issuer></samlp:AuthnRequest>`
	el, err = BuildAuthnRequest(r, custom)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := ParseAuthnRequest(roundTrip(t, el)); !got.ForceAuthn || got.ACSURL != r.ACSURL {
		t.Fatalf("custom template: %+v", got)
	}
	for name, bad := range map[string]string{
		"not an AuthnRequest": `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="@@ID@@"/>`,
		"no ID variable":      `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="fixed" Version="2.0"/>`,
		"malformed":           `<samlp:AuthnRequest`,
		"doctype":             `<!DOCTYPE x><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="@@ID@@"/>`,
	} {
		if err := ValidateRequestTemplate(bad); err == nil {
			t.Errorf("%s template accepted", name)
		}
	}
	if err := ValidateRequestTemplate(custom); err != nil {
		t.Fatal(err)
	}
}

func TestAssertionBuildParseCheck(t *testing.T) {
	idp := newIdentity(t, "idp", time.Now().Add(time.Hour))
	spec := AssertionSpec{ID: "_as1", IssueInstant: t0, Issuer: "urn:acme.example.test", NameID: "auth0|alice", NameIDFormat: NameIDUnspecified,
		Audience: "urn:sp", Recipient: "https://sp.example.test/acs", InResponseTo: "_req1", NotBefore: t0, NotOnOrAfter: t0.Add(time.Hour),
		AuthnInstant: t0, SessionIndex: "sess_1", AuthnContextClassRef: AuthnContextUnspecified, TypedAttributes: true, IncludeNameFormat: true,
		Attributes: []Attribute{{Name: ClaimEmail, Values: []string{"alice@example.test"}}, {Name: ClaimGroups, Values: []string{"a", "b"}}}}
	signed, err := Signer{Key: idp.key, Cert: idp.cert}.SignEnveloped(BuildAssertion(spec))
	if err != nil {
		t.Fatal(err)
	}
	resp := BuildResponse(ResponseSpec{ID: "_r1", InResponseTo: "_req1", Destination: spec.Recipient, Issuer: spec.Issuer, IssueInstant: t0, StatusCode: StatusSuccess}, signed)
	if s := serialize(t, resp); !strings.Contains(s, `xsi:type="xs:string"`) || !strings.Contains(s, `NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"`) {
		t.Fatalf("typed attributes / name format missing: %s", s)
	}
	doc, err := Parse([]byte(serialize(t, resp)))
	if err != nil {
		t.Fatal(err)
	}
	v, err := VerifyResponse(doc, Trust{Certs: []*x509.Certificate{idp.cert}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	env, err := ParseResponseEnvelope(v.Response)
	if err != nil || env.StatusCode != StatusSuccess || env.InResponseTo != "_req1" || env.Destination != spec.Recipient {
		t.Fatalf("envelope %+v %v", env, err)
	}
	a, err := ParseAssertion(v.Assertion)
	if err != nil {
		t.Fatal(err)
	}
	if a.NameID != "auth0|alice" || a.SessionIndex != "sess_1" || a.Issuer != spec.Issuer || strings.Join(a.Attributes[ClaimGroups], ",") != "a,b" || a.Attributes[ClaimEmail][0] != "alice@example.test" {
		t.Fatalf("parsed assertion %+v", a)
	}
	ok := Expect{Now: t0.Add(time.Minute), Skew: 2 * time.Minute, Audience: "urn:sp", Recipient: spec.Recipient, InResponseTo: "_req1"}
	if err := a.Check(ok); err != nil {
		t.Fatalf("valid assertion: %v", err)
	}
	for name, e := range map[string]Expect{
		"expired":          {Now: t0.Add(time.Hour + 3*time.Minute), Skew: 2 * time.Minute, Audience: "urn:sp", Recipient: spec.Recipient, InResponseTo: "_req1"},
		"not yet valid":    {Now: t0.Add(-3 * time.Minute), Skew: 2 * time.Minute, Audience: "urn:sp", Recipient: spec.Recipient, InResponseTo: "_req1"},
		"wrong audience":   {Now: ok.Now, Skew: ok.Skew, Audience: "urn:other", Recipient: spec.Recipient, InResponseTo: "_req1"},
		"wrong recipient":  {Now: ok.Now, Skew: ok.Skew, Audience: "urn:sp", Recipient: "https://evil.example.test/acs", InResponseTo: "_req1"},
		"other request":    {Now: ok.Now, Skew: ok.Skew, Audience: "urn:sp", Recipient: spec.Recipient, InResponseTo: "_req2"},
		"unsolicited here": {Now: ok.Now, Skew: ok.Skew, Audience: "urn:sp", Recipient: spec.Recipient},
	} {
		if err := a.Check(e); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Within the 2-minute skew either side.
	for _, at := range []time.Time{t0.Add(-time.Minute), t0.Add(time.Hour + time.Minute)} {
		e := ok
		e.Now = at
		if err := a.Check(e); err != nil {
			t.Errorf("skew at %v: %v", at, err)
		}
	}
	// Every AudienceRestriction must name the SP (SAML Core §2.5.1.4).
	narrowed := BuildAssertion(spec)
	cond := narrowed.FindElement("./Conditions")
	extra := cond.CreateElement("saml:AudienceRestriction")
	extra.CreateElement("saml:Audience").SetText("urn:other")
	na, err := ParseAssertion(roundTrip(t, narrowed))
	if err != nil {
		t.Fatal(err)
	}
	if err := na.Check(ok); err == nil {
		t.Fatal("an AudienceRestriction without the SP was satisfied by another")
	}
	extra.CreateElement("saml:Audience").SetText("urn:sp")
	if na, _ = ParseAssertion(roundTrip(t, narrowed)); na.Check(ok) != nil {
		t.Fatal("two restrictions both naming the SP refused")
	}
	// An unsolicited assertion is accepted only when allowed.
	spec.InResponseTo = ""
	u, _ := ParseAssertion(roundTrip(t, BuildAssertion(spec)))
	if err := u.Check(Expect{Now: ok.Now, Skew: ok.Skew, Audience: "urn:sp", Recipient: spec.Recipient, AllowUnsolicited: true}); err != nil {
		t.Fatalf("unsolicited allowed: %v", err)
	}
	if err := u.Check(Expect{Now: ok.Now, Skew: ok.Skew, Audience: "urn:sp", Recipient: spec.Recipient, InResponseTo: "_req1"}); err == nil {
		t.Fatal("unsolicited assertion answered a request")
	}
}

func TestLogoutMessages(t *testing.T) {
	lr, err := ParseLogoutRequest(roundTrip(t, BuildLogoutRequest(LogoutRequest{ID: "_l1", IssueInstant: t0, Issuer: "urn:sp", Destination: "https://idp/slo",
		NameID: "auth0|alice", NameIDFormat: NameIDUnspecified, SessionIndex: "sess_1"})))
	if err != nil || lr.ID != "_l1" || lr.NameID != "auth0|alice" || lr.SessionIndex != "sess_1" || lr.Issuer != "urn:sp" {
		t.Fatalf("logout request %+v %v", lr, err)
	}
	resp, err := ParseLogoutResponse(roundTrip(t, BuildLogoutResponse(LogoutResponse{ID: "_l2", InResponseTo: "_l1", IssueInstant: t0, Issuer: "urn:idp", Destination: "https://sp/slo", StatusCode: StatusSuccess})))
	if err != nil || resp.InResponseTo != "_l1" || resp.StatusCode != StatusSuccess {
		t.Fatalf("logout response %+v %v", resp, err)
	}
	if _, err := ParseLogoutRequest(mustRoot(t, assertionXML("_a", "x"))); !errors.Is(err, ErrStructure) {
		t.Fatalf("wrong root: %v", err)
	}
}

func TestMetadataRoundTrip(t *testing.T) {
	idp := newIdentity(t, "idp", time.Now().Add(time.Hour))
	next := newIdentity(t, "idp-next", time.Now().Add(time.Hour))
	raw := serialize(t, BuildMetadata(EntityDescriptor{EntityID: "urn:acme.example.test", IdP: &IdPDescriptor{
		SigningCerts: []*x509.Certificate{idp.cert, next.cert}, NameIDFormats: []string{NameIDUnspecified, NameIDEmail},
		SSO: []Endpoint{{Binding: BindingRedirect, Location: "https://acme/samlp/c1"}, {Binding: BindingPOST, Location: "https://acme/samlp/c1"}},
		SLO: []Endpoint{{Binding: BindingRedirect, Location: "https://acme/samlp/c1/logout"}}}}))
	md, err := ParseMetadata([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if md.EntityID != "urn:acme.example.test" || md.IdP == nil || len(md.IdP.SigningCerts) != 2 || md.IdP.SSOLocation(BindingPOST) != "https://acme/samlp/c1" || md.IdP.SLOLocation(BindingRedirect) == "" {
		t.Fatalf("IdP metadata %+v", md.IdP)
	}
	sp := newIdentity(t, "sp", time.Now().Add(time.Hour))
	raw = serialize(t, BuildMetadata(EntityDescriptor{EntityID: "urn:auth0:acme:corp", SP: &SPDescriptor{SigningCerts: []*x509.Certificate{sp.cert},
		EncryptionCerts: []*x509.Certificate{sp.cert}, AuthnRequestsSigned: true, WantAssertionsSigned: true,
		ACS: []Endpoint{{Binding: BindingPOST, Location: "https://acme/login/callback?connection=corp"}}}}))
	md, err = ParseMetadata([]byte(raw))
	if err != nil || md.SP == nil || !md.SP.AuthnRequestsSigned || len(md.SP.EncryptionCerts) != 1 || md.SP.ACS[0].Location != "https://acme/login/callback?connection=corp" {
		t.Fatalf("SP metadata %+v %v", md.SP, err)
	}
	two := `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">` + strings.TrimPrefix(raw, `<?xml version="1.0" encoding="UTF-8"?>`) + strings.TrimPrefix(raw, `<?xml version="1.0" encoding="UTF-8"?>`) + `</md:EntitiesDescriptor>`
	if _, err := ParseMetadata([]byte(two)); err == nil {
		t.Fatal("ambiguous EntitiesDescriptor accepted")
	}
}
