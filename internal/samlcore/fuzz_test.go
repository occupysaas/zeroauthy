package samlcore

import "testing"

func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		`<a/>`, `<?xml version="1.0"?><a b="c"><d>e</d></a>`,
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_1"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_2"/></samlp:Response>`,
		`<!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>`, `<a><!-- c --><b/></a>`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		doc, err := Parse(raw)
		if err != nil {
			return
		}
		if doc.Root() == nil {
			t.Fatal("parsed document without a root")
		}
		_, _ = Canonicalize(doc.Root(), false)
		_, _ = Canonicalize(doc.Root(), true)
	})
}

// FuzzVerifyWSFedToken feeds arbitrary wresult documents to the WS-Fed
// token verifier (Plan 37b): it must never panic and never accept a token
// without a trusted signature.
func FuzzVerifyWSFedToken(f *testing.F) {
	for _, seed := range []string{
		`<t:RequestSecurityTokenResponse xmlns:t="` + NSTrust2005 + `"><t:RequestedSecurityToken><saml:Assertion xmlns:saml="` + NSAssertion11 + `" MajorVersion="1" AssertionID="_1"/></t:RequestedSecurityToken></t:RequestSecurityTokenResponse>`,
		`<trust:RequestSecurityTokenResponseCollection xmlns:trust="` + NSTrust13 + `"><trust:RequestSecurityTokenResponse><trust:RequestedSecurityToken><saml:Assertion xmlns:saml="` + NSAssertion + `" ID="_2"/></trust:RequestedSecurityToken></trust:RequestSecurityTokenResponse></trust:RequestSecurityTokenResponseCollection>`,
		`<a/>`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if tok, err := VerifyWSFedToken(raw, Trust{}); err == nil {
			t.Fatalf("accepted a token with no trust anchors: %+v", tok)
		}
	})
}
