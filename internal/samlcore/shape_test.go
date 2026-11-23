package samlcore

import (
	"errors"
	"strings"
	"testing"
)

const dsNS = `xmlns:ds="http://www.w3.org/2000/09/xmldsig#"`

// sigXML is a structurally complete (unsigned) ds:Signature.
func sigXML(uri string, transforms ...string) string {
	if transforms == nil {
		transforms = []string{"http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"}
	}
	var tr strings.Builder
	for _, t := range transforms {
		tr.WriteString(`<ds:Transform Algorithm="` + t + `"/>`)
	}
	return `<ds:Signature ` + dsNS + `><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>` +
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="` + uri + `"><ds:Transforms>` + tr.String() +
		`</ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AA==</ds:DigestValue></ds:Reference></ds:SignedInfo>` +
		`<ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>`
}

func TestMessageShapeRules(t *testing.T) {
	for name, tc := range map[string]struct {
		raw string
		ok  bool
	}{
		"one assertion":          {responseXML("_r", assertionXML("_a", "x")), true},
		"two assertions":         {responseXML("_r", assertionXML("_a", "x")+assertionXML("_b", "y")), false},
		"nested assertion":       {responseXML("_r", strings.Replace(assertionXML("_a", "x"), "</saml:Subject>", "</saml:Subject>"+assertionXML("_b", "y"), 1)), false},
		"assertion not direct":   {responseXML("_r", `<samlp:Extensions>`+assertionXML("_a", "x")+`</samlp:Extensions>`), false},
		"duplicate IDs":          {responseXML("_a", assertionXML("_a", "x")), false},
		"signature in subject":   {responseXML("_r", strings.Replace(assertionXML("_a", "x"), "<saml:Subject>", "<saml:Subject>"+sigXML("#_a"), 1)), false},
		"signature on assertion": {responseXML("_r", strings.Replace(assertionXML("_a", "x"), "</saml:Issuer>", "</saml:Issuer>"+sigXML("#_a"), 1)), true},
		"not a response":         {assertionXML("_a", "x"), false},
	} {
		t.Run(name, func(t *testing.T) {
			err := checkMessageShape(mustRoot(t, tc.raw))
			if tc.ok != (err == nil) {
				t.Fatalf("ok=%v err=%v", tc.ok, err)
			}
		})
	}
}

func TestSignatureShapeRules(t *testing.T) {
	envOnly := []string{"http://www.w3.org/2000/09/xmldsig#enveloped-signature"}
	for name, tc := range map[string]struct {
		sig string
		ok  bool
	}{
		"reference to own ID":         {sigXML("#_a"), true},
		"empty reference (whole doc)": {sigXML(""), false},
		"reference to another ID":     {sigXML("#_other"), false},
		"xpath transform":             {sigXML("#_a", "http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/TR/1999/REC-xpath-19991116"), false},
		"not enveloped":               {sigXML("#_a", "http://www.w3.org/2001/10/xml-exc-c14n#"), false},
		"enveloped only":              {sigXML("#_a", envOnly...), true},
		"two references":              {strings.Replace(sigXML("#_a"), "</ds:SignedInfo>", `<ds:Reference URI="#_a"/></ds:SignedInfo>`, 1), false},
		"inclusive c14n method":       {strings.Replace(sigXML("#_a"), `<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`, `<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>`, 1), false},
	} {
		t.Run(name, func(t *testing.T) {
			el := mustRoot(t, strings.Replace(assertionXML("_a", "x"), "</saml:Issuer>", "</saml:Issuer>"+tc.sig, 1))
			err := checkSignatureShape(el, directChildren(el, NSDSig, "Signature")[0], Trust{}, "ID")
			if tc.ok != (err == nil) {
				t.Fatalf("ok=%v err=%v", tc.ok, err)
			}
		})
	}
	// SHA-1 signature or digest needs AllowSHA1.
	for _, sha1 := range []string{
		strings.Replace(sigXML("#_a"), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "http://www.w3.org/2000/09/xmldsig#rsa-sha1", 1),
		strings.Replace(sigXML("#_a"), "http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2000/09/xmldsig#sha1", 1),
	} {
		el := mustRoot(t, strings.Replace(assertionXML("_a", "x"), "</saml:Issuer>", "</saml:Issuer>"+sha1, 1))
		sig := directChildren(el, NSDSig, "Signature")[0]
		if err := checkSignatureShape(el, sig, Trust{}, "ID"); !errors.Is(err, ErrWeakAlg) {
			t.Fatalf("SHA-1 without opt-in: %v", err)
		}
		if err := checkSignatureShape(el, sig, Trust{AllowSHA1: true}, "ID"); err != nil {
			t.Fatalf("SHA-1 with opt-in: %v", err)
		}
	}
	// A signature that is not the element's direct child is refused before
	// any cryptography.
	nested := mustRoot(t, strings.Replace(assertionXML("_a", "x"), "<saml:Subject>", "<saml:Subject>"+sigXML("#_a"), 1))
	if _, err := VerifyEnveloped(nested, Trust{}); !errors.Is(err, ErrStructure) {
		t.Fatalf("nested signature: %v", err)
	}
}
