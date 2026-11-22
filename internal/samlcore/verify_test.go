package samlcore

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"
)

// signedAssertion returns a serialized assertion signed by id.
func signedAssertion(t *testing.T, signer testIdentity, id, nameID string) string {
	t.Helper()
	signed, err := Signer{Key: signer.key, Cert: signer.cert}.SignEnveloped(mustRoot(t, assertionXML(id, nameID)))
	if err != nil {
		t.Fatal(err)
	}
	s := serialize(t, signed)
	return s[strings.Index(s, "<saml:Assertion"):]
}

func verifyRaw(t *testing.T, raw string, trust Trust) (*VerifiedResponse, error) {
	t.Helper()
	doc, err := Parse([]byte(raw))
	if err != nil {
		return nil, err
	}
	return VerifyResponse(doc, trust, nil)
}

// TestVerifyWrappingCorpus is Plan 37a Review Focus 1: every XML signature
// wrapping shape is refused, and accepted responses expose only signed data.
func TestVerifyWrappingCorpus(t *testing.T) {
	idp := newIdentity(t, "idp", time.Now().Add(time.Hour))
	trust := Trust{Certs: []*x509.Certificate{idp.cert}}
	signedA := signedAssertion(t, idp, "_a", "alice@example.test")
	evil := func(id string) string { return assertionXML(id, "admin@example.test") }

	got, err := verifyRaw(t, responseXML("_r", signedA), trust)
	if err != nil {
		t.Fatalf("valid response refused: %v", err)
	}
	if !got.AssertionSigned || got.ResponseSigned || NameID(got.Assertion) != "alice@example.test" {
		t.Fatalf("valid response: %+v %q", got, NameID(got.Assertion))
	}

	attacks := map[string]string{
		"moved assertion into extensions": responseXML("_r", evil("_evil")+`<samlp:Extensions>`+signedA+`</samlp:Extensions>`),
		"evil assertion before signed":    responseXML("_r", evil("_evil")+signedA),
		"duplicate ID":                    responseXML("_r", signedA+evil("_a")),
		"duplicate ID, evil first":        responseXML("_r", evil("_a")+signedA),
		"signed assertion hidden in signature object": responseXML("_r", strings.Replace(evil("_evil"), "</saml:Issuer>",
			"</saml:Issuer>"+signatureOf(signedA)[:len(signatureOf(signedA))-len("</ds:Signature>")]+`<ds:Object>`+signedA+`</ds:Object></ds:Signature>`, 1)),
		"modified signed content":    responseXML("_r", strings.Replace(signedA, "alice@example.test", "admin@example.test", 1)),
		"signature moved into child": responseXML("_r", moveSignatureIntoSubject(signedA)),
		"no signature at all":        responseXML("_r", assertionXML("_u", "admin@example.test")),
		"signature by untrusted key": responseXML("_r", signedAssertion(t, newIdentity(t, "evil", time.Now().Add(time.Hour)), "_a", "admin@example.test")),
		"assertion outside response": responseXML("_r", "") + "",
	}
	attacks["assertion outside response"] = `<wrap xmlns:samlp="` + nsP + `">` + responseXML("_r", "") + signedA + `</wrap>`
	for name, raw := range attacks {
		t.Run(name, func(t *testing.T) {
			if v, err := verifyRaw(t, raw, trust); err == nil {
				t.Fatalf("accepted; NameID %q", NameID(v.Assertion))
			}
		})
	}

	// NameID comment injection: the signature stays valid (comments are not
	// canonicalized), but the value read is the whole signed text.
	injected := signedAssertion(t, idp, "_c", "admin@example.test.evil.example")
	injected = strings.Replace(injected, "admin@example.test", "admin@example.test<!---->", 1)
	v, err := verifyRaw(t, responseXML("_r", injected), trust)
	if err != nil {
		t.Fatalf("comment-injected response: %v", err)
	}
	if got := NameID(v.Assertion); got != "admin@example.test.evil.example" {
		t.Fatalf("comment injection truncated NameID to %q", got)
	}
	if got := v.Assertion.FindElement("./Subject/NameID").Text(); got != "admin@example.test.evil.example" {
		t.Fatalf("verified element still splits text: %q", got)
	}
}

func TestVerifyResponseSignedOnly(t *testing.T) {
	idp := newIdentity(t, "idp", time.Now().Add(time.Hour))
	trust := Trust{Certs: []*x509.Certificate{idp.cert}}
	resp, err := Signer{Key: idp.key, Cert: idp.cert}.SignEnveloped(mustRoot(t, responseXML("_r", assertionXML("_a", "bob@example.test"))))
	if err != nil {
		t.Fatal(err)
	}
	raw := serialize(t, resp)
	v, err := verifyRaw(t, raw, trust)
	if err != nil {
		t.Fatal(err)
	}
	if !v.ResponseSigned || v.AssertionSigned || NameID(v.Assertion) != "bob@example.test" {
		t.Fatalf("response-signed: %+v", v)
	}
	// A second, unsigned assertion appended after signing is refused.
	tampered := strings.Replace(raw, "</samlp:Response>", assertionXML("_b", "admin@example.test")+"</samlp:Response>", 1)
	if _, err := verifyRaw(t, tampered, trust); err == nil {
		t.Fatal("appended assertion accepted")
	}
}

func signatureOf(signed string) string {
	i := strings.Index(signed, "<ds:Signature")
	j := strings.Index(signed, "</ds:Signature>") + len("</ds:Signature>")
	return signed[i:j]
}

func moveSignatureIntoSubject(signed string) string {
	sig := signatureOf(signed)
	out := strings.Replace(signed, sig, "", 1)
	return strings.Replace(out, "<saml:Subject>", "<saml:Subject>"+sig, 1)
}

// A signed Response containing a signed Assertion ("sign both") verifies;
// a nested signature that claims the outer element is still refused.
func TestVerifyResponseBothSigned(t *testing.T) {
	idp := newIdentity(t, "idp", time.Now().Add(time.Hour))
	trust := Trust{Certs: []*x509.Certificate{idp.cert}}
	signer := Signer{Key: idp.key, Cert: idp.cert}
	resp, err := signer.SignEnveloped(mustRoot(t, responseXML("_r", signedAssertion(t, idp, "_a", "both@example.test"))))
	if err != nil {
		t.Fatal(err)
	}
	v, err := verifyRaw(t, serialize(t, resp), trust)
	if err != nil || !v.ResponseSigned || !v.AssertionSigned || NameID(v.Assertion) != "both@example.test" {
		t.Fatalf("sign both: %+v %v", v, err)
	}
	nested := mustRoot(t, strings.Replace(assertionXML("_a", "x"), "<saml:Subject>", "<saml:Subject>"+sigXML("#_a"), 1))
	nested.FindElement("./Issuer").Parent().InsertChildAt(1, mustRoot(t, sigXML("#_a")))
	if _, err := VerifyEnveloped(nested, trust); !errors.Is(err, ErrStructure) {
		t.Fatalf("nested signature claiming the element: %v", err)
	}
}
