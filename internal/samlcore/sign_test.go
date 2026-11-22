package samlcore

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

func TestSignVerifyRoundTrips(t *testing.T) {
	idp := newIdentity(t, "idp", time.Now().Add(time.Hour))
	for _, alg := range []struct{ sig, digest string }{
		{AlgRSASHA256, DigestSHA256}, {AlgRSASHA384, DigestSHA384}, {AlgRSASHA512, DigestSHA512}, {AlgRSASHA1, DigestSHA1},
	} {
		t.Run(alg.sig+"/"+alg.digest, func(t *testing.T) {
			doc, err := Parse([]byte(assertionXML("_a1", "alice@example.test")))
			if err != nil {
				t.Fatal(err)
			}
			signed, err := Signer{Key: idp.key, Cert: idp.cert, Algorithm: alg.sig, Digest: alg.digest}.SignEnveloped(doc.Root())
			if err != nil {
				t.Fatal(err)
			}
			// SAML schema order: the Signature follows the Issuer.
			kids := signed.ChildElements()
			if len(kids) < 2 || kids[0].Tag != "Issuer" || kids[1].Tag != "Signature" {
				t.Fatalf("signature position: %v", tags(kids))
			}
			sha1 := alg.sig == AlgRSASHA1 || alg.digest == DigestSHA1
			trust := Trust{Certs: []*x509.Certificate{idp.cert}, AllowSHA1: sha1}
			verified, err := VerifyEnveloped(roundTrip(t, signed), trust)
			if err != nil {
				t.Fatal(err)
			}
			if got := verified.FindElement("./Subject/NameID").Text(); got != "alice@example.test" {
				t.Fatalf("verified NameID %q", got)
			}
			if sha1 {
				trust.AllowSHA1 = false
				if _, err := VerifyEnveloped(roundTrip(t, signed), trust); err == nil {
					t.Fatal("SHA-1 accepted without AllowSHA1")
				}
			}
		})
	}
	if _, err := (Signer{Key: idp.key, Cert: idp.cert, Algorithm: "rsa-md5", Digest: DigestSHA256}).SignEnveloped(mustRoot(t, assertionXML("_x", "x"))); err == nil {
		t.Fatal("unknown algorithm accepted")
	}
}

func TestThumbprints(t *testing.T) {
	idp := newIdentity(t, "idp", time.Now().Add(time.Hour))
	s1, s384 := Thumbprints(idp.cert)
	if len(s1) != 40 || len(s384) != 96 || strings.ToLower(s1) != s1 {
		t.Fatalf("thumbprint shapes %q %q", s1, s384)
	}
	signed, err := Signer{Key: idp.key, Cert: idp.cert}.SignEnveloped(mustRoot(t, assertionXML("_t", "t@example.test")))
	if err != nil {
		t.Fatal(err)
	}
	for name, trust := range map[string]Trust{
		"sha1 thumbprint":        {Thumbprints: []string{strings.ToUpper(s1)}},
		"sha1 with colons":       {Thumbprints: []string{colons(s1)}},
		"sha384 thumbprint":      {Thumbprints384: []string{s384}},
	} {
		if _, err := VerifyEnveloped(roundTrip(t, signed), trust); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	other := newIdentity(t, "other", time.Now().Add(time.Hour))
	o1, o384 := Thumbprints(other.cert)
	if _, err := VerifyEnveloped(roundTrip(t, signed), Trust{Thumbprints: []string{o1}, Thumbprints384: []string{o384}}); err == nil {
		t.Fatal("unmatched thumbprint trusted")
	}
}

// An expired pinned certificate still verifies: SAML metadata trust anchors
// are honoured regardless of their validity dates (D-0130 ruling).
func TestExpiredTrustAnchor(t *testing.T) {
	idp := newIdentity(t, "idp", time.Now().Add(-24*time.Hour))
	signed, err := Signer{Key: idp.key, Cert: idp.cert}.SignEnveloped(mustRoot(t, assertionXML("_e", "e@example.test")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEnveloped(roundTrip(t, signed), Trust{Certs: []*x509.Certificate{idp.cert}}); err != nil {
		t.Fatal(err)
	}
}
