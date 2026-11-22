package samlcore

import (
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/third_party/etree"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// testIdentity is a throwaway RSA key and self-signed certificate.
type testIdentity struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

func newIdentity(t testing.TB, cn string, notAfter time.Time) testIdentity {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: notAfter.Add(-48 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testIdentity{key: key, cert: cert}
}

const (
	nsP = `urn:oasis:names:tc:SAML:2.0:protocol`
	nsA = `urn:oasis:names:tc:SAML:2.0:assertion`
)

func assertionXML(id, nameID string) string {
	return `<saml:Assertion xmlns:saml="` + nsA + `" ID="` + id + `" Version="2.0" IssueInstant="2026-11-21T00:00:00Z">` +
		`<saml:Issuer>https://idp.example.test</saml:Issuer>` +
		`<saml:Subject><saml:NameID>` + nameID + `</saml:NameID></saml:Subject>` +
		`<saml:Conditions><saml:AudienceRestriction><saml:Audience>urn:sp</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
		`</saml:Assertion>`
}

func responseXML(id, inner string) string {
	return `<samlp:Response xmlns:samlp="` + nsP + `" xmlns:saml="` + nsA + `" ID="` + id + `" Version="2.0" IssueInstant="2026-11-21T00:00:00Z">` +
		`<saml:Issuer>https://idp.example.test</saml:Issuer>` + inner + `</samlp:Response>`
}

func mustRoot(t testing.TB, raw string) *etree.Element {
	t.Helper()
	doc, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return doc.Root()
}

// roundTrip serializes el and parses it again, as a received message would be.
func roundTrip(t testing.TB, el *etree.Element) *etree.Element {
	t.Helper()
	return mustRoot(t, serialize(t, el))
}

func serialize(t testing.TB, el *etree.Element) string {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())
	s, err := doc.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func tags(els []*etree.Element) []string {
	out := make([]string, len(els))
	for i, e := range els {
		out[i] = e.Tag
	}
	return out
}

func colons(hex string) string {
	var b strings.Builder
	for i := 0; i < len(hex); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hex[i : i+2])
	}
	return b.String()
}
