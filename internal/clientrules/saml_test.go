package clientrules

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testCertPEM(t *testing.T) string {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sp"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestParseAddons(t *testing.T) {
	cert := testCertPEM(t)
	certJSON, _ := json.Marshal(cert)
	full := `{"samlp":{"mappings":{"email":"mail","groups":["memberOf","groups"]},"audience":"urn:sp","recipient":"https://sp.example.test/acs",
		"createUpnClaim":false,"mapUnknownClaimsAsIs":true,"passthroughClaimsWithNoMapping":false,"mapIdentities":false,
		"signatureAlgorithm":"rsa-sha1","digestAlgorithm":"sha1","issuer":"urn:idp","destination":"https://sp.example.test/acs",
		"lifetimeInSeconds":600,"signResponse":true,"nameIdentifierFormat":"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		"nameIdentifierProbes":["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"],
		"authnContextClassRef":"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
		"logout":{"callback":"https://sp.example.test/slo","slo_enabled":false},"binding":"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		"typedAttributes":false,"includeAttributeNameFormat":false,"signingCert":` + string(certJSON) + `}}`
	a, err := ParseAddons(json.RawMessage(full))
	if err != nil {
		t.Fatal(err)
	}
	s := a.SAMLP
	if s == nil || s.Audience != "urn:sp" || *s.LifetimeInSeconds != 600 || *s.SignResponse != true || s.Logout.Callback != "https://sp.example.test/slo" ||
		strings.Join(s.Mappings["groups"], ",") != "memberOf,groups" || s.Mappings["email"][0] != "mail" || s.SigningCert == "" {
		t.Fatalf("parsed %+v", s)
	}
	// Reading back keeps single mappings as strings.
	pub, _ := json.Marshal(PublicAddons(a))
	if !strings.Contains(string(pub), `"email":"mail"`) || !strings.Contains(string(pub), `"groups":["memberOf","groups"]`) {
		t.Fatalf("public form %s", pub)
	}
	for _, empty := range []string{`null`, `{}`, `{"samlp":null}`} {
		if a, err := ParseAddons(json.RawMessage(empty)); err != nil || a != nil {
			t.Fatalf("%s: %+v %v", empty, a, err)
		}
	}
	if a, err := ParseAddons(json.RawMessage(`{"samlp":{}}`)); err != nil || a == nil || a.SAMLP == nil {
		t.Fatalf("enabled with defaults: %+v %v", a, err)
	}
	for name, bad := range map[string]string{
		"other add-on":          `{"aws":{}}`,
		"unknown member":        `{"samlp":{"nope":1}}`,
		"not an object":         `{"samlp":[]}`,
		"bad algorithm":         `{"samlp":{"signatureAlgorithm":"rsa-md5"}}`,
		"bad digest":            `{"samlp":{"digestAlgorithm":"md5"}}`,
		"lifetime zero":         `{"samlp":{"lifetimeInSeconds":0}}`,
		"lifetime too long":     `{"samlp":{"lifetimeInSeconds":86401}}`,
		"lifetime fractional":   `{"samlp":{"lifetimeInSeconds":1.5}}`,
		"bad binding":           `{"samlp":{"binding":"urn:x"}}`,
		"relative recipient":    `{"samlp":{"recipient":"/acs"}}`,
		"javascript callback":   `{"samlp":{"logout":{"callback":"javascript:alert(1)"}}}`,
		"logout unknown member": `{"samlp":{"logout":{"x":1}}}`,
		"mapping wrong type":    `{"samlp":{"mappings":{"email":1}}}`,
		"too many names":        `{"samlp":{"mappings":{"email":["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q"]}}}`,
		"bad certificate":       `{"samlp":{"signingCert":"not a cert"}}`,
		"probe wrong type":      `{"samlp":{"nameIdentifierProbes":"x"}}`,
		"boolean as string":     `{"samlp":{"signResponse":"true"}}`,
		"duplicate key":         `{"samlp":{"audience":"a","audience":"b"}}`,
	} {
		if _, err := ParseAddons(json.RawMessage(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
