package rules

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func samlCert(t *testing.T) string {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "idp"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestParseSAML(t *testing.T) {
	cert := samlCert(t)
	ok := map[string]any{"signInEndpoint": "https://idp.example.test/sso", "signingCert": cert, "fieldsMap": map[string]any{"email": "mail", "groups": []any{"memberOf"}},
		"idpinitiated": map[string]any{"enabled": true, "client_id": "app", "client_protocol": "oidc", "client_authorizequery": "response_type=code&scope=openid"},
		"thumbprints":  []any{"ignored-and-recomputed"}, "domain_aliases": []any{"example.test"}}
	s, errs := Parse(Input{Strategy: SAMLP, Name: "corp", Options: ok})
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if s.SAML == nil || s.SAML.SignInEndpoint != "https://idp.example.test/sso" || len(s.SAML.Certs) != 1 || len(s.SAML.Thumbprints) != 1 || len(s.SAML.Thumbprints[0]) != 40 ||
		len(s.SAML.Thumbprints384[0]) != 96 || s.SAML.FieldsMap["email"][0] != "mail" || !s.SAML.IdPInitiated.Enabled || s.SAML.IdPInitiated.ClientID != "app" ||
		s.SAML.ProtocolBinding != BindingRedirect || !s.SAML.Deflate || s.SAML.SignatureAlgorithm != "rsa-sha256" {
		t.Fatalf("settings %+v", s.SAML)
	}
	if s.SAML.EntityID != "" {
		t.Fatal("entityId default is applied with the tenant name, not here")
	}
	// Legacy cert alias and base64 DER.
	der := strings.Join(strings.Split(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(cert, "-----BEGIN CERTIFICATE-----"), "-----END CERTIFICATE-----\n")), "\n"), "")
	if _, errs := Parse(Input{Strategy: SAMLP, Name: "corp", Options: map[string]any{"signInEndpoint": "https://idp/sso", "cert": der}}); len(errs) > 0 {
		t.Fatalf("legacy cert: %v", errs)
	}
	// Base64 of the PEM, as the Deploy CLI exports and re-imports it.
	if s, errs := Parse(Input{Strategy: SAMLP, Name: "corp", Options: map[string]any{"signInEndpoint": "https://idp/sso", "signingCert": base64.StdEncoding.EncodeToString([]byte(cert))}}); len(errs) > 0 || len(s.SAML.Certs) != 1 {
		t.Fatalf("base64 PEM: %v", errs)
	}
	for name, mutate := range map[string]func(map[string]any){
		"no endpoint":          func(o map[string]any) { delete(o, "signInEndpoint") },
		"no certificate":       func(o map[string]any) { delete(o, "signingCert") },
		"bad certificate":      func(o map[string]any) { o["signingCert"] = "nope" },
		"javascript endpoint":  func(o map[string]any) { o["signInEndpoint"] = "javascript:alert(1)" },
		"bad binding":          func(o map[string]any) { o["protocolBinding"] = "urn:x" },
		"bad algorithm":        func(o map[string]any) { o["signatureAlgorithm"] = "rsa-md5" },
		"bad template":         func(o map[string]any) { o["requestTemplate"] = "<x/>" },
		"fieldsMap wrong type": func(o map[string]any) { o["fieldsMap"] = map[string]any{"email": 1} },
		"idp-initiated wsfed": func(o map[string]any) {
			o["idpinitiated"] = map[string]any{"enabled": true, "client_id": "app", "client_protocol": "wsfed"}
		},
		"idp-initiated no app": func(o map[string]any) { o["idpinitiated"] = map[string]any{"enabled": true} },
		"supplied private key": func(o map[string]any) {
			o["decryptionKey"] = map[string]any{"key": "-----BEGIN PRIVATE KEY-----", "cert": cert}
		},
		"supplied signing key": func(o map[string]any) { o["signing_key"] = map[string]any{"key": "k", "cert": cert} },
		"rsa-1_5 not allowed": func(o map[string]any) {
			o["assertion_decryption_settings"] = map[string]any{"allowed_key_transport": []any{"rsa-oaep", "rsa-3des"}}
		},
		"debug wrong type":      func(o map[string]any) { o["debug"] = "yes" },
		"metadata and endpoint": func(o map[string]any) { o["metadataXml"] = "<not metadata/>" },
	} {
		o := map[string]any{}
		for k, v := range ok {
			o[k] = v
		}
		mutate(o)
		if _, errs := Parse(Input{Strategy: SAMLP, Name: "corp", Options: o}); len(errs) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
	if _, errs := Parse(Input{Strategy: SAMLP, Name: "a|b", Options: ok}); len(errs) == 0 {
		t.Error("name with | accepted")
	}
	o := map[string]any{"signInEndpoint": "https://idp/sso", "signingCert": cert, "assertion_decryption_settings": map[string]any{"allowed_key_transport": []any{"rsa-oaep", "rsa-1_5"}}}
	if s, errs := Parse(Input{Strategy: SAMLP, Name: "corp", Options: o}); len(errs) > 0 || !s.SAML.AllowRSA15 {
		t.Fatalf("explicit rsa-1_5: %v", errs)
	}
}
