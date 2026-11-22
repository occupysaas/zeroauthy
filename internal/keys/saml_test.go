package keys

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

// TestSAMLSigningKey: SAML signs with the tenant's current key and publishes
// the current and next certificates (Plan 37a).
func TestSAMLSigningKey(t *testing.T) {
	m, st := newManager(t)
	ctx := context.Background()
	if _, _, err := m.SAMLSigner(ctx, "ten_a"); err == nil {
		t.Fatal("signer without keys")
	}
	if err := m.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	signer, cert, err := m.SAMLSigner(ctx, "ten_a")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("saml"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], sig); err != nil {
		t.Fatal("certificate does not match the signing key")
	}
	ks, _ := st.SigningKeys().List(ctx, "ten_a")
	var current string
	for _, k := range ks {
		if k.Status == "current" {
			current = string(k.CertificateDER)
		}
	}
	if current != string(cert.Raw) {
		t.Fatal("SAML signer is not the current key")
	}
	certs, err := m.SAMLCertificates(ctx, "ten_a")
	if err != nil || len(certs) == 0 || string(certs[0].Raw) != current {
		t.Fatalf("published certificates: %d %v", len(certs), err)
	}
	if _, _, err := m.SAMLSigner(ctx, "ten_b"); err == nil {
		t.Fatal("other tenant's key used")
	}
}
