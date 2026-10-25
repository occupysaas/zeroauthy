package keycert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestCertificateIdentity(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	der, err := Create(priv, now)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.Cmp(priv.N) != 0 || pub.E != priv.E {
		t.Fatal("certificate does not contain supplied RSA public key")
	}
	if !cert.NotBefore.Equal(now.Add(-5*time.Minute)) || !cert.NotAfter.Equal(now.AddDate(10, 0, 0)) {
		t.Fatalf("validity = %s to %s", cert.NotBefore, cert.NotAfter)
	}
	if cert.Subject.CommonName != "zeroauthy signing key" {
		t.Fatalf("subject = %q", cert.Subject.CommonName)
	}
}

func TestCertificateEncodings(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := Create(priv, time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	desc, err := Describe(der)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := pem.Decode([]byte(desc.Cert))
	if p == nil || p.Type != "CERTIFICATE" || !bytes.Equal(p.Bytes, der) {
		t.Fatal("cert is not a PEM encoding of the stored DER")
	}
	sum := sha256.Sum256(der)
	if desc.Fingerprint != hex.EncodeToString(sum[:]) {
		t.Fatalf("fingerprint = %q", desc.Fingerprint)
	}
	if desc.Thumbprint != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatalf("thumbprint = %q", desc.Thumbprint)
	}
	if desc.PKCS7 == "" {
		t.Fatal("missing PKCS#7 representation")
	}
}

func TestCertificatePKCS7OpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl unavailable")
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := Create(priv, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	desc, err := Describe(der)
	if err != nil {
		t.Fatal(err)
	}
	p7, err := base64.StdEncoding.DecodeString(desc.PKCS7)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "certs.p7b")
	if err := os.WriteFile(in, p7, 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "certs.pem")
	if b, err := exec.Command("openssl", "pkcs7", "-inform", "DER", "-in", in, "-print_certs", "-out", out).CombinedOutput(); err != nil {
		parsed, _ := exec.Command("openssl", "asn1parse", "-inform", "DER", "-in", in).CombinedOutput()
		t.Fatalf("openssl pkcs7: %v: %s\nasn1parse: %s", err, b, parsed)
	}
	pemBytes, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := pem.Decode(pemBytes)
	if p == nil || !bytes.Equal(p.Bytes, der) {
		t.Fatal("OpenSSL recovered a different certificate")
	}
}
