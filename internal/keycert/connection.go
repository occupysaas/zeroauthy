package keycert

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1" // Auth0's certificate identifier format, not a signature.
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"time"
)

// CreateConnection makes a public self-signed connection certificate for an
// RSA or EC signer; it does not establish a TLS trust relationship.
func CreateConnection(signer crypto.Signer, subject string, now time.Time) ([]byte, error) {
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return nil, e
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	t := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: subject}, NotBefore: now.UTC().Add(-5 * time.Minute), NotAfter: now.UTC().AddDate(10, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement, BasicConstraintsValid: true}
	return x509.CreateCertificate(rand.Reader, t, t, signer.Public(), signer)
}

// DescribeConnection leaves signing-key SHA-256 helpers unchanged.
func DescribeConnection(der []byte) (cert, pkcs, fingerprint, thumbprint string, err error) {
	if _, err = x509.ParseCertificate(der); err != nil {
		return
	}
	var p7 []byte
	p7, err = certificatePKCS7(der)
	if err != nil {
		return
	}
	cert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	pkcs = string(pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: p7}))
	sum := sha1.Sum(der)
	thumbprint = strings.ToUpper(hex.EncodeToString(sum[:]))
	var chunks []string
	for i := 0; i < len(thumbprint); i += 2 {
		chunks = append(chunks, thumbprint[i:i+2])
	}
	fingerprint = strings.Join(chunks, ":")
	return
}
