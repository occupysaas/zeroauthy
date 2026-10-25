package keycert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

// PublicCertificate is the stable public representation returned by the
// Management API. Fingerprint is SHA-256 hex; Thumbprint is base64url SHA-256.
type PublicCertificate struct {
	Cert        string `json:"cert"`
	Fingerprint string `json:"fingerprint"`
	Thumbprint  string `json:"thumbprint"`
	PKCS7       string `json:"pkcs7"`
}

// Create makes a self-signed certificate representation for an RSA key. It
// is not a TLS identity or a trust-chain certificate.
func Create(priv *rsa.PrivateKey, now time.Time) ([]byte, error) {
	if priv == nil || priv.N == nil || priv.E < 3 {
		return nil, errors.New("keycert: invalid RSA private key")
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	now = now.UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "zeroauthy signing key"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}
	return x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
}

// Describe validates DER and derives public certificate encodings.
func Describe(der []byte) (PublicCertificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return PublicCertificate{}, err
	}
	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		return PublicCertificate{}, errors.New("keycert: certificate public key is not RSA")
	}
	sum := sha256.Sum256(der)
	p7, err := certificatePKCS7(der)
	if err != nil {
		return PublicCertificate{}, err
	}
	return PublicCertificate{
		Cert:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		Fingerprint: hex.EncodeToString(sum[:]),
		Thumbprint:  base64.RawURLEncoding.EncodeToString(sum[:]),
		PKCS7:       base64.StdEncoding.EncodeToString(p7),
	}, nil
}
