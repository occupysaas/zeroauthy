// Package clientcred parses client credential PEMs and verifies JWTs signed
// by a client credential (client assertions and JAR request objects).
package clientcred

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	minRSABits = 2048
	maxRSABits = 4096
)

// Error is a client-input problem (HTTP 400) naming the offending field.
type Error struct{ Field, Msg string }

func (e *Error) Error() string { return e.Field + ": " + e.Msg }

// Parsed is the normalised form of a credential PEM.
type Parsed struct {
	DER          []byte // PKIX SubjectPublicKeyInfo
	KID          string // RFC 7638 thumbprint, base64url
	Thumbprint   string // same value, reported as thumbprint_sha256
	CertNotAfter *time.Time
}

// AlgAllowed reports whether alg is one of the supported signature algorithms.
func AlgAllowed(alg string) bool {
	switch jose.SignatureAlgorithm(alg) {
	case jose.RS256, jose.RS384, jose.PS256:
		return true
	}
	return false
}

// ParsePEM parses an SPKI or PKCS#1 RSA public key (credType "public_key") or
// an X.509 certificate (credType "x509_cert"). An empty alg means RS256.
func ParsePEM(credType, pemText, alg string) (*Parsed, error) {
	if alg == "" {
		alg = string(jose.RS256)
	}
	if !AlgAllowed(alg) {
		return nil, &Error{"alg", "must be RS256, RS384 or PS256"}
	}
	if credType != "public_key" && credType != "x509_cert" {
		return nil, &Error{"credential_type", "must be public_key or x509_cert"}
	}
	block, rest := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, &Error{"pem", "no PEM block found"}
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, &Error{"pem", "exactly one PEM block is allowed"}
	}
	var (
		pub      any
		notAfter *time.Time
		err      error
	)
	switch {
	case credType == "x509_cert" && block.Type == "CERTIFICATE":
		var c *x509.Certificate
		if c, err = x509.ParseCertificate(block.Bytes); err == nil {
			pub = c.PublicKey
			t := c.NotAfter.UTC()
			notAfter = &t
		}
	case credType == "public_key" && block.Type == "PUBLIC KEY":
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
	case credType == "public_key" && block.Type == "RSA PUBLIC KEY":
		pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, &Error{"pem", "PEM block type does not match credential_type"}
	}
	if err != nil {
		return nil, &Error{"pem", "could not parse PEM content"}
	}
	rk, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, &Error{"pem", "only RSA keys are supported"}
	}
	if bits := rk.N.BitLen(); bits < minRSABits || bits > maxRSABits {
		return nil, &Error{"pem", "RSA key must be 2048 to 4096 bits"}
	}
	der, err := x509.MarshalPKIXPublicKey(rk)
	if err != nil {
		return nil, &Error{"pem", "could not encode public key"}
	}
	tp, err := (&jose.JSONWebKey{Key: rk}).Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, &Error{"pem", "could not compute thumbprint"}
	}
	id := base64.RawURLEncoding.EncodeToString(tp)
	return &Parsed{DER: der, KID: id, Thumbprint: id, CertNotAfter: notAfter}, nil
}
