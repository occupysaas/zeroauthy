// Package selfsigned serves HTTPS for test environments from a throwaway
// certificate authority generated in memory at startup
// (server.tls_self_signed). The CA key never leaves the process; only the CA
// certificate is exported so test clients can trust it.
package selfsigned

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultValidity is how long the CA and its leaf certificates are valid.
// Every start generates a new CA, so it only has to outlive one run.
const DefaultValidity = 30 * 24 * time.Hour

// maxCached bounds the on-demand certificate cache. Issuance is limited to
// known hosts, so this is only a backstop against registry churn.
const maxCached = 4096

// Config describes the authority to generate.
type Config struct {
	// Hosts are the DNS names (wildcards allowed) and IP addresses of the
	// startup certificate. Ports and brackets are stripped.
	Hosts []string
	// Allow reports whether a TLS server name the startup certificate does
	// not cover may receive an on-demand certificate. Nil refuses all.
	Allow func(ctx context.Context, host string) (bool, error)
	// Validity defaults to DefaultValidity.
	Validity time.Duration
}

// Authority holds the in-memory CA and the certificates it issued.
type Authority struct {
	caCert   *x509.Certificate
	caKey    *ecdsa.PrivateKey
	caPEM    []byte
	leaf     *tls.Certificate
	leafX509 *x509.Certificate
	allow    func(context.Context, string) (bool, error)
	validity time.Duration

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// New generates an ECDSA P-256 CA and a startup leaf certificate it signs.
func New(cfg Config) (*Authority, error) {
	validity := cfg.Validity
	if validity <= 0 {
		validity = DefaultValidity
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("selfsigned: CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"zeroauthy"}, CommonName: "zeroauthy self-signed test CA " + serial.Text(16)[:8]},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("selfsigned: CA certificate: %w", err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	a := &Authority{
		caCert: ca, caKey: key, allow: cfg.Allow, validity: validity,
		caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		cache: map[string]*tls.Certificate{},
	}
	dns, ips := splitHosts(cfg.Hosts)
	if len(dns) == 0 && len(ips) == 0 {
		return nil, errors.New("selfsigned: no hosts for the certificate")
	}
	a.leaf, err = a.issue(dns, ips)
	if err != nil {
		return nil, err
	}
	a.leafX509 = a.leaf.Leaf
	return a, nil
}

// splitHosts normalizes hosts into deduplicated DNS names and IPs, keeping
// their first-seen order.
func splitHosts(hosts []string) ([]string, []net.IP) {
	var dns []string
	var ips []net.IP
	seen := map[string]bool{}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if name, _, err := net.SplitHostPort(h); err == nil {
			h = name
		}
		h = strings.TrimSuffix(strings.Trim(h, "[]"), ".")
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			if !seen[ip.String()] {
				seen[ip.String()] = true
				ips = append(ips, ip)
			}
			continue
		}
		if !seen[h] {
			seen[h] = true
			dns = append(dns, h)
		}
	}
	return dns, ips
}

func randomSerial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("selfsigned: serial: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}

// issue signs a server certificate for the names with a fresh key.
func (a *Authority) issue(dns []string, ips []net.IP) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("selfsigned: leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	notAfter := now.Add(a.validity)
	if notAfter.After(a.caCert.NotAfter) {
		notAfter = a.caCert.NotAfter
	}
	cn := ""
	if len(dns) > 0 {
		cn = dns[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"zeroauthy"}, CommonName: cn},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.caCert, &key.PublicKey, a.caKey)
	if err != nil {
		return nil, fmt.Errorf("selfsigned: leaf certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der, a.caCert.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

// CACertPEM returns the CA certificate in PEM form. It never contains a key.
func (a *Authority) CACertPEM() []byte { return append([]byte(nil), a.caPEM...) }

// Fingerprint is the SHA-256 of the CA certificate, as colon-separated
// uppercase hex (the form openssl x509 -fingerprint -sha256 prints).
func (a *Authority) Fingerprint() string {
	sum := sha256.Sum256(a.caCert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// Leaf is the startup certificate.
func (a *Authority) Leaf() *tls.Certificate { return a.leaf }

// WriteCAFile writes the CA certificate (public, mode 0644) to path,
// replacing any earlier file atomically.
func (a *Authority) WriteCAFile(path string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".zeroauthy-ca-*.pem")
	if err != nil {
		return fmt.Errorf("selfsigned: write CA file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(a.caPEM); err != nil {
		tmp.Close()
		return fmt.Errorf("selfsigned: write CA file: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return fmt.Errorf("selfsigned: write CA file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("selfsigned: write CA file: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("selfsigned: write CA file: %w", err)
	}
	return nil
}

// TLSConfig serves the startup certificate and on-demand certificates.
func (a *Authority) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: a.GetCertificate, NextProtos: []string{"h2", "http/1.1"}}
}

// GetCertificate returns the startup certificate when it covers the server
// name (or the client sent none, as when connecting by IP address). Other
// names get a certificate of their own only when Allow accepts them, so the
// CA never signs an arbitrary SNI value.
func (a *Authority) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.TrimSuffix(strings.ToLower(hello.ServerName), ".")
	if name == "" || a.leafX509.VerifyHostname(name) == nil {
		return a.leaf, nil
	}
	a.mu.Lock()
	c := a.cache[name]
	a.mu.Unlock()
	if c != nil {
		return c, nil
	}
	if a.allow == nil || net.ParseIP(name) != nil {
		return nil, fmt.Errorf("selfsigned: no certificate for %q", name)
	}
	ctx := context.Background()
	if hc := hello.Context(); hc != nil {
		ctx = hc
	}
	ok, err := a.allow(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("selfsigned: checking %q: %w", name, err)
	}
	if !ok {
		return nil, fmt.Errorf("selfsigned: %q is not a known host", name)
	}
	c, err = a.issue([]string{name}, nil)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if prev := a.cache[name]; prev != nil {
		return prev, nil
	}
	if len(a.cache) >= maxCached {
		clear(a.cache)
	}
	a.cache[name] = c
	return c, nil
}
