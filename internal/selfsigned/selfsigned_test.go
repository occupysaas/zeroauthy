package selfsigned

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func newAuthority(t *testing.T, allow func(context.Context, string) (bool, error)) *Authority {
	t.Helper()
	a, err := New(Config{
		Hosts: []string{"localhost", "127.0.0.1", "::1", "System.Example.Test:8443", "auth.example.test", "*.auth.example.test", "[::1]:443", "zeroauthy", "localhost"},
		Allow: allow,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func caPool(t *testing.T, a *Authority) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(a.CACertPEM()) {
		t.Fatal("CA PEM did not parse")
	}
	return pool
}

func verify(t *testing.T, a *Authority, c *tls.Certificate, name string) error {
	t.Helper()
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	_, err = leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: caPool(t, a), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err
}

func TestStartupLeafSANsAndChain(t *testing.T) {
	a := newAuthority(t, nil)
	leaf, err := x509.ParseCertificate(a.Leaf().Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	wantDNS := []string{"localhost", "system.example.test", "auth.example.test", "*.auth.example.test", "zeroauthy"}
	if !slices.Equal(leaf.DNSNames, wantDNS) {
		t.Fatalf("DNS SANs = %q, want %q", leaf.DNSNames, wantDNS)
	}
	var ips []string
	for _, ip := range leaf.IPAddresses {
		ips = append(ips, ip.String())
	}
	if !slices.Equal(ips, []string{"127.0.0.1", "::1"}) {
		t.Fatalf("IP SANs = %q", ips)
	}
	for _, name := range []string{"localhost", "127.0.0.1", "::1", "system.example.test", "auth.example.test", "acme.auth.example.test", "zeroauthy"} {
		if err := verify(t, a, a.Leaf(), name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := verify(t, a, a.Leaf(), "evil.test"); err == nil {
		t.Error("leaf verified for an unlisted host")
	}
	if d := leaf.NotAfter.Sub(leaf.NotBefore); d > 32*24*time.Hour || d < 24*time.Hour {
		t.Errorf("leaf validity = %v", d)
	}
	if leaf.IsCA {
		t.Error("leaf is a CA")
	}
}

func TestEachStartRegenerates(t *testing.T) {
	a, b := newAuthority(t, nil), newAuthority(t, nil)
	if bytes.Equal(a.CACertPEM(), b.CACertPEM()) {
		t.Fatal("two starts produced the same CA")
	}
	if err := verify(t, b, a.Leaf(), "localhost"); err == nil {
		t.Fatal("a leaf verified against another start's CA")
	}
}

func TestCAFileHoldsOnlyTheCertificate(t *testing.T) {
	a := newAuthority(t, nil)
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := a.WriteCAFile(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("CA file contains a private key")
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("CA file is not exactly one certificate: %q", raw)
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !ca.IsCA {
		t.Fatalf("CA file certificate: %+v %v", ca, err)
	}
	sum := sha256.Sum256(block.Bytes)
	if got := strings.ReplaceAll(a.Fingerprint(), ":", ""); !strings.EqualFold(got, hex.EncodeToString(sum[:])) {
		t.Fatalf("fingerprint %s does not match the written certificate", a.Fingerprint())
	}
	if info, _ := os.Stat(path); info.Mode().Perm()&0o022 != 0 {
		t.Fatalf("CA file mode = %v", info.Mode())
	}
	// Overwriting on the next start works.
	if err := newAuthority(t, nil).WriteCAFile(path); err != nil {
		t.Fatal(err)
	}
}

func TestOnDemandIssuance(t *testing.T) {
	var asked []string
	a := newAuthority(t, func(_ context.Context, host string) (bool, error) {
		asked = append(asked, host)
		switch host {
		case "late.tenant.test":
			return true, nil
		case "broken.test":
			return false, errors.New("store down")
		}
		return false, nil
	})
	hello := func(name string) *tls.ClientHelloInfo { return &tls.ClientHelloInfo{ServerName: name} }

	// Covered names and connections without SNI get the startup leaf.
	for _, name := range []string{"", "localhost", "acme.auth.example.test", "ZEROAUTHY"} {
		c, err := a.GetCertificate(hello(name))
		if err != nil || c != a.Leaf() {
			t.Errorf("%q: got %v, %v; want startup leaf", name, c, err)
		}
	}
	if len(asked) != 0 {
		t.Fatalf("covered names consulted the allow list: %q", asked)
	}

	c, err := a.GetCertificate(hello("Late.Tenant.Test."))
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(t, a, c, "late.tenant.test"); err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(c.Certificate[0])
	if !slices.Equal(leaf.DNSNames, []string{"late.tenant.test"}) {
		t.Fatalf("on-demand SANs = %q", leaf.DNSNames)
	}
	again, err := a.GetCertificate(hello("late.tenant.test"))
	if err != nil || again != c {
		t.Fatalf("second handshake was not served from cache: %v", err)
	}
	if slices.Index(asked, "late.tenant.test") != len(asked)-1 || len(asked) != 1 {
		t.Fatalf("allow consulted %q", asked)
	}

	for _, name := range []string{"evil.test", "broken.test", "a.b.auth.example.test"} {
		if c, err := a.GetCertificate(hello(name)); err == nil {
			t.Errorf("%s: issued %v for an unknown host", name, c)
		}
	}
}

func TestNoAllowRefusesUnknownSNI(t *testing.T) {
	a := newAuthority(t, nil)
	if _, err := a.GetCertificate(&tls.ClientHelloInfo{ServerName: "unknown.test"}); err == nil {
		t.Fatal("issued without an allow function")
	}
}

func TestHandshakeTrustingOnlyTheCA(t *testing.T) {
	a := newAuthority(t, func(_ context.Context, host string) (bool, error) { return host == "late.tenant.test", nil })
	ln, err := tls.Listen("tcp", "127.0.0.1:0", a.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = conn.(*tls.Conn).Handshake(); conn.Close() }()
		}
	}()
	for _, name := range []string{"system.example.test", "late.tenant.test", "127.0.0.1"} {
		conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: caPool(t, a), ServerName: name})
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		conn.Close()
	}
	if conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: caPool(t, a), ServerName: "evil.test"}); err == nil {
		conn.Close()
		t.Error("handshake succeeded for an unknown host")
	}
}
