package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// TestSelfSignedTLSHandshake: with server.tls_self_signed a client that
// trusts only the written CA file reaches the system host, a seeded tenant
// domain, a configured extra host and a tenant added after startup, and an
// unknown SNI name gets no certificate.
func TestSelfSignedTLSHandshake(t *testing.T) {
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "seed.yaml")
	if err := os.WriteFile(seedPath, []byte("tenants:\n  - name: acme\n    domains: [acme.example.test]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "ca.pem")
	cfg := &config.Config{Server: testServer, Storage: config.Storage{DSN: "memory://"}, Seed: seedPath}
	cfg.Server.SystemHost = "system.localhost:8443"
	cfg.Server.TLSSelfSigned = true
	cfg.Server.TLSSelfSignedCAFile = caFile
	cfg.Server.TLSSelfSignedHosts = []string{"zeroauthy,10.9.8.7"}
	var logged strings.Builder
	a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(&logged, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if a.selfSigned == nil {
		t.Fatal("no self-signed authority")
	}
	out := logged.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "testing") || !strings.Contains(out, a.selfSigned.Fingerprint()) || !strings.Contains(out, caFile) {
		t.Fatalf("startup log lacks the warning, fingerprint or CA path:\n%s", out)
	}
	if strings.Contains(out, "PRIVATE KEY") {
		t.Fatal("private key logged")
	}

	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(pemBytes), "PRIVATE KEY") {
		t.Fatal("CA file holds a private key")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		t.Fatal("CA file does not parse")
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", a.selfSigned.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: a.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	addr := ln.Addr().String()

	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
	get := func(host string) (int, error) {
		res, err := client.Get("https://" + host + "/.well-known/openid-configuration")
		if err != nil {
			return 0, err
		}
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, res.Body)
		return res.StatusCode, nil
	}
	for _, host := range []string{"system.localhost:8443", "acme.example.test"} {
		if code, err := get(host); err != nil || code != http.StatusOK {
			t.Errorf("%s: %d %v", host, code, err)
		}
	}
	handshake := func(name string) error {
		conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: roots, ServerName: name})
		if err == nil {
			conn.Close()
		}
		return err
	}
	for _, name := range []string{"zeroauthy", "10.9.8.7", "localhost", "127.0.0.1"} {
		if err := handshake(name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	if err := a.store.Tenants().Create(context.Background(), &store.Tenant{ID: "late", Name: "late", Domains: []string{"late.example.test", "ported.example.test:9443"}}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"late.example.test", "ported.example.test"} {
		if err := handshake(name); err != nil {
			t.Errorf("tenant added after startup %s: %v", name, err)
		}
	}
	if err := handshake("evil.example.test"); err == nil {
		t.Error("handshake succeeded for an unknown host")
	}
}

func TestNoSelfSignedByDefault(t *testing.T) {
	cfg := &config.Config{Server: testServer, Storage: config.Storage{DSN: "memory://"}}
	a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if a.selfSigned != nil {
		t.Fatal("self-signed authority without server.tls_self_signed")
	}
}
