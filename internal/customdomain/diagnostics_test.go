package customdomain_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const publicIP = "8.8.8.8"

// probeFixture serves discovery for example.com over TLS on a local listener;
// the injected dialer maps the validated public address to it and records
// every dial target.
type probeFixture struct {
	*fixture
	svc     *customdomain.Service
	mu      sync.Mutex
	dials   []string
	handler http.HandlerFunc
}

func newProbeFixture(t *testing.T, domain string) (*probeFixture, string) {
	t.Helper()
	p := &probeFixture{fixture: newFixture(t)}
	p.handler = func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": "https://example.com/", "authorization_endpoint": "https://example.com/authorize",
			"token_endpoint": "https://example.com/oauth/token", "jwks_uri": "https://example.com/.well-known/jwks.json",
		})
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		h := p.handler
		p.mu.Unlock()
		h(w, r)
	}))
	srv.StartTLS()
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	target := srv.Listener.Addr().String()
	probe := customdomain.ProbeDeps{
		RootCAs: roots,
		Timeout: 500 * time.Millisecond,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			p.mu.Lock()
			p.dials = append(p.dials, addr)
			p.mu.Unlock()
			if addr != net.JoinHostPort(publicIP, "443") {
				return nil, errors.New("unexpected dial target " + addr)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, target)
		},
	}
	cfg := customdomain.ServiceConfig{BaseDomain: "auth.example.test", OriginDomain: "auth.example.test", OriginTLSReady: true, ManagedEnabled: true}
	p.svc = customdomain.NewServiceWithProbe(p.st, p.dns, cfg, p.clk.now, rand.Reader, probe)
	d := p.activeSelfManaged(t, "acme", domain)
	p.dns.ips = [][]netip.Addr{{netip.MustParseAddr(publicIP)}}
	return p, d.ID
}

func (p *probeFixture) test(t *testing.T, id string) (customdomain.Diagnostic, error) {
	t.Helper()
	p.clk.add(31 * time.Second) // per-domain attempt budget
	return p.svc.Test(context.Background(), "acme", id)
}

func TestDomainDiagnostic(t *testing.T) {
	p, id := newProbeFixture(t, "example.com")
	before := p.get(t, &store.CustomDomain{TenantID: "acme", ID: id})
	diag, err := p.test(t, id)
	if err != nil || !diag.Success {
		t.Fatalf("success = %+v, %v", diag, err)
	}
	if after := p.get(t, &store.CustomDomain{TenantID: "acme", ID: id}); after.Revision != before.Revision {
		t.Fatal("diagnostics mutated the domain")
	}
	// A domain that is not ready is a conflict, not a probe.
	pending := p.create(t, "acme", "pending.acme.test", customdomain.TypeManaged)
	if _, err := p.test(t, pending.ID); !errors.Is(err, customdomain.ErrNotReady) {
		t.Fatalf("pending = %v", err)
	}
	// Resolver outages are infrastructure failures (503), not observations.
	p.dns.ipErr = errors.New("servfail")
	if _, err := p.test(t, id); !errors.Is(err, customdomain.ErrDiagnosticUnavailable) {
		t.Fatalf("resolver outage = %v", err)
	}
}

func TestDomainDiagnosticSSRF(t *testing.T) {
	addrs := func(s ...string) []netip.Addr {
		out := []netip.Addr{}
		for _, a := range s {
			out = append(out, netip.MustParseAddr(a))
		}
		return out
	}
	for name, answer := range map[string][]netip.Addr{
		"private v4":    addrs("10.0.0.5"),
		"loopback":      addrs("127.0.0.1"),
		"link-local":    addrs("169.254.169.254"),
		"cgnat":         addrs("100.64.0.1"),
		"documentation": addrs("192.0.2.10"),
		"loopback v6":   addrs("::1"),
		"ula v6":        addrs("fd00::1"),
		"mapped":        addrs("::ffff:10.0.0.5"),
		"6to4":          addrs("2002:a00:5::1"),
		"nat64":         addrs("64:ff9b::a00:5"),
		"unspecified":   addrs("0.0.0.0"),
		"multicast":     addrs("224.0.0.1"),
		"mixed":         addrs(publicIP, "10.0.0.5"),
		"three":         addrs(publicIP, "1.1.1.1", "9.9.9.9"),
	} {
		t.Run(name, func(t *testing.T) {
			p, id := newProbeFixture(t, "example.com")
			p.dns.ips = [][]netip.Addr{answer}
			diag, err := p.test(t, id)
			if err != nil || diag.Success || diag.Message == "" {
				t.Fatalf("diag = %+v, %v", diag, err)
			}
			if len(p.dials) != 0 {
				t.Fatalf("dialed %v", p.dials)
			}
		})
	}
	// Rebinding: the dial uses the validated answer; nothing re-resolves.
	t.Run("rebinding", func(t *testing.T) {
		p, id := newProbeFixture(t, "example.com")
		p.dns.ips = [][]netip.Addr{addrs(publicIP), addrs("10.0.0.5")}
		calls := p.dns.ipCalls
		if diag, err := p.test(t, id); err != nil || !diag.Success {
			t.Fatalf("diag = %+v, %v", diag, err)
		}
		if p.dns.ipCalls-calls != 1 || len(p.dials) != 1 || p.dials[0] != net.JoinHostPort(publicIP, "443") {
			t.Fatalf("lookups=%d dials=%v", p.dns.ipCalls-calls, p.dials)
		}
	})
	t.Run("environment proxy", func(t *testing.T) {
		t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
		t.Setenv("https_proxy", "http://127.0.0.1:1")
		p, id := newProbeFixture(t, "example.com")
		if diag, err := p.test(t, id); err != nil || !diag.Success || len(p.dials) != 1 {
			t.Fatalf("diag = %+v, %v, dials %v", diag, err, p.dials)
		}
	})
	for name, h := range map[string]http.HandlerFunc{
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://10.0.0.5/.well-known/openid-configuration", http.StatusFound)
		},
		"oversize": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"issuer":"https://example.com/","x":"` + strings.Repeat("a", 70000) + `"}`))
		},
		"slow": func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-time.After(3 * time.Second):
			case <-r.Context().Done():
			}
		},
		"wrong issuer": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": "https://evil.test/", "authorization_endpoint": "https://example.com/authorize", "token_endpoint": "https://example.com/oauth/token", "jwks_uri": "https://example.com/.well-known/jwks.json"})
		},
		"foreign endpoint": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": "https://example.com/", "authorization_endpoint": "https://evil.test/authorize", "token_endpoint": "https://example.com/oauth/token", "jwks_uri": "https://example.com/.well-known/jwks.json"})
		},
		"not found": func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) },
	} {
		t.Run(name, func(t *testing.T) {
			p, id := newProbeFixture(t, "example.com")
			p.mu.Lock()
			p.handler = h
			p.mu.Unlock()
			if diag, err := p.test(t, id); err != nil || diag.Success || diag.Message == "" {
				t.Fatalf("diag = %+v, %v", diag, err)
			}
		})
	}
	// The local certificate does not cover this name.
	t.Run("wrong certificate", func(t *testing.T) {
		p, id := newProbeFixture(t, "login.acme.test")
		if diag, err := p.test(t, id); err != nil || diag.Success {
			t.Fatalf("diag = %+v, %v", diag, err)
		}
	})
}
