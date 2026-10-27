package federation

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeResolver answers each lookup with the next answer set in turn.
type fakeResolver struct {
	mu      sync.Mutex
	answers [][]netip.Addr
	calls   int
}

func (r *fakeResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.answers[min(r.calls, len(r.answers)-1)]
	r.calls++
	return a, nil
}

func addrs(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, a := range s {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

// policyTo builds a production-shaped policy whose resolver is fake and whose
// final dial lands on srv, recording the pinned address it was asked for.
func policyTo(srv *httptest.Server, r Resolver, dialed *[]string) NetworkPolicy {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	target := srv.Listener.Addr().String()
	return NetworkPolicy{
		Resolver: r, RootCAs: pool, RequestTimeout: time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			*dialed = append(*dialed, addr)
			var d net.Dialer
			return d.DialContext(ctx, network, target)
		},
	}
}

func get(t *testing.T, rt http.RoundTripper, url string) (*http.Response, error) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	_, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, err
}

func TestFederationTransport(t *testing.T) {
	big := bytes.Repeat([]byte("x"), 2<<20)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte("ok"))
		case "/big":
			_, _ = w.Write(big)
		case "/gzip":
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			_, _ = zw.Write(big)
			_ = zw.Close()
		case "/slow":
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			time.Sleep(2 * time.Second)
		case "/redirect":
			http.Redirect(w, r, "https://example.com/ok", http.StatusFound)
		}
	}))
	defer srv.Close()

	t.Run("pinned public address", func(t *testing.T) {
		var dialed []string
		rt := NewTransport(policyTo(srv, &fakeResolver{answers: [][]netip.Addr{addrs("8.8.8.8")}}, &dialed))
		if _, err := get(t, rt, "https://example.com/ok"); err != nil {
			t.Fatal(err)
		}
		if len(dialed) != 1 || !strings.HasPrefix(dialed[0], "8.8.8.8:") {
			t.Fatalf("dialed %v", dialed)
		}
	})
	for name, answers := range map[string][][]netip.Addr{
		"private":   {addrs("10.0.0.5")},
		"loopback":  {addrs("127.0.0.1")},
		"metadata":  {addrs("169.254.169.254")},
		"mixed":     {addrs("8.8.8.8", "192.168.1.1")},
		"ipv6 ula":  {addrs("fd00::1")},
		"mapped v4": {addrs("::ffff:10.0.0.1")},
	} {
		t.Run(name, func(t *testing.T) {
			var dialed []string
			rt := NewTransport(policyTo(srv, &fakeResolver{answers: answers}, &dialed))
			if _, err := get(t, rt, "https://example.com/ok"); !errors.Is(err, ErrNetworkPolicy) {
				t.Fatalf("err %v", err)
			}
			if len(dialed) != 0 {
				t.Fatalf("dialed %v", dialed)
			}
		})
	}
	t.Run("rebinding", func(t *testing.T) {
		var dialed []string
		rt := NewTransport(policyTo(srv, &fakeResolver{answers: [][]netip.Addr{addrs("8.8.8.8"), addrs("127.0.0.1")}}, &dialed))
		if _, err := get(t, rt, "https://example.com/ok"); err != nil {
			t.Fatal(err)
		}
		if _, err := get(t, rt, "https://example.com/ok"); !errors.Is(err, ErrNetworkPolicy) {
			t.Fatalf("rebound err %v", err)
		}
	})
	t.Run("literal private address", func(t *testing.T) {
		var dialed []string
		rt := NewTransport(policyTo(srv, &fakeResolver{answers: [][]netip.Addr{addrs("8.8.8.8")}}, &dialed))
		if _, err := get(t, rt, "https://10.1.2.3/ok"); !errors.Is(err, ErrNetworkPolicy) {
			t.Fatalf("err %v", err)
		}
	})
	public := func() http.RoundTripper {
		var dialed []string
		return NewTransport(policyTo(srv, &fakeResolver{answers: [][]netip.Addr{addrs("8.8.8.8")}}, &dialed))
	}
	for name, url := range map[string]string{
		"http":        "http://example.com/ok",
		"credentials": "https://user:pass@example.com/ok",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := get(t, public(), url); !errors.Is(err, ErrNetworkPolicy) {
				t.Fatalf("err %v", err)
			}
		})
	}
	t.Run("redirect", func(t *testing.T) {
		if _, err := get(t, public(), "https://example.com/redirect"); !errors.Is(err, ErrNetworkPolicy) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("oversized", func(t *testing.T) {
		if _, err := get(t, public(), "https://example.com/big"); !errors.Is(err, ErrResponseTooLarge) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("oversized decoded", func(t *testing.T) {
		if _, err := get(t, public(), "https://example.com/gzip"); !errors.Is(err, ErrResponseTooLarge) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("slow body", func(t *testing.T) {
		start := time.Now()
		_, err := get(t, public(), "https://example.com/slow")
		if err == nil || time.Since(start) > 1900*time.Millisecond {
			t.Fatalf("slow body err=%v after %v", err, time.Since(start))
		}
	})
	t.Run("proxy environment ignored", func(t *testing.T) {
		t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
		t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
		if _, err := get(t, public(), "https://example.com/ok"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("fixture loopback", func(t *testing.T) {
		pool := x509.NewCertPool()
		pool.AddCert(srv.Certificate())
		rt := NewTransport(FixturePolicy(pool))
		if _, err := get(t, rt, srv.URL+"/ok"); err != nil {
			t.Fatal(err)
		}
		if _, err := get(t, NewTransport(NetworkPolicy{RootCAs: pool}), srv.URL+"/ok"); !errors.Is(err, ErrNetworkPolicy) {
			t.Fatalf("production policy reached loopback: %v", err)
		}
	})
}
