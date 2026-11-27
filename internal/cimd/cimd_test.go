package cimd

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/zeroauthy/zeroauthy/internal/federation"
)

func TestCheckURL(t *testing.T) {
	ok := []string{"https://app.example/client.json", "https://app.example/clients/a?v=1", "https://app.example:8443/c"}
	bad := []string{"http://app.example/client.json", "https://app.example", "https://app.example/", "https://app.example/c#x",
		"https://u:p@app.example/c", "https://app.example/a/../c", "https://app.example/./c", "app.example/c", "", "https://app.example/" + strings.Repeat("a", 200)}
	for _, u := range ok {
		if err := CheckURL(u); err != nil {
			t.Errorf("%q refused: %v", u, err)
		}
	}
	for _, u := range bad {
		if CheckURL(u) == nil {
			t.Errorf("%q accepted", u)
		}
	}
}

type fixedResolver struct{ addr netip.Addr }

func (r fixedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{r.addr}, nil
}

// fixture serves documents over TLS; paths map to handlers.
func fixture(t *testing.T, routes map[string]http.HandlerFunc) (*httptest.Server, *Fetcher) {
	t.Helper()
	mux := http.NewServeMux()
	for p, h := range routes {
		mux.HandleFunc(p, h)
	}
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	policy := federation.FixturePolicy(pool)
	policy.RequestTimeout = 500 * time.Millisecond
	return srv, NewFetcher(policy)
}

func doc(url string, extra map[string]any) []byte {
	m := map[string]any{"client_id": url, "client_name": "Example", "redirect_uris": []string{"https://app.example/cb"}}
	for k, v := range extra {
		if v == nil {
			delete(m, k)
			continue
		}
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return b
}

func serveJSON(body func(r *http.Request) []byte, header map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for k, v := range header {
			w.Header().Set(k, v)
		}
		_, _ = w.Write(body(r))
	}
}

func self(r *http.Request) string { return "https://" + r.Host + r.URL.Path }

// Review Focus 3: every refused fetch is refused before data is used.
func TestCIMDFetchPolicy(t *testing.T) {
	ctx := context.Background()
	// The production policy never dials loopback or private addresses.
	for _, a := range []string{"127.0.0.1", "10.0.0.7", "169.254.169.254", "::1"} {
		f := NewFetcher(federation.NetworkPolicy{Resolver: fixedResolver{netip.MustParseAddr(a)}})
		if _, err := f.Fetch(ctx, "https://metadata.internal.test/client.json"); !errors.Is(err, federation.ErrNetworkPolicy) {
			t.Errorf("%s: %v", a, err)
		}
	}
	if _, err := NewFetcher(federation.NetworkPolicy{}).Fetch(ctx, "http://app.example/client.json"); err == nil {
		t.Error("http URL fetched")
	}
	srv, f := fixture(t, map[string]http.HandlerFunc{
		"/big": serveJSON(func(*http.Request) []byte {
			return []byte(`{"client_id":"` + strings.Repeat("a", MaxDocumentBytes) + `"}`)
		}, nil),
		"/slow": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			time.Sleep(2 * time.Second)
		},
		"/redirect": func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/ok", http.StatusFound) },
		"/missing":  http.NotFound,
		"/html": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write(doc(self(r), nil))
		},
		"/array": serveJSON(func(*http.Request) []byte { return []byte(`[1]`) }, nil),
		"/ok":    serveJSON(func(r *http.Request) []byte { return doc(self(r), nil) }, nil),
	})
	for _, p := range []string{"/big", "/slow", "/redirect", "/missing", "/html", "/array"} {
		if _, err := f.Fetch(ctx, srv.URL+p); err == nil {
			t.Errorf("%s fetched", p)
		}
	}
	if _, err := f.Fetch(ctx, srv.URL+"/ok"); err != nil {
		t.Fatalf("ok: %v", err)
	}
}

func TestCIMDCacheBounds(t *testing.T) {
	srv, f := fixture(t, map[string]http.HandlerFunc{
		"/none":  serveJSON(func(r *http.Request) []byte { return doc(self(r), nil) }, nil),
		"/short": serveJSON(func(r *http.Request) []byte { return doc(self(r), nil) }, map[string]string{"Cache-Control": "public, max-age=60"}),
		"/hour":  serveJSON(func(r *http.Request) []byte { return doc(self(r), nil) }, map[string]string{"Cache-Control": "max-age=3600"}),
		"/long":  serveJSON(func(r *http.Request) []byte { return doc(self(r), nil) }, map[string]string{"Cache-Control": "max-age=9999999"}),
		"/nost":  serveJSON(func(r *http.Request) []byte { return doc(self(r), nil) }, map[string]string{"Cache-Control": "no-store"}),
	})
	for p, want := range map[string]time.Duration{"/none": MinCache, "/short": MinCache, "/hour": time.Hour, "/long": MaxCache, "/nost": MinCache} {
		d, err := f.Fetch(context.Background(), srv.URL+p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if d.MaxAge != want {
			t.Errorf("%s: max age %v, want %v", p, d.MaxAge, want)
		}
	}
}

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
)

func rsaKey(t *testing.T) *rsa.PrivateKey {
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		testKey = k
	})
	return testKey
}

func publicJWK(t *testing.T, kid string) map[string]any {
	b, _ := json.Marshal(jose.JSONWebKey{Key: &rsaKey(t).PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"})
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func evaluate(t *testing.T, f *Fetcher, url string, extra map[string]any) (Mapped, Validation) {
	t.Helper()
	var members map[string]json.RawMessage
	if err := json.Unmarshal(doc(url, extra), &members); err != nil {
		t.Fatal(err)
	}
	return f.Evaluate(context.Background(), &Document{URL: url, Members: members})
}

// Review Focus 2: the document must name its own URL.
func TestCIMDBinding(t *testing.T) {
	f := NewFetcher(federation.NetworkPolicy{})
	const url = "https://app.example/client.json"
	if _, v := evaluate(t, f, url, map[string]any{"client_id": "https://evil.example/client.json"}); v.Valid || len(v.Violations) == 0 {
		t.Fatalf("mismatched client_id: %+v", v)
	}
	if _, v := evaluate(t, f, url, map[string]any{"client_id": url + "/"}); v.Valid {
		t.Fatal("client_id must equal the URL exactly")
	}
	if _, v := evaluate(t, f, url, map[string]any{"client_id": nil}); v.Valid {
		t.Fatal("missing client_id")
	}
	if m, v := evaluate(t, f, url, nil); !v.Valid || m.ExternalClientID != url {
		t.Fatalf("matching document: %+v %+v", m, v)
	}
}

func TestCIMDMapping(t *testing.T) {
	f := NewFetcher(federation.NetworkPolicy{})
	const url = "https://app.example/client.json"
	m, v := evaluate(t, f, url, map[string]any{"client_name": nil, "grant_types": []string{"authorization_code", "client_credentials"}, "logo_uri": "https://app.example/l.png"})
	if !v.Valid || m.Name != "app.example" || m.AppType != "spa" || m.TokenEndpointAuthMethod != "none" ||
		!slices.Equal(m.GrantTypes, []string{"authorization_code"}) || !slices.Equal(m.Callbacks, []string{"https://app.example/cb"}) || m.LogoURI != "https://app.example/l.png" || len(v.Warnings) == 0 {
		t.Fatalf("public: %+v %+v", m, v)
	}
	m, v = evaluate(t, f, url, map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks": map[string]any{"keys": []any{publicJWK(t, "key-1")}}})
	if !v.Valid || m.AppType != "regular_web" || m.TokenEndpointAuthMethod != "private_key_jwt" || len(m.Credentials) != 1 ||
		m.Credentials[0].KID != "key-1" || m.Credentials[0].Alg != "RS256" || len(m.Credentials[0].DER) == 0 {
		t.Fatalf("private_key_jwt: %+v %+v", m, v)
	}
	priv, _ := json.Marshal(jose.JSONWebKey{Key: rsaKey(t), KeyID: "k"})
	var privJWK map[string]any
	_ = json.Unmarshal(priv, &privJWK)
	for name, extra := range map[string]map[string]any{
		"secret":            {"client_secret": "s"},
		"secret expiry":     {"client_secret_expires_at": 0},
		"basic auth":        {"token_endpoint_auth_method": "client_secret_basic"},
		"no keys":           {"token_endpoint_auth_method": "private_key_jwt"},
		"both jwks":         {"token_endpoint_auth_method": "private_key_jwt", "jwks": map[string]any{"keys": []any{publicJWK(t, "")}}, "jwks_uri": "https://app.example/jwks"},
		"private key":       {"token_endpoint_auth_method": "private_key_jwt", "jwks": map[string]any{"keys": []any{privJWK}}},
		"no redirect_uris":  {"redirect_uris": nil},
		"empty redirects":   {"redirect_uris": []string{}},
		"bad redirect":      {"redirect_uris": []string{"http://app.example/cb"}},
		"wildcard redirect": {"redirect_uris": []string{"https://*.app.example/cb"}},
		"response token":    {"response_types": []string{"token"}},
		"name not string":   {"client_name": 7},
		"http jwks_uri":     {"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "http://app.example/jwks"},
	} {
		if _, v := evaluate(t, f, url, extra); v.Valid || len(v.Violations) == 0 {
			t.Errorf("%s accepted: %+v", name, v)
		}
	}
}

func TestCIMDJWKSURI(t *testing.T) {
	var srv *httptest.Server
	srv, f := fixture(t, map[string]http.HandlerFunc{
		"/jwks": serveJSON(func(*http.Request) []byte {
			b, _ := json.Marshal(map[string]any{"keys": []any{publicJWK(t, "")}})
			return b
		}, nil),
	})
	url := srv.URL + "/client.json"
	m, v := evaluate(t, f, url, map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": srv.URL + "/jwks"})
	if !v.Valid || len(m.Credentials) != 1 || m.JWKSURI != srv.URL+"/jwks" || m.Credentials[0].KID == "" {
		t.Fatalf("jwks_uri: %+v %+v", m, v)
	}
	if m, v := evaluate(t, f, url, map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": srv.URL + "/missing"}); v.Valid || len(m.Credentials) != 0 {
		t.Fatalf("unreachable jwks_uri: %+v", v)
	}
}
