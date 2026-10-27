package federation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type microsoftKeyFixture struct {
	mu    sync.Mutex
	keys  []map[string]any
	paths []string
	srv   *httptest.Server
	now   time.Time
}

func newMicrosoftKeyFixture(t *testing.T) (*microsoftKeyFixture, *Providers, *rsa.PrivateKey) {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &microsoftKeyFixture{now: fixedTime}
	f.keys = []map[string]any{microsoftTestJWK(t, private, "key-1", testMicrosoftTemplate)}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.paths = append(f.paths, r.URL.RequestURI())
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": f.keys})
	}))
	t.Cleanup(f.srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(f.srv.Certificate())
	ps := NewProviders(FixturePolicy(roots), func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now }).WithMicrosoftFixture(MicrosoftOverride{AuthorityBaseURL: f.srv.URL, JWKSURL: f.srv.URL + "/keys"})
	return f, ps, private
}

func microsoftTestJWK(t *testing.T, private *rsa.PrivateKey, kid, issuer string) map[string]any {
	t.Helper()
	raw, err := json.Marshal(jose.JSONWebKey{Key: &private.PublicKey, KeyID: kid, Use: "sig", Algorithm: "RS256"})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	out["issuer"] = issuer
	return out
}

func TestMicrosoftSigningKey(t *testing.T) {
	ctx := context.Background()
	cache := CacheKey{TenantID: "local", ConnectionID: "connection", Revision: 1}
	issuer := testMicrosoftBase + "/" + testMicrosoftTenant + "/v2.0"
	for _, tc := range []struct {
		name, authority, tenant, tokenIssuer, keyIssuer string
		bad                                             bool
	}{
		{"template", "organizations", testMicrosoftTenant, issuer, testMicrosoftTemplate, false},
		{"concrete", "organizations", testMicrosoftTenant, issuer, issuer, false},
		{"personal", "consumers", testMicrosoftConsumer, testMicrosoftBase + "/" + testMicrosoftConsumer + "/v2.0", testMicrosoftTemplate, false},
		{"directory GUID", testMicrosoftTenant, testMicrosoftTenant, issuer, testMicrosoftTemplate, false},
		{"directory DNS", "example.onmicrosoft.com", testMicrosoftTenant, issuer, issuer, false},
		{"consumer key denies work", "organizations", testMicrosoftTenant, issuer, testMicrosoftBase + "/" + testMicrosoftConsumer + "/v2.0", true},
		{"wrong key tenant", "organizations", testMicrosoftTenant, issuer, testMicrosoftBase + "/" + testMicrosoftOtherTenant + "/v2.0", true},
		{"missing key issuer", "organizations", testMicrosoftTenant, issuer, "", true},
		{"arbitrary key template", "organizations", testMicrosoftTenant, issuer, "https://attacker.invalid/{tenantid}/v2.0", true},
		{"wrong token issuer", "organizations", testMicrosoftTenant, "https://attacker.invalid/jwks", testMicrosoftTemplate, true},
		{"URL tenant", "organizations", "https://attacker.invalid/jwks", issuer, testMicrosoftTemplate, true},
		{"uppercase tenant", "organizations", "AAAAAAAA-bbbb-cccc-dddd-eeeeeeeeeeee", issuer, testMicrosoftTemplate, true},
		{"organizations denies consumer", "organizations", testMicrosoftConsumer, testMicrosoftBase + "/" + testMicrosoftConsumer + "/v2.0", testMicrosoftTemplate, true},
		{"consumer denies work", "consumers", testMicrosoftTenant, issuer, testMicrosoftTemplate, true},
		{"directory denies wrong tenant", testMicrosoftOtherTenant, testMicrosoftTenant, issuer, testMicrosoftTemplate, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, ps, private := newMicrosoftKeyFixture(t)
			f.keys[0]["issuer"] = tc.keyIssuer
			key, err := ps.microsoftKey(ctx, cache, tc.authority, f.srv.URL+"/keys", "key-1", tc.tokenIssuer, tc.tenant)
			if tc.bad {
				if !errors.Is(err, ErrProviderResponse) || key != nil {
					t.Fatalf("key=%v err=%v", key, err)
				}
			} else {
				if err != nil || key == nil {
					t.Fatalf("key=%v err=%v", key, err)
				}
				retained, err := ps.microsoftSigningKey(ctx, cache, tc.authority, f.srv.URL+"/keys", "key-1", tc.tokenIssuer, tc.tenant)
				if err != nil || retained.Issuer != tc.keyIssuer {
					t.Fatalf("retained issuer: %+v, %v", retained, err)
				}
				signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: private}, nil)
				signed, _ := signer.Sign([]byte("signed payload"))
				if _, err := signed.Verify(key); err != nil {
					t.Fatal(err)
				}
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			for _, path := range f.paths {
				if path != "/keys" {
					t.Fatalf("untrusted claims changed path: %v", f.paths)
				}
			}
		})
	}
	for name, mutate := range map[string]func(*microsoftKeyFixture){
		"missing kid":            func(f *microsoftKeyFixture) { delete(f.keys[0], "kid") },
		"nonstring issuer":       func(f *microsoftKeyFixture) { f.keys[0]["issuer"] = []string{testMicrosoftTemplate} },
		"missing issuer":         func(f *microsoftKeyFixture) { delete(f.keys[0], "issuer") },
		"duplicate eligible kid": func(f *microsoftKeyFixture) { f.keys = append(f.keys, f.keys[0]) },
		"none algorithm":         func(f *microsoftKeyFixture) { f.keys[0]["alg"] = "none" },
		"HS256 algorithm":        func(f *microsoftKeyFixture) { f.keys[0]["alg"] = "HS256" },
		"wrong use":              func(f *microsoftKeyFixture) { f.keys[0]["use"] = "enc" },
		"empty JWKS":             func(f *microsoftKeyFixture) { f.keys = nil },
		"too many keys": func(f *microsoftKeyFixture) {
			k := f.keys[0]
			f.keys = make([]map[string]any, 101)
			for i := range f.keys {
				f.keys[i] = k
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, ps, _ := newMicrosoftKeyFixture(t)
			mutate(f)
			if key, err := ps.microsoftKey(ctx, cache, "organizations", f.srv.URL+"/keys", "key-1", issuer, testMicrosoftTenant); !errors.Is(err, ErrProviderResponse) || key != nil {
				t.Fatalf("key=%v err=%v", key, err)
			}
		})
	}
	t.Run("kid required and bounded", func(t *testing.T) {
		f, ps, _ := newMicrosoftKeyFixture(t)
		for _, kid := range []string{"", "bad\x00kid", "bad\nkid", strings.Repeat("k", 1025)} {
			if _, err := ps.microsoftKey(ctx, cache, "organizations", f.srv.URL+"/keys", kid, issuer, testMicrosoftTenant); !errors.Is(err, ErrProviderResponse) {
				t.Fatalf("kid %q: %v", kid, err)
			}
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.paths) != 0 {
			t.Fatalf("invalid kid fetched keys: %v", f.paths)
		}
	})
	t.Run("ineligible duplicate and per token issuer check", func(t *testing.T) {
		f, ps, private := newMicrosoftKeyFixture(t)
		f.keys = []map[string]any{microsoftTestJWK(t, private, "key-1", issuer), microsoftTestJWK(t, private, "key-1", testMicrosoftBase+"/"+testMicrosoftConsumer+"/v2.0")}
		if _, err := ps.microsoftKey(ctx, cache, "organizations", f.srv.URL+"/keys", "key-1", issuer, testMicrosoftTenant); err != nil {
			t.Fatal(err)
		}
		if _, err := ps.microsoftKey(ctx, cache, "organizations", f.srv.URL+"/keys", "key-1", testMicrosoftBase+"/"+testMicrosoftOtherTenant+"/v2.0", testMicrosoftOtherTenant); !errors.Is(err, ErrProviderResponse) {
			t.Fatalf("cached key bypassed tenant check: %v", err)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.paths) != 1 {
			t.Fatalf("issuer mismatch refreshed keys: %v", f.paths)
		}
	})
	t.Run("rollover expiry isolation and unknown kid refresh", func(t *testing.T) {
		f, ps, private := newMicrosoftKeyFixture(t)
		lookup := func(c CacheKey, authority, path, kid string) error {
			_, err := ps.microsoftKey(ctx, c, authority, f.srv.URL+path, kid, issuer, testMicrosoftTenant)
			return err
		}
		if err := lookup(cache, "organizations", "/keys", "key-1"); err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		f.keys = append(f.keys, microsoftTestJWK(t, private, "key-2", testMicrosoftTemplate))
		f.mu.Unlock()
		var wg sync.WaitGroup
		for range 24 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := lookup(cache, "organizations", "/keys", "key-2"); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		f.mu.Lock()
		hits := len(f.paths)
		f.mu.Unlock()
		if hits != 2 {
			t.Fatalf("rollover fetches=%d want 2", hits)
		}
		if err := lookup(cache, "organizations", "/keys", "absent"); !errors.Is(err, ErrProviderResponse) {
			t.Fatalf("unknown kid %v", err)
		}
		f.mu.Lock()
		hits = len(f.paths)
		f.mu.Unlock()
		if hits != 3 {
			t.Fatalf("unknown kid fetches=%d want 3", hits)
		}
		for _, c := range []CacheKey{{TenantID: "other", ConnectionID: "connection", Revision: 1}, {TenantID: "local", ConnectionID: "other", Revision: 1}, {TenantID: "local", ConnectionID: "connection", Revision: 2}} {
			if err := lookup(c, "organizations", "/keys", "key-1"); err != nil {
				t.Fatal(err)
			}
		}
		if err := lookup(cache, "example.com", "/keys", "key-1"); err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		hits = len(f.paths)
		f.now = f.now.Add(5 * time.Minute)
		f.mu.Unlock()
		if hits != 7 {
			t.Fatalf("isolation fetches=%d want 7", hits)
		}
		if err := lookup(cache, "organizations", "/keys", "key-1"); err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.paths) != 8 {
			t.Fatalf("expiry fetches=%d want 8", len(f.paths))
		}
	})
	t.Run("JWKS URL isolation", func(t *testing.T) {
		f, ps, _ := newMicrosoftKeyFixture(t)
		ps.WithMicrosoftFixture(MicrosoftOverride{AuthorityBaseURL: f.srv.URL})
		for _, path := range []string{"/common/discovery/v2.0/keys", "/organizations/discovery/v2.0/keys", "/common/discovery/v2.0/keys"} {
			if _, err := ps.microsoftKey(ctx, cache, "organizations", f.srv.URL+path, "key-1", issuer, testMicrosoftTenant); err != nil {
				t.Fatal(err)
			}
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.paths) != 2 || f.paths[0] != "/common/discovery/v2.0/keys" || f.paths[1] != "/organizations/discovery/v2.0/keys" {
			t.Fatalf("JWKS isolation requests: %v", f.paths)
		}
	})

	t.Run("JWKS cannot escape pinned policy", func(t *testing.T) {
		f, ps, _ := newMicrosoftKeyFixture(t)
		for _, endpoint := range []string{f.srv.URL + "/other", testMicrosoftBase + "/evil/discovery/v2.0/keys", "https://attacker.invalid/keys"} {
			if _, err := ps.microsoftKey(ctx, cache, "organizations", endpoint, "key-1", issuer, testMicrosoftTenant); !errors.Is(err, ErrProviderResponse) {
				t.Fatalf("endpoint %q: %v", endpoint, err)
			}
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.paths) != 0 {
			t.Fatalf("unpinned path fetched: %v", f.paths)
		}
	})
}
