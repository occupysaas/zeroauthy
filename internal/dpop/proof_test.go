package dpop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"math/big"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func fixture(t *testing.T) (*Service, tenant.Resolved, *ecdsa.PrivateKey, time.Time) {
	t.Helper()
	now := time.Unix(1900000000, 0)
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	master := make([]byte, 32)
	rand.Read(master)
	w, e := keys.NewLocalWrapper(master)
	if e != nil {
		t.Fatal(e)
	}
	return &Service{Store: memory.New(), Wrapper: w, Now: func() time.Time { return now }}, tenant.Resolved{Tenant: &store.Tenant{ID: "tenant"}, Host: "tenant.example"}, k, now
}
func signed(t *testing.T, key any, alg jose.SignatureAlgorithm, header map[jose.HeaderKey]any, claims map[string]any) string {
	t.Helper()
	o := &jose.SignerOptions{}
	for k, v := range header {
		o.WithHeader(k, v)
	}
	s, e := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, o)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(claims)
	v, e := s.Sign(b)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := v.CompactSerialize()
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func proof(t *testing.T, k *ecdsa.PrivateKey, now time.Time, jti, nonce string) string {
	return signed(t, k, jose.ES256, map[jose.HeaderKey]any{"typ": "dpop+jwt", "jwk": jose.JSONWebKey{Key: &k.PublicKey}}, map[string]any{"htm": "POST", "htu": "https://tenant.example/oauth/token", "iat": now.Unix(), "jti": jti, "nonce": nonce})
}
func TestProofValidation(t *testing.T) {
	s, res, k, now := fixture(t)
	for _, tc := range []struct {
		name string
		edit func(map[jose.HeaderKey]any, map[string]any)
		want bool
	}{
		{"valid", func(h map[jose.HeaderKey]any, c map[string]any) {}, true},
		{"wrong type", func(h map[jose.HeaderKey]any, c map[string]any) { h["typ"] = "JWT" }, false},
		{"private key", func(h map[jose.HeaderKey]any, c map[string]any) { h["jwk"] = jose.JSONWebKey{Key: k} }, false},
		{"remote key", func(h map[jose.HeaderKey]any, c map[string]any) { h["jku"] = "https://evil.example/keys" }, false},
		{"critical", func(h map[jose.HeaderKey]any, c map[string]any) { h["crit"] = []string{"foo"}; h["foo"] = true }, false},
		{"wrong method", func(h map[jose.HeaderKey]any, c map[string]any) { c["htm"] = "GET" }, false},
		{"wrong origin", func(h map[jose.HeaderKey]any, c map[string]any) { c["htu"] = "https://other.example/oauth/token" }, false},
		{"fragment", func(h map[jose.HeaderKey]any, c map[string]any) { c["htu"] = "https://tenant.example/oauth/token#x" }, false},
		{"credentials", func(h map[jose.HeaderKey]any, c map[string]any) { c["htu"] = "https://u@tenant.example/oauth/token" }, false},
		{"normalization", func(h map[jose.HeaderKey]any, c map[string]any) {
			c["htu"] = "https://TENANT.example:443/oauth/%74oken?x=1"
		}, true},
		{"old", func(h map[jose.HeaderKey]any, c map[string]any) { c["iat"] = now.Add(-61 * time.Second).Unix() }, false},
		{"future", func(h map[jose.HeaderKey]any, c map[string]any) { c["iat"] = now.Add(6 * time.Second).Unix() }, false},
		{"fraction", func(h map[jose.HeaderKey]any, c map[string]any) { c["iat"] = float64(now.Unix()) + .5 }, false},
		{"missing jti", func(h map[jose.HeaderKey]any, c map[string]any) { delete(c, "jti") }, false},
		{"long jti", func(h map[jose.HeaderKey]any, c map[string]any) { c["jti"] = strings.Repeat("a", 201) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := map[jose.HeaderKey]any{"typ": "dpop+jwt", "jwk": jose.JSONWebKey{Key: &k.PublicKey}}
			c := map[string]any{"htm": "POST", "htu": "https://tenant.example/oauth/token", "iat": now.Unix(), "jti": tc.name}
			tc.edit(h, c)
			r := httptest.NewRequest("POST", "https://ignored.local/oauth/token?q=x", nil)
			r.Header.Set("DPoP", signed(t, k, jose.ES256, h, c))
			p, e := s.Verify(context.Background(), r, res, AuthorizationServer, false, "", "")
			if (e == nil) != tc.want {
				t.Fatalf("success=%v error=%v", p != nil, e)
			}
		})
	}
	for _, bad := range []string{"bad", strings.Repeat("x", 16385), proof(t, k, now, "comma", "") + ","} {
		r := httptest.NewRequest("POST", "https://tenant.example/oauth/token", nil)
		r.Header.Set("DPoP", bad)
		if _, e := s.Verify(r.Context(), r, res, AuthorizationServer, false, "", ""); e == nil {
			t.Fatal("invalid accepted")
		}
	}
	r := httptest.NewRequest("POST", "https://tenant.example/oauth/token", nil)
	r.Header["Dpop"] = []string{proof(t, k, now, "repeat", ""), proof(t, k, now, "repeat2", "")}
	if _, e := s.Verify(r.Context(), r, res, AuthorizationServer, false, "", ""); e == nil {
		t.Fatal("duplicate header accepted")
	}
}
func TestProofRSA(t *testing.T) {
	s, res, _, now := fixture(t)
	for _, bits := range []int{1024, 2048} {
		k, e := rsa.GenerateKey(rand.Reader, bits)
		if e != nil {
			t.Fatal(e)
		}
		r := httptest.NewRequest("POST", "https://tenant.example/oauth/token", nil)
		r.Header.Set("DPoP", signed(t, k, jose.RS256, map[jose.HeaderKey]any{"typ": "dpop+jwt", "jwk": jose.JSONWebKey{Key: &k.PublicKey}}, map[string]any{"htm": "POST", "htu": "https://tenant.example/oauth/token", "iat": now.Unix(), "jti": "rsa"}))
		_, de := s.Verify(r.Context(), r, res, AuthorizationServer, false, "", "")
		if (de == nil) != (bits == 2048) {
			t.Fatalf("bits=%d err=%v", bits, de)
		}
	}
}
func TestNonceReplay(t *testing.T) {
	s, res, k, now := fixture(t)
	r := httptest.NewRequest("POST", "https://tenant.example/oauth/token", nil)
	r.Header.Set("DPoP", proof(t, k, now, "challenge", ""))
	_, e := s.Verify(r.Context(), r, res, AuthorizationServer, true, "", "")
	if e == nil || e.Code != "use_dpop_nonce" || e.Nonce == "" {
		t.Fatal("missing challenge")
	}
	nonce := e.Nonce
	r.Header.Set("DPoP", proof(t, k, now, "retry", nonce))
	p, e := s.Verify(r.Context(), r, res, AuthorizationServer, true, "", "")
	if e != nil || p.JKT == "" {
		t.Fatalf("retry error %v", e)
	}
	copy := *s
	if _, e := copy.Verify(r.Context(), r, res, AuthorizationServer, true, "", ""); e == nil || e.Code != "invalid_dpop_proof" {
		t.Fatal("replay accepted")
	}
	r.Header.Set("DPoP", proof(t, k, now, "domain", nonce))
	if _, e := s.Verify(r.Context(), r, res, UserInfo, true, "", ""); e == nil || e.Code != "use_dpop_nonce" {
		t.Fatal("cross domain nonce accepted")
	}
	s.Now = func() time.Time { return now.Add(time.Minute) }
	r.Header.Set("DPoP", proof(t, k, now.Add(time.Minute), "expired", nonce))
	if _, e := s.Verify(r.Context(), r, res, AuthorizationServer, true, "", ""); e == nil || e.Code != "use_dpop_nonce" {
		t.Fatal("expired nonce accepted")
	}
}
func TestConcurrentProof(t *testing.T) {
	s, res, k, now := fixture(t)
	raw := proof(t, k, now, "one", "")
	var wg sync.WaitGroup
	wins := make(chan bool, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest("POST", "https://tenant.example/oauth/token", nil)
			r.Header.Set("DPoP", raw)
			_, e := s.Verify(r.Context(), r, res, AuthorizationServer, false, "", "")
			wins <- e == nil
		}()
	}
	wg.Wait()
	close(wins)
	n := 0
	for win := range wins {
		if win {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("wins %d", n)
	}
}

func TestMalformedProofClaims(t *testing.T) {
	s, res, k, now := fixture(t)
	for _, body := range []string{
		`{"htm":"POST","htu":"https://tenant.example/oauth/token","jti":"x","iat":1900000000,"iat":1900000000}`,
		`{"HTM":"POST","HTU":"https://tenant.example/oauth/token","JTI":"x","IAT":1900000000}`,
		`{"htm":"POST","htu":"https://tenant.example/oauth/token","jti":"x","iat":"1900000000"}`,
	} {
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k}, (&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", jose.JSONWebKey{Key: &k.PublicKey}))
		obj, _ := signer.Sign([]byte(body))
		raw, _ := obj.CompactSerialize()
		r := httptest.NewRequest("POST", res.Origin()+"/oauth/token", nil)
		r.Header.Set("DPoP", raw)
		if _, e := s.Verify(r.Context(), r, res, AuthorizationServer, false, "", ""); e == nil {
			t.Fatal("malformed claims accepted")
		}
	}
	_ = now
}

type brokenStore struct{ store.Store }

func (b brokenStore) DPoP() store.DPoP { return brokenProof{} }

type brokenProof struct{}

func (brokenProof) UseProof(context.Context, string, string, string, string, time.Time, time.Time) error {
	return errors.New("storage unavailable")
}
func (brokenProof) PurgeBefore(context.Context, time.Time, int) (int, error) {
	return 0, errors.New("storage unavailable")
}
func TestProofInfrastructureFailure(t *testing.T) {
	s, res, k, now := fixture(t)
	s.Store = brokenStore{s.Store}
	r := httptest.NewRequest("POST", res.Origin()+"/oauth/token", nil)
	r.Header.Set("DPoP", proof(t, k, now, "failure", ""))
	if _, e := s.Verify(r.Context(), r, res, AuthorizationServer, false, "", ""); e == nil || !e.Internal {
		t.Fatal("storage failure accepted")
	}
	s.Wrapper = nil
	r.Header.Set("DPoP", proof(t, k, now, "noncefail", ""))
	if _, e := s.Verify(r.Context(), r, res, AuthorizationServer, true, "", ""); e == nil || !e.Internal {
		t.Fatal("wrapper failure accepted")
	}
}
func TestProofKeyConfusion(t *testing.T) {
	s, res, k, now := fixture(t)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	for _, tc := range []struct {
		name string
		key  any
		alg  jose.SignatureAlgorithm
		jwk  jose.JSONWebKey
	}{{"wrong signature", other, jose.ES256, jose.JSONWebKey{Key: &k.PublicKey}}, {"wrong curve", p384, jose.ES384, jose.JSONWebKey{Key: &p384.PublicKey}}, {"symmetric", make([]byte, 32), jose.HS256, jose.JSONWebKey{Key: make([]byte, 32)}}, {"oversized RSA", k, jose.ES256, jose.JSONWebKey{Key: &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 4097), E: 65537}}}} {
		r := httptest.NewRequest("POST", res.Origin()+"/oauth/token", nil)
		r.Header.Set("DPoP", signed(t, tc.key, tc.alg, map[jose.HeaderKey]any{"typ": "dpop+jwt", "jwk": tc.jwk}, map[string]any{"htm": "POST", "htu": res.Origin() + "/oauth/token", "jti": tc.name, "iat": now.Unix()}))
		if _, e := s.Verify(r.Context(), r, res, AuthorizationServer, false, "", ""); e == nil {
			t.Fatal(tc.name + " accepted")
		}
	}
}
func TestUniqueProofJSON(t *testing.T) {
	for _, s := range []string{`{"jwk":{"x":"one","x":"two"}}`, `{"alg":"ES256","alg":"none"}`, `{"nested":[{"iat":1,"iat":2}]}`, `{"a":1} {"a":2}`} {
		if uniqueJSON([]byte(s)) {
			t.Fatal("ambiguous JSON accepted")
		}
	}
}
func TestNonceIsolation(t *testing.T) {
	s, res, k, now := fixture(t)
	r := httptest.NewRequest("POST", res.Origin()+"/oauth/token", nil)
	r.Header.Set("DPoP", proof(t, k, now, "challenge2", ""))
	_, failure := s.Verify(r.Context(), r, res, UserInfo, true, "", "")
	nonce := failure.Nonce
	for _, which := range []string{"AS", "tenant", "key", "origin"} {
		copyRes := res
		copyKey := k
		domain := UserInfo
		switch which {
		case "AS":
			domain = AuthorizationServer
		case "tenant":
			copyT := *res.Tenant
			copyT.ID = "other"
			copyRes.Tenant = &copyT
		case "key":
			copyKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case "origin":
			copyRes.Host = "other.example"
		}
		r.Header.Set("DPoP", proof(t, copyKey, now, "isolation-"+which, nonce))
		_, e := s.Verify(r.Context(), r, copyRes, domain, true, "", "")
		if e == nil {
			t.Fatal("nonce isolation failed")
		}
	}
}
