package federation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

var fixedTime = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

// idp is a local OpenID provider over TLS.
type idp struct {
	t         *testing.T
	srv       *httptest.Server
	key       *rsa.PrivateKey
	kid       string
	mu        sync.Mutex
	keys      []jose.JSONWebKey // published JWKS
	claims    func(c map[string]any)
	header    func(h map[jose.HeaderKey]any)
	sign      func(payload []byte) string // overrides signing
	accessTok string
	userinfo  map[string]any
	meta      func(m map[string]any)
	tokenReqs []*http.Request
	forms     []url.Values
	jwksHits  int
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	p := &idp{t: t, kid: "k1", accessTok: "upstream-access-token"}
	p.key, _ = rsa.GenerateKey(rand.Reader, 2048)
	p.keys = []jose.JSONWebKey{{Key: &p.key.PublicKey, KeyID: p.kid, Algorithm: "RS256", Use: "sig"}}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *idp) issuer() string { return p.srv.URL }

func (p *idp) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		m := map[string]any{"issuer": p.issuer(), "authorization_endpoint": p.issuer() + "/authorize",
			"token_endpoint": p.issuer() + "/token", "jwks_uri": p.issuer() + "/jwks", "userinfo_endpoint": p.issuer() + "/userinfo",
			"code_challenge_methods_supported": []string{"S256"}, "id_token_signing_alg_values_supported": []string{"RS256"}}
		if p.meta != nil {
			p.meta(m)
		}
		_ = json.NewEncoder(w).Encode(m)
	case "/jwks":
		p.jwksHits++
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: p.keys})
	case "/token":
		_ = r.ParseForm()
		p.tokenReqs = append(p.tokenReqs, r)
		p.forms = append(p.forms, r.PostForm)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": p.accessTok, "token_type": "Bearer",
			"expires_in": 3600, "refresh_token": "upstream-refresh", "id_token": p.idToken()})
	case "/userinfo":
		if r.Header.Get("Authorization") != "Bearer "+p.accessTok {
			w.WriteHeader(401)
			return
		}
		_ = json.NewEncoder(w).Encode(p.userinfo)
	}
}

func (p *idp) idToken() string {
	c := map[string]any{"iss": p.issuer(), "aud": "client", "sub": "Subject-1", "nonce": "nonce-1",
		"iat": fixedTime.Unix(), "exp": fixedTime.Add(time.Hour).Unix(), "email": "a@example.com", "email_verified": true, "name": "A"}
	if p.claims != nil {
		p.claims(c)
	}
	payload, _ := json.Marshal(c)
	if p.sign != nil {
		return p.sign(payload)
	}
	h := map[jose.HeaderKey]any{"kid": p.kid}
	if p.header != nil {
		p.header(h)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key}, &jose.SignerOptions{ExtraHeaders: h})
	if err != nil {
		p.t.Fatal(err)
	}
	obj, _ := signer.Sign(payload)
	s, _ := obj.CompactSerialize()
	return s
}

func (p *idp) policy() NetworkPolicy {
	pool := x509.NewCertPool()
	pool.AddCert(p.srv.Certificate())
	return FixturePolicy(pool)
}

func (p *idp) providers() *Providers {
	return NewProviders(p.policy(), func() time.Time { return fixedTime })
}

func oidcConfig() Config {
	return Config{Strategy: StrategyOIDC, ClientID: "client", Scopes: []string{"openid", "profile"}, Revision: 1}
}

// startOIDC discovers and returns the exchange input of a fresh attempt.
func (p *idp) exchangeInput(t *testing.T, ps *Providers) ExchangeInput {
	t.Helper()
	cfg := oidcConfig()
	cfg.DiscoveryURL = p.issuer() + "/.well-known/openid-configuration"
	key := CacheKey{TenantID: "ten", ConnectionID: "con", Revision: 1}
	meta, err := ps.Discover(context.Background(), key, cfg.DiscoveryURL, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Issuer = meta.Issuer
	return ExchangeInput{Config: cfg, Cache: key, Endpoints: meta.Endpoints(), Issuer: meta.Issuer,
		CallbackURL: "https://login.example/login/callback", Code: "code-1", CodeVerifier: "verifier-1",
		Nonce: "nonce-1", ClientSecret: "provider-secret", Now: fixedTime}
}

func TestOIDCValidation(t *testing.T) {
	ctx := context.Background()
	t.Run("valid exchange", func(t *testing.T) {
		p := newIDP(t)
		ps := p.providers()
		in := p.exchangeInput(t, ps)
		res, err := ps.For(in.Config).Exchange(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		if res.Profile.Subject != "Subject-1" || *res.Profile.Email != "a@example.com" || !*res.Profile.EmailVerified {
			t.Fatalf("profile %+v", res.Profile)
		}
		if res.Tokens.AccessToken != "upstream-access-token" || res.Tokens.RefreshToken != "upstream-refresh" || res.Tokens.ExpiresAt != fixedTime.Add(time.Hour) {
			t.Fatalf("tokens %+v", res.Tokens)
		}
		f := p.forms[0]
		if f.Get("grant_type") != "authorization_code" || f.Get("code_verifier") != "verifier-1" || f.Get("redirect_uri") != in.CallbackURL || f.Get("client_secret") != "" {
			t.Fatalf("token form %v", f)
		}
		if u, pw, ok := p.tokenReqs[0].BasicAuth(); !ok || u != "client" || pw != "provider-secret" {
			t.Fatal("client_secret_basic not used")
		}
	})
	t.Run("authorization url", func(t *testing.T) {
		p := newIDP(t)
		ps := p.providers()
		in := p.exchangeInput(t, ps)
		raw, err := ps.For(in.Config).AuthorizationURL(StartInput{Config: in.Config, Endpoints: in.Endpoints, CallbackURL: in.CallbackURL,
			State: "st", Nonce: "nonce-1", CodeChallenge: "chal"})
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(raw)
		q := u.Query()
		if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") != "chal" ||
			q.Get("state") != "st" || q.Get("nonce") != "nonce-1" || q.Get("scope") != "openid profile" || q.Get("redirect_uri") != in.CallbackURL || q.Get("prompt") != "" {
			t.Fatalf("authorize %s", raw)
		}
	})
	for name, mutate := range map[string]func(p *idp){
		"wrong iss":        func(p *idp) { p.claims = func(c map[string]any) { c["iss"] = "https://evil.example" } },
		"wrong aud":        func(p *idp) { p.claims = func(c map[string]any) { c["aud"] = "other" } },
		"multi aud no azp": func(p *idp) { p.claims = func(c map[string]any) { c["aud"] = []string{"client", "other"} } },
		"wrong azp":        func(p *idp) { p.claims = func(c map[string]any) { c["azp"] = "other" } },
		"wrong nonce":      func(p *idp) { p.claims = func(c map[string]any) { c["nonce"] = "replayed" } },
		"missing nonce":    func(p *idp) { p.claims = func(c map[string]any) { delete(c, "nonce") } },
		"expired":          func(p *idp) { p.claims = func(c map[string]any) { c["exp"] = fixedTime.Add(-61 * time.Second).Unix() } },
		"future iat":       func(p *idp) { p.claims = func(c map[string]any) { c["iat"] = fixedTime.Add(61 * time.Second).Unix() } },
		"missing sub":      func(p *idp) { p.claims = func(c map[string]any) { delete(c, "sub") } },
		"bad at_hash":      func(p *idp) { p.claims = func(c map[string]any) { c["at_hash"] = "AAAAAAAAAAAAAAAAAAAAAA" } },
		"wrong signature": func(p *idp) {
			other, _ := rsa.GenerateKey(rand.Reader, 2048)
			p.key = other
		},
		"alg none": func(p *idp) {
			p.sign = func(payload []byte) string {
				return b64(`{"alg":"none","kid":"k1"}`) + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
			}
		},
		"HS256": func(p *idp) {
			p.sign = func(payload []byte) string {
				s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
				o, _ := s.Sign(payload)
				c, _ := o.CompactSerialize()
				return c
			}
		},
		"header jku": func(p *idp) { p.header = func(h map[jose.HeaderKey]any) { h["jku"] = "https://evil.example/jwks" } },
		"ambiguous kid": func(p *idp) {
			p.header = func(h map[jose.HeaderKey]any) { delete(h, "kid") }
			other, _ := rsa.GenerateKey(rand.Reader, 2048)
			p.keys = append(p.keys, jose.JSONWebKey{Key: &other.PublicKey, KeyID: "k2", Algorithm: "RS256", Use: "sig"})
		},
		"encryption key": func(p *idp) { p.keys[0].Use = "enc" },
		"mismatched userinfo": func(p *idp) {
			p.claims = func(c map[string]any) { delete(c, "email") }
			p.userinfo = map[string]any{"sub": "someone-else", "email": "x@example.com"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := newIDP(t)
			ps := p.providers()
			in := p.exchangeInput(t, ps)
			mutate(p)
			if _, err := ps.For(in.Config).Exchange(ctx, in); !errors.Is(err, ErrProviderResponse) {
				t.Fatalf("err %v", err)
			}
			if len(p.tokenReqs) != 1 {
				t.Fatalf("token requests %d (no retry allowed)", len(p.tokenReqs))
			}
		})
	}
	t.Run("skew tolerated", func(t *testing.T) {
		p := newIDP(t)
		ps := p.providers()
		in := p.exchangeInput(t, ps)
		p.claims = func(c map[string]any) {
			c["exp"] = fixedTime.Add(-59 * time.Second).Unix()
			c["iat"] = fixedTime.Add(59 * time.Second).Unix()
			c["at_hash"] = atHash(p.accessTok)
		}
		if _, err := ps.For(in.Config).Exchange(ctx, in); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("userinfo merges with matching sub", func(t *testing.T) {
		p := newIDP(t)
		ps := p.providers()
		in := p.exchangeInput(t, ps)
		p.claims = func(c map[string]any) { delete(c, "email"); delete(c, "email_verified") }
		p.userinfo = map[string]any{"sub": "Subject-1", "email": "u@example.com", "email_verified": false}
		res, err := ps.For(in.Config).Exchange(ctx, in)
		if err != nil || *res.Profile.Email != "u@example.com" || *res.Profile.EmailVerified {
			t.Fatalf("%+v %v", res.Profile, err)
		}
	})
	t.Run("unknown kid rotation coalesced", func(t *testing.T) {
		p := newIDP(t)
		ps := p.providers()
		in := p.exchangeInput(t, ps)
		if _, err := ps.For(in.Config).Exchange(ctx, in); err != nil {
			t.Fatal(err)
		}
		before := p.jwksHits
		rotated, _ := rsa.GenerateKey(rand.Reader, 2048)
		p.mu.Lock()
		p.key, p.kid = rotated, "k2"
		p.keys = append(p.keys, jose.JSONWebKey{Key: &rotated.PublicKey, KeyID: "k2", Algorithm: "RS256", Use: "sig"})
		p.mu.Unlock()
		var wg sync.WaitGroup
		errs := make(chan error, 4)
		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := ps.For(in.Config).Exchange(ctx, in)
				errs <- err
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		if p.jwksHits-before != 1 {
			t.Fatalf("unknown kid refreshed %d times", p.jwksHits-before)
		}
		// A kid that stays unknown refreshes once and fails.
		p.mu.Lock()
		p.kid = "never-published"
		p.mu.Unlock()
		if _, err := ps.For(in.Config).Exchange(ctx, in); !errors.Is(err, ErrProviderResponse) {
			t.Fatalf("unknown kid err %v", err)
		}
	})
	t.Run("discovery checks", func(t *testing.T) {
		for name, mutate := range map[string]func(m map[string]any){
			"issuer mismatch": func(m map[string]any) { m["issuer"] = "https://evil.example" },
			"no S256":         func(m map[string]any) { m["code_challenge_methods_supported"] = []string{"plain"} },
			"no RS256":        func(m map[string]any) { m["id_token_signing_alg_values_supported"] = []string{"HS256"} },
			"private jwks":    func(m map[string]any) { m["jwks_uri"] = "https://10.0.0.1/jwks" },
			"bad auth method": func(m map[string]any) { m["token_endpoint_auth_methods_supported"] = []string{"private_key_jwt"} },
		} {
			t.Run(name, func(t *testing.T) {
				p := newIDP(t)
				p.meta = mutate
				ps := p.providers()
				expected := ""
				if name == "issuer mismatch" {
					expected = p.issuer()
					p.meta = nil
					p.meta = func(m map[string]any) { m["issuer"] = "https://evil.example" }
				}
				_, err := ps.Discover(ctx, CacheKey{TenantID: "t", ConnectionID: "c", Revision: 1}, p.issuer()+"/.well-known/openid-configuration", expected)
				if !errors.Is(err, ErrProviderResponse) {
					t.Fatalf("err %v", err)
				}
			})
		}
		p := newIDP(t)
		p.meta = func(m map[string]any) { m["token_endpoint_auth_methods_supported"] = []string{"client_secret_post"} }
		meta, err := p.providers().Discover(ctx, CacheKey{TenantID: "t", ConnectionID: "c", Revision: 1}, p.issuer()+"/.well-known/openid-configuration", "")
		if err != nil || meta.Endpoints().TokenAuthMethod != "client_secret_post" {
			t.Fatalf("post selection %v %v", meta, err)
		}
	})
	t.Run("cache bounds", func(t *testing.T) {
		c := newTTLCache[string](3, time.Minute, func() time.Time { return fixedTime })
		for _, k := range []string{"a", "b", "c", "d"} {
			c.put(k, k)
		}
		if _, ok := c.get("a"); ok || c.len() != 3 {
			t.Fatal("cache exceeded its bound")
		}
		later := newTTLCache[string](3, 10*time.Minute, func() time.Time { return fixedTime })
		if later.ttl != maxCacheTTL {
			t.Fatalf("ttl %v exceeds five minutes", later.ttl)
		}
		now := fixedTime
		exp := newTTLCache[string](3, time.Minute, func() time.Time { return now })
		exp.put("k", "v")
		now = now.Add(time.Minute)
		if _, ok := exp.get("k"); ok {
			t.Fatal("expired entry used")
		}
	})
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func atHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}
