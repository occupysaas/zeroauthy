package federation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const testMicrosoftClient = "01234567-89ab-cdef-0123-456789abcdef"
const testMicrosoftOID = "abcdef01-2345-6789-abcd-ef0123456789"

type microsoftAdapterFixture struct {
	*idp
	authority, tenant, keyIssuer string
	mutate                       func(map[string]any)
	failure                      string
	paths                        []string
}

func newMicrosoftAdapterFixture(t *testing.T, authority, tenant string) (*microsoftAdapterFixture, *Providers, ExchangeInput) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &microsoftAdapterFixture{idp: &idp{t: t, key: key, kid: "key-1", accessTok: "microsoft-sensitive-access"}, authority: authority, tenant: tenant, keyIssuer: testMicrosoftTemplate}
	f.idp.claims = func(c map[string]any) {
		c["iss"] = testMicrosoftBase + "/" + f.tenant + "/v2.0"
		c["tid"], c["ver"], c["oid"], c["aud"] = f.tenant, "2.0", strings.ToUpper(testMicrosoftOID), testMicrosoftClient
		c["sub"] = "CaseSensitive-Personal-Sub"
		if f.mutate != nil {
			f.mutate(c)
		}
	}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.paths = append(f.paths, r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/" + authority + "/v2.0/.well-known/openid-configuration":
			issuer := testMicrosoftTemplate
			if authority != "consumers" && authority != "organizations" {
				issuer = testMicrosoftBase + "/" + tenant + "/v2.0"
			}
			_ = json.NewEncoder(w).Encode(microsoftTestMetadata(authority, issuer))
		case "/keys":
			f.jwksHits++
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{microsoftTestJWK(t, key, "key-1", f.keyIssuer)}})
		case "/" + authority + "/oauth2/v2.0/token":
			_ = r.ParseForm()
			f.tokenReqs = append(f.tokenReqs, r)
			f.forms = append(f.forms, r.PostForm)
			if f.failure == "denied" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"access_denied","error_description":"sensitive-provider-message microsoft-sensitive-access"}`))
				return
			}
			if f.failure == "timeout" {
				<-r.Context().Done()
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": f.accessTok, "token_type": "Bearer", "expires_in": 3600, "id_token": f.idToken()})
		default:
			t.Errorf("unexpected request: %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(f.srv.Certificate())
	ps := NewProviders(FixturePolicy(roots), func() time.Time { return fixedTime }).WithMicrosoftFixture(MicrosoftOverride{AuthorityBaseURL: f.srv.URL, JWKSURL: f.srv.URL + "/keys"})
	strategy, opts := "waad", `,"tenant_domain":"`+authority+`"`
	if authority == "consumers" {
		strategy, opts = "windowslive", ""
	}
	if authority == "organizations" {
		opts = `,"useCommonEndpoint":true`
	}
	cfg, err := ParseConfig(configSpec(t, strategy, `{"client_id":"`+testMicrosoftClient+`","client_secret":"provider-secret"`+opts+`}`))
	if err != nil {
		t.Fatal(err)
	}
	cache := CacheKey{TenantID: "local", ConnectionID: "connection", Revision: 1}
	meta, err := ps.DiscoverMicrosoft(context.Background(), cache, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return f, ps, ExchangeInput{Config: cfg, Cache: cache, Endpoints: meta.Endpoints(), Issuer: meta.Issuer, CallbackURL: "https://login.example/login/callback", Code: "code-1", CodeVerifier: "verifier-1", Nonce: "nonce-1", ClientSecret: "provider-secret", Now: fixedTime}
}

func TestMicrosoftAdapter(t *testing.T) {
	for _, tc := range []struct{ name, authority, tenant, want string }{
		{"personal", "consumers", testMicrosoftConsumer, "CaseSensitive-Personal-Sub"},
		{"work", testMicrosoftTenant, testMicrosoftTenant, testMicrosoftOID},
		{"school", "school.onmicrosoft.com", testMicrosoftTenant, testMicrosoftOID},
		{"organization A", "organizations", testMicrosoftTenant, testMicrosoftTenant + ":" + testMicrosoftOID},
		{"organization B", "organizations", testMicrosoftOtherTenant, testMicrosoftOtherTenant + ":" + testMicrosoftOID},
		{"guest resource directory", "resource.example", testMicrosoftTenant, testMicrosoftOID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, ps, in := newMicrosoftAdapterFixture(t, tc.authority, tc.tenant)
			if tc.name == "guest resource directory" {
				f.mutate = func(c map[string]any) { c["idp"] = "https://sts.windows.net/" + testMicrosoftOtherTenant + "/" }
			}
			raw, err := ps.For(in.Config).AuthorizationURL(StartInput{Config: in.Config, Endpoints: in.Endpoints, CallbackURL: in.CallbackURL, State: "state-1", Nonce: in.Nonce, CodeChallenge: "challenge-1"})
			if err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(raw)
			want := url.Values{"response_type": {"code"}, "response_mode": {"query"}, "client_id": {testMicrosoftClient}, "redirect_uri": {in.CallbackURL}, "scope": {"openid profile email"}, "state": {"state-1"}, "nonce": {"nonce-1"}, "code_challenge": {"challenge-1"}, "code_challenge_method": {"S256"}}
			if u.Scheme+"://"+u.Host+u.Path != f.srv.URL+"/"+tc.authority+"/oauth2/v2.0/authorize" || u.Query().Encode() != want.Encode() {
				t.Fatalf("authorization %s", raw)
			}
			// An accidental UserInfo/Graph path in a snapshot must still never be used.
			in.Endpoints.UserInfoURL = f.srv.URL + "/forbidden-userinfo"
			f.mutate = chainMicrosoftClaims(f.mutate, func(c map[string]any) { delete(c, "email"); c["at_hash"] = atHash(f.accessTok) })
			result, err := ps.For(in.Config).Exchange(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			if result.Profile.Subject != tc.want || result.Profile.Email != nil || result.Tokens.AccessToken != "microsoft-sensitive-access" {
				t.Fatalf("unexpected result %+v", result.Profile)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.tokenReqs) != 1 {
				t.Fatalf("token requests %d", len(f.tokenReqs))
			}
			form := f.forms[0]
			if form.Encode() != (url.Values{"grant_type": {"authorization_code"}, "code": {"code-1"}, "redirect_uri": {in.CallbackURL}, "code_verifier": {"verifier-1"}, "client_id": {testMicrosoftClient}, "client_secret": {"provider-secret"}}).Encode() || f.tokenReqs[0].Method != "POST" || f.tokenReqs[0].Header.Get("Authorization") != "" {
				t.Fatalf("token POST/authentication %+v", form)
			}
		})
	}
	for name, mutate := range map[string]func(*microsoftAdapterFixture, *ExchangeInput){
		"wrong version": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.mutate = func(c map[string]any) { c["ver"] = "1.0" }
		},
		"missing version": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.mutate = func(c map[string]any) { delete(c, "ver") }
		},
		"malformed tid": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.mutate = func(c map[string]any) { c["tid"] = "https://attacker.invalid" }
		},
		"uppercase tid": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.mutate = func(c map[string]any) { c["tid"] = strings.ToUpper(testMicrosoftTenant) }
		},
		"missing tid": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.mutate = func(c map[string]any) { delete(c, "tid") }
		},
		"wrong issuer": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.mutate = func(c map[string]any) { c["iss"] = "https://attacker.invalid/token-secret" }
		},
		"wrong key issuer": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.keyIssuer = testMicrosoftBase + "/" + testMicrosoftConsumer + "/v2.0"
		},
		"consumer through waad":      func(f *microsoftAdapterFixture, _ *ExchangeInput) { f.tenant = testMicrosoftConsumer },
		"wrong pinned DNS directory": func(f *microsoftAdapterFixture, _ *ExchangeInput) { f.tenant = testMicrosoftOtherTenant },
		"missing oid": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.mutate = func(c map[string]any) { delete(c, "oid") }
		},
		"malformed oid": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.mutate = func(c map[string]any) { c["oid"] = "not-a-guid" }
		},
		"wrong aud": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.mutate = func(c map[string]any) { c["aud"] = "other" }
		},
		"multi aud missing azp": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.mutate = func(c map[string]any) { c["aud"] = []string{testMicrosoftClient, "other"} }
		},
		"wrong azp": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.mutate = func(c map[string]any) { c["azp"] = "other" }
		},
		"malformed azp": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.mutate = func(c map[string]any) { c["azp"] = 42 }
		},
		"wrong nonce": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.mutate = func(c map[string]any) { c["nonce"] = "replayed" }
		},
		"missing sub": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.mutate = func(c map[string]any) { delete(c, "sub") }
		},
		"expired": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.mutate = func(c map[string]any) { c["exp"] = fixedTime.Add(-61 * time.Second).Unix() }
		},
		"future iat": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.mutate = func(c map[string]any) { c["iat"] = fixedTime.Add(61 * time.Second).Unix() }
		},
		"future nbf": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.mutate = func(c map[string]any) { c["nbf"] = fixedTime.Add(61 * time.Second).Unix() }
		},
		"malformed nbf": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.mutate = func(c map[string]any) { c["nbf"] = "now" }
		},
		"bad at_hash": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.mutate = func(c map[string]any) { c["at_hash"] = "bad" }
		},
		"wrong signature": func(f *microsoftAdapterFixture, _ *ExchangeInput) { f.key, _ = rsa.GenerateKey(rand.Reader, 2048) },
		"alg none": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.sign = func(payload []byte) string {
				return b64(`{"alg":"none","kid":"key-1"}`) + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
			}
		},
		"HS256": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.sign = func(payload []byte) string {
				s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")}, (&jose.SignerOptions{}).WithHeader("kid", "key-1"))
				o, _ := s.Sign(payload)
				raw, _ := o.CompactSerialize()
				return raw
			}
		},
		"header jwk": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.header = func(h map[jose.HeaderKey]any) { h["jwk"] = jose.JSONWebKey{Key: &f.key.PublicKey} }
		},
		"header jku": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.header = func(h map[jose.HeaderKey]any) { h["jku"] = f.srv.URL + "/attacker-key" }
		},
		"header x5u": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.header = func(h map[jose.HeaderKey]any) { h["x5u"] = f.srv.URL + "/attacker-key" }
		},
		"header x5c": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.header = func(h map[jose.HeaderKey]any) {
				h["x5c"] = []string{base64.StdEncoding.EncodeToString(f.srv.Certificate().Raw)}
			}
		},
		"missing kid": func(f *microsoftAdapterFixture, _ *ExchangeInput) {
			f.header = func(h map[jose.HeaderKey]any) { delete(h, "kid") }
		},
		"provider denial":   func(f *microsoftAdapterFixture, _ *ExchangeInput) { f.failure = "denied" },
		"ambiguous timeout": func(f *microsoftAdapterFixture, _ *ExchangeInput) { f.failure = "timeout" },
	} {
		t.Run(name, func(t *testing.T) {
			f, ps, in := newMicrosoftAdapterFixture(t, "school.example", testMicrosoftTenant)
			mutate(f, &in)
			ctx := context.Background()
			if name == "ambiguous timeout" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 250*time.Millisecond)
				defer cancel()
			}
			result, err := ps.For(in.Config).Exchange(ctx, in)
			if !errors.Is(err, ErrProviderResponse) {
				t.Fatalf("expected provider rejection; got %v", err)
			}
			if result.Profile.Subject != "" || result.Tokens.AccessToken != "" || result.Tokens.IDToken != "" {
				t.Fatal("rejected exchange returned an identity or tokens")
			}
			for _, secret := range []string{"microsoft-sensitive-access", "provider-secret", "sensitive-provider-message", "token-secret"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaked %s: %v", secret, err)
				}
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.tokenReqs) != 1 {
				t.Fatalf("retried token request: %d", len(f.tokenReqs))
			}
			for _, path := range f.paths {
				if strings.Contains(path, "attacker") {
					t.Fatalf("untrusted request %s", path)
				}
			}
		})
	}
	t.Run("organization through personal", func(t *testing.T) {
		f, ps, in := newMicrosoftAdapterFixture(t, "consumers", testMicrosoftConsumer)
		f.tenant = testMicrosoftTenant
		if _, err := ps.For(in.Config).Exchange(context.Background(), in); !errors.Is(err, ErrProviderResponse) {
			t.Fatalf("organization accepted: %v", err)
		}
	})
	t.Run("skew and multiple audiences", func(t *testing.T) {
		f, ps, in := newMicrosoftAdapterFixture(t, "organizations", testMicrosoftTenant)
		f.mutate = func(c map[string]any) {
			c["nbf"] = fixedTime.Add(59 * time.Second).Unix()
			c["iat"] = fixedTime.Add(59 * time.Second).Unix()
			c["exp"] = fixedTime.Add(-59 * time.Second).Unix()
			c["aud"] = []string{testMicrosoftClient, "other"}
			c["azp"] = testMicrosoftClient
		}
		if _, err := ps.For(in.Config).Exchange(context.Background(), in); err != nil {
			t.Fatal(err)
		}
	})
}

func chainMicrosoftClaims(first, second func(map[string]any)) func(map[string]any) {
	return func(c map[string]any) {
		if first != nil {
			first(c)
		}
		second(c)
	}
}
