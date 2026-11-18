package federation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func appleProviderInput(t *testing.T, p *idp) (*Providers, ExchangeInput, *ecdsa.PrivateKey) {
	t.Helper()
	ps := p.providers().WithAppleFixture(AppleOverride{Endpoints: Endpoints{AuthorizationURL: p.issuer() + "/authorize", TokenURL: p.issuer() + "/token", JWKSURL: p.issuer() + "/jwks", TokenAuthMethod: authPost}, Issuer: p.issuer(), DiscoveryURL: p.issuer() + "/.well-known/openid-configuration"})
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	in := ExchangeInput{Config: Config{Strategy: StrategyApple, ClientID: "client", AppleTeamID: appleTestTeam, AppleKID: appleTestKID}, Cache: CacheKey{TenantID: "t", ConnectionID: "a", Revision: 1}, CallbackURL: "https://login.example/login/callback", Code: "code", Nonce: "nonce-1", ClientSecret: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), Now: fixedTime}
	return ps, in, key
}

func TestAppleAuthorizeURL(t *testing.T) {
	for _, s256 := range []bool{false, true} {
		for _, scopes := range [][]string{nil, {"name", "email"}} {
			p := newIDP(t)
			ps, in, _ := appleProviderInput(t, p)
			p.meta = func(m map[string]any) {
				if !s256 {
					delete(m, "code_challenge_methods_supported")
				}
				m["authorization_endpoint"] = "https://attacker.example/authorize"
			}
			m, err := ps.AppleMetadata(context.Background(), in.Cache)
			if err != nil {
				t.Fatal(err)
			}
			in.Config.Scopes = scopes
			raw, err := ps.For(in.Config).AuthorizationURL(StartInput{Config: in.Config, Endpoints: m.Endpoints(), CallbackURL: in.CallbackURL, State: "state", Nonce: "nonce", CodeChallenge: "challenge"})
			if err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(raw)
			q := u.Query()
			mode := "query"
			if len(scopes) > 0 {
				mode = "form_post"
			}
			if u.Host != p.srv.Listener.Addr().String() || q.Get("response_mode") != mode || q.Get("nonce") != "nonce" || (q.Get("code_challenge_method") == "S256") != s256 {
				t.Fatalf("authorize: %s", raw)
			}
		}
	}
	// Caller-controlled endpoints cannot replace fixed Apple endpoints.
	ps := NewProviders(NetworkPolicy{}, nil)
	raw, err := ps.For(Config{Strategy: StrategyApple}).AuthorizationURL(StartInput{Config: Config{Strategy: StrategyApple, ClientID: "client"}, Endpoints: Endpoints{AuthorizationURL: "https://attacker.example"}, State: "s", Nonce: "n", CallbackURL: "https://login.example/cb"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	if u.Scheme+"://"+u.Host+u.Path != rules.AppleAuthorizationURL {
		t.Fatal(raw)
	}
}

func TestAppleExchange(t *testing.T) {
	for _, mutation := range []string{"valid", "issuer", "audience", "nonce", "expired", "future", "signature", "missing nonce", "native", "nonAppleNative"} {
		t.Run(mutation, func(t *testing.T) {
			p := newIDP(t)
			ps, in, key := appleProviderInput(t, p)
			p.claims = func(c map[string]any) {
				switch mutation {
				case "issuer":
					c["iss"] = "https://wrong.example"
				case "audience":
					c["aud"] = "other.bundle"
				case "nonce":
					c["nonce"] = "wrong"
				case "expired":
					c["exp"] = fixedTime.Add(-time.Hour).Unix()
				case "future":
					c["iat"] = fixedTime.Add(time.Hour).Unix()
				case "missing nonce", "native", "nonAppleNative":
					delete(c, "nonce")
				}
			}
			if mutation == "signature" {
				other, _ := rsa.GenerateKey(rand.Reader, 2048)
				p.sign = func(payload []byte) string {
					s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: other}, nil)
					o, _ := s.Sign(payload)
					v, _ := o.CompactSerialize()
					return v
				}
			}
			if mutation == "native" {
				in.AppleNative = true
				in.Nonce = ""
				in.Config.ClientID = "com.example.bundle"
				p.claims = func(c map[string]any) { delete(c, "nonce"); c["aud"] = "com.example.bundle" }
			}
			if mutation == "nonAppleNative" {
				in.AppleNative = true
				in.Config.Strategy = StrategyGoogle
				in.Endpoints = Endpoints{TokenURL: p.issuer() + "/token", JWKSURL: p.issuer() + "/jwks", TokenAuthMethod: authPost}
				in.Issuer = p.issuer()
			}
			res, err := ps.For(in.Config).Exchange(context.Background(), in)
			if mutation != "valid" && mutation != "native" {
				if err == nil {
					t.Fatal("unsafe token accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if res.Profile.Subject != "Subject-1" {
				t.Fatal(res.Profile)
			}
			f := p.forms[0]
			if f.Get("client_id") != in.Config.ClientID || f.Get("client_secret") == in.ClientSecret || f.Has("code_verifier") {
				t.Fatal("incorrect Apple token form")
			}
			obj, err := jose.ParseSigned(f.Get("client_secret"), []jose.SignatureAlgorithm{jose.ES256})
			if err != nil {
				t.Fatal(err)
			}
			body, err := obj.Verify(&key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			var c map[string]any
			_ = json.Unmarshal(body, &c)
			if c["sub"] != in.Config.ClientID || c["iss"] != appleTestTeam || c["aud"] != rules.AppleIssuer {
				t.Fatal("incorrect client secret claims")
			}
		})
	}
}

func TestAppleProfileEmailVerified(t *testing.T) {
	for _, v := range []any{true, "true", "false", nil, false, "TRUE", 1} {
		p := newIDP(t)
		ps, in, _ := appleProviderInput(t, p)
		p.claims = func(c map[string]any) {
			delete(c, "email_verified")
			if v != nil {
				c["email_verified"] = v
			}
		}
		res, err := ps.For(in.Config).Exchange(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		want := v == true || v == "true"
		if res.Profile.EmailVerified == nil || *res.Profile.EmailVerified != want {
			t.Fatalf("%v: %+v", v, res.Profile)
		}
	}
}
func TestAppleProfilePrivateEmail(t *testing.T) {
	p := newIDP(t)
	ps, in, _ := appleProviderInput(t, p)
	p.claims = func(c map[string]any) {
		c["email"] = "relay@privaterelay.appleid.com"
		c["is_private_email"] = "true"
		c["real_user_status"] = 2
		c["untrusted"] = "drop"
		c["name"] = "Token Name"
	}
	user, err := ParseAppleUser(`{"name":{"firstName":"Posted","lastName":"Name"},"email":"attacker@example.test"}`)
	if err != nil {
		t.Fatal(err)
	}
	in.AppleUser = user
	res, err := ps.For(in.Config).Exchange(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if *res.Profile.Email != "relay@privaterelay.appleid.com" || res.Profile.ProviderData["is_private_email"] != "true" || len(res.Profile.ProviderData) != 2 || *res.Profile.Name != "Token Name" {
		t.Fatalf("profile %+v", res.Profile)
	}
}
func TestParseAppleUser(t *testing.T) {
	for _, raw := range []string{`{"name":{"firstName":1}}`, `[]`, `null`, `{} {}`, `{"name":{"firstName":"\u0000"}}`, string(make([]byte, 1025))} {
		if _, err := ParseAppleUser(raw); err == nil {
			t.Fatalf("accepted invalid user %q", raw)
		}
	}
	u, err := ParseAppleUser(`{"name":{"firstName":"Ada","lastName":"Lovelace"},"email":"ignored"}`)
	if err != nil || u.FirstName != "Ada" || u.LastName != "Lovelace" {
		t.Fatalf("%+v %v", u, err)
	}
}
func TestAppleIdentityProfilePersistence(t *testing.T) {
	e := newIdentityEnv(t, "")
	c := &store.Connection{TenantID: "ten", ID: "con_apple", Name: "apple", Strategy: StrategyApple, FederationRevision: 1}
	if err := e.st.Connections().Create(e.ctx, c); err != nil {
		t.Fatal(err)
	}
	r := result("Raw|Subject", func(p *Profile) {
		p.Name = strp("First Name")
		p.GivenName = strp("First")
		p.ProviderData = map[string]any{"is_private_email": true}
	})
	u, err := e.login(c, r)
	if err != nil {
		t.Fatal(err)
	}
	if u.UserID != "apple|Raw|Subject" || u.Identities[0].UserID != "Raw|Subject" || u.Identities[0].Linked() || u.Identities[0].ProviderData["is_private_email"] != true {
		t.Fatalf("identity %+v", u)
	}
	// Memory clones must not expose the stored provider map.
	u.Identities[0].ProviderData["is_private_email"] = false
	stored, _ := e.st.Users().Get(e.ctx, "ten", u.UserID)
	if stored.Identities[0].ProviderData["is_private_email"] != true {
		t.Fatal("provider map aliased")
	}
	r.Profile.Name = strp("Overwrite")
	r.Profile.GivenName = strp("Overwrite")
	r.Profile.Email = strp("new@example.test")
	r.Profile.ProviderData = map[string]any{"is_private_email": false}
	u, err = e.login(c, r)
	if err != nil || u.Name != "First Name" || u.GivenName != "First" || u.Email != "new@example.test" || u.Identities[0].Linked() || u.Identities[0].ProviderData["is_private_email"] != false {
		t.Fatalf("repeat %+v %v", u, err)
	}
	other, err := e.login(c, result("Different", func(p *Profile) { p.Email = strp("new@example.test") }))
	if err != nil || other.UserID == u.UserID {
		t.Fatal("email auto link")
	}
}

func TestAppleMetadataPKCEPolicy(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		value                any
		present, valid, s256 bool
	}{
		{"absent", nil, false, true, false}, {"empty", []any{}, true, true, false}, {"plain", []any{"plain"}, true, true, false}, {"S256", []any{"S256"}, true, true, true}, {"null", nil, true, false, false}, {"string", "S256", true, false, false}, {"mixed", []any{"S256", 1}, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newIDP(t)
			ps, in, _ := appleProviderInput(t, p)
			p.meta = func(m map[string]any) {
				delete(m, "code_challenge_methods_supported")
				if tc.present {
					m["code_challenge_methods_supported"] = tc.value
				}
			}
			m, err := ps.AppleMetadata(context.Background(), in.Cache)
			if (err == nil) != tc.valid {
				t.Fatalf("metadata error %v", err)
			}
			if err == nil && m.PKCES256 != tc.s256 {
				t.Fatalf("PKCE: %+v", m)
			}
		})
	}
}
func TestAppleProfilePostedName(t *testing.T) {
	p := newIDP(t)
	ps, in, _ := appleProviderInput(t, p)
	p.claims = func(c map[string]any) { delete(c, "name"); delete(c, "email"); delete(c, "email_verified") }
	user, err := ParseAppleUser(`{"name":{"firstName":"Ada","lastName":"Lovelace"},"email":"untrusted@example.test"}`)
	if err != nil {
		t.Fatal(err)
	}
	in.AppleUser = user
	res, err := ps.For(in.Config).Exchange(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if res.Profile.Name == nil || *res.Profile.Name != "Ada Lovelace" || *res.Profile.GivenName != "Ada" || *res.Profile.FamilyName != "Lovelace" || res.Profile.Email != nil || *res.Profile.EmailVerified || *res.Profile.Nickname != "Subject-1" {
		t.Fatalf("profile %+v", res.Profile)
	}
}
func TestApplePostedNameBounds(t *testing.T) {
	raw := `{"name":{"firstName":"` + strings.Repeat("a", 150) + `","lastName":"` + strings.Repeat("b", 150) + `"}}`
	if _, err := ParseAppleUser(raw); err == nil {
		t.Fatal("combined name exceeds root name limit")
	}
}
func TestAppleExchangePKCE(t *testing.T) {
	p := newIDP(t)
	ps, in, _ := appleProviderInput(t, p)
	in.Endpoints.PKCES256 = true
	in.CodeVerifier = "proof"
	if _, err := ps.For(in.Config).Exchange(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if p.forms[0].Get("code_verifier") != "proof" {
		t.Fatal("PKCE verifier dropped")
	}
}

func TestAppleIdentityFirstLoginSync(t *testing.T) {
	e := newIdentityEnv(t, "")
	c := &store.Connection{TenantID: "ten", ID: "con_apple", Name: "apple", Strategy: StrategyApple, SetUserRootAttributes: rules.SyncOnFirstLogin, FederationRevision: 1}
	if err := e.st.Connections().Create(e.ctx, c); err != nil {
		t.Fatal(err)
	}
	r := result("subject", func(p *Profile) { p.ProviderData = map[string]any{"is_private_email": true} })
	if _, err := e.login(c, r); err != nil {
		t.Fatal(err)
	}
	r.Profile.Name = strp("Ignored")
	r.Profile.Email = strp("new@example.test")
	r.Profile.ProviderData = map[string]any{"is_private_email": false}
	u, err := e.login(c, r)
	if err != nil || u.Name != "Alice" || u.Email != "a@example.com" || u.Identities[0].ProviderData["is_private_email"] != false || u.Identities[0].Linked() {
		t.Fatalf("first-login policy: %+v %v", u, err)
	}
}
