package federation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/go-jose/go-jose/v4"
	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"net/url"
	"testing"
	"time"
)

func TestExplicitEndpointsNoDiscovery(t *testing.T) {
	p := newIDP(t)
	cfg := oidcConfig()
	cfg.Channel = "back_channel"
	cfg.Explicit = &rules.ExplicitEndpoints{Issuer: p.issuer(), Authorization: p.issuer() + "/authorize", Token: p.issuer() + "/token", JWKS: p.issuer() + "/jwks"}
	m, e := p.providers().ResolveEnterpriseMetadata(context.Background(), CacheKey{}, cfg)
	if e != nil || m.JWKSURI != p.issuer()+"/jwks" {
		t.Fatal(m, e)
	}
}
func TestOIDCMetadataWins(t *testing.T) {
	p := newIDP(t)
	cfg := oidcConfig()
	cfg.Channel = "front_channel"
	cfg.DiscoveryURL = "https://must-not-call.invalid/discovery"
	cfg.Explicit = &rules.ExplicitEndpoints{Metadata: map[string]any{"issuer": p.issuer(), "authorization_endpoint": p.issuer() + "/authorize", "jwks_uri": p.issuer() + "/jwks"}}
	m, e := p.providers().ResolveEnterpriseMetadata(context.Background(), CacheKey{}, cfg)
	if e != nil || m.Issuer != p.issuer() {
		t.Fatal(m, e)
	}
}
func TestPKCEAuto(t *testing.T) {
	for _, tc := range []struct {
		methods any
		want    string
	}{{[]any{"S256", "plain"}, "S256"}, {[]any{"plain"}, "plain"}, {nil, ""}} {
		p := newIDP(t)
		p.meta = func(m map[string]any) {
			if tc.methods == nil {
				delete(m, "code_challenge_methods_supported")
			} else {
				m["code_challenge_methods_supported"] = tc.methods
			}
		}
		cfg := oidcConfig()
		cfg.Channel = "back_channel"
		cfg.PKCE = "auto"
		cfg.DiscoveryURL = p.issuer() + "/.well-known/openid-configuration"
		m, e := p.providers().ResolveEnterpriseMetadata(context.Background(), CacheKey{}, cfg)
		if e != nil || m.Endpoints().PKCEMethod != tc.want {
			t.Fatal(m, e)
		}
	}
}
func TestPKCEPlainDisabled(t *testing.T) {
	for _, tc := range []struct{ mode, want string }{{"plain", "plain"}, {"disabled", ""}, {"S256", "S256"}} {
		p := newIDP(t)
		ps := p.providers()
		cfg := oidcConfig()
		cfg.Channel = "back_channel"
		cfg.SendNonce = true
		cfg.PKCE = tc.mode
		cfg.DiscoveryURL = p.issuer() + "/.well-known/openid-configuration"
		m, e := ps.ResolveEnterpriseMetadata(context.Background(), CacheKey{}, cfg)
		if e != nil {
			t.Fatal(e)
		}
		ept := m.Endpoints()
		redirect, e := ps.For(cfg).AuthorizationURL(StartInput{Config: cfg, Endpoints: ept, CallbackURL: "https://login.example/callback", State: "state", Nonce: "nonce", CodeChallenge: "challenge"})
		if e != nil {
			t.Fatal(e)
		}
		u, _ := url.Parse(redirect)
		if u.Query().Get("code_challenge_method") != tc.want {
			t.Fatal(redirect)
		}
		in := p.exchangeInput(t, ps)
		in.Config = cfg
		in.Endpoints = ept
		_, e = ps.For(cfg).Exchange(context.Background(), in)
		if e != nil {
			t.Fatal(e)
		}
		p.mu.Lock()
		_, has := p.forms[0]["code_verifier"]
		p.mu.Unlock()
		if has != (tc.want != "") {
			t.Fatal("verifier presence", has, tc)
		}
	}
}
func TestNonceOptional(t *testing.T) {
	for _, send := range []bool{false, true} {
		p := newIDP(t)
		p.claims = func(c map[string]any) { delete(c, "nonce") }
		ps := p.providers()
		in := p.exchangeInput(t, ps)
		in.Config.Channel = "back_channel"
		in.Config.SendNonce = send
		_, e := ps.For(in.Config).Exchange(context.Background(), in)
		if (e != nil) != send {
			t.Fatalf("send=%t: %v", send, e)
		}
	}
}
func TestIDTokenAlgAllowlist(t *testing.T) {
	p := newIDP(t)
	ps := p.providers()
	in := p.exchangeInput(t, ps)
	in.Config.IDTokenAlgs = []string{"PS256"}
	if _, e := ps.For(in.Config).Exchange(context.Background(), in); e == nil {
		t.Fatal("RS256 outside allowlist accepted")
	}
}

func TestExplicitEndpointsPinnedOnAttempt(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{13}, 32))
	p := newIDP(t)
	spec := connrules.Spec{Name: "enterprise", Strategy: "oidc", EnabledClients: []string{"client"}, Options: connrules.Options{Extra: map[string]any{"type": "back_channel", "client_id": "client", "scope": "openid", "client_secret": "fixture", "issuer": "https://provider.example", "authorization_endpoint": "https://provider.example" + "/authorize", "token_endpoint": "https://provider.example" + "/token", "jwks_uri": "https://provider.example" + "/jwks", "connection_settings": map[string]any{"pkce": "plain"}}}}
	c := &store.Connection{TenantID: "local", ID: "con_enterprise", FederationRevision: 1}
	connrules.Apply(&spec, c)
	c.FederationSecretsSealed, _ = SealCredentials(w, "local", c.ID, Credentials{ClientSecret: "fixture"})
	if e := st.Connections().Create(ctx, c); e != nil {
		t.Fatal(e)
	}
	tn := &store.Tenant{ID: "local", Name: "local"}
	client := &store.Client{TenantID: "local", ClientID: "client", IsFirstParty: true}
	txn := &store.AuthTransaction{TenantID: "local", ID: "txn", ClientID: "client", Params: map[string]string{}, ExpiresAt: fixedTime.Add(time.Hour)}
	if e := st.Tenants().Create(ctx, tn); e != nil {
		t.Fatal(e)
	}
	if e := st.Clients().Create(ctx, client); e != nil {
		t.Fatal(e)
	}
	if e := st.AuthTransactions().Create(ctx, txn); e != nil {
		t.Fatal(e)
	}
	svc := &FlowService{Service: Service{Wrapper: w, Now: func() time.Time { return fixedTime }}, Store: st, Providers: p.providers()}
	b, e := svc.Begin(ctx, BeginInput{Tenant: tn, Origin: "https://local.example", Txn: txn, Client: client, Connection: c})
	if e != nil {
		t.Fatal(e)
	}
	u, _ := url.Parse(b.URL)
	a, e := st.Federation().GetAttempt(ctx, "local", StateHash(u.Query().Get("state")))
	if e != nil || a.Endpoints.TokenURL != "https://provider.example"+"/token" || a.Endpoints.PKCEMethod != "plain" {
		t.Fatal(a, e)
	}
	pr, e := svc.openProof("local", a.StateHash, a.SealedProof)
	if e != nil || u.Query().Get("code_challenge") != pr.Verifier {
		t.Fatal("plain verifier mismatch", e)
	}
}

func TestOIDCIDTokenES256(t *testing.T) {
	p := newIDP(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p.keys = []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: p.kid, Algorithm: "ES256", Use: "sig"}}
	p.sign = func(payload []byte) string {
		s, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, &jose.SignerOptions{ExtraHeaders: map[jose.HeaderKey]any{"kid": p.kid}})
		if e != nil {
			t.Fatal(e)
		}
		obj, e := s.Sign(payload)
		if e != nil {
			t.Fatal(e)
		}
		raw, e := obj.CompactSerialize()
		if e != nil {
			t.Fatal(e)
		}
		return raw
	}
	ps := p.providers()
	in := p.exchangeInput(t, ps)
	if _, e := ps.For(in.Config).Exchange(context.Background(), in); e != nil {
		t.Fatal(e)
	}
}
