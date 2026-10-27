package federation

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
)

func TestGoogleAdapter(t *testing.T) {
	ps := NewProviders(NetworkPolicy{}, nil)
	cfg, err := ParseConfig(configSpec(t, "google-oauth2", `{"client_id":"client","client_secret":"s","email":false}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ps.For(cfg).AuthorizationURL(StartInput{Config: cfg, Endpoints: GoogleEndpoints(), CallbackURL: "https://login.example/login/callback",
		State: "st", Nonce: "n", CodeChallenge: "ch"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	if !strings.HasPrefix(raw, rules.GoogleAuthorizationURL+"?") || q.Get("scope") != "openid profile" || q.Get("hd") != "" ||
		q.Get("access_type") != "" || q.Get("code_challenge_method") != "S256" || q.Get("nonce") != "n" {
		t.Fatalf("authorize %s", raw)
	}
	e := GoogleEndpoints()
	if e.TokenURL != rules.GoogleTokenURL || e.JWKSURL != rules.GoogleJWKSURL || e.TokenAuthMethod != "client_secret_post" {
		t.Fatalf("endpoints %+v", e)
	}
	for _, iss := range []string{"https://accounts.google.com", "accounts.google.com"} {
		if !issuerMatches(cfg, rules.GoogleIssuer, iss) {
			t.Errorf("issuer %q rejected", iss)
		}
	}
	if issuerMatches(cfg, rules.GoogleIssuer, "https://accounts.google.com/") {
		t.Error("lookalike issuer accepted")
	}
	for _, opts := range []string{`{"client_id":"c","client_secret":"s","allowed_domains":["example.com"]}`, `{"client_id":"c","client_secret":"s","hd":"example.com"}`, `{"client_id":"c","client_secret":"s","gmail":true}`} {
		if _, err := ParseConfig(configSpec(t, "google-oauth2", opts)); err == nil {
			t.Errorf("accepted %s", opts)
		}
	}

	// Google's hd claim is only a hint: it never restricts or grants.
	p := newIDP(t)
	p.claims = func(c map[string]any) { c["hd"] = "other.example" }
	gps := p.providers()
	in := p.exchangeInput(t, gps)
	in.Config.Strategy = StrategyGoogle
	in.Endpoints.TokenAuthMethod = "client_secret_post"
	res, err := gps.For(in.Config).Exchange(context.Background(), in)
	if err != nil || res.Profile.Subject != "Subject-1" {
		t.Fatalf("%v %v", res, err)
	}
	if f := p.forms[0]; f.Get("client_secret") != "provider-secret" {
		t.Fatal("Google token request not client_secret_post")
	}
}

func TestGoogleEmailAccountProfiles(t *testing.T) {
	for _, tc := range []struct {
		name, email, hd string
		verified        bool
	}{
		{"Gmail", "person@gmail.com", "", true},
		{"Workspace", "person@school.example", "school.example", true},
		{"non Gmail", "person@example.net", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newIDP(t)
			p.claims = func(c map[string]any) {
				c["sub"] = "Google-CaseSensitive-Sub"
				c["email"] = tc.email
				c["email_verified"] = tc.verified
				if tc.hd != "" {
					c["hd"] = tc.hd
				}
			}
			ps := p.providers()
			in := p.exchangeInput(t, ps)
			in.Config.Strategy = StrategyGoogle
			in.Endpoints.TokenAuthMethod = authPost
			res, err := ps.For(in.Config).Exchange(context.Background(), in)
			if err != nil || res.Profile.Subject != "Google-CaseSensitive-Sub" || res.Profile.Email == nil || *res.Profile.Email != tc.email || res.Profile.EmailVerified == nil || *res.Profile.EmailVerified != tc.verified {
				t.Fatalf("profile %+v error %v", res.Profile, err)
			}
		})
	}
}
