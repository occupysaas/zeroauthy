package federation

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
)

func TestGoogleAppsConfig(t *testing.T) {
	cfg, err := ParseConfig(configSpec(t, "google-apps", `{"client_id":"client","client_secret":"s","domain":"Corp.Example.com","tenant_domain":"corp.example.com",
		"domain_aliases":["corp.example.net"],"ext_groups":true,"ext_is_suspended":true,"scope":["email","profile"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Issuer != rules.GoogleIssuer || cfg.GoogleApps == nil || cfg.GoogleApps.Domain != "corp.example.com" || !cfg.GoogleApps.APIEnableUsers ||
		cfg.GoogleApps.APIEnableGroups || cfg.GoogleApps.MapUserIDToID || cfg.IsSocial || strings.Join(cfg.DomainAliases, ",") != "corp.example.net" {
		t.Fatalf("%+v %+v", cfg, cfg.GoogleApps)
	}
	raw, err := NewProviders(NetworkPolicy{}, nil).For(cfg).AuthorizationURL(StartInput{Config: cfg, Endpoints: GoogleEndpoints(),
		CallbackURL: "https://login.example/login/callback", State: "st", Nonce: "n", CodeChallenge: "ch"})
	if err != nil {
		t.Fatal(err)
	}
	q, _ := url.ParseQuery(raw[strings.IndexByte(raw, '?')+1:])
	if !strings.HasPrefix(raw, rules.GoogleAuthorizationURL+"?") || q.Get("hd") != "corp.example.com" || q.Get("scope") != "openid profile email" ||
		q.Get("access_type") != "" || q.Get("prompt") != "" {
		t.Fatalf("authorize %s", raw)
	}
	// The directory consent asks for offline Directory API access.
	raw, _ = NewProviders(NetworkPolicy{}, nil).For(cfg).AuthorizationURL(StartInput{Config: cfg, Endpoints: GoogleEndpoints(),
		CallbackURL: "https://login.example/login/callback", State: "st", Nonce: "n", CodeChallenge: "ch", DirectoryConsent: []string{rules.DirectoryUserScope}})
	q, _ = url.ParseQuery(raw[strings.IndexByte(raw, '?')+1:])
	if q.Get("access_type") != "offline" || q.Get("prompt") != "consent" || !strings.HasSuffix(q.Get("scope"), " "+rules.DirectoryUserScope) {
		t.Fatalf("consent %s", raw)
	}

	for _, opts := range []string{
		`{"client_id":"c","client_secret":"s"}`,
		`{"client_id":"c","client_secret":"s","domain":"localhost"}`,
		`{"client_id":"c","client_secret":"s","domain":"corp.example.com","tenant_domain":"other.example.com"}`,
		`{"client_id":"c","client_secret":"s","domain":"corp.example.com","admin_refresh_token":"x"}`,
		`{"client_id":"c","client_secret":"s","domain":"corp.example.com","admin_access_token":"x"}`,
		`{"client_id":"c","client_secret":"s","domain":"corp.example.com","allow_setting_login_scopes":true}`,
		`{"client_id":"c","client_secret":"s","domain":"corp.example.com","handle_login_from_social":true}`,
		`{"client_id":"c","client_secret":"s","domain":"corp.example.com","gmail":true}`,
		`{"client_id":"c","client_secret":"s","domain":"corp.example.com","scope":["email","profile","https://www.googleapis.com/auth/drive"]}`,
		`{"client_id":"c","client_secret":"s","domain":"corp.example.com","ext_groups":"yes"}`,
		`{"client_id":"c","domain":"corp.example.com"}`,
	} {
		if _, err := ParseConfig(configSpec(t, "google-apps", opts)); err == nil {
			t.Errorf("accepted %s", opts)
		}
	}

	next, err := ParseConfig(configSpec(t, "google-apps", `{"client_id":"client","client_secret":"s","domain":"other.example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfigUpdate(cfg, next); !errors.Is(err, ErrImmutable) {
		t.Fatalf("domain change: %v", err)
	}
	next, _ = ParseConfig(configSpec(t, "google-apps", `{"client_id":"client","client_secret":"s","domain":"corp.example.com","map_user_id_to_id":true}`))
	if err := ValidateConfigUpdate(cfg, next); !errors.Is(err, ErrImmutable) {
		t.Fatalf("map_user_id_to_id change: %v", err)
	}
}

// The hd claim of the verified ID token binds a login to the Workspace
// domain; the email suffix and the hd request parameter prove nothing.
func TestGoogleAppsHostedDomain(t *testing.T) {
	for _, tc := range []struct {
		name     string
		claims   map[string]any
		mapID    bool
		subject  string
		rejected bool
	}{
		{name: "member", claims: map[string]any{"hd": "corp.example.com", "email": "Ann@Corp.Example.com"}, subject: "ann@corp.example.com"},
		{name: "secondary domain email", claims: map[string]any{"hd": "corp.example.com", "email": "ann@corp.example.net"}, subject: "ann@corp.example.net"},
		{name: "stable subject", claims: map[string]any{"hd": "corp.example.com"}, mapID: true, subject: "Subject-1"},
		{name: "consumer account", claims: map[string]any{"email": "ann@corp.example.com"}, rejected: true},
		{name: "other workspace", claims: map[string]any{"hd": "evil.example.com", "email": "ann@corp.example.com"}, rejected: true},
		{name: "suffix lookalike", claims: map[string]any{"hd": "corp.example.com.evil.example"}, rejected: true},
		{name: "unverified email", claims: map[string]any{"hd": "corp.example.com", "email_verified": false}, rejected: true},
		{name: "non-string hd", claims: map[string]any{"hd": []any{"corp.example.com"}}, rejected: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newIDP(t)
			p.claims = func(c map[string]any) {
				for k, v := range tc.claims {
					c[k] = v
				}
			}
			ps := p.providers()
			in := p.exchangeInput(t, ps)
			in.Config.Strategy = StrategyGoogleApps
			in.Config.GoogleApps = &rules.GoogleAppsSettings{Domain: "corp.example.com", MapUserIDToID: tc.mapID, APIEnableUsers: true}
			in.Endpoints.TokenAuthMethod = authPost
			res, err := ps.For(in.Config).Exchange(context.Background(), in)
			if tc.rejected {
				if !errors.Is(err, ErrProviderResponse) {
					t.Fatalf("accepted: %+v %v", res.Profile, err)
				}
				return
			}
			if err != nil || res.Profile.Subject != tc.subject {
				t.Fatalf("profile %+v error %v", res.Profile, err)
			}
		})
	}
}
