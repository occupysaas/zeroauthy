package provider

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/federation/providers"
)

// TestSocialStandIn runs zeroauthy's descriptor provider against the
// stand-in for every Plan 39b strategy: authorize, the code exchange and
// the profile, so the E2E lane fails here first when the two drift.
func TestSocialStandIn(t *testing.T) {
	var p *Provider
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { p.ServeHTTP(w, r) }))
	defer srv.Close()
	p, _ = New(srv.URL)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	ps := federation.NewProviders(federation.FixturePolicy(pool), nil).WithSocialFixture(srv.URL + "/social")
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, d := range providers.All() {
		t.Run(d.Strategy, func(t *testing.T) {
			if d.Retired != nil {
				t.Skip("retired: TestRetiredProviders")
			}
			if d.Protocol == providers.ProtocolOAuth1 {
				t.Skip("OAuth 1.0a descriptors: TestSocialStandInOAuth1")
			}
			opts := map[string]any{"client_id": ClientID, "client_secret": ClientSecret}
			if len(d.BaseURLHosts) > 0 {
				opts["baseUrl"] = "https://" + d.BaseURLHosts[0]
			}
			if d.Strategy == "salesforce-community" {
				opts["community_base_url"] = "https://community.example"
			}
			if _, ok := d.Flag("email"); ok {
				opts["email"] = true
			}
			raw, _ := json.Marshal(map[string]any{"name": "c", "strategy": d.Strategy, "options": opts})
			var spec connrules.Spec
			if err := json.Unmarshal(raw, &spec); err != nil {
				t.Fatal(err)
			}
			cfg, err := federation.ParseConfig(spec)
			if err != nil {
				t.Fatal(err)
			}
			e, err := ps.SocialEndpoints(cfg, "my-shop")
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256([]byte("verifier-1"))
			auth, err := ps.For(cfg).AuthorizationURL(federation.StartInput{Config: cfg, Endpoints: e, CallbackURL: "https://login.example/login/callback",
				State: "state-1", CodeChallenge: base64.RawURLEncoding.EncodeToString(sum[:])})
			if err != nil {
				t.Fatal(err)
			}
			res, err := client.Get(auth)
			if err != nil || res.StatusCode != 200 {
				t.Fatalf("authorize %v %v", res.StatusCode, err)
			}
			res.Body.Close()
			u, _ := url.Parse(auth)
			q := u.Query()
			post := url.Values{"subject": {"user-1"}, "decision": {"allow"}, "redirect_uri": {q.Get(redirectParamOf(d))}, "state": {q.Get("state")}, "code_challenge": {q.Get("code_challenge")}}
			res, err = client.PostForm(u.Scheme+"://"+u.Host+u.Path, post)
			if err != nil || res.StatusCode != http.StatusFound {
				t.Fatalf("allow %v %v", res.StatusCode, err)
			}
			loc, _ := url.Parse(res.Header.Get("Location"))
			result, err := ps.For(cfg).Exchange(context.Background(), federation.ExchangeInput{Config: cfg, Endpoints: e, CallbackURL: "https://login.example/login/callback",
				Code: loc.Query().Get("code"), CodeVerifier: "verifier-1", ClientSecret: ClientSecret})
			if err != nil {
				t.Fatal(err)
			}
			if result.Profile.Subject != "user-1" {
				t.Fatalf("subject %q", result.Profile.Subject)
			}
			wantEmail := d.Profile.Email != "" || d.Hook == providers.HookLine
			if wantEmail != (result.Profile.Email != nil) || wantEmail && *result.Profile.Email != SocialEmail(d.Strategy, "user-1") {
				t.Fatalf("email %v", result.Profile.Email)
			}
			if wantEmail && *result.Profile.EmailVerified != (d.EmailVerified.Rule != providers.EmailNever) {
				t.Fatalf("email_verified %v (rule %s)", *result.Profile.EmailVerified, d.EmailVerified.Rule)
			}
			_ = fmt.Sprint(strings.TrimSpace(""))
		})
	}
}
