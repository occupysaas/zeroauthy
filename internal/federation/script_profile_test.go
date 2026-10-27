package federation

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/federation/script"
)

// fakeExecutor returns a fixed result and records the request.
type fakeExecutor struct {
	out  string
	err  error
	last script.Request
}

func (f *fakeExecutor) Execute(_ context.Context, r script.Request) (json.RawMessage, error) {
	f.last = r
	return json.RawMessage(f.out), f.err
}
func (f *fakeExecutor) Close() error { return nil }

func oauthFixture(t *testing.T) (*Providers, Config, ExchangeInput) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"bearer","refresh_token":"rt","expires_in":60,"id_token":"opaque","unlisted":"x"}`))
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	ps := NewProviders(FixturePolicy(pool), func() time.Time { return fixedTime })
	cfg := Config{Strategy: StrategyOAuth2, ClientID: "c", AuthorizationURL: srv.URL + "/a", TokenURL: srv.URL + "/t", Scopes: []string{"read"},
		Script: "function fetchUserProfile(a, c, cb) {}"}
	return ps, cfg, ExchangeInput{Config: cfg, Cache: CacheKey{TenantID: "ten", ConnectionID: "con", Revision: 1},
		CallbackURL: "https://l.example/login/callback", Code: "x", CodeVerifier: "v", ClientSecret: "s", Now: fixedTime}
}

func TestOAuthScriptProfile(t *testing.T) {
	ctx := context.Background()
	ps, cfg, in := oauthFixture(t)
	exec := &fakeExecutor{out: `{"user_id":"Sub","email":"a@example.com","extra":"ignored"}`}
	ps.WithScripts(exec)
	res, err := ps.For(cfg).Exchange(ctx, in)
	if err != nil || res.Profile.Subject != "Sub" || *res.Profile.Email != "a@example.com" || res.Tokens.AccessToken != "at" {
		t.Fatalf("%+v %v", res, err)
	}
	if exec.last.AccessToken != "at" || exec.last.TenantID != "ten" || exec.last.ConnectionID != "con" || exec.last.Source != cfg.Script {
		t.Fatalf("request %+v", exec.last)
	}
	want := map[string]any{"access_token": "at", "refresh_token": "rt", "token_type": "bearer", "expires_in": int64(60), "id_token": "opaque"}
	if len(exec.last.Context) != len(want) {
		t.Fatalf("context %v", exec.last.Context)
	}
	for k, v := range want {
		if exec.last.Context[k] != v {
			t.Fatalf("context %s = %v", k, exec.last.Context[k])
		}
	}
	for name, out := range map[string]string{
		"missing user_id": `{"email":"a@example.com"}`,
		"app_metadata":    `{"user_id":"s","app_metadata":{"role":"admin"}}`,
		"identities":      `{"user_id":"s","identities":[]}`,
		"not an object":   `"s"`,
	} {
		exec.out = out
		if _, err := ps.For(cfg).Exchange(ctx, in); !errors.Is(err, ErrProfile) {
			t.Errorf("%s: %v", name, err)
		}
	}
	exec.err = script.ErrTimeout
	if _, err := ps.For(cfg).Exchange(ctx, in); !errors.Is(err, ErrProviderResponse) {
		t.Errorf("script failure: %v", err)
	}
}

// A missing or unsafe Node runtime disables custom OAuth2 only.
func TestScriptRuntimeUnavailable(t *testing.T) {
	ctx := context.Background()
	ps, cfg, in := oauthFixture(t)
	if _, err := ps.For(cfg).Exchange(ctx, in); !errors.Is(err, ErrScriptUnavailable) {
		t.Fatalf("no executor: %v", err)
	}
	r, err := script.NewRunner(script.Config{Node: "/nonexistent/node"}, script.NewBroker(http.DefaultClient))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ps.WithScripts(r)
	if _, err := ps.For(cfg).Exchange(ctx, in); !errors.Is(err, ErrScriptUnavailable) {
		t.Fatalf("missing node: %v", err)
	}
	// Google and OIDC still work on the same Providers configuration.
	p := newIDP(t)
	gps := p.providers().WithScripts(r)
	gin := p.exchangeInput(t, gps)
	if _, err := gps.For(gin.Config).Exchange(ctx, gin); err != nil {
		t.Fatalf("oidc with unavailable scripts: %v", err)
	}
}
