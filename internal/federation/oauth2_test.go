package federation

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOAuthExchange(t *testing.T) {
	var forms []url.Values
	var basic []bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		forms = append(forms, r.PostForm)
		_, _, ok := r.BasicAuth()
		basic = append(basic, ok)
		w.Header().Set("Content-Type", "application/json")
		if r.PostForm.Get("code") == "bad" {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"code upstream-secret-detail"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"bearer","scope":"read"}`))
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	ps := NewProviders(FixturePolicy(pool), func() time.Time { return fixedTime })
	cfg := Config{Strategy: StrategyOAuth2, ClientID: "client", AuthorizationURL: srv.URL + "/authorize?audience=api", TokenURL: srv.URL + "/token", Scopes: []string{"read", "profile"}}
	raw, err := ps.For(cfg).AuthorizationURL(StartInput{Config: cfg, CallbackURL: "https://login.example/login/callback", State: "st", CodeChallenge: "ch"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	if q := u.Query(); q.Get("audience") != "api" || q.Get("code_challenge_method") != "S256" || q.Get("scope") != "read profile" || q.Get("nonce") != "" {
		t.Fatalf("authorize %s", raw)
	}
	in := ExchangeInput{Config: cfg, CallbackURL: "https://login.example/login/callback", Code: "c", CodeVerifier: "v", ClientSecret: "s", Now: fixedTime}
	res, err := ps.For(cfg).Exchange(context.Background(), in)
	if err != nil || res.Tokens.AccessToken != "at" || res.Profile.Subject != "" {
		t.Fatalf("%+v %v", res, err)
	}
	f := forms[0]
	if f.Get("client_secret") != "s" || f.Get("client_id") != "client" || f.Get("code_verifier") != "v" || f.Get("redirect_uri") != in.CallbackURL || basic[0] {
		t.Fatalf("form %v basic %v", f, basic[0])
	}
	in.Code = "bad"
	_, err = ps.For(cfg).Exchange(context.Background(), in)
	if !errors.Is(err, ErrProviderResponse) || strings.Contains(err.Error(), "upstream-secret-detail") {
		t.Fatalf("error %v", err)
	}
	if len(forms) != 2 {
		t.Fatalf("retried: %d", len(forms))
	}
}
