package script

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/federation/oauth1sig"
)

// parseOAuthHeader splits an OAuth Authorization header into its parameters.
func parseOAuthHeader(h string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(h, "OAuth "), ", ") {
		k, v, _ := strings.Cut(part, "=")
		v, _ = url.QueryUnescape(strings.Trim(v, `"`))
		out[k] = v
	}
	return out
}

// TestBrokerOAuthSigning: a script GET with oauth set is signed host-side
// with the connection's consumer credentials and the user's token; the
// consumer secret never enters the sandbox. Without OAuth 1.0a credentials
// the option is refused.
func TestBrokerOAuthSigning(t *testing.T) {
	creds := &oauth1sig.Credentials{ConsumerKey: "ck-throwaway", ConsumerSecret: "cs-throwaway", Token: "user-token", TokenSecret: "user-token-secret"}
	var got http.Header
	var gotURL string
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, gotURL = r.Header.Clone(), "https://"+r.Host+r.URL.RequestURI()
		_, _ = w.Write([]byte(`{"id":"1"}`))
	}))
	defer api.Close()
	b := NewBroker(tlsClient(api))
	if _, err := b.get(context.Background(), &execution{oauth1: creds}, GetOptions{URL: api.URL + "/me?x=1", OAuth: true, Headers: map[string]string{"Authorization": "Bearer spoof"}}); err != nil {
		t.Fatal(err)
	}
	p := parseOAuthHeader(got.Get("Authorization"))
	if p["oauth_consumer_key"] != "ck-throwaway" || p["oauth_token"] != "user-token" || p["oauth_signature_method"] != "HMAC-SHA1" {
		t.Fatalf("header %q", got.Get("Authorization"))
	}
	sig := p["oauth_signature"]
	delete(p, "oauth_signature")
	want, _ := oauth1sig.Sign(*creds, "GET", gotURL, nil, p)
	if sig != want {
		t.Fatalf("signature %s, want %s", sig, want)
	}
	if strings.Contains(got.Get("Authorization"), "cs-throwaway") || strings.Contains(got.Get("Authorization"), "user-token-secret") {
		t.Fatal("secret in header")
	}
	if _, err := b.get(context.Background(), &execution{}, GetOptions{URL: api.URL + "/me", OAuth: true}); !errors.Is(err, ErrBroker) {
		t.Fatalf("oauth without credentials: %v", err)
	}
}

// TestOAuth1ScriptArguments: an OAuth 1.0a script is called as
// fetchUserProfile(token, tokenSecret, context, callback).
func TestOAuth1ScriptArguments(t *testing.T) {
	r := newTestRunner(t, http.DefaultClient)
	raw, err := r.Execute(context.Background(), Request{TenantID: "ten", ConnectionID: "con", AccessToken: "tok", TokenSecret: "tok-secret",
		Context: map[string]any{"screen_name": "someone"}, OAuth1: &oauth1sig.Credentials{ConsumerKey: "k", ConsumerSecret: "s", Token: "tok", TokenSecret: "tok-secret"},
		Source: `function fetchUserProfile(token, tokenSecret, ctx, cb) { cb(null, {user_id: token + '/' + tokenSecret + '/' + ctx.screen_name}); }`})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if m["user_id"] != "tok/tok-secret/someone" {
		t.Fatalf("profile %v", m)
	}
}
