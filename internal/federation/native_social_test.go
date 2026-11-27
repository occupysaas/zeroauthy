package federation

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func googleNativeSetup(t *testing.T) (*idp, *Providers, Config) {
	t.Helper()
	p := newIDP(t)
	ps := p.providers().WithGoogleFixture(GoogleOverride{Endpoints: Endpoints{JWKSURL: p.srv.URL + "/jwks"}, Issuer: p.issuer()})
	cfg := socConfig(t, StrategyGoogle, "")
	cfg.ClientID = "web-client.apps.googleusercontent.com"
	return p, ps, cfg
}

// TestNativeGoogleAudience (Review Focus 3): a Google ID token is accepted
// only when its aud is the connection's client_id; a token issued to another
// app is refused. An Android azp beside the right aud is accepted. Native
// tokens carry no nonce.
func TestNativeGoogleAudience(t *testing.T) {
	cache := CacheKey{TenantID: "ten", ConnectionID: "con_g", Revision: 1}
	for name, c := range map[string]struct {
		claims func(map[string]any)
		ok     bool
	}{
		"connection audience": {func(c map[string]any) { c["aud"] = "web-client.apps.googleusercontent.com" }, true},
		"android azp": {func(c map[string]any) {
			c["aud"] = "web-client.apps.googleusercontent.com"
			c["azp"] = "android-client.apps.googleusercontent.com"
		}, true},
		"other app":     {func(c map[string]any) { c["aud"] = "someone-else.apps.googleusercontent.com" }, false},
		"other app azp": {func(c map[string]any) { c["aud"] = "someone-else"; c["azp"] = "web-client.apps.googleusercontent.com" }, false},
		"no audience":   {func(c map[string]any) { delete(c, "aud") }, false},
		"wrong issuer": {func(c map[string]any) {
			c["aud"] = "web-client.apps.googleusercontent.com"
			c["iss"] = "https://evil.example"
		}, false},
		"expired": {func(c map[string]any) {
			c["aud"] = "web-client.apps.googleusercontent.com"
			c["exp"] = fixedTime.Add(-2 * clockSkew).Unix()
		}, false},
		"missing subject": {func(c map[string]any) { c["aud"] = "web-client.apps.googleusercontent.com"; delete(c, "sub") }, false},
	} {
		t.Run(name, func(t *testing.T) {
			p, ps, cfg := googleNativeSetup(t)
			p.claims = func(m map[string]any) { delete(m, "nonce"); c.claims(m) }
			res, err := ps.NativeGoogleProfile(t.Context(), cfg, cache, p.idToken())
			if c.ok != (err == nil) {
				t.Fatalf("err %v", err)
			}
			if c.ok && (res.Profile.Subject != "Subject-1" || res.Profile.EmailVerified == nil || !*res.Profile.EmailVerified || res.Tokens.AccessToken != "") {
				t.Fatalf("result %+v", res)
			}
		})
	}
	// A token signed by another key is refused.
	p, ps, cfg := googleNativeSetup(t)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	p.claims = func(m map[string]any) { m["aud"] = cfg.ClientID }
	p.sign = func(payload []byte) string {
		s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: other}, (&jose.SignerOptions{}).WithHeader("kid", p.kid))
		obj, _ := s.Sign(payload)
		out, _ := obj.CompactSerialize()
		return out
	}
	if _, err := ps.NativeGoogleProfile(t.Context(), cfg, cache, p.idToken()); err == nil {
		t.Fatal("foreign signature accepted")
	}
}

const fbNativeToken = "throwaway-facebook-session-info-token"

func fbNativeFixture(t *testing.T, debug string) (*socFixture, *Providers, Config) {
	f := newSocFixture(t)
	f.on("/facebook/v24.0/debug_token", jsonHandler(200, debug))
	return f, f.providers(), socConfig(t, "facebook", "")
}

// TestNativeFacebookToken: the session-info token is checked with
// debug_token for the connection's app; the subject is debug_token's
// user_id; user_profile is untrusted, must name the same user and never
// yields a verified email.
func TestNativeFacebookToken(t *testing.T) {
	const ok = `{"data":{"app_id":"throwaway-client","type":"USER","is_valid":true,"user_id":"10150000000000001"}}`
	f, ps, cfg := fbNativeFixture(t, ok)
	up, err := ParseFacebookUser(`{"id":"10150000000000001","name":"Fay Book","first_name":"Fay","last_name":"Book","email":"fay@example.com"}`)
	if err != nil {
		t.Fatal(err)
	}
	res, err := ps.NativeFacebookProfile(t.Context(), cfg, socTestSecret, fbNativeToken, up)
	if err != nil {
		t.Fatal(err)
	}
	p := res.Profile
	if p.Subject != "10150000000000001" || p.Name == nil || *p.Name != "Fay Book" || p.Email == nil || p.EmailVerified == nil || *p.EmailVerified {
		t.Fatalf("profile %+v", p)
	}
	h := f.headers["/facebook/v24.0/debug_token"]
	q := f.queries["/facebook/v24.0/debug_token"]
	if h.Get("Authorization") != "Bearer throwaway-client|"+socTestSecret || !strings.Contains(q, "input_token="+fbNativeToken) || strings.Contains(q, socTestSecret) {
		t.Fatalf("debug_token request %v %s", h, q)
	}
	if res, err := ps.NativeFacebookProfile(t.Context(), cfg, socTestSecret, fbNativeToken, nil); err != nil || res.Profile.Email != nil {
		t.Fatalf("no user_profile: %+v %v", res, err)
	}
	for name, debug := range map[string]string{
		"other app": `{"data":{"app_id":"other-app","is_valid":true,"user_id":"1"}}`,
		"invalid":   `{"data":{"app_id":"throwaway-client","is_valid":false,"user_id":"1"}}`,
		"no user":   `{"data":{"app_id":"throwaway-client","is_valid":true}}`,
		"error":     `{"error":{"message":"bad"}}`,
		"app token": `{"data":{"app_id":"throwaway-client","type":"APP","is_valid":true,"user_id":"1"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, ps, cfg := fbNativeFixture(t, debug)
			if _, err := ps.NativeFacebookProfile(t.Context(), cfg, socTestSecret, fbNativeToken, nil); !errors.Is(err, ErrProviderResponse) || strings.Contains(err.Error(), socTestSecret) || strings.Contains(err.Error(), fbNativeToken) {
				t.Fatalf("err %v", err)
			}
		})
	}
	// A user_profile naming another user is refused.
	other, _ := ParseFacebookUser(`{"id":"999","name":"Someone Else"}`)
	if _, err := ps.NativeFacebookProfile(t.Context(), cfg, socTestSecret, fbNativeToken, other); !errors.Is(err, ErrProviderResponse) {
		t.Fatalf("mismatched user_profile: %v", err)
	}
	for _, raw := range []string{`[]`, `{"id":1}`, `{"name":"` + strings.Repeat("a", 3000) + `"}`, `not json`} {
		if _, err := ParseFacebookUser(raw); err == nil {
			t.Fatalf("user_profile %q accepted", raw[:min(len(raw), 20)])
		}
	}
	_ = http.StatusOK
}
