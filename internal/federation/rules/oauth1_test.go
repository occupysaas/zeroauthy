package rules

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"maps"
	"testing"
)

func oauth1Input(extra map[string]any) Input {
	o := map[string]any{"client_id": "consumer-key", "client_secret": "consumer-secret",
		"requestTokenURL": "https://provider.example/oauth/request_token", "accessTokenURL": "https://provider.example/oauth/access_token",
		"userAuthorizationURL": "https://provider.example/oauth/authorize",
		"scripts":              map[string]any{"fetchUserProfile": "function fetchUserProfile(t, s, c, cb) { cb(null, {user_id: 'x'}); }"}}
	maps.Copy(o, extra)
	for k, v := range o {
		if v == nil {
			delete(o, k)
		}
	}
	return Input{Strategy: OAuth1, Name: "oauth1-conn", Options: o}
}

func TestOAuth1Rules(t *testing.T) {
	if !IsFederated(OAuth1) || !IsSocial(OAuth1) || !NeedsSocialCapability(OAuth1) || !NeedsSocialCapability("amazon") || NeedsSocialCapability(OAuth2) {
		t.Fatal("oauth1 classification")
	}
	s, errs := Parse(oauth1Input(nil))
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if s.OAuth1 == nil || s.OAuth1.SignatureMethod != "HMAC-SHA1" || s.OAuth1.RequestTokenURL != "https://provider.example/oauth/request_token" ||
		s.OAuth1.AccessTokenURL != "https://provider.example/oauth/access_token" || s.OAuth1.UserAuthorizationURL != "https://provider.example/oauth/authorize" || s.Script == "" {
		t.Fatalf("settings %+v %+v", s, s.OAuth1)
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	if s, errs := Parse(oauth1Input(map[string]any{"signatureMethod": "RSA-SHA1", "client_secret": pemKey})); len(errs) > 0 || s.OAuth1.SignatureMethod != "RSA-SHA1" {
		t.Fatalf("RSA-SHA1: %v", errs)
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	smallPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(small)}))
	for name, extra := range map[string]map[string]any{
		"plaintext":            {"signatureMethod": "PLAINTEXT"},
		"hmac named":           {"signatureMethod": "HMAC-SHA1"},
		"rsa without pem":      {"signatureMethod": "RSA-SHA1"},
		"rsa short key":        {"signatureMethod": "RSA-SHA1", "client_secret": smallPEM},
		"no request url":       {"requestTokenURL": nil},
		"no access url":        {"accessTokenURL": nil},
		"no authorization url": {"userAuthorizationURL": nil},
		"http url":             {"accessTokenURL": "http://provider.example/oauth/access_token"},
		"loopback url":         {"requestTokenURL": "https://127.0.0.1/oauth/request_token"},
		"no script":            {"scripts": nil},
		"empty script":         {"scripts": map[string]any{"fetchUserProfile": " "}},
		"oauth2 endpoint":      {"authorizationURL": "https://provider.example/authorize"},
		"freeform":             {"freeform_scopes": []any{"x"}},
		"no secret":            {"client_secret": nil},
	} {
		t.Run(name, func(t *testing.T) {
			if _, errs := Parse(oauth1Input(extra)); len(errs) == 0 {
				t.Fatal("accepted")
			}
		})
	}
	in := oauth1Input(map[string]any{"client_secret": nil})
	in.HasSealedSecret = true
	if _, errs := Parse(in); len(errs) > 0 {
		t.Fatalf("patch keeping the sealed secret: %v", errs)
	}
}
