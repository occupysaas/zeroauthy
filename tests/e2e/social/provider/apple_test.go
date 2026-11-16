package provider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestAppleFixtureClientSecret(t *testing.T) {
	p, err := New("https://idp.example")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := p.RegisterApple(AppleRegistration{ServicesID: "com.example.web", BundleID: "com.example.native", TeamID: "ABCDEFGHIJ", KeyID: "1234567890", PublicKey: &key.PublicKey}); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "native", "signature", "team", "kid", "audience", "subject", "expired", "future", "tooLong"} {
		t.Run(mode, func(t *testing.T) {
			client := "com.example.web"
			if mode == "native" {
				client = "com.example.native"
			}
			code, err := p.AppleCode(client, "relay")
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			claims := map[string]any{"iss": "ABCDEFGHIJ", "sub": client, "aud": "https://appleid.apple.com", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
			kid := "1234567890"
			signkey := key
			switch mode {
			case "signature":
				signkey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			case "team":
				claims["iss"] = "WRONGTEAM1"
			case "kid":
				kid = "WRONGKEY01"
			case "audience":
				claims["aud"] = "https://idp.example"
			case "subject":
				claims["sub"] = "wrong.bundle"
			case "expired":
				claims["exp"] = now.Add(-time.Minute).Unix()
			case "future":
				claims["iat"] = now.Add(time.Hour).Unix()
			case "tooLong":
				claims["exp"] = now.Add(200 * 24 * time.Hour).Unix()
			}
			signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: signkey}, (&jose.SignerOptions{}).WithHeader("kid", kid))
			payload, _ := json.Marshal(claims)
			obj, _ := signer.Sign(payload)
			secret, _ := obj.CompactSerialize()
			form := url.Values{"client_id": {client}, "client_secret": {secret}, "grant_type": {"authorization_code"}, "code": {code}}
			req := httptest.NewRequest(http.MethodPost, "https://idp.example/apple/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)
			want := http.StatusBadRequest
			if mode == "valid" || mode == "native" {
				want = http.StatusOK
			}
			if rec.Code != want {
				t.Fatalf("status %d want %d", rec.Code, want)
			}
			if want == http.StatusOK {
				var out map[string]any
				_ = json.Unmarshal(rec.Body.Bytes(), &out)
				token, _ := jose.ParseSigned(out["id_token"].(string), []jose.SignatureAlgorithm{jose.RS256})
				body, err := token.Verify(&p.key.PublicKey)
				if err != nil {
					t.Fatal(err)
				}
				var claims map[string]any
				_ = json.Unmarshal(body, &claims)
				if claims["aud"] != client || claims["email_verified"] != "true" || claims["is_private_email"] != "true" {
					t.Fatal(claims)
				}
			}
		})
	}
}
func TestAppleFixtureFormPost(t *testing.T) {
	p, _ := New("https://idp.example")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_ = p.RegisterApple(AppleRegistration{ServicesID: "com.example.web", TeamID: "ABCDEFGHIJ", KeyID: "1234567890", PublicKey: &key.PublicKey})
	for i := 0; i < 2; i++ {
		f := url.Values{"client_id": {"com.example.web"}, "state": {"state"}, "nonce": {"nonce"}, "redirect_uri": {"https://login.example/login/callback"}, "response_mode": {"form_post"}, "scope": {"name email"}, "subject": {"relay"}, "decision": {"allow"}}
		req := httptest.NewRequest(http.MethodPost, "https://idp.example/apple/authorize", strings.NewReader(f.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `method="post"`) || !strings.Contains(rec.Body.String(), `name="code"`) {
			t.Fatalf("form callback %d %s", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), `name="user"`) != (i == 0) {
			t.Fatal("Apple user was not one time")
		}
	}
}
