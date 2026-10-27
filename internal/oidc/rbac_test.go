package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// A signed ID token or another JWT type cannot become a userinfo access token
// merely by carrying the same user subject and issuer.
func TestRBACProfileUserinfo(t *testing.T) {
	e := newUserinfoEnv(t)
	ctx := context.Background()
	base := func() map[string]any {
		return map[string]any{"iss": "https://acme.example.test/", "sub": "auth0|1", "aud": []string{"https://api.test", "https://acme.example.test/userinfo"}, "iat": uiNow.Unix(), "exp": uiNow.Add(time.Hour).Unix(), "scope": "openid email", "client_id": "client", "jti": "unique"}
	}
	for _, typ := range []string{"JWT", "at+jwt"} {
		c := base()
		if typ == "JWT" {
			delete(c, "client_id")
			c["azp"] = "client"
		}
		raw, err := e.km.SignWithType(ctx, "ten_a", c, typ)
		if err != nil {
			t.Fatal(err)
		}
		rec := e.call("GET", "Bearer "+raw)
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != 200 || body["sub"] != "auth0|1" || body["email"] != "alice@acme.test" {
			t.Fatalf("%s: %d %s", typ, rec.Code, rec.Body)
		}
		if body["permissions"] != nil || body["roles"] != nil {
			t.Fatalf("userinfo leaked RBAC: %#v", body)
		}
	}
	for _, tc := range []struct {
		name, key string
		value     any
	}{
		{"wrong audience", "aud", "https://api.test"},
		{"wrong issuer", "iss", "https://other.example.test/"},
		{"ID token shaped", "scope", nil},
		{"no openid", "scope", "email"},
		{"no client", "client_id", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			if tc.value == nil {
				delete(c, tc.key)
			} else {
				c[tc.key] = tc.value
			}
			raw, err := e.km.SignWithType(ctx, "ten_a", c, "at+jwt")
			if err != nil {
				t.Fatal(err)
			}
			if rec := e.call("GET", "Bearer "+raw); rec.Code != 401 {
				t.Fatalf("%s: %d %s", tc.name, rec.Code, rec.Body)
			}
		})
	}
	// Add a previous managed key with a test-only signer to produce a genuinely
	// valid signature with an unsupported type. Public SignWithType forbids it.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub := jose.JSONWebKey{Key: &priv.PublicKey, KeyID: "typed-fixture", Algorithm: "RS256", Use: "sig"}
	pubJSON, err := pub.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.SigningKeys().Create(ctx, &store.SigningKey{TenantID: "ten_a", KID: "typed-fixture", Alg: "RS256", Status: store.KeyPrevious, PublicJWK: pubJSON, CreatedAt: uiNow}); err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: priv}, (&jose.SignerOptions{}).WithType("application/jwt").WithHeader("kid", "typed-fixture"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(base()).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	var verified map[string]any
	if err := e.km.Verify(ctx, "ten_a", raw, &verified); err != nil {
		t.Fatalf("fixture signature invalid: %v", err)
	}
	if rec := e.call("GET", "Bearer "+raw); rec.Code != 401 {
		t.Fatalf("unsupported type: %d %s", rec.Code, rec.Body)
	}
}
