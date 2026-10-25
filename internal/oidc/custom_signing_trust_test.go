package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func TestSigningTrustExcludesCustomKeysHTTP(t *testing.T) {
	e := newUserinfoEnv(t)
	attacker, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{Key: &attacker.PublicKey, KeyID: "attacker", Algorithm: "RS256", Use: "sig"}
	pub, _ := jwk.MarshalJSON()
	if err := e.st.CustomSigningKeys().Replace(context.Background(), &store.CustomSigningKeySet{TenantID: "ten_a", JWKS: json.RawMessage(`{"keys":[` + string(pub) + `]}`)}); err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: attacker}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "attacker"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(map[string]any{"iss": "https://acme.example.test/", "sub": "auth0|1", "aud": "https://acme.example.test/userinfo", "iat": uiNow.Unix(), "exp": uiNow.Add(time.Hour).Unix()}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if rec := e.call("GET", "Bearer "+raw); rec.Code != 401 {
		t.Fatalf("userinfo accepted custom signer: %d %s", rec.Code, rec.Body)
	}
	res := tenant.Resolved{Tenant: &store.Tenant{ID: "ten_a"}, Host: "acme.example.test"}
	if _, _, ok, err := (&Handlers{Keys: e.km}).idTokenHint(context.Background(), res, raw); err != nil || ok {
		t.Fatalf("logout hint trusted custom signer: ok=%v err=%v", ok, err)
	}
	if err := e.km.Verify(context.Background(), "ten_a", raw, nil); !errors.Is(err, keys.ErrInvalidToken) {
		t.Fatalf("manager accepted custom signer: %v", err)
	}
}
