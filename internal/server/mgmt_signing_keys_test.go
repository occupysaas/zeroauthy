package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestSigningKeyRouteRequiresReadScope(t *testing.T) {
	h, _ := newMgmtEnv(t)
	reader := m2mToken(t, h, "acme.example.test", acmeMgmtAPI)
	rec, _ := sendJSON(h, http.MethodGet, "https://acme.example.test/api/v2/keys/signing", reader, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET signing keys with only read:clients = %d %s", rec.Code, rec.Body)
	}
}

func TestSigningTrustExcludesCustomKeysHTTP(t *testing.T) {
	h, st := newMgmtEnv(t)
	ctx := context.Background()
	tn, err := st.Tenants().GetByName(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	attacker, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{Key: &attacker.PublicKey, KeyID: "attacker", Algorithm: "RS256", Use: "sig"}
	pub, _ := jwk.MarshalJSON()
	if err := st.CustomSigningKeys().Replace(ctx, &store.CustomSigningKeySet{TenantID: tn.ID, JWKS: json.RawMessage(`{"keys":[` + string(pub) + `]}`)}); err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: attacker}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "attacker"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(map[string]any{"iss": "https://acme.example.test/", "sub": "m2m", "aud": acmeMgmtAPI, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "scope": "read:clients", "azp": "m2m", "gty": "client-credentials"}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := sendJSON(h, http.MethodGet, "https://acme.example.test/api/v2/clients", raw, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("management API accepted custom signer: %d %s", rec.Code, rec.Body)
	}
}
