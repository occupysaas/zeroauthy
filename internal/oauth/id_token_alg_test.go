package oauth

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
)

func TestIDTokenHS256(t *testing.T) {
	m := &Minter{Keys: newTestKeys(t, "ten_a"), Now: fixedNow}
	secret := []byte(secrets.RandomString(48))
	raw, err := m.IDToken(t.Context(), IDTokenParams{SigningAlg: "HS256", SigningSecret: secret, TenantID: "ten_a", Issuer: "https://a.example/", ClientID: "c", User: &store.User{UserID: "u"}, Scopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.HS256})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Headers[0].KeyID != "" {
		t.Fatal("symmetric key ID exposed")
	}
	var claims map[string]any
	if err := parsed.Claims(secret, &claims); err != nil || claims["aud"] != "c" {
		t.Fatal("HS256 ID token did not verify")
	}
}
func TestIDTokenPS256(t *testing.T) {
	km := newTestKeys(t, "ten_a")
	m := &Minter{Keys: km, Now: fixedNow}
	raw, err := m.IDToken(t.Context(), IDTokenParams{SigningAlg: "PS256", TenantID: "ten_a", Issuer: "https://a.example/", ClientID: "c", User: &store.User{UserID: "u"}, Scopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.PS256})
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := km.JWKS(t.Context(), "ten_a")
	if err != nil {
		t.Fatal(err)
	}
	keys := jwks.Key(parsed.Headers[0].KeyID)
	if len(keys) != 1 {
		t.Fatal("tenant key missing")
	}
	var claims map[string]any
	if parsed.Claims(keys[0].Key, &claims) != nil || claims["sub"] != "u" {
		t.Fatal("PS256 did not verify")
	}
}
func TestHS256SecretRotation(t *testing.T) {
	f := newFixture(t)
	tid := f.tenantID(t, "acme")
	client, err := f.st.Clients().Get(t.Context(), tid, "code-web")
	if err != nil {
		t.Fatal(err)
	}
	oldSecret, newSecret := secrets.RandomString(64), secrets.RandomString(64)
	mint := func(secret string) string {
		sealed, err := keys.SealClientSecret(f.h.Wrapper, tid, client.ClientID, secret)
		if err != nil {
			t.Fatal(err)
		}
		client.IDTokenAlg = "HS256"
		client.Secrets = []store.ClientSecret{{Sealed: sealed, CreatedAt: fixedNow()}}
		if err := f.st.Clients().Update(t.Context(), client); err != nil {
			t.Fatal(err)
		}
		code := f.issueCode(t, client.ClientID, "https://web.acme.test/cb", "", []string{"openid"}, "")
		form := codeForm(code, client.ClientID, "https://web.acme.test/cb", "")
		form.Set("client_secret", secret)
		rec, out := f.call(t, false, tokenCall{host: "acme.example.test", form: form})
		if rec.Code != 200 {
			t.Fatalf("exchange status=%d", rec.Code)
		}
		raw := out["id_token"].(string)
		parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.HS256})
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if parsed.Claims([]byte(secret), &got) != nil {
			t.Fatal("current secret did not verify")
		}
		return raw
	}
	_ = mint(oldSecret)
	raw := mint(newSecret)
	parsed, _ := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.HS256})
	var got map[string]any
	if parsed.Claims([]byte(oldSecret), &got) == nil {
		t.Fatal("rotated ID token verifies with old secret")
	}
}
