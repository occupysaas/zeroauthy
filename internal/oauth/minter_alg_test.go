package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func algParams(alg string, secret []byte) AccessTokenParams {
	return AccessTokenParams{
		TenantID: "ten_a", Issuer: "https://a.example.test/", Subject: "auth0|u1",
		Audience: []string{"https://api.test", "https://a.example.test/userinfo"},
		ClientID: "app", Scopes: []string{"openid"}, SigningAlg: alg, SigningSecret: secret,
	}
}

func TestMinterHS256(t *testing.T) {
	m := &Minter{Keys: newTestKeys(t, "ten_a"), Now: fixedNow}
	secret := []byte("0123456789abcdef0123456789abcdef")
	raw, err := m.AccessToken(context.Background(), algParams("HS256", secret))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.HS256})
	if err != nil {
		t.Fatal(err)
	}
	if h := tok.Headers[0]; h.KeyID != "" || h.Algorithm != "HS256" || h.ExtraHeaders[jose.HeaderType] != "JWT" {
		t.Fatalf("header %+v", h)
	}
	var c struct {
		Aud jwt.Audience `json:"aud"`
	}
	if err := tok.Claims(secret, &c); err != nil {
		t.Fatalf("does not verify with the secret: %v", err)
	}
	if len(c.Aud) != 1 || c.Aud[0] != "https://api.test" {
		t.Fatalf("aud = %v, want only the API (LR35-9)", c.Aud)
	}
	if err := tok.Claims([]byte("another-secret-0123456789"), &c); err == nil {
		t.Fatal("verified with another secret")
	}
}

func TestMinterHS256Refusals(t *testing.T) {
	m := &Minter{Keys: newTestKeys(t, "ten_a"), Now: fixedNow}
	if _, err := m.AccessToken(context.Background(), algParams("HS256", nil)); err == nil {
		t.Fatal("HS256 without a secret")
	}
	if _, err := m.AccessToken(context.Background(), algParams("ES256", nil)); err == nil {
		t.Fatal("unknown algorithm")
	}
}

func TestMinterHS256Dialects(t *testing.T) {
	m := &Minter{Keys: newTestKeys(t, "ten_a"), Now: fixedNow}
	p := algParams("HS256", []byte("0123456789abcdef"))
	p.TokenDialect = "rfc9068_profile"
	raw, err := m.AccessToken(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.HS256})
	if tok.Headers[0].ExtraHeaders[jose.HeaderType] != "at+jwt" {
		t.Fatalf("typ %v", tok.Headers[0].ExtraHeaders)
	}
}

func TestMinterPS256(t *testing.T) {
	km := newTestKeys(t, "ten_a")
	m := &Minter{Keys: km, Now: fixedNow}
	raw, err := m.AccessToken(context.Background(), algParams("PS256", nil))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.PS256})
	if err != nil {
		t.Fatal(err)
	}
	set, _ := km.JWKS(context.Background(), "ten_a")
	ks := set.Key(tok.Headers[0].KeyID)
	if len(ks) != 1 {
		t.Fatal("kid not in JWKS")
	}
	var c struct {
		Aud jwt.Audience `json:"aud"`
	}
	if err := tok.Claims(ks[0].Key, &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Aud) != 2 || c.Aud[1] != "https://a.example.test/userinfo" {
		t.Fatalf("aud = %v, want the userinfo audience kept (C18)", c.Aud)
	}
}

func TestMinterEmptyAlgIsRS256(t *testing.T) {
	km := newTestKeys(t, "ten_a")
	m := &Minter{Keys: km, Now: fixedNow}
	for _, alg := range []string{"", "RS256"} {
		raw, err := m.AccessToken(context.Background(), algParams(alg, []byte("ignored-secret-0123")))
		if err != nil {
			t.Fatal(err)
		}
		verifyToken(t, km, "ten_a", raw)
	}
}

func TestMinterHS256ShortSecret(t *testing.T) {
	m := &Minter{Keys: newTestKeys(t, "ten_a"), Now: fixedNow}
	secret := []byte("0123456789abcdef") // legacy stored secret shorter than the new 32-character write minimum
	raw, err := m.AccessToken(context.Background(), algParams("HS256", secret))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(raw, ".")
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if parts[2] != base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) {
		t.Fatal("signature does not match HMAC-SHA256 of the secret")
	}
}
