package federation

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"github.com/go-jose/go-jose/v4"
	"testing"
	"time"
)

func TestGlobalRevocationJWT(t *testing.T) {
	p := newIDP(t)
	cfg := oidcConfig()
	cfg.Issuer = p.issuer()
	cfg.DiscoveryURL = p.issuer() + "/.well-known/openid-configuration"
	ps := p.providers()
	wrong, _ := rsa.GenerateKey(rand.Reader, 2048)
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
		typ    string
		wrong  bool
		good   bool
	}{
		{name: "valid", typ: "global-token-revocation+jwt", good: true},
		{name: "wrong issuer", typ: "global-token-revocation+jwt", mutate: func(c map[string]any) { c["iss"] = "https://other.example/" }},
		{name: "wrong subject", typ: "global-token-revocation+jwt", mutate: func(c map[string]any) { c["sub"] = "other-client" }},
		{name: "wrong audience", typ: "global-token-revocation+jwt", mutate: func(c map[string]any) { c["aud"] = "https://other.example/" }},
		{name: "expired", typ: "global-token-revocation+jwt", mutate: func(c map[string]any) { c["exp"] = fixedTime.Add(-time.Second).Unix() }},
		{name: "long expiration", typ: "global-token-revocation+jwt", mutate: func(c map[string]any) { c["exp"] = fixedTime.Add(301 * time.Second).Unix() }},
		{name: "future issued", typ: "global-token-revocation+jwt", mutate: func(c map[string]any) { c["iat"] = fixedTime.Add(GlobalRevocationClockSkew + time.Second).Unix() }},
		{name: "missing jti", typ: "global-token-revocation+jwt", mutate: func(c map[string]any) { delete(c, "jti") }},
		{name: "wrong key", typ: "global-token-revocation+jwt", wrong: true},
		{name: "wrong type", typ: "JWT"},
		{name: "id token", typ: "JWT", mutate: func(c map[string]any) { c["nonce"] = "nonce" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := map[string]any{"iss": p.issuer(), "sub": "client", "aud": "https://tenant.example/", "iat": fixedTime.Unix(), "exp": fixedTime.Add(5 * time.Minute).Unix(), "jti": "unique"}
			if tc.mutate != nil {
				tc.mutate(c)
			}
			key := p.key
			if tc.wrong {
				key = wrong
			}
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType(jose.ContentType(tc.typ)).WithHeader("kid", p.kid))
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(c)
			obj, _ := signer.Sign(raw)
			jwt, _ := obj.CompactSerialize()
			verified, err := ps.VerifyGlobalRevocation(t.Context(), CacheKey{TenantID: "t", ConnectionID: "c"}, cfg, jwt, "https://tenant.example/", fixedTime)
			if tc.good {
				if err != nil || verified.JTI != "unique" {
					t.Fatalf("valid rejected: %v", err)
				}
			} else if err == nil {
				t.Fatal("invalid accepted")
			}
		})
	}
	if _, err := ps.VerifyGlobalRevocation(t.Context(), CacheKey{}, cfg, "eyJhbGciOiJub25lIn0.e30.", "https://tenant.example/", fixedTime); err == nil {
		t.Fatal("none accepted")
	}
}
