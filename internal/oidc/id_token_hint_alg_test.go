package oidc

import (
	"encoding/json"
	"github.com/go-jose/go-jose/v4"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"testing"
)

func TestHS256IDTokenHint(t *testing.T) {
	e := newUserinfoEnv(t)
	w, _ := keys.NewLocalWrapper([]byte(secrets.RandomString(32)))
	secret := secrets.RandomString(48)
	sealed, _ := keys.SealClientSecret(w, "ten_a", "hs-client", secret)
	c := &store.Client{TenantID: "ten_a", ClientID: "hs-client", AppType: store.AppTypeRegularWeb, TokenEndpointAuthMethod: store.AuthMethodClientSecretPost, IDTokenAlg: "HS256", Secrets: []store.ClientSecret{{Sealed: sealed}}}
	if err := e.st.Clients().Create(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{Store: e.st, Keys: e.km, Wrapper: w}
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte(secret)}, (&jose.SignerOptions{}).WithType("JWT"))
	data, _ := json.Marshal(map[string]any{"iss": "https://acme.example.test/", "aud": "hs-client", "sub": "u", "sid": "session", "exp": 1})
	signed, _ := signer.Sign(data)
	raw, _ := signed.CompactSerialize()
	res := tenant.Resolved{Tenant: &store.Tenant{ID: "ten_a"}, Host: "acme.example.test"}
	aud, sid, ok, err := h.idTokenHint(t.Context(), res, raw)
	if err != nil || !ok || aud != "hs-client" || sid != "session" {
		t.Fatalf("valid expired HS256 hint rejected: %v %v", ok, err)
	}
	c.IDTokenAlg = "RS256"
	if err := e.st.Clients().Update(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, _ := h.idTokenHint(t.Context(), res, raw); ok {
		t.Fatal("HMAC hint accepted for asymmetric client")
	}
}

func TestLogoutTokenNotIDTokenHint(t *testing.T) {
	e := newUserinfoEnv(t)
	h := &Handlers{Store: e.st, Keys: e.km}
	res := tenant.Resolved{Tenant: &store.Tenant{ID: "ten_a"}, Host: "acme.example.test"}
	for _, typ := range []string{"logout+jwt", "JWT"} {
		raw, err := e.km.SignWithType(t.Context(), "ten_a", map[string]any{"iss": res.Issuer(), "aud": "rp", "sub": "u", "sid": "session", "events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}}, typ)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, ok, _ := h.idTokenHint(t.Context(), res, raw); ok {
			t.Fatalf("%s logout token treated as an ID-token hint", typ)
		}
	}
}
