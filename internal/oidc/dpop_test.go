package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/go-jose/go-jose/v4"
	"github.com/zeroauthy/zeroauthy/internal/dpop"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"net/http/httptest"
	"testing"
	"time"
)

func TestUserinfoDPoP(t *testing.T) {
	e := newUserinfoEnv(t)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	thumb, _ := (&jose.JSONWebKey{Key: &k.PublicKey}).Thumbprint(crypto.SHA256)
	jkt := base64.RawURLEncoding.EncodeToString(thumb)
	raw := e.token(t, "ten_a", map[string]any{"cnf": map[string]string{"jkt": jkt}})
	if r := e.call("GET", "Bearer "+raw); r.Code != 401 {
		t.Fatal("Bearer downgrade accepted")
	}
	master := make([]byte, 32)
	rand.Read(master)
	w, _ := keys.NewLocalWrapper(master)
	s := &dpop.Service{Store: e.st, Wrapper: w, Now: func() time.Time { return uiNow }}
	h := &Handlers{Keys: e.km, Store: e.st, Now: func() time.Time { return uiNow }, DPoP: s}
	tn, _ := e.st.Tenants().Get(context.Background(), "ten_a")
	res := tenant.Resolved{Tenant: tn, Host: "acme.example.test"}
	call := func(nonce string, alter bool) *httptest.ResponseRecorder {
		sum := sha256.Sum256([]byte(raw))
		ath := base64.RawURLEncoding.EncodeToString(sum[:])
		if alter {
			ath = "other"
		}
		payload, _ := json.Marshal(map[string]any{"htm": "GET", "htu": res.Origin() + "/userinfo", "jti": secrets.RandomString(20), "iat": uiNow.Unix(), "ath": ath, "nonce": nonce})
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k}, (&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", jose.JSONWebKey{Key: &k.PublicKey}))
		obj, _ := signer.Sign(payload)
		proof, _ := obj.CompactSerialize()
		r := httptest.NewRequest("GET", res.Origin()+"/userinfo", nil)
		r = r.WithContext(tenant.WithResolved(r.Context(), res))
		r.Header.Set("Authorization", "DPoP "+raw)
		r.Header.Set("DPoP", proof)
		rec := httptest.NewRecorder()
		h.Userinfo(rec, r)
		return rec
	}
	rec := call("", false)
	if rec.Code != 401 || rec.Header().Get("DPoP-Nonce") == "" || rec.Header().Get("WWW-Authenticate") != `DPoP error="use_dpop_nonce"` {
		t.Fatal("nonce challenge missing")
	}
	nonce := rec.Header().Get("DPoP-Nonce")
	if rec = call(nonce, false); rec.Code != 200 {
		t.Fatalf("valid %d", rec.Code)
	}
	if rec = call(nonce, true); rec.Code != 401 {
		t.Fatal("token substitution accepted")
	}
}

func TestDPoPDiscovery(t *testing.T) {
	h, _ := setup(t)
	rec := get(h, "https://acme.example.test/.well-known/openid-configuration")
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	v, _ := out["dpop_signing_alg_values_supported"].([]any)
	if len(v) != 2 || v[0] != "ES256" || v[1] != "RS256" {
		t.Fatal("discovery algorithms missing")
	}
}
