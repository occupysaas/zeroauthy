package signingrules

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestManagedKeyProjection(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{Key: &priv.PublicKey, KeyID: "managed-kid", Algorithm: "RS256", Use: "sig"}
	raw, _ := jwk.MarshalJSON()
	k := &store.SigningKey{TenantID: "t", KID: "managed-kid", Alg: "RS256", Status: store.KeyCurrent, PrivateKey: []byte("sealed sentinel"), PublicJWK: raw, CreatedAt: time.Unix(1, 0)}
	projected, err := Project(k)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(projected)
	for _, forbidden := range []string{"private_key", "privateKey", "sealed sentinel", `"d"`, `"p"`, `"q"`, `"dp"`, `"dq"`, `"qi"`, `"oth"`} {
		if bytes.Contains(b, []byte(forbidden)) {
			t.Fatalf("projection contains private field %q: %s", forbidden, b)
		}
	}
	if projected.KID != k.KID || projected.CurrentSince != nil || projected.CurrentUntil != nil || projected.RevokedAt != nil {
		t.Fatalf("bad K1 projection: %#v", projected)
	}
}

func TestCustomSigningValidation(t *testing.T) {
	keys := make([]json.RawMessage, 10)
	for i := range keys {
		keys[i] = rsaJWK(t, "kid-"+string(rune('a'+i)), false)
	}
	for _, count := range []int{1, 10} {
		b, _ := json.Marshal(map[string]any{"keys": keys[:count]})
		if _, err := ParseCustom(b); err != nil {
			t.Fatalf("%d valid keys: %v", count, err)
		}
	}
	ec := ecJWK(t, "ec-valid", false)
	if _, err := ParseCustom(append([]byte(`{"keys":[`), append(ec, []byte(`]}`)...)...)); err != nil {
		t.Fatalf("valid EC key: %v", err)
	}
	tooMany := append(append([]json.RawMessage{}, keys...), rsaJWK(t, "eleven", false))
	b, _ := json.Marshal(map[string]any{"keys": tooMany})
	if _, err := ParseCustom(b); err == nil {
		t.Fatal("accepted 11 keys")
	}
	invalid := []string{
		`{"keys":[{"kty":"RSA","kid":"x","kid":"y","n":"AQ","e":"Aw","alg":"RS256","use":"sig"}]}`,
		`{"keys":[{"kty":"RSA","kid":"x","n":"AQ","e":"Aw","d":"AQ","alg":"RS256","use":"sig"}]}`,
		`{"keys":[{"kty":"oct","kid":"x","k":"AQ","alg":"HS256","use":"sig"}]}`,
		`{"keys":[{"kty":"RSA","kid":"x","n":"AQ","e":"Aw","alg":"RS256","use":"enc"}]}`,
		`{"keys":[{"kty":"EC","kid":"x","crv":"P-384","x":"AQ","y":"AQ","alg":"ES384","use":"sig"}]}`,
		`{"keys":[{"kty":"RSA","kid":"x","n":"AQ","e":"Aw","alg":"RS256","use":"sig","x5c":["not a certificate"]}]}`,
		`{"keys":[{"kty":"RSA","kid":"x","n":"AQ","e":"Aw","alg":"RS256","use":"sig","x5u":"https://example.invalid/key"}]}`,
		`{"keys":[{"kty":"RSA","kid":"x","n":"AQ","e":"Aw","alg":"RS256","use":"sig","extra":true}]}`,
		`{"keys":[{"kty":"RSA","kid":"x","n":"AQ","e":"Aw","alg":"RS256","use":"sig","key_ops":["sign"]}]}`,
		string(append([]byte(`{"keys":[`), append(ecJWK(t, "ec-private", true), []byte(`]}`)...)...)),
	}
	for _, raw := range invalid {
		if _, err := ParseCustom([]byte(raw)); err == nil {
			t.Errorf("accepted invalid JWKS %s", raw)
		}
	}
	dup := []json.RawMessage{rsaJWK(t, "same", false), rsaJWK(t, "same", false)}
	b, _ = json.Marshal(map[string]any{"keys": dup})
	if _, err := ParseCustom(b); err == nil {
		t.Fatal("accepted duplicate key IDs")
	}
	if ids, err := KeyIDs(json.RawMessage(b)); err == nil && len(ids) == 2 {
		t.Fatal("KeyIDs accepted duplicate IDs")
	}
}

func rsaJWK(t *testing.T, kid string, private bool) json.RawMessage {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())}
	if private {
		m["d"] = base64.RawURLEncoding.EncodeToString(k.D.Bytes())
	}
	b, _ := json.Marshal(m)
	return b
}

func ecJWK(t *testing.T, kid string, private bool) json.RawMessage {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pad := func(b []byte) []byte { out := make([]byte, 32); copy(out[32-len(b):], b); return out }
	m := map[string]string{"kty": "EC", "kid": kid, "alg": "ES256", "use": "sig", "crv": "P-256", "x": base64.RawURLEncoding.EncodeToString(pad(k.X.Bytes())), "y": base64.RawURLEncoding.EncodeToString(pad(k.Y.Bytes()))}
	if private {
		m["d"] = base64.RawURLEncoding.EncodeToString(k.D.Bytes())
	}
	b, _ := json.Marshal(m)
	return b
}
