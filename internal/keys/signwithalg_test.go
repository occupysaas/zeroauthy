package keys

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestSignWithAlgPS256(t *testing.T) {
	m, _ := newManager(t)
	ctx := context.Background()
	if err := m.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"JWT", "at+jwt"} {
		raw, err := m.SignWithAlg(ctx, "ten_a", map[string]any{"sub": "u1"}, typ, jose.PS256)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.PS256})
		if err != nil {
			t.Fatalf("%s: not PS256: %v", typ, err)
		}
		h := parsed.Headers[0]
		if h.Algorithm != "PS256" || h.KeyID == "" || h.ExtraHeaders[jose.HeaderType] != typ {
			t.Fatalf("%s: header %+v", typ, h)
		}
		var got map[string]any
		if err := m.Verify(ctx, "ten_a", raw, &got); err != nil || got["sub"] != "u1" {
			t.Fatalf("%s: Verify = %v %v", typ, got, err)
		}
		if _, err := m.SignWithAlg(ctx, "ten_a", map[string]any{"sub": "u1"}, typ, jose.RS256); err != nil {
			t.Fatal(err)
		}
	}
	set, err := m.JWKS(ctx, "ten_a")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range set.Keys {
		// C19: a JWK marked alg RS256 is skipped by jose-based verifiers
		// for a PS256 token, so the published key carries no alg.
		if k.Algorithm != "" {
			t.Fatalf("JWK alg = %q, want none (C19)", k.Algorithm)
		}
	}
}

func TestSignWithAlgRefusals(t *testing.T) {
	m, _ := newManager(t)
	ctx := context.Background()
	if err := m.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	for _, alg := range []jose.SignatureAlgorithm{jose.HS256, jose.RS384, jose.ES256, "none", ""} {
		if _, err := m.SignWithAlg(ctx, "ten_a", map[string]any{}, "JWT", alg); err == nil {
			t.Errorf("accepted %q", alg)
		}
	}
	if _, err := m.SignWithAlg(ctx, "ten_a", map[string]any{}, "jwt", jose.PS256); err == nil {
		t.Error("accepted a token type outside the allowlist")
	}
	if _, err := m.SignWithAlg(ctx, "ten_none", map[string]any{}, "JWT", jose.PS256); !errors.Is(err, ErrNoSigningKey) {
		t.Errorf("no key: %v", err)
	}
}

func TestAPISigningSecretBinding(t *testing.T) {
	_, _ = newManager(t)
	w, err := NewLocalWrapper(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealAPISigningSecret(w, "ten_a", "rs1", "0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := OpenAPISigningSecret(w, "ten_a", "rs1", sealed); err != nil || string(got) != "0123456789abcdef" {
		t.Fatalf("round trip: %q %v", got, err)
	}
	for _, c := range [][2]string{{"ten_b", "rs1"}, {"ten_a", "rs2"}} {
		if _, err := OpenAPISigningSecret(w, c[0], c[1], sealed); err == nil {
			t.Errorf("opened for %v", c)
		}
	}
}

// TestJWKSOmitsStoredAlg covers keys generated before C19 was resolved: their
// stored JWK still says alg RS256, and the published set drops it while the
// kid, use and modulus stay exactly as stored. New keys are stored without alg.
func TestJWKSOmitsStoredAlg(t *testing.T) {
	m, st := newManager(t)
	ctx := context.Background()
	if err := m.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	ks, err := st.SigningKeys().List(ctx, "ten_a")
	if err != nil || len(ks) == 0 {
		t.Fatalf("keys = %v %v", ks, err)
	}
	for _, k := range ks {
		if strings.Contains(string(k.PublicJWK), `"alg"`) {
			t.Fatalf("new key stored with alg: %s", k.PublicJWK)
		}
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	legacy := jose.JSONWebKey{Key: &priv.PublicKey, KeyID: "legacy-key-0001", Algorithm: "RS256", Use: "sig"}
	stored, err := legacy.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SigningKeys().Create(ctx, &store.SigningKey{TenantID: "ten_a", KID: legacy.KeyID, Alg: "RS256", Status: store.KeyPrevious, PublicJWK: stored, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	set, err := m.JWKS(ctx, "ten_a")
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	if err := json.Unmarshal(stored, &want); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, k := range out.Keys {
		if _, ok := k["alg"]; ok {
			t.Fatalf("published JWK has alg: %v", k)
		}
		if k["kid"] == legacy.KeyID {
			found = true
			if k["kty"] != "RSA" || k["use"] != "sig" || k["n"] != want["n"] || k["e"] != want["e"] {
				t.Fatalf("published JWK changed beyond alg: %v vs %v", k, want)
			}
		}
	}
	if !found {
		t.Fatalf("legacy key not published: %s", body)
	}
}
