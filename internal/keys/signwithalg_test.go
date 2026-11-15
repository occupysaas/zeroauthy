package keys

import (
	"context"
	"errors"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
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
		if k.Algorithm != "RS256" {
			t.Fatalf("JWK alg = %q, want RS256 (C19)", k.Algorithm)
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
