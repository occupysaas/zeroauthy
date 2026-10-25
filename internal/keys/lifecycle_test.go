package keys

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestSigningRevocationAcrossManagers(t *testing.T) {
	a, st := newManager(t)
	b := NewManager(st.SigningKeys(), a.wrap)
	ctx := context.Background()
	if err := a.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	raw, err := a.Sign(ctx, "ten_a", map[string]any{"sub": "legacy"})
	if err != nil {
		t.Fatal(err)
	}
	ks, _ := st.SigningKeys().List(ctx, "ten_a")
	oldCurrent := ks[0]
	if _, err := b.RotateWithResult(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := a.Verify(ctx, "ten_a", raw, &claims); err != nil {
		t.Fatalf("previous token: %v", err)
	}
	if _, err := b.Revoke(ctx, "ten_a", oldCurrent.KID); err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(ctx, "ten_a", raw, &claims); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify after revoke = %v", err)
	}
	if _, err := a.Sign(ctx, "ten_a", nil); err == nil {
		t.Fatal("stale manager signed with retired key")
	}
}

type unavailableSigningStore struct{ store.SigningKeys }

func (u unavailableSigningStore) List(context.Context, string) ([]*store.SigningKey, error) {
	return nil, errors.New("injected store outage")
}

func TestSigningStoreOutage(t *testing.T) {
	m, st := newManager(t)
	ctx := context.Background()
	if err := m.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Sign(ctx, "ten_a", map[string]any{"sub": "warm"}); err != nil {
		t.Fatal(err)
	}
	degraded := NewManager(unavailableSigningStore{st.SigningKeys()}, m.wrap)
	if _, err := degraded.Sign(ctx, "ten_a", nil); err == nil {
		t.Fatal("Sign hid storage outage")
	}
	if _, err := degraded.VerificationKeys(ctx, "ten_a"); err == nil {
		t.Fatal("VerificationKeys hid storage outage")
	}
}

func TestSigningTrustExcludesCustomKeys(t *testing.T) {
	m, st := newManager(t)
	ctx := context.Background()
	if err := m.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	attacker, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub := jose.JSONWebKey{Key: &attacker.PublicKey, Algorithm: "RS256", Use: "sig", KeyID: "attacker"}
	encoded, _ := pub.MarshalJSON()
	if err := st.CustomSigningKeys().Replace(ctx, &store.CustomSigningKeySet{TenantID: "ten_a", JWKS: []byte(`{"keys":[` + string(encoded) + `]}`)}); err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: attacker}, (&jose.SignerOptions{}).WithHeader("kid", "attacker"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(map[string]any{"sub": "forged"}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := m.Verify(ctx, "ten_a", raw, &claims); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("custom forged token accepted: %v", err)
	}
}

func TestM20CustomKeyForgery(t *testing.T) { TestSigningTrustExcludesCustomKeys(t) }
