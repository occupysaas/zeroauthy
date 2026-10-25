package keys

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestSigningBackfillIdentity(t *testing.T) {
	m, st := newManager(t)
	ctx := context.Background()
	legacy := make([]*store.SigningKey, 0, 4)
	for _, status := range []store.KeyStatus{store.KeyCurrent, store.KeyNext, store.KeyPrevious, store.KeyRevoked} {
		k, err := m.generate("ten_a", status)
		if err != nil {
			t.Fatal(err)
		}
		k.CertificateDER = nil
		legacy = append(legacy, k)
		if err := st.SigningKeys().Create(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	legacyToken, err := m.Sign(ctx, "ten_a", map[string]any{"sub": "pre-upgrade"})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := st.SigningKeys().List(ctx, "ten_a")
	if err := m.BackfillCertificates(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	after, _ := st.SigningKeys().List(ctx, "ten_a")
	if len(before) != len(after) {
		t.Fatalf("row count changed: %d -> %d", len(before), len(after))
	}
	for i, got := range after {
		want := before[i]
		if got.KID != want.KID || got.Status != want.Status || string(got.PrivateKey) != string(want.PrivateKey) || string(got.PublicJWK) != string(want.PublicJWK) {
			t.Fatalf("key identity changed for %s", want.KID)
		}
		if len(got.CertificateDER) == 0 {
			t.Fatalf("certificate missing for %s", got.KID)
		}
	}
	if err := m.Ensure(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := m.Verify(ctx, "ten_a", legacyToken, &claims); err != nil || claims["sub"] != "pre-upgrade" {
		t.Fatalf("legacy token after backfill: claims=%v err=%v", claims, err)
	}
	final, _ := st.SigningKeys().List(ctx, "ten_a")
	if len(final) != len(legacy) {
		t.Fatalf("Ensure changed legacy rows: %d", len(final))
	}
}

type failingUnwrapper struct{ Wrapper }

func (f failingUnwrapper) Unwrap([]byte, []byte) ([]byte, error) {
	return nil, errors.New("injected unwrap failure")
}

type failingCertificateCAS struct{ store.SigningKeys }

func (f failingCertificateCAS) SetCertificateIfAbsent(context.Context, string, string, []byte) (*store.SigningKey, error) {
	return nil, errors.New("injected CAS failure")
}

func TestSigningBackfillFailure(t *testing.T) {
	m, st := newManager(t)
	ctx := context.Background()
	k, err := m.generate("ten_a", store.KeyCurrent)
	if err != nil {
		t.Fatal(err)
	}
	k.CertificateDER = nil
	if err := st.SigningKeys().Create(ctx, k); err != nil {
		t.Fatal(err)
	}
	failing := NewManager(st.SigningKeys(), failingUnwrapper{m.wrap})
	if err := failing.BackfillCertificates(ctx, "ten_a"); err == nil {
		t.Fatal("expected unwrap error")
	}
	unchanged, _ := st.SigningKeys().List(ctx, "ten_a")
	if len(unchanged) != 1 || unchanged[0].KID != k.KID || len(unchanged[0].CertificateDER) != 0 {
		t.Fatal("failed backfill changed the signing key")
	}
	if err := m.BackfillCertificates(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	if err := m.BackfillCertificates(ctx, "ten_a"); err != nil {
		t.Fatalf("retry not idempotent: %v", err)
	}
	completed, _ := st.SigningKeys().List(ctx, "ten_a")
	if len(completed) != 1 || len(completed[0].CertificateDER) == 0 {
		t.Fatal("retry did not add certificate")
	}
}

func TestSigningBackfillCASFailure(t *testing.T) {
	m, st := newManager(t)
	ctx := context.Background()
	k, err := m.generate("ten_a", store.KeyCurrent)
	if err != nil {
		t.Fatal(err)
	}
	k.CertificateDER = nil
	if err := st.SigningKeys().Create(ctx, k); err != nil {
		t.Fatal(err)
	}
	broken := NewManager(failingCertificateCAS{st.SigningKeys()}, m.wrap)
	if err := broken.BackfillCertificates(ctx, "ten_a"); err == nil {
		t.Fatal("expected CAS error")
	}
	rows, _ := st.SigningKeys().List(ctx, "ten_a")
	if len(rows) != 1 || len(rows[0].CertificateDER) != 0 || rows[0].KID != k.KID {
		t.Fatal("CAS failure altered row")
	}
	if err := m.BackfillCertificates(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
}
