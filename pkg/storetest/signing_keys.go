package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newSigningKey(tenantID, kid string, status store.KeyStatus, age time.Duration) *store.SigningKey {
	return &store.SigningKey{
		TenantID:   tenantID,
		KID:        kid,
		Alg:        "RS256",
		Status:     status,
		PrivateKey: []byte("sealed-" + kid),
		PublicJWK:  []byte(`{"kid":"` + kid + `"}`),
		CreatedAt:  ts(age),
	}
}

func statuses(t *testing.T, s store.Store, tenantID string) map[string]store.KeyStatus {
	t.Helper()
	ks, err := s.SigningKeys().List(context.Background(), tenantID)
	mustNoErr(t, err)
	out := map[string]store.KeyStatus{}
	for _, k := range ks {
		out[k.KID] = k.Status
	}
	return out
}

func testSigningKeys(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("CreateList", func(t *testing.T) {
		s := open(t, newStore)
		k2 := newSigningKey("ten_a", "k2", store.KeyNext, time.Hour)
		k1 := newSigningKey("ten_a", "k1", store.KeyCurrent, 0)
		mustNoErr(t, s.SigningKeys().Create(ctx, k2))
		mustNoErr(t, s.SigningKeys().Create(ctx, k1))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_b", "k1", store.KeyCurrent, 0)))
		mustErrIs(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k1", store.KeyCurrent, 0)), store.ErrConflict)

		got, err := s.SigningKeys().List(ctx, "ten_a")
		mustNoErr(t, err)
		mustEqual(t, got, []*store.SigningKey{k1, k2})

		got, err = s.SigningKeys().List(ctx, "ten_none")
		mustNoErr(t, err)
		mustEqual(t, len(got), 0)
	})

	t.Run("Rotate", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k1", store.KeyCurrent, 0)))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k2", store.KeyNext, time.Hour)))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_b", "b1", store.KeyCurrent, 0)))

		mustNoErr(t, s.SigningKeys().Rotate(ctx, "ten_a", newSigningKey("ten_a", "k3", store.KeyNext, 2*time.Hour)))
		mustEqual(t, statuses(t, s, "ten_a"), map[string]store.KeyStatus{
			"k1": store.KeyPrevious, "k2": store.KeyCurrent, "k3": store.KeyNext,
		})

		mustNoErr(t, s.SigningKeys().Rotate(ctx, "ten_a", newSigningKey("ten_a", "k4", store.KeyNext, 3*time.Hour)))
		mustEqual(t, statuses(t, s, "ten_a"), map[string]store.KeyStatus{
			"k1": store.KeyRevoked, "k2": store.KeyPrevious, "k3": store.KeyCurrent, "k4": store.KeyNext,
		})

		// Other tenants are untouched.
		mustEqual(t, statuses(t, s, "ten_b"), map[string]store.KeyStatus{"b1": store.KeyCurrent})
	})

	t.Run("RotateWithoutNextChangesNothing", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k1", store.KeyCurrent, 0)))
		err := s.SigningKeys().Rotate(ctx, "ten_a", newSigningKey("ten_a", "k2", store.KeyNext, time.Hour))
		mustErrIs(t, err, store.ErrNotFound)
		mustEqual(t, statuses(t, s, "ten_a"), map[string]store.KeyStatus{"k1": store.KeyCurrent})
	})

	t.Run("RotateDuplicateKIDChangesNothing", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k1", store.KeyCurrent, 0)))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k2", store.KeyNext, time.Hour)))
		err := s.SigningKeys().Rotate(ctx, "ten_a", newSigningKey("ten_a", "k1", store.KeyNext, 2*time.Hour))
		mustErrIs(t, err, store.ErrConflict)
		mustEqual(t, statuses(t, s, "ten_a"), map[string]store.KeyStatus{"k1": store.KeyCurrent, "k2": store.KeyNext})
	})
}
