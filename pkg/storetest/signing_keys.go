package storetest

import (
	"context"
	"fmt"
	"sync"
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

	t.Run("SingleCurrentAndNext", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k1", store.KeyCurrent, 0)))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k2", store.KeyNext, 0)))
		mustErrIs(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k3", store.KeyCurrent, 0)), store.ErrConflict)
		mustErrIs(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k4", store.KeyNext, 0)), store.ErrConflict)
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k5", store.KeyPrevious, 0)))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k6", store.KeyPrevious, 0)))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_b", "k1", store.KeyCurrent, 0))) // other tenant
	})

	t.Run("RotateRequiresNextStatus", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k1", store.KeyCurrent, 0)))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k2", store.KeyNext, time.Hour)))
		if err := s.SigningKeys().Rotate(ctx, "ten_a", newSigningKey("ten_a", "k3", store.KeyCurrent, 2*time.Hour)); err == nil {
			t.Fatal("Rotate accepted a successor without status next")
		}
		mustEqual(t, statuses(t, s, "ten_a"), map[string]store.KeyStatus{"k1": store.KeyCurrent, "k2": store.KeyNext})
	})

	t.Run("ConcurrentRotate", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k0", store.KeyCurrent, 0)))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "k1", store.KeyNext, time.Hour)))
		const n = 6
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = s.SigningKeys().Rotate(ctx, "ten_a", newSigningKey("ten_a", fmt.Sprintf("r%d", i), store.KeyNext, time.Duration(i+2)*time.Hour))
			}()
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Errorf("Rotate %d: %v", i, err)
			}
		}
		counts := map[store.KeyStatus]int{}
		for _, st := range statuses(t, s, "ten_a") {
			counts[st]++
		}
		if counts[store.KeyCurrent] != 1 || counts[store.KeyNext] != 1 || len(statuses(t, s, "ten_a")) != n+2 {
			t.Fatalf("unexpected end state: %v", statuses(t, s, "ten_a"))
		}
	})
}
