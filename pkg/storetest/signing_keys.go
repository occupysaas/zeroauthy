package storetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func timePtr(t time.Time) *time.Time { return &t }

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

	t.Run("TenantIsolation", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "shared-kid", store.KeyPrevious, 0)))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_b", "shared-kid", store.KeyPrevious, 0)))
		if _, err := s.SigningKeys().Get(ctx, "ten_a", "missing"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("cross-tenant key read: %v", err)
		}
		if got, err := s.SigningKeys().Get(ctx, "ten_b", "shared-kid"); err != nil || got.TenantID != "ten_b" {
			t.Fatalf("tenant B key: %+v %v", got, err)
		}
	})

	t.Run("RotateRetainsPrevious", func(t *testing.T) {
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
			"k1": store.KeyPrevious, "k2": store.KeyPrevious, "k3": store.KeyCurrent, "k4": store.KeyNext,
		})

		// Other tenants are untouched.
		mustEqual(t, statuses(t, s, "ten_b"), map[string]store.KeyStatus{"b1": store.KeyCurrent})
	})

	t.Run("AtomicResultsAndTimestamps", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "c0", store.KeyCurrent, 0)))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "n0", store.KeyNext, time.Hour)))
		at1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		r1, err := s.SigningKeys().RotateWithResult(ctx, "ten_a", newSigningKey("ten_a", "n1", store.KeyNext, 2*time.Hour), at1)
		mustNoErr(t, err)
		if r1.Current.KID != "n0" || r1.Next.KID != "n1" {
			t.Fatalf("first result = %#v", r1)
		}
		if r1.Current.CurrentSince == nil || !r1.Current.CurrentSince.Equal(at1) {
			t.Fatalf("current_since = %v", r1.Current.CurrentSince)
		}
		at2 := at1.Add(time.Hour)
		r2, err := s.SigningKeys().RotateWithResult(ctx, "ten_a", newSigningKey("ten_a", "n2", store.KeyNext, 3*time.Hour), at2)
		mustNoErr(t, err)
		if r2.Current.KID != r1.Next.KID || r2.Next.KID != "n2" {
			t.Fatalf("second result = %#v", r2)
		}
		if r2.Current.CurrentSince == nil || !r2.Current.CurrentSince.Equal(at2) {
			t.Fatalf("current_since = %v", r2.Current.CurrentSince)
		}
		old, err := s.SigningKeys().Get(ctx, "ten_a", "n0")
		mustNoErr(t, err)
		if old.CurrentUntil == nil || !old.CurrentUntil.Equal(at2) {
			t.Fatalf("old current_until = %v", old.CurrentUntil)
		}
		if got := statuses(t, s, "ten_a"); got["c0"] != store.KeyPrevious || got["n0"] != store.KeyPrevious {
			t.Fatalf("prior keys were not retained: %v", got)
		}
	})

	t.Run("ConcurrentRotationResults", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("a")))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "current-0", store.KeyCurrent, 0)))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "queued-0", store.KeyNext, time.Hour)))
		const n = 5
		results := make([]*store.SigningKeyRotation, n)
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range results {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				results[i], errs[i] = s.SigningKeys().RotateWithResult(ctx, "ten_a", newSigningKey("ten_a", fmt.Sprintf("queued-%d", i+1), store.KeyNext, time.Duration(i+2)*time.Hour), ts(time.Duration(i+2)*time.Hour))
			}(i)
		}
		wg.Wait()
		byCurrent := map[string]*store.SigningKeyRotation{}
		for i, result := range results {
			if errs[i] != nil {
				t.Errorf("rotate %d: %v", i, errs[i])
				continue
			}
			if result == nil || result.Current == nil || result.Next == nil {
				t.Errorf("rotate %d returned incomplete result: %#v", i, result)
				continue
			}
			byCurrent[result.Current.KID] = result
		}
		current := "queued-0"
		var last *store.SigningKeyRotation
		for range n {
			result := byCurrent[current]
			if result == nil {
				t.Fatalf("no operation result promoted queued key %q: %#v", current, byCurrent)
			}
			last, current = result, result.Next.KID
		}
		got := statuses(t, s, "ten_a")
		if got[last.Current.KID] != store.KeyCurrent || got[last.Next.KID] != store.KeyNext {
			t.Fatalf("final result does not match final store state: result=%#v state=%v", last, got)
		}
	})

	t.Run("RevokeStateAndTimestamp", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "c", store.KeyCurrent, 0)))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "n", store.KeyNext, time.Hour)))
		at := time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC)
		if _, err := s.SigningKeys().Revoke(ctx, "ten_a", "c", at); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("revoke current: %v", err)
		}
		_, err := s.SigningKeys().RotateWithResult(ctx, "ten_a", newSigningKey("ten_a", "n2", store.KeyNext, 2*time.Hour), at)
		mustNoErr(t, err)
		first, err := s.SigningKeys().Revoke(ctx, "ten_a", "c", at)
		mustNoErr(t, err)
		second, err := s.SigningKeys().Revoke(ctx, "ten_a", "c", at.Add(time.Hour))
		mustNoErr(t, err)
		if first.RevokedAt == nil || !first.RevokedAt.Equal(at) || second.RevokedAt == nil || !second.RevokedAt.Equal(at) {
			t.Fatalf("revocation time changed: %v %v", first.RevokedAt, second.RevokedAt)
		}
	})

	t.Run("CertificateCAS", func(t *testing.T) {
		s := open(t, newStore)
		k := newSigningKey("ten_a", "c", store.KeyCurrent, 0)
		k.CurrentSince = timePtr(ts(0))
		mustNoErr(t, s.SigningKeys().Create(ctx, k))
		var wg sync.WaitGroup
		results := make([]*store.SigningKey, 2)
		for i := range results {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				got, err := s.SigningKeys().SetCertificateIfAbsent(ctx, "ten_a", "c", []byte{byte(i + 4)})
				if err != nil {
					t.Errorf("CAS: %v", err)
					return
				}
				results[i] = got
			}(i)
		}
		wg.Wait()
		if !bytes.Equal(results[0].CertificateDER, results[1].CertificateDER) {
			t.Fatalf("CAS returned competing certificates: %v %v", results[0].CertificateDER, results[1].CertificateDER)
		}
		results[0].CertificateDER[0] ^= 0xff
		*results[0].CurrentSince = time.Time{}
		got, err := s.SigningKeys().Get(ctx, "ten_a", "c")
		mustNoErr(t, err)
		if bytes.Equal(results[0].CertificateDER, got.CertificateDER) || got.CurrentSince.IsZero() {
			t.Fatal("mutating returned snapshot changed persisted state")
		}
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
		// Rotate serializes on the tenant's row, so the tenant exists as it
		// always does outside tests.
		tn := newTenant("a")
		mustNoErr(t, s.Tenants().Create(ctx, tn))
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
		got := statuses(t, s, "ten_a")
		counts := map[store.KeyStatus]int{}
		for kid, st := range got {
			counts[st]++
			if st != store.KeyCurrent && st != store.KeyNext && st != store.KeyPrevious && st != store.KeyRevoked {
				t.Errorf("key %s has status %q", kid, st)
			}
		}
		if counts[store.KeyCurrent] != 1 || counts[store.KeyNext] != 1 || len(got) != n+2 ||
			counts[store.KeyCurrent]+counts[store.KeyNext]+counts[store.KeyPrevious]+counts[store.KeyRevoked] != n+2 {
			t.Fatalf("unexpected end state: %v", got)
		}
	})
}
