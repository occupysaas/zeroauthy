package storetest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func customSet(tenantID string, kids ...string) *store.CustomSigningKeySet {
	keys := make([]string, len(kids))
	for i, kid := range kids {
		keys[i] = fmt.Sprintf(`{"kid":%q}`, kid)
	}
	return &store.CustomSigningKeySet{TenantID: tenantID, JWKS: []byte(`{"keys":[` + join(keys, ",") + `]}`)}
}

func testCustomSigningKeys(t *testing.T, newStore Factory) {
	ctx := context.Background()
	t.Run("ReplaceGetDeleteIsolationCopy", func(t *testing.T) {
		s := open(t, newStore)
		in := customSet("ten_a", "custom-a")
		mustNoErr(t, s.CustomSigningKeys().Replace(ctx, in))
		in.JWKS[0] = 'x'
		got, err := s.CustomSigningKeys().Get(ctx, "ten_a")
		mustNoErr(t, err)
		if string(got.JWKS) != `{"keys":[{"kid":"custom-a"}]}` {
			t.Fatalf("stored set changed with input: %s", got.JWKS)
		}
		got.JWKS[0] = 'x'
		got, err = s.CustomSigningKeys().Get(ctx, "ten_a")
		mustNoErr(t, err)
		if string(got.JWKS) != `{"keys":[{"kid":"custom-a"}]}` {
			t.Fatalf("returned set aliases storage: %s", got.JWKS)
		}
		if _, err := s.CustomSigningKeys().Get(ctx, "ten_b"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("cross-tenant read: %v", err)
		}
		if err := s.CustomSigningKeys().Delete(ctx, "ten_none"); err != nil {
			t.Fatalf("delete absent: %v", err)
		}
		mustNoErr(t, s.CustomSigningKeys().Delete(ctx, "ten_a"))
		if _, err := s.CustomSigningKeys().Get(ctx, "ten_a"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("get after delete: %v", err)
		}
	})

	t.Run("DeepCopy", func(t *testing.T) {
		s := open(t, newStore)
		input := customSet("ten_a", "original")
		mustNoErr(t, s.CustomSigningKeys().Replace(ctx, input))
		input.JWKS[0] = 'x'
		got, err := s.CustomSigningKeys().Get(ctx, "ten_a")
		mustNoErr(t, err)
		got.JWKS[0] = 'x'
		got2, err := s.CustomSigningKeys().Get(ctx, "ten_a")
		mustNoErr(t, err)
		if string(got2.JWKS) != `{"keys":[{"kid":"original"}]}` {
			t.Fatalf("custom key set was not detached: %s", got2.JWKS)
		}
	})

	t.Run("CustomManagedCollision", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "current", store.KeyCurrent, 0)))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "next", store.KeyNext, time.Hour)))
		mustErrIs(t, s.CustomSigningKeys().Replace(ctx, customSet("ten_a", "current")), store.ErrConflict)
		mustNoErr(t, s.CustomSigningKeys().Replace(ctx, customSet("ten_a", "custom")))
		mustErrIs(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "custom", store.KeyPrevious, 2*time.Hour)), store.ErrConflict)
		_, err := s.SigningKeys().RotateWithResult(ctx, "ten_a", newSigningKey("ten_a", "custom", store.KeyNext, 2*time.Hour), time.Now())
		mustErrIs(t, err, store.ErrConflict)
		if got := statuses(t, s, "ten_a"); got["current"] != store.KeyCurrent || got["next"] != store.KeyNext {
			t.Fatalf("collision changed managed state: %v", got)
		}
	})

	t.Run("TransactionRollbackAndTenantDelete", func(t *testing.T) {
		s := open(t, newStore)
		rollback := errors.New("rollback")
		if err := s.WithTx(ctx, func(tx store.Store) error {
			if err := tx.CustomSigningKeys().Replace(ctx, customSet("ten_a", "custom")); err != nil {
				return err
			}
			return rollback
		}); !errors.Is(err, rollback) {
			t.Fatalf("WithTx: %v", err)
		}
		if _, err := s.CustomSigningKeys().Get(ctx, "ten_a"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("rolled back custom set remains: %v", err)
		}
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("a")))
		mustNoErr(t, s.CustomSigningKeys().Replace(ctx, customSet("ten_a", "custom")))
		mustNoErr(t, s.Tenants().Delete(ctx, "ten_a"))
		if _, err := s.CustomSigningKeys().Get(ctx, "ten_a"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("tenant delete did not cascade: %v", err)
		}
	})

	t.Run("ConcurrentReplaceCollision", func(t *testing.T) {
		s := open(t, newStore)
		// The serialization lock is the tenant row, so exercise concurrent
		// replacements against a real tenant as the API does.
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("a")))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "same", store.KeyCurrent, 0)))
		const n = 8
		var wg sync.WaitGroup
		errs := make([]error, n)
		for i := range errs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				errs[i] = s.CustomSigningKeys().Replace(ctx, customSet("ten_a", fmt.Sprintf("id-%d", i)))
			}(i)
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				t.Errorf("noncolliding Replace: %v", err)
			}
		}
		mustErrIs(t, s.CustomSigningKeys().Replace(ctx, customSet("ten_a", "same")), store.ErrConflict)
	})

	t.Run("ConcurrentCustomReplaceAndManagedCreate", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("a")))
		const kid = "race"
		start := make(chan struct{})
		var wg sync.WaitGroup
		var customErr, managedErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			customErr = s.CustomSigningKeys().Replace(ctx, customSet("ten_a", kid))
		}()
		go func() {
			defer wg.Done()
			<-start
			managedErr = s.SigningKeys().Create(ctx, newSigningKey("ten_a", kid, store.KeyPrevious, 0))
		}()
		close(start)
		wg.Wait()
		if (customErr == nil) == (managedErr == nil) {
			t.Fatalf("expected exactly one collision contender to win: custom=%v managed=%v", customErr, managedErr)
		}
		if customErr != nil && !errors.Is(customErr, store.ErrConflict) {
			t.Fatalf("custom replacement error: %v", customErr)
		}
		if managedErr != nil && !errors.Is(managedErr, store.ErrConflict) {
			t.Fatalf("managed create error: %v", managedErr)
		}
	})

	t.Run("ConcurrentCustomReplaceAndManagedRotate", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("a")))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "current", store.KeyCurrent, 0)))
		mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey("ten_a", "queued", store.KeyNext, time.Hour)))
		start := make(chan struct{})
		var wg sync.WaitGroup
		var customErr, rotateErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			customErr = s.CustomSigningKeys().Replace(ctx, customSet("ten_a", "race-next"))
		}()
		go func() {
			defer wg.Done()
			<-start
			_, rotateErr = s.SigningKeys().RotateWithResult(ctx, "ten_a", newSigningKey("ten_a", "race-next", store.KeyNext, 2*time.Hour), ts(2*time.Hour))
		}()
		close(start)
		wg.Wait()
		if (customErr == nil) == (rotateErr == nil) {
			t.Fatalf("expected exactly one contender to win: custom=%v rotate=%v", customErr, rotateErr)
		}
		if customErr != nil && !errors.Is(customErr, store.ErrConflict) {
			t.Fatalf("custom replace: %v", customErr)
		}
		if rotateErr != nil && !errors.Is(rotateErr, store.ErrConflict) {
			t.Fatalf("rotation: %v", rotateErr)
		}
	})
}

func join(values []string, sep string) string {
	if len(values) == 0 {
		return ""
	}
	out := values[0]
	for _, value := range values[1:] {
		out += sep + value
	}
	return out
}
