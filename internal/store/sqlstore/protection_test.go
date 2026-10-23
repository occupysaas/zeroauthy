package sqlstore

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProtectionConcurrentAdmission(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			dsn := mk(t)
			a := mustOpen(t, dsn)
			b := mustOpenRaw(t, dsn)
			if err := a.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "tenant"}); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			l := store.ProtectionLimit{Key: store.ProtectionKey{TenantID: "t", Kind: "brute-force"}, Algorithm: "brute-force", Capacity: 3, Lockout: time.Hour}
			var wg sync.WaitGroup
			var admitted atomic.Int32
			for i := range 20 {
				wg.Go(func() {
					s := a
					if i%2 == 1 {
						s = b
					}
					r, e := s.Protection().Reserve(ctx, []store.ProtectionLimit{l}, now)
					if e != nil {
						t.Error(e)
					} else if r.Allowed {
						admitted.Add(1)
					}
				})
			}
			wg.Wait()
			if admitted.Load() != 3 {
				t.Fatalf("admitted %d, want 3", admitted.Load())
			}
			var used atomic.Int32
			for i := range 20 {
				wg.Go(func() {
					s := a
					if i%2 == 1 {
						s = b
					}
					ok, e := s.Protection().UseProof(ctx, "global-proof", now, now.Add(5*time.Minute))
					if e != nil {
						t.Error(e)
					} else if ok {
						used.Add(1)
					}
				})
			}
			wg.Wait()
			if used.Load() != 1 {
				t.Fatalf("proof used %d times", used.Load())
			}
		})
	}
}
func TestProtectionStaleCompletion(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			dsn := mk(t)
			a := mustOpen(t, dsn)
			b := mustOpenRaw(t, dsn)
			if e := a.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "tenant"}); e != nil {
				t.Fatal(e)
			}
			now := time.Now().UTC()
			l := store.ProtectionLimit{Key: store.ProtectionKey{TenantID: "t", Kind: "brute-force"}, Algorithm: "brute-force", Capacity: 1, Lockout: time.Hour}
			old, e := a.Protection().Reserve(ctx, []store.ProtectionLimit{l}, now)
			if e != nil || !old.Allowed {
				t.Fatalf("reserve %v %v", old, e)
			}
			if e = b.Protection().Clear(ctx, "t", store.ProtectionFilter{}); e != nil {
				t.Fatal(e)
			}
			fresh, e := b.Protection().Reserve(ctx, []store.ProtectionLimit{l}, now)
			if e != nil || !fresh.Allowed {
				t.Fatalf("reserve %v %v", fresh, e)
			}
			if e = b.Protection().Complete(ctx, fresh.Receipt, "failure", now); e != nil {
				t.Fatal(e)
			}
			if e = a.Protection().Complete(ctx, old.Receipt, "success", now); e != nil {
				t.Fatal(e)
			}
			r, e := a.Protection().Reserve(ctx, []store.ProtectionLimit{l}, now)
			if e != nil || r.Allowed {
				t.Fatalf("stale completion changed fresh generation: %v %v", r, e)
			}
		})
	}
}

func TestProtectionCompletionAfterTransactionSnapshot(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		if name == "sqlite" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			dsn := mk(t)
			a := mustOpen(t, dsn)
			b := mustOpenRaw(t, dsn)
			if e := a.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "tenant"}); e != nil {
				t.Fatal(e)
			}
			now := time.Now().UTC()
			l := store.ProtectionLimit{Key: store.ProtectionKey{TenantID: "t", Kind: "brute-force"}, Algorithm: "brute-force", Capacity: 1, Lockout: time.Hour}
			err := a.WithTx(ctx, func(st store.Store) error {
				var count int
				if e := st.(*Store).queryRow(ctx, `SELECT COUNT(*) FROM protection_buckets`).Scan(&count); e != nil {
					return e
				}
				r, e := b.Protection().Reserve(ctx, []store.ProtectionLimit{l}, now)
				if e != nil {
					return e
				}
				if e = st.Protection().Complete(ctx, r.Receipt, "refund", now); e != nil {
					return e
				}
				fresh, e := st.Protection().Reserve(ctx, []store.ProtectionLimit{l}, now)
				if e == nil && !fresh.Allowed {
					t.Error("completion read stale membership snapshot")
				}
				return e
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
