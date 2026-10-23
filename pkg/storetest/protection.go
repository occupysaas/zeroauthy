package storetest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func protectionFixture(t *testing.T, f Factory) (store.Store, store.ProtectionLimit, time.Time) {
	t.Helper()
	s := open(t, f)
	mustNoErr(t, s.Tenants().Create(context.Background(), newTenant("protection")))
	return s, store.ProtectionLimit{Key: store.ProtectionKey{TenantID: "ten_protection", Kind: "brute-force", ConnectionID: "con_a", Identifier: "a@example.test", IP: "192.0.2.1"}, Algorithm: "brute-force", Capacity: 3, Lockout: 30 * 24 * time.Hour}, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}
func reserveProtection(t *testing.T, s store.Store, now time.Time, limits ...store.ProtectionLimit) store.ProtectionAdmission {
	t.Helper()
	a, err := s.Protection().Reserve(context.Background(), limits, now)
	mustNoErr(t, err)
	return a
}
func testProtection(t *testing.T, f Factory) {
	testProtectionLifecycle(t, f)
	testProtectionEdges(t, f)
	ctx := context.Background()
	t.Run("TestProtectionConcurrentAdmission", func(t *testing.T) {
		s, l, now := protectionFixture(t, f)
		var admitted atomic.Int32
		var wg sync.WaitGroup
		for range 20 {
			wg.Go(func() {
				a, err := s.Protection().Reserve(ctx, []store.ProtectionLimit{l}, now)
				if err != nil {
					t.Error(err)
				} else if a.Allowed {
					admitted.Add(1)
				}
			})
		}
		wg.Wait()
		if admitted.Load() != 3 {
			t.Fatalf("admitted %d, want 3", admitted.Load())
		}
	})
	t.Run("TestProtectionStaleCompletion", func(t *testing.T) {
		s, l, now := protectionFixture(t, f)
		l.Capacity = 1
		old := reserveProtection(t, s, now, l)
		mustNoErr(t, s.Protection().Clear(ctx, l.Key.TenantID, store.ProtectionFilter{}))
		fresh := reserveProtection(t, s, now, l)
		mustNoErr(t, s.Protection().Complete(ctx, fresh.Receipt, "failure", now))
		mustNoErr(t, s.Protection().Complete(ctx, old.Receipt, "success", now))
		if reserveProtection(t, s, now, l).Allowed {
			t.Fatal("stale success cleared fresh failure")
		}
		mustNoErr(t, s.Protection().Clear(ctx, l.Key.TenantID, store.ProtectionFilter{}))
		mustNoErr(t, s.Protection().Complete(ctx, old.Receipt, "failure", now))
		if !reserveProtection(t, s, now, l).Allowed {
			t.Fatal("stale failure recreated charge")
		}
	})
	t.Run("TestProtectionCompletionOrdering", func(t *testing.T) {
		for _, successFirst := range []bool{false, true} {
			t.Run(fmt.Sprint(successFirst), func(t *testing.T) {
				s, l, now := protectionFixture(t, f)
				l.Capacity = 2
				old := reserveProtection(t, s, now, l)
				newer := reserveProtection(t, s, now, l)
				if successFirst {
					mustNoErr(t, s.Protection().Complete(ctx, old.Receipt, "success", now))
				}
				mustNoErr(t, s.Protection().Complete(ctx, newer.Receipt, "failure", now))
				if !successFirst {
					mustNoErr(t, s.Protection().Complete(ctx, old.Receipt, "success", now))
				}
				mustNoErr(t, s.Protection().Complete(ctx, old.Receipt, "success", now))
				a := reserveProtection(t, s, now, l)
				if !a.Allowed {
					t.Fatal("success did not refund")
				}
				if reserveProtection(t, s, now, l).Allowed {
					t.Fatal("older success erased newer failure")
				}
			})
		}
	})
	t.Run("TestProtectionAtomicBudgets", func(t *testing.T) {
		s, l, now := protectionFixture(t, f)
		l.Capacity = 1
		full := l
		full.Key.Identifier = "full"
		reserveProtection(t, s, now, full)
		if reserveProtection(t, s, now, l, full).Allowed {
			t.Fatal("over capacity")
		}
		if !reserveProtection(t, s, now, l).Allowed {
			t.Fatal("denied multi-budget request charged first bucket")
		}
	})
	t.Run("TestProtectionAlgorithms", func(t *testing.T) {
		for _, algo := range []string{"fixed-window", "token-bucket", "brute-force"} {
			t.Run(algo, func(t *testing.T) {
				s, l, now := protectionFixture(t, f)
				l.Algorithm = algo
				l.Capacity = 1
				l.Window = time.Minute
				l.Refill = time.Minute
				l.Lockout = time.Minute
				a := reserveProtection(t, s, now, l)
				mustNoErr(t, s.Protection().Complete(ctx, a.Receipt, "failure", now))
				if reserveProtection(t, s, now.Add(30*time.Second), l).Allowed {
					t.Fatal("expired too early")
				}
				if !reserveProtection(t, s, now.Add(time.Minute), l).Allowed {
					t.Fatal("did not refill/expire")
				}
			})
		}
	})
	t.Run("TestProtectionAbandoned", func(t *testing.T) {
		s, l, now := protectionFixture(t, f)
		l.Capacity = 1
		a := reserveProtection(t, s, now, l)
		mustNoErr(t, s.Protection().Complete(ctx, a.Receipt, "refund", now.Add(60*time.Second)))
		if reserveProtection(t, s, now.Add(60*time.Second), l).Allowed {
			t.Fatal("abandoned reservation was refunded")
		}
	})
	t.Run("TestProtectionRiskAndProof", func(t *testing.T) {
		s, l, now := protectionFixture(t, f)
		mustNoErr(t, s.Protection().RecordRisk(ctx, l.Key.TenantID, "attempt", "ip", now))
		mustNoErr(t, s.Protection().RecordRisk(ctx, l.Key.TenantID, "attempt", "ip", now.Add(time.Minute)))
		count, err := s.Protection().RiskCount(ctx, l.Key.TenantID, "ip", now.Add(14*time.Minute))
		mustNoErr(t, err)
		if count != 1 {
			t.Fatalf("risk %d", count)
		}
		count, err = s.Protection().RiskCount(ctx, l.Key.TenantID, "ip", now.Add(15*time.Minute))
		mustNoErr(t, err)
		if count != 0 {
			t.Fatal("risk did not expire")
		}
		for i := range 2 {
			used, err := s.Protection().UseProof(ctx, "opaque", now, now.Add(5*time.Minute))
			mustNoErr(t, err)
			if used != (i == 0) {
				t.Fatal("proof replay")
			}
		}
		mustNoErr(t, s.Tenants().Delete(ctx, l.Key.TenantID))
		used, err := s.Protection().UseProof(ctx, "opaque", now, now.Add(5*time.Minute))
		mustNoErr(t, err)
		if used {
			t.Fatal("tenant delete removed replay tombstone")
		}
		used, err = s.Protection().UseProof(ctx, "opaque", now.Add(5*time.Minute), now.Add(10*time.Minute))
		mustNoErr(t, err)
		if !used {
			t.Fatal("proof did not expire")
		}
	})
	t.Run("TestProtectionRollback", func(t *testing.T) {
		s, l, now := protectionFixture(t, f)
		l.Capacity = 1
		err := s.WithTx(ctx, func(tx store.Store) error {
			a := reserveProtection(t, tx, now, l)
			if !a.Allowed {
				t.Fatal("initial admission")
			}
			return store.ErrInvalid
		})
		if !errors.Is(err, store.ErrInvalid) {
			t.Fatal(err)
		}
		if !reserveProtection(t, s, now, l).Allowed {
			t.Fatal("rollback retained charge")
		}
	})
}

func testProtectionLifecycle(t *testing.T, f Factory) {
	ctx := context.Background()
	t.Run("TestProtectionPolicyUpdate", func(t *testing.T) {
		s, l, now := protectionFixture(t, f)
		l.Capacity = 2
		tenant, err := s.Tenants().Get(ctx, l.Key.TenantID)
		mustNoErr(t, err)
		tenant.ProtectionSettings.BruteForce.MaxAttempts = 2
		mustNoErr(t, s.Tenants().Update(ctx, tenant))
		a := reserveProtection(t, s, now, l)
		mustNoErr(t, s.Protection().Complete(ctx, a.Receipt, "failure", now))
		tenant.ProtectionSettings.BruteForce.MaxAttempts = 1
		mustNoErr(t, s.Tenants().Update(ctx, tenant))
		l.Capacity = 1
		blocks, err := s.Protection().Blocks(ctx, tenant.ID, store.ProtectionFilter{}, now)
		mustNoErr(t, err)
		if len(blocks) != 1 {
			t.Fatal("lower threshold erased failure or left old threshold")
		}
		tenant.ProtectionSettings.BruteForce.MaxAttempts = 3
		mustNoErr(t, s.Tenants().Update(ctx, tenant))
		blocks, err = s.Protection().Blocks(ctx, tenant.ID, store.ProtectionFilter{}, now)
		mustNoErr(t, err)
		if len(blocks) != 0 {
			t.Fatal("increase retained block")
		}
	})
	t.Run("TestProtectionDeletion", func(t *testing.T) {
		for _, entity := range []string{"user", "connection"} {
			t.Run(entity, func(t *testing.T) {
				s, l, now := protectionFixture(t, f)
				l.Capacity = 1
				mustNoErr(t, s.Connections().Create(ctx, &store.Connection{TenantID: l.Key.TenantID, ID: l.Key.ConnectionID, Name: "Database", Strategy: "auth0"}))
				mustNoErr(t, s.Users().Create(ctx, &store.User{TenantID: l.Key.TenantID, UserID: "auth0|a", Email: l.Key.Identifier, Identities: []store.Identity{{Connection: "Database", Provider: "auth0", UserID: "a"}}}))
				a := reserveProtection(t, s, now, l)
				mustNoErr(t, s.Protection().Complete(ctx, a.Receipt, "failure", now))
				if entity == "user" {
					mustNoErr(t, s.Users().Delete(ctx, l.Key.TenantID, "auth0|a"))
				} else {
					mustNoErr(t, s.Connections().Delete(ctx, l.Key.TenantID, l.Key.ConnectionID))
				}
				if !reserveProtection(t, s, now, l).Allowed {
					t.Fatal("deleted entity retained bucket")
				}
			})
		}
	})
	t.Run("TestProtectionSweep", func(t *testing.T) {
		s, l, now := protectionFixture(t, f)
		l.Lockout = time.Minute
		for i := range 4 {
			l.Key.Identifier = fmt.Sprint(i)
			a := reserveProtection(t, s, now, l)
			mustNoErr(t, s.Protection().Complete(ctx, a.Receipt, "failure", now))
			mustNoErr(t, s.Protection().RecordRisk(ctx, l.Key.TenantID, fmt.Sprint(i), "ip", now))
			_, err := s.Protection().UseProof(ctx, fmt.Sprint(i), now, now.Add(time.Minute))
			mustNoErr(t, err)
		}
		total := 0
		for range 30 {
			n, err := s.Protection().Sweep(ctx, now.Add(time.Hour), 1)
			mustNoErr(t, err)
			if n > 1 {
				t.Fatal("unbounded sweep")
			}
			total += n
			if n == 0 {
				break
			}
		}
		if total != 16 {
			t.Fatalf("sweep removed %d items, want 16", total)
		}
	})
}

func testProtectionEdges(t *testing.T, f Factory) {
	ctx := context.Background()
	t.Run("TestProtectionSweepAbandonedBound", func(t *testing.T) {
		s, l, now := protectionFixture(t, f)
		for i := range 3 {
			l.Key.Identifier = fmt.Sprint(i)
			reserveProtection(t, s, now, l)
		}
		n, err := s.Protection().Sweep(ctx, now.Add(time.Minute), 1)
		mustNoErr(t, err)
		if n != 1 {
			t.Fatalf("abandoned sweep progress=%d, want 1", n)
		}
	})

	t.Run("TestProtectionHistoryOutlivesReceiptExpiry", func(t *testing.T) {
		s, l, now := protectionFixture(t, f)
		l.Capacity = 1
		l.Lockout = time.Hour
		a := reserveProtection(t, s, now, l)
		mustNoErr(t, s.Protection().Complete(ctx, a.Receipt, "failure", now.Add(30*time.Second)))
		_, err := s.Protection().Sweep(ctx, now.Add(time.Hour), 100)
		mustNoErr(t, err)
		if reserveProtection(t, s, now.Add(time.Hour), l).Allowed {
			t.Fatal("receipt expiry erased live failure history")
		}
	})
	t.Run("TestProtectionRollbackAllState", func(t *testing.T) {
		s, l, now := protectionFixture(t, f)
		l.Capacity = 1
		a := reserveProtection(t, s, now, l)
		mustNoErr(t, s.Protection().Complete(ctx, a.Receipt, "failure", now))
		err := s.WithTx(ctx, func(tx store.Store) error {
			if e := tx.Protection().Clear(ctx, l.Key.TenantID, store.ProtectionFilter{}); e != nil {
				return e
			}
			if _, e := tx.Protection().UseProof(ctx, "rollback", now, now.Add(5*time.Minute)); e != nil {
				return e
			}
			if e := tx.Protection().RecordRisk(ctx, l.Key.TenantID, "rollback", "ip", now); e != nil {
				return e
			}
			return store.ErrInvalid
		})
		if !errors.Is(err, store.ErrInvalid) {
			t.Fatal(err)
		}
		if reserveProtection(t, s, now, l).Allowed {
			t.Fatal("rolled back clear persisted")
		}
		used, err := s.Protection().UseProof(ctx, "rollback", now, now.Add(5*time.Minute))
		mustNoErr(t, err)
		if !used {
			t.Fatal("rolled back proof persisted")
		}
		n, err := s.Protection().RiskCount(ctx, l.Key.TenantID, "ip", now)
		mustNoErr(t, err)
		if n != 0 {
			t.Fatal("rolled back risk persisted")
		}
	})

	t.Run("TestProtectionInvalidAndUnknown", func(t *testing.T) {
		s, l, now := protectionFixture(t, f)
		a, err := s.Protection().Reserve(ctx, nil, now)
		mustNoErr(t, err)
		if !a.Allowed || a.Receipt.ID != "" {
			t.Fatal("empty budgets must be no-op admission")
		}
		bad := l
		bad.Key.TenantID = "missing"
		if _, err = s.Protection().Reserve(ctx, []store.ProtectionLimit{bad}, now); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("unknown tenant: %v", err)
		}
		bad = l
		bad.Capacity = 0
		if _, err = s.Protection().Reserve(ctx, []store.ProtectionLimit{bad}, now); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("capacity: %v", err)
		}
		bad = l
		bad.Key.TenantID = "another"
		if _, err = s.Protection().Reserve(ctx, []store.ProtectionLimit{l, bad}, now); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("mixed tenants: %v", err)
		}
		if _, err = s.Protection().Reserve(ctx, []store.ProtectionLimit{l, l}, now); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("duplicate key: %v", err)
		}
		if err = s.Protection().Complete(ctx, store.ProtectionReceipt{}, "invalid", now); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("outcome: %v", err)
		}
	})
	t.Run("TestProtectionFractionalRefillAndRefund", func(t *testing.T) {
		s, l, now := protectionFixture(t, f)
		l.Algorithm = "token-bucket"
		l.Capacity = 1
		l.Refill = time.Second
		a := reserveProtection(t, s, now, l)
		mustNoErr(t, s.Protection().Complete(ctx, a.Receipt, "failure", now))
		if reserveProtection(t, s, now.Add(500*time.Millisecond), l).Allowed {
			t.Fatal("half token admitted")
		}
		a = reserveProtection(t, s, now.Add(time.Second), l)
		if !a.Allowed {
			t.Fatal("fractional credit lost")
		}
		mustNoErr(t, s.Protection().Complete(ctx, a.Receipt, "success", now.Add(time.Second)))
		if !reserveProtection(t, s, now.Add(time.Second), l).Allowed {
			t.Fatal("success did not refund")
		}
	})
	t.Run("TestProtectionNewerSuccessSuppressesOlderFailure", func(t *testing.T) {
		s, l, now := protectionFixture(t, f)
		l.Capacity = 2
		old := reserveProtection(t, s, now, l)
		newer := reserveProtection(t, s, now, l)
		mustNoErr(t, s.Protection().Complete(ctx, newer.Receipt, "success", now))
		mustNoErr(t, s.Protection().Complete(ctx, old.Receipt, "failure", now))
		if !reserveProtection(t, s, now, l).Allowed || !reserveProtection(t, s, now, l).Allowed {
			t.Fatal("older completion recreated reset history")
		}
	})
}
