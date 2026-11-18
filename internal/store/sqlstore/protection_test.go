package sqlstore

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/protectionstate"
)

func TestProtectionMigrationFrom37(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			t.Run("upgrade", func(t *testing.T) {
				testProtectionUpgradeFrom37(t, mk(t), false)
			})
			if name == "mysql" {
				t.Run("resume after ALTER", func(t *testing.T) {
					testProtectionUpgradeFrom37(t, mk(t), true)
				})
			}
		})
	}
}

func testProtectionUpgradeFrom37(t *testing.T, dsn string, interrupted bool) {
	t.Helper()
	ctx := t.Context()
	s := openAtVersion(t, dsn, 37)
	seedLegacyTenant(t, s, "t")
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	expires := now.Add(time.Hour)
	l := store.ProtectionLimit{
		Key:       store.ProtectionKey{TenantID: "t", Kind: store.ProtectionBruteForce, ConnectionID: "db", Identifier: "alice@example.test"},
		Algorithm: "brute-force", Capacity: 1, Lockout: time.Hour,
	}
	bucketID := protectionstate.ID(l.Key)
	mustExec(t, s, `INSERT INTO protection_buckets (
tenant_id,bucket_id,kind,connection_id,identifier,ip,generation,algorithm,capacity,window_us,refill_us,lockout_us,tokens,failures,reserved,next_sequence,updated_at,blocked_until,expires_at
) VALUES (?,?,?,?,?,?,'old','brute-force',1,0,0,?,1,1,0,1,?,?,?)`, l.Key.TenantID, bucketID, l.Key.Kind, l.Key.ConnectionID, l.Key.Identifier, l.Key.IP, l.Lockout.Microseconds(), now.UnixMicro(), expires.UnixMicro(), expires.UnixMicro())
	mustExec(t, s, `INSERT INTO protection_receipts (tenant_id,id,reserved_at,completed,outcome,expires_at) VALUES ('t','r',?,TRUE,'failure',?)`, now.UnixMicro(), expires.UnixMicro())
	mustExec(t, s, `INSERT INTO protection_reservations (tenant_id,receipt_id,bucket_id,generation,admission_sequence,outcome) VALUES ('t','r',?,'old',1,'failure')`, bucketID)
	if interrupted {
		// Simulate MySQL committing the ALTER before recording the version.
		mustExec(t, s, `ALTER TABLE protection_buckets ADD COLUMN brute_force_denial_claimed BOOLEAN NOT NULL DEFAULT FALSE`)
	}
	version, err := s.SchemaVersion(ctx)
	if err != nil || version != 37 {
		t.Fatalf("before upgrade: version=%d err=%v", version, err)
	}
	for range 2 {
		mustEvent(t, s.Migrate(ctx))
	}
	version, err = s.SchemaVersion(ctx)
	if err != nil || version != s.LatestVersion() {
		t.Fatalf("after upgrade: version=%d err=%v", version, err)
	}
	var failures, pending int
	var claimed bool
	mustEvent(t, s.queryRow(ctx, `SELECT failures,reserved,brute_force_denial_claimed FROM protection_buckets WHERE tenant_id=? AND bucket_id=?`, l.Key.TenantID, bucketID).Scan(&failures, &pending, &claimed))
	if failures != 1 || pending != 0 || claimed {
		t.Fatalf("migrated bucket: failures=%d pending=%d claimed=%t", failures, pending, claimed)
	}

	other := mustOpenRaw(t, dsn)
	start := make(chan struct{})
	var wg sync.WaitGroup
	var claims atomic.Int32
	for _, st := range []*Store{s, other} {
		wg.Go(func() {
			<-start
			a, err := st.Protection().Reserve(ctx, []store.ProtectionLimit{l}, now)
			if err != nil || a.Allowed || !a.RetryAt.Equal(expires) {
				t.Errorf("expected preserved block until %v: admission=%+v err=%v", expires, a, err)
			}
			if a.FirstBruteForceDenial {
				claims.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	if claims.Load() != 1 {
		t.Fatalf("first denial claimed %d times across two connections", claims.Load())
	}
}

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

// An existing MySQL REPEATABLE READ snapshot must not hide subsequently
// committed risk events, for either counting or idempotent insertion.
func TestProtectionRiskAfterTransactionSnapshot(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		if name == "sqlite" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			for _, operation := range []string{"count", "duplicate"} {
				t.Run(operation, func(t *testing.T) {
					ctx := context.Background()
					dsn := mk(t)
					a := mustOpen(t, dsn)
					b := mustOpenRaw(t, dsn)
					if e := a.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "tenant"}); e != nil {
						t.Fatal(e)
					}
					now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
					e := a.WithTx(ctx, func(st store.Store) error {
						var n int
						if e := st.(*Store).queryRow(ctx, `SELECT COUNT(*) FROM protection_risk_events`).Scan(&n); e != nil {
							return e
						}
						if e := b.Protection().RecordRisk(ctx, "t", "attempt", "ip", now); e != nil {
							return e
						}
						if operation == "duplicate" {
							return st.Protection().RecordRisk(ctx, "t", "attempt", "ip", now.Add(time.Minute))
						}
						n, e := st.Protection().RiskCount(ctx, "t", "ip", now)
						if e == nil && n != 1 {
							t.Errorf("snapshot hid committed event: count=%d", n)
						}
						return e
					})
					if e != nil {
						t.Fatal(e)
					}
					n, e := a.Protection().RiskCount(ctx, "t", "ip", now.Add(15*time.Minute))
					if e != nil {
						t.Fatal(e)
					}
					if n != 0 {
						t.Fatal("duplicate renewed original event expiry")
					}
				})
			}
		})
	}
}
