package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func twoHandles(t *testing.T, dsn string) (*Store, *Store) {
	t.Helper()
	a := mustOpen(t, dsn)
	b := mustOpenRaw(t, dsn)
	return a, b
}
func runPair(fn func(int) error) []error {
	var wg sync.WaitGroup
	errs := make([]error, 2)
	start := make(chan struct{})
	for i := range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; errs[i] = fn(i) }()
	}
	close(start)
	wg.Wait()
	return errs
}
func oneWinner(t *testing.T, errs []error) {
	t.Helper()
	wins := 0
	for _, err := range errs {
		if err == nil {
			wins++
		} else if !errors.Is(err, store.ErrConflict) {
			t.Fatal(err)
		}
	}
	if wins != 1 {
		t.Fatalf("wins=%d errors=%v", wins, errs)
	}
}

func TestCustomDomainIndependentHandles(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			a, b := twoHandles(t, mk(t))
			handles := []*Store{a, b}
			for _, id := range []string{"a", "b"} {
				if err := a.Tenants().Create(ctx, &store.Tenant{ID: id, Name: id}); err != nil {
					t.Fatal(err)
				}
			}
			oneWinner(t, runPair(func(i int) error {
				return handles[i].CustomDomains().PutHost(ctx, &store.HostBinding{Host: []string{"BÜCHER.example.test.", "xn--bcher-kva.example.test"}[i], TenantID: []string{"a", "b"}[i], DomainID: "domain", Kind: store.HostPublic})
			}))
			// Privileged tenant writes and pending API claims compete in the same registry.
			oneWinner(t, runPair(func(i int) error {
				if i == 0 {
					return a.Tenants().Create(ctx, &store.Tenant{ID: "new", Name: "new", Domains: []string{"RACE.example.test."}})
				}
				return b.CustomDomains().PutHost(ctx, &store.HostBinding{Host: "race.example.test", TenantID: "a", DomainID: "domain", Kind: store.HostPublic})
			}))
			d := &store.CustomDomain{TenantID: "a", ID: "default", Domain: "default.example.test"}
			if err := a.CustomDomains().Create(ctx, d); err != nil {
				t.Fatal(err)
			}
			errs := runPair(func(i int) error {
				if i == 0 {
					return a.CustomDomains().SetDefault(ctx, "a", d.ID)
				}
				return b.CustomDomains().Delete(ctx, "a", d.ID, d.Revision)
			})
			if errs[1] != nil {
				t.Fatal(errs[1])
			}
			if errs[0] != nil && !errors.Is(errs[0], store.ErrNotFound) {
				t.Fatal(errs[0])
			}
			def, err := a.CustomDomains().GetDefault(ctx, "a")
			if err != nil || def != "" {
				t.Fatalf("dangling default %q %v", def, err)
			}
			leases := make([]*store.TLSLease, 2)
			oneWinner(t, runPair(func(i int) error {
				var err error
				leases[i], err = handles[i].TLSAssets().ClaimLease(ctx, "contended", fmt.Sprint(i), time.Minute)
				return err
			}))
			var lease *store.TLSLease
			for _, l := range leases {
				if l != nil {
					lease = l
				}
			}
			if err := b.TLSAssets().ReleaseLease(ctx, *lease); err != nil {
				t.Fatal(err)
			}
			next, err := a.TLSAssets().ClaimLease(ctx, "contended", "successor", time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if next.Fence <= lease.Fence {
				t.Fatal("fence history reset")
			}
		})
	}
}

func TestTLSLeaseCheckedHandleBlocksClaim(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			a, b := twoHandles(t, mk(t))
			lease, err := a.TLSAssets().ClaimLease(ctx, "resource", "old", 200*time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			checked := make(chan struct{})
			finish := make(chan struct{})
			txResult := make(chan error, 1)
			go func() {
				txResult <- a.WithTx(ctx, func(tx store.Store) error {
					if err := tx.TLSAssets().CheckLease(ctx, *lease); err != nil {
						return err
					}
					close(checked)
					if err := tx.TLSAssets().Put(ctx, &store.TLSAsset{Key: "stale"}, 0); err != nil {
						return err
					}
					<-finish
					return nil
				})
			}()
			select {
			case <-checked:
			case err := <-txResult:
				t.Fatalf("check transaction failed: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("check did not start")
			}
			// Claim waits on the checked row, then uses time read after acquiring it.
			claimResult := make(chan error, 1)
			var successor *store.TLSLease
			go func() {
				var err error
				successor, err = b.TLSAssets().ClaimLease(ctx, "resource", "new", time.Minute)
				claimResult <- err
			}()
			time.Sleep(260 * time.Millisecond)
			select {
			case err := <-claimResult:
				close(finish)
				<-txResult
				t.Fatalf("claim bypassed transaction lock: %v", err)
			default:
			}
			close(finish)
			if err := <-txResult; !errors.Is(err, store.ErrConflict) {
				t.Fatalf("expired checked transaction: %v", err)
			}
			if err := <-claimResult; err != nil {
				t.Fatal(err)
			}
			if successor.Fence <= lease.Fence {
				t.Fatal("successor fence did not increase")
			}
			if _, err := a.TLSAssets().Get(ctx, "stale"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("stale asset survived: %v", err)
			}
		})
	}
}

func TestCustomDomainDistributedAttemptBudgets(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			a, b := twoHandles(t, mk(t))
			handles := []*Store{a, b}
			if err := a.Tenants().Create(ctx, &store.Tenant{ID: "tenant", Name: "tenant"}); err != nil {
				t.Fatal(err)
			}
			admitted := make([]bool, 2)
			errs := runPair(func(i int) error {
				retry, err := handles[i].CustomDomains().AdmitAttempt(ctx, "tenant", "same")
				admitted[i] = retry == 0
				return err
			})
			for _, err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			if admitted[0] == admitted[1] {
				t.Fatalf("same-domain admissions=%v", admitted)
			}
			for i := range 18 {
				retry, err := handles[i%2].CustomDomains().AdmitAttempt(ctx, "tenant", fmt.Sprint(i))
				if err != nil || retry != 0 {
					t.Fatalf("fill attempt %d: %v %v", i, retry, err)
				}
			}
			errs = runPair(func(i int) error {
				retry, err := handles[i].CustomDomains().AdmitAttempt(ctx, "tenant", fmt.Sprintf("final-%d", i))
				admitted[i] = retry == 0
				return err
			})
			for _, err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			if admitted[0] == admitted[1] {
				t.Fatalf("tenant-limit admissions=%v", admitted)
			}
			var count int
			if err := a.queryRow(ctx, `SELECT COUNT(*) FROM custom_domain_attempts WHERE tenant_id='tenant'`).Scan(&count); err != nil || count != 20 {
				t.Fatalf("refused attempt mutated domain counter: %d %v", count, err)
			}
			// Seed exact storage-time boundaries in SQL. Attempts at/older than 30s and
			// 60s are eligible; a later 30s expiry still refuses without changing counts.
			mustExec(t, a, `UPDATE custom_domain_attempts SET attempted_at=`+a.wallMicros()+`-30000000 WHERE tenant_id='tenant' AND domain_id='same'`)
			mustExec(t, a, `UPDATE custom_tenant_attempts SET attempted_at=`+a.wallMicros()+`-60000000 WHERE tenant_id='tenant'`)
			retry, err := b.CustomDomains().AdmitAttempt(ctx, "tenant", "same")
			if err != nil || retry != 0 {
				t.Fatalf("storage boundary rejected: %v %v", retry, err)
			}
			retry, err = a.CustomDomains().AdmitAttempt(ctx, "tenant", "same")
			if err != nil || retry <= 0 || retry > 30*time.Second {
				t.Fatalf("fresh boundary admitted: %v %v", retry, err)
			}
			if name == "sqlite" {
				return
			} // SQLite serializes the whole write transaction.

			// Establish an old MySQL consistent-read snapshot before another handle
			// fills the budget; admission must use locking/current reads after its lock.
			for i := range 18 {
				retry, err := a.CustomDomains().AdmitAttempt(ctx, "tenant", fmt.Sprintf("fill-%d", i))
				if err != nil || retry != 0 {
					t.Fatal(retry, err)
				}
			}
			err = a.WithTx(ctx, func(st store.Store) error {
				tx := st.(*Store)
				var n int
				if err := tx.queryRow(ctx, `SELECT COUNT(*) FROM custom_tenant_attempts WHERE tenant_id='tenant'`).Scan(&n); err != nil {
					return err
				}
				if retry, err := b.CustomDomains().AdmitAttempt(ctx, "tenant", "twentieth"); err != nil || retry != 0 {
					return fmt.Errorf("competing admission: %v %v", retry, err)
				}
				retry, err := tx.CustomDomains().AdmitAttempt(ctx, "tenant", "snapshot-stale")
				if err != nil {
					return err
				}
				if retry <= 0 {
					return errors.New("admitted against stale snapshot")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCustomDomainCapIndependentHandles(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			a, b := twoHandles(t, mk(t))
			handles := []*Store{a, b}
			if err := a.Tenants().Create(ctx, &store.Tenant{ID: "tenant", Name: "tenant"}); err != nil {
				t.Fatal(err)
			}
			for i := range 99 {
				d := &store.CustomDomain{TenantID: "tenant", ID: fmt.Sprint(i), Domain: fmt.Sprintf("domain-%d.example.test", i)}
				if err := a.CustomDomains().Create(ctx, d); err != nil {
					t.Fatal(err)
				}
			}
			var readers sync.WaitGroup
			readers.Add(2)
			oneWinner(t, runPair(func(i int) error {
				return handles[i].WithTx(ctx, func(tx store.Store) error {
					rows, err := tx.CustomDomains().List(ctx, "tenant")
					if err != nil {
						return err
					}
					if name != "sqlite" {
						if len(rows) != 99 {
							return fmt.Errorf("expected99 before racing writes, got%d", len(rows))
						}
						readers.Done()
						readers.Wait()
					}
					return tx.CustomDomains().Create(ctx, &store.CustomDomain{TenantID: "tenant", ID: fmt.Sprintf("racer-%d", i), Domain: fmt.Sprintf("racer-%d.example.test", i)})
				})
			}))
			rows, err := a.CustomDomains().List(ctx, "tenant")
			if err != nil || len(rows) != 100 {
				t.Fatalf("cap raced: %d %v", len(rows), err)
			}
		})
	}
}

func TestCustomDomainAttemptTimeAfterTenantLock(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			a, b := twoHandles(t, mk(t))
			if err := a.Tenants().Create(ctx, &store.Tenant{ID: "tenant", Name: "tenant"}); err != nil {
				t.Fatal(err)
			}
			retry, err := a.CustomDomains().AdmitAttempt(ctx, "tenant", "domain")
			if err != nil || retry != 0 {
				t.Fatal(retry, err)
			}
			mustExec(t, a, `UPDATE custom_domain_attempts SET attempted_at=`+a.wallMicros()+`-29800000 WHERE tenant_id='tenant'`)
			locked := make(chan struct{})
			release := make(chan struct{})
			txResult := make(chan error, 1)
			go func() {
				txResult <- a.WithTx(ctx, func(st store.Store) error {
					tx := st.(*Store)
					if err := tx.lockTenant(ctx, "tenant"); err != nil {
						return err
					}
					close(locked)
					<-release
					return nil
				})
			}()
			select {
			case <-locked:
			case err := <-txResult:
				t.Fatal(err)
			case <-time.After(5 * time.Second):
				t.Fatal("tenant lock not acquired")
			}
			result := make(chan error, 1)
			go func() {
				retry, err := b.CustomDomains().AdmitAttempt(ctx, "tenant", "domain")
				if err == nil && retry != 0 {
					err = fmt.Errorf("used time from before waiting for lock: %v", retry)
				}
				result <- err
			}()
			time.Sleep(260 * time.Millisecond)
			close(release)
			if err := <-txResult; err != nil {
				t.Fatal(err)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTLSLeaseStoredExpiryBoundary(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			a, b := twoHandles(t, mk(t))
			lease, err := a.TLSAssets().ClaimLease(ctx, "resource", "owner", time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			mustExec(t, a, `UPDATE tls_leases SET lease_until=`+a.wallMicros()+` WHERE resource_key='resource'`)
			if err := b.TLSAssets().CheckLease(ctx, *lease); !errors.Is(err, store.ErrConflict) {
				t.Fatalf("expired check: %v", err)
			}
			if _, err := b.TLSAssets().RenewLease(ctx, *lease, time.Minute); !errors.Is(err, store.ErrConflict) {
				t.Fatalf("expired renew: %v", err)
			}
			if err := b.TLSAssets().ReleaseLease(ctx, *lease); !errors.Is(err, store.ErrConflict) {
				t.Fatalf("expired release: %v", err)
			}
			next, err := b.TLSAssets().ClaimLease(ctx, "resource", "next", time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if next.Fence <= lease.Fence {
				t.Fatal("expiry reset fence")
			}
		})
	}
}

// A tenant row lock must not be combined with an old REPEATABLE READ snapshot
// of its domain projection. Deleted API names must not become operator claims,
// and API names activated since the snapshot must not cause duplicate inserts.
func TestTenantProjectionCurrentAfterSnapshot(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		if name == "sqlite" {
			continue
		} // SQLite serializes these write transactions.
		t.Run(name, func(t *testing.T) {
			for _, change := range []string{"delete", "activate"} {
				t.Run(change, func(t *testing.T) {
					a, b := twoHandles(t, mk(t))
					if err := a.Tenants().Create(ctx, &store.Tenant{ID: "tenant", Name: "tenant", CanonicalHost: "canonical.example.test"}); err != nil {
						t.Fatal(err)
					}
					domain := &store.CustomDomain{TenantID: "tenant", ID: "custom", Domain: "api.example.test"}
					activate := func() error {
						return b.WithTx(ctx, func(tx store.Store) error {
							if err := tx.CustomDomains().Create(ctx, domain); err != nil {
								return err
							}
							if err := tx.CustomDomains().PutHost(ctx, &store.HostBinding{Host: domain.Domain, TenantID: domain.TenantID, DomainID: domain.ID, Kind: store.HostPublic, Active: true}); err != nil {
								return err
							}
							tn, err := tx.Tenants().Get(ctx, "tenant")
							if err != nil {
								return err
							}
							tn.Domains = append(tn.Domains, domain.Domain)
							return tx.Tenants().Update(ctx, tn)
						})
					}
					if change == "delete" {
						if err := activate(); err != nil {
							t.Fatal(err)
						}
					}
					var observed []string
					err := a.WithTx(ctx, func(tx store.Store) error {
						if _, err := tx.CustomDomains().List(ctx, "tenant"); err != nil {
							return err
						} // Establish MySQL snapshot without a tenant lock.
						if change == "delete" {
							if err := b.CustomDomains().Delete(ctx, domain.TenantID, domain.ID, domain.Revision); err != nil {
								return err
							}
						} else {
							if err := activate(); err != nil {
								return err
							}
						}
						tn, err := tx.Tenants().Get(ctx, "tenant")
						if err != nil {
							return err
						}
						observed = append([]string{}, tn.Domains...)
						tn.FriendlyName = "metadata update"
						return tx.Tenants().Update(ctx, tn)
					})
					if err != nil {
						t.Fatalf("metadata update after %s: %v", change, err)
					}
					wantPresent := change == "activate"
					if slices.Contains(observed, domain.Domain) != wantPresent {
						t.Errorf("Get returned stale projection after %s: %v", change, observed)
					}
					got, err := a.Tenants().Get(ctx, "tenant")
					if err != nil {
						t.Fatal(err)
					}
					if slices.Contains(got.Domains, domain.Domain) != wantPresent {
						t.Errorf("persisted stale projection after %s: %v", change, got.Domains)
					}
					h, err := a.CustomDomains().GetHost(ctx, domain.Domain)
					_, routeErr := a.Tenants().GetByDomain(ctx, domain.Domain)
					if wantPresent {
						if err != nil || h.Kind != store.HostPublic || routeErr != nil {
							t.Fatalf("API ownership changed: %+v %v route:%v", h, err, routeErr)
						}
					} else {
						if !errors.Is(err, store.ErrNotFound) {
							t.Errorf("deleted API name resurrected: %+v %v", h, err)
						}
						if !errors.Is(routeErr, store.ErrNotFound) {
							t.Errorf("deleted API name remains routable: %v", routeErr)
						}
					}
				})
			}
		})
	}
}
