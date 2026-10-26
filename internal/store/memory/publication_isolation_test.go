package memory

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// A worker's host/certificate publication is not visible before the outer
// transaction finishes its final lease check. Readers through the transaction
// view (including a nested savepoint) must still see their own writes.
func TestPublicationReadIsolation(t *testing.T) {
	ctx := context.Background()
	type reader struct {
		name, old, next string
		read            func(store.Store) (string, error)
	}
	readers := []reader{
		{"host", "false", "true", func(s store.Store) (string, error) {
			h, e := s.CustomDomains().GetHost(ctx, "login.customer.example")
			if e != nil {
				return "", e
			}
			return fmt.Sprint(h.Active), nil
		}},
		{"resolver", "missing", "tenant", func(s store.Store) (string, error) {
			v, e := s.Tenants().GetByDomain(ctx, "login.customer.example")
			if errors.Is(e, store.ErrNotFound) {
				return "missing", nil
			}
			if e != nil {
				return "", e
			}
			return v.ID, nil
		}},
		{"certificate", "old", "new", func(s store.Store) (string, error) {
			a, e := s.TLSAssets().Get(ctx, "cert")
			if e != nil {
				return "", e
			}
			return string(a.Ciphertext), nil
		}},
		{"domain", "pending", "ready", func(s store.Store) (string, error) {
			d, e := s.CustomDomains().Get(ctx, "tenant", "domain")
			if e != nil {
				return "", e
			}
			return d.Status, nil
		}},
		{"domain-list", "pending", "ready", func(s store.Store) (string, error) {
			ds, e := s.CustomDomains().List(ctx, "tenant")
			if e != nil {
				return "", e
			}
			return ds[0].Status, nil
		}},
		{"due", "0", "1", func(s store.Store) (string, error) {
			ds, e := s.CustomDomains().ListDue(ctx, 10)
			return fmt.Sprint(len(ds)), e
		}},
		{"default", "", "domain", func(s store.Store) (string, error) { return s.CustomDomains().GetDefault(ctx, "tenant") }},
		{"expired-certificates", "old", "new", func(s store.Store) (string, error) {
			as, e := s.TLSAssets().ListExpired(ctx, 10)
			if e != nil {
				return "", e
			}
			return string(as[0].Ciphertext), nil
		}},
		{"tenant", "old", "new", func(s store.Store) (string, error) {
			v, e := s.Tenants().Get(ctx, "tenant")
			if e != nil {
				return "", e
			}
			return v.FriendlyName, nil
		}},
		{"tenant-name", "old", "new", func(s store.Store) (string, error) {
			v, e := s.Tenants().GetByName(ctx, "tenant")
			if e != nil {
				return "", e
			}
			return v.FriendlyName, nil
		}},
		{"tenant-list", "old", "new", func(s store.Store) (string, error) {
			vs, e := s.Tenants().List(ctx)
			if e != nil {
				return "", e
			}
			return vs[0].FriendlyName, nil
		}},
		{"client", "old", "new", func(s store.Store) (string, error) {
			v, e := s.Clients().Get(ctx, "tenant", "client")
			if e != nil {
				return "", e
			}
			return v.Name, nil
		}},
	}
	for _, outcome := range []string{"callback-error", "lease-expired", "commit"} {
		t.Run(outcome, func(t *testing.T) {
			s, set := clockStore(t)
			other := &Store{state: s.state}
			tenant, e := s.Tenants().Get(ctx, "tenant")
			requireOK(t, e)
			tenant.FriendlyName = "old"
			requireOK(t, s.Tenants().Update(ctx, tenant))
			requireOK(t, s.CustomDomains().Create(ctx, &store.CustomDomain{TenantID: "tenant", ID: "domain", Domain: "login.customer.example", Status: "pending"}))
			requireOK(t, s.CustomDomains().PutHost(ctx, &store.HostBinding{Host: "login.customer.example", TenantID: "tenant", DomainID: "domain", Kind: store.HostPublic}))
			requireOK(t, s.TLSAssets().Put(ctx, &store.TLSAsset{Key: "cert", Kind: store.TLSAssetCertificate, Ciphertext: []byte("old"), ExpiresAt: s.now()}, 0))
			requireOK(t, s.Clients().Create(ctx, &store.Client{TenantID: "tenant", ClientID: "client", Name: "old"}))
			lease, e := s.TLSAssets().ClaimLease(ctx, "cert", "worker", time.Minute)
			requireOK(t, e)
			published := make(chan struct{})
			finish := make(chan struct{})
			done := make(chan error, 1)
			stop := errors.New("callback rollback")
			go func() {
				done <- s.WithTx(ctx, func(tx store.Store) error {
					if e := tx.TLSAssets().CheckLease(ctx, *lease); e != nil {
						return e
					}
					h, e := tx.CustomDomains().GetHost(ctx, "login.customer.example")
					if e != nil {
						return e
					}
					h.Active = true
					if e = tx.CustomDomains().PutHost(ctx, h); e != nil {
						return e
					}
					a, e := tx.TLSAssets().Get(ctx, "cert")
					if e != nil {
						return e
					}
					a.Ciphertext = []byte("new")
					if e = tx.TLSAssets().Put(ctx, a, a.Revision); e != nil {
						return e
					}
					d, e := tx.CustomDomains().Get(ctx, "tenant", "domain")
					if e != nil {
						return e
					}
					d.Status = "ready"
					at := s.now()
					d.NextAttemptAt = &at
					if e = tx.CustomDomains().Update(ctx, d, d.Revision); e != nil {
						return e
					}
					if e = tx.CustomDomains().SetDefault(ctx, "tenant", "domain"); e != nil {
						return e
					}
					tn, e := tx.Tenants().Get(ctx, "tenant")
					if e != nil {
						return e
					}
					tn.FriendlyName = "new"
					tn.Domains = []string{"login.customer.example"}
					if e = tx.Tenants().Update(ctx, tn); e != nil {
						return e
					}
					c, e := tx.Clients().Get(ctx, "tenant", "client")
					if e != nil {
						return e
					}
					c.Name = "new"
					if e = tx.Clients().Update(ctx, c); e != nil {
						return e
					}
					// Transaction-local and nested readers must never block on their own gate.
					if e = tx.WithTx(ctx, func(inner store.Store) error {
						for _, r := range readers {
							v, e := r.read(inner)
							if e != nil {
								return e
							}
							if v != r.next {
								return fmt.Errorf("local %s=%q want %q", r.name, v, r.next)
							}
						}
						return nil
					}); e != nil {
						return e
					}
					close(published)
					<-finish
					if outcome == "callback-error" {
						return stop
					}
					return nil
				})
			}()
			select {
			case <-published:
			case e := <-done:
				t.Fatalf("transaction failed before publication: %v", e)
			case <-time.After(5 * time.Second):
				t.Fatal("transaction-local reads blocked")
			}
			type result struct {
				reader reader
				value  string
				err    error
			}
			attempted := make(chan struct{}, len(readers))
			results := make(chan result, len(readers))
			for i, r := range readers {
				go func(i int, r reader) {
					handle := s
					if i%2 == 1 {
						handle = other
					}
					attempted <- struct{}{}
					v, e := r.read(handle)
					results <- result{r, v, e}
				}(i, r)
			}
			for range readers {
				<-attempted
			}
			// The transaction remains paused until every external read is attempted.
			// This bounded negative assertion catches early visibility; all readers are
			// then drained and their eventual values asserted after the outcome.
			var early []result
			select {
			case r := <-results:
				early = append(early, r)
			case <-time.After(30 * time.Millisecond):
			}
			earlyCount := len(early)
			if outcome == "lease-expired" {
				set(time.Minute)
			}
			close(finish)
			e = <-done
			switch outcome {
			case "callback-error":
				requireError(t, e, stop)
			case "lease-expired":
				requireError(t, e, store.ErrConflict)
			default:
				requireOK(t, e)
			}
			for range len(readers) - len(early) {
				early = append(early, <-results)
			}
			for _, r := range early {
				requireOK(t, r.err)
				want := r.reader.old
				if outcome == "commit" {
					want = r.reader.next
				}
				if r.value != want {
					t.Errorf("%s observed %q after %s, want %q", r.reader.name, r.value, outcome, want)
				}
			}
			if earlyCount > 0 {
				t.Errorf("external %s returned before transaction completion", early[0].reader.name)
			}
			// Reading a new value while the transaction was paused is invalid even if
			// the callback eventually committed it.
			// The channel contents captured before finish distinguish that schedule.
		})
	}
}
