package customdomain_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func registryStore(t *testing.T) *memory.Store {
	t.Helper()
	st := memory.New()
	ctx := context.Background()
	for _, id := range []string{"a", "b"} {
		if err := st.Tenants().Create(ctx, &store.Tenant{ID: id, Name: id, CanonicalHost: id + ".example.test", Domains: []string{id + ".example.test"}}); err != nil {
			t.Fatal(err)
		}
	}
	return st
}
func TestDomainAliasOwnership(t *testing.T) {
	ctx := context.Background()
	st := registryStore(t)
	pending := &store.CustomDomain{TenantID: "a", ID: "pending", Domain: "pending.example.test", Generation: 1}
	ready := &store.CustomDomain{TenantID: "a", ID: "ready", Domain: "ready.example.test", Generation: 1}
	for _, d := range []*store.CustomDomain{pending, ready} {
		if err := st.CustomDomains().Create(ctx, d); err != nil {
			t.Fatal(err)
		}
		if err := st.CustomDomains().PutHost(ctx, &store.HostBinding{Host: d.Domain, TenantID: "a", DomainID: d.ID, Generation: 1, Kind: store.HostPublic, Active: d.ID == "ready"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := customdomain.ReconcileOperatorAliases(ctx, st, "a", []string{"a.example.test", "localhost:8443", "[::1]:9443", "127.0.0.1:8443"}); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Tenants().Get(ctx, "a")
	if !slices.Contains(got.Domains, "ready.example.test") || slices.Contains(got.Domains, "pending.example.test") {
		t.Fatalf("projection=%v", got.Domains)
	}
	for _, host := range []string{"pending.example.test", "b.example.test"} {
		if err := customdomain.ReconcileOperatorAliases(ctx, st, "a", []string{"a.example.test", host}); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("overlap %s = %v", host, err)
		}
	}
	if err := customdomain.ReconcileOperatorAliases(ctx, st, "a", []string{"other.example.test"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("canonical removal = %v", err)
	}
	if err := customdomain.ReconcileOperatorAliases(ctx, st, "a", []string{"a.example.test", "A.example.test."}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate = %v", err)
	}
	if _, err := customdomain.ResolveHost(ctx, st, "pending.example.test"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("pending routes: %v", err)
	}
	if h, err := customdomain.ResolveHost(ctx, st, "READY.example.test.:443"); err != nil || h.DomainID != "ready" {
		t.Fatalf("ready=%+v,%v", h, err)
	}
}
func TestOperatorAliasRacesClaimAndDeletion(t *testing.T) {
	for n := 0; n < 20; n++ {
		ctx := context.Background()
		st := registryStore(t)
		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			errs <- customdomain.ReconcileOperatorAliases(ctx, st, "a", []string{"a.example.test", "shared.example.test"})
		}()
		go func() {
			defer wg.Done()
			<-start
			errs <- st.WithTx(ctx, func(tx store.Store) error {
				d := &store.CustomDomain{TenantID: "b", ID: "public", Domain: "shared.example.test", Generation: 1}
				if err := tx.CustomDomains().Create(ctx, d); err != nil {
					return err
				}
				return tx.CustomDomains().PutHost(ctx, &store.HostBinding{Host: d.Domain, TenantID: "b", DomainID: d.ID, Generation: 1, Kind: store.HostPublic})
			})
		}()
		close(start)
		wg.Wait()
		close(errs)
		success := 0
		for err := range errs {
			if err == nil {
				success++
			} else if !errors.Is(err, store.ErrConflict) {
				t.Fatal(err)
			}
		}
		if success != 1 {
			t.Fatalf("owners succeeded=%d", success)
		}
		claim, err := st.CustomDomains().GetHost(ctx, "shared.example.test")
		if err != nil {
			t.Fatal(err)
		}
		if claim.TenantID == "b" {
			if _, err := customdomain.ResolveHost(ctx, st, claim.Host); !errors.Is(err, store.ErrNotFound) {
				t.Fatal("pending claim promoted")
			}
			d, _ := st.CustomDomains().Get(ctx, "b", "public")
			if err := st.CustomDomains().Delete(ctx, "b", "public", d.Revision); err != nil {
				t.Fatal(err)
			}
		}
	}
}
