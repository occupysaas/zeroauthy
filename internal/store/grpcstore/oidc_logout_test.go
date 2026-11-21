package grpcstore

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"testing"
)

func TestOIDCClientCodec(t *testing.T) {
	yes := true
	roundTrip(t, "oidc-controls", &store.Client{TenantID: "t", ClientID: "c", IsFirstParty: true, IDTokenAlg: "PS256", OIDCSupport: &store.OIDCSupport{IsAllowed: true, AllowAllScopes: &yes, AllowedScopes: []string{}}, OIDCLogout: &store.OIDCLogout{BackchannelURLs: []string{"https://rp.example/logout"}, InitiatorsMode: "all", IncludeSessionMetadata: &yes}}, clientToPB, clientFromPB)
}

func TestOIDCLogoutCapabilityRefusesWrites(t *testing.T) {
	ctx := t.Context()
	backing := memory.New()
	c := serveEventsFaults(t, backing, &eventsFaults{oidcMissing: true})
	defer c.Close()
	if err := c.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
		t.Fatal(err)
	}
	plain := &store.Client{TenantID: "t", ClientID: "c", Name: "original", IsFirstParty: true}
	if err := c.Clients().Create(ctx, plain); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*store.Client){
		func(c *store.Client) { c.OIDCSupport = &store.OIDCSupport{IsAllowed: false} },
		func(c *store.Client) { c.OIDCLogout = &store.OIDCLogout{} },
		func(c *store.Client) { c.IDTokenAlg = "PS256" },
	} {
		changed := *plain
		changed.Name = "not persisted"
		mutate(&changed)
		if err := c.Clients().Update(ctx, &changed); !errors.Is(err, store.ErrOIDCLogoutUnavailable) {
			t.Fatalf("update: %v", err)
		}
		changed.ClientID = "new"
		if err := c.Clients().Create(ctx, &changed); !errors.Is(err, store.ErrOIDCLogoutUnavailable) {
			t.Fatalf("create: %v", err)
		}
	}
	got, err := backing.Clients().Get(ctx, "t", "c")
	if err != nil || got.Name != "original" || got.OIDCSupport != nil {
		t.Fatalf("write reached old plugin: %+v %v", got, err)
	}
	if err := c.WithTx(ctx, func(tx store.Store) error {
		v := *plain
		v.OIDCSupport = &store.OIDCSupport{IsAllowed: false}
		return tx.Clients().Update(ctx, &v)
	}); !errors.Is(err, store.ErrOIDCLogoutUnavailable) {
		t.Fatalf("transaction: %v", err)
	}
}

type transientOIDCStore struct {
	store.Store
	fail bool
}

func (s *transientOIDCStore) CheckOIDCLogoutSupport(context.Context) error {
	if s.fail {
		s.fail = false
		return errors.New("temporary backing probe failure")
	}
	return nil
}
func TestOIDCCapabilityTransientRetry(t *testing.T) {
	c := serveEventsFaults(t, &transientOIDCStore{Store: memory.New(), fail: true}, &eventsFaults{})
	defer c.Close()
	err := c.CheckOIDCLogoutSupport(t.Context())
	if err == nil || errors.Is(err, store.ErrOIDCLogoutUnavailable) {
		t.Fatalf("transient probe latched unsupported: %v", err)
	}
	if err := c.CheckOIDCLogoutSupport(t.Context()); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

// Embedding the old Store surface deliberately hides the optional v1 repositories.
type oldOIDCBacking struct{ store.Store }

func (s oldOIDCBacking) Sessions() store.Sessions { return oldOIDCSessions{s.Store.Sessions()} }

type oldOIDCSessions struct{ store.Sessions }

func TestOIDCCapabilityRequiresBackingRepositories(t *testing.T) {
	c := serveEventsFaults(t, oldOIDCBacking{memory.New()}, &eventsFaults{})
	defer c.Close()
	if err := c.CheckOIDCLogoutSupport(t.Context()); !errors.Is(err, store.ErrOIDCLogoutUnavailable) {
		t.Fatalf("old backing advertised v1: %v", err)
	}
}
