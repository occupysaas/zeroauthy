package grpcstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func orgSeed(t *testing.T, s store.Store) {
	t.Helper()
	ctx := context.Background()
	if err := s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, id := range []string{"u1", "u2"} {
		if err := s.Users().Create(ctx, &store.User{TenantID: "t", UserID: "auth0|" + id, Email: id + "@t.test", Username: id, Identities: []store.Identity{{Connection: "Database", Provider: store.StrategyDatabase, UserID: id}}, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOrganizationsPluginRoundTrip(t *testing.T) {
	ctx := context.Background()
	c := inProcess(t)
	defer c.Close()
	if err := c.CheckOrganizationsSupport(ctx); err != nil {
		t.Fatal(err)
	}
	if !store.OrganizationsSupported(c) {
		t.Fatal("capable plugin reported unsupported")
	}
	// The shared conformance suite exercises every method through the wire.
	storetest.RunSuites(t, func(t *testing.T) store.Store { return serve(t, memory.New()) }, "Organizations")

	orgSeed(t, c)
	o := c.Organizations()
	var created []string
	for _, n := range []string{"a", "b", "c"} {
		org := &store.Organization{TenantID: "t", ID: orgrules.NewID(), Name: n, DisplayName: n, ThirdPartyClientAccess: "block", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
		if err := o.Create(ctx, org, nil); err != nil {
			t.Fatal(err)
		}
		created = append(created, org.ID)
	}
	// Error mapping.
	dup := &store.Organization{TenantID: "t", ID: orgrules.NewID(), Name: "a", DisplayName: "a", ThirdPartyClientAccess: "block"}
	if err := o.Create(ctx, dup, nil); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	if _, err := o.Get(ctx, "t", orgrules.NewID()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing org: %v", err)
	}
	if err := o.AddMembers(ctx, "t", created[0], []string{"auth0|ghost"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
	// Pagination: Next round-trips and ends.
	first, err := o.List(ctx, "t", store.OrgPage{Take: 2, Sort: "name:1"})
	if err != nil || len(first.Items) != 2 || first.Next == "" {
		t.Fatalf("first page: %+v, %v", first, err)
	}
	second, err := o.List(ctx, "t", store.OrgPage{From: first.Next, Take: 2, Sort: "name:1"})
	if err != nil || len(second.Items) != 1 || second.Items[0].Name != "c" || second.Next != "" {
		t.Fatalf("second page: %+v, %v", second, err)
	}
	// Transactions carry the handle: a failed callback rolls the write back.
	txID := orgrules.NewID()
	boom := errors.New("boom")
	err = c.WithTx(ctx, func(tx store.Store) error {
		if err := tx.Organizations().Create(ctx, &store.Organization{TenantID: "t", ID: txID, Name: "tx", DisplayName: "tx", ThirdPartyClientAccess: "block"}, nil); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("WithTx: %v", err)
	}
	if _, err := o.Get(ctx, "t", txID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("organization survived rollback: %v", err)
	}
}

// ErrPrecondition travels the wire as itself (limits).
func TestOrganizationsPreconditionMapping(t *testing.T) {
	ctx := context.Background()
	m := memory.New()
	c := serve(t, m)
	defer c.Close()
	orgSeed(t, c)
	m.SetOrgLimits(store.OrgLimits{OrganizationsPerTenant: 1, ConnectionsPerOrganization: 1, RolesPerMember: 1})
	mk := func(n string) *store.Organization {
		return &store.Organization{TenantID: "t", ID: orgrules.NewID(), Name: n, DisplayName: n, ThirdPartyClientAccess: "block"}
	}
	if err := c.Organizations().Create(ctx, mk("a"), nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Organizations().Create(ctx, mk("b"), nil); !errors.Is(err, store.ErrPrecondition) {
		t.Fatalf("limit: %v", err)
	}
}

type oldOrganizationsPlugin struct{ *Server }

func (oldOrganizationsPlugin) OrganizationsCapabilities(context.Context, *storev1.PingRequest) (*storev1.OrganizationsCapabilitiesResult, error) {
	return nil, status.Error(codes.Unimplemented, "pre-Organizations plugin")
}

func TestOrganizationsOldPlugin(t *testing.T) {
	ctx := context.Background()
	c := serveWith(t, oldOrganizationsPlugin{NewServer(memory.New())})
	defer c.Close()
	if err := c.CheckOrganizationsSupport(ctx); !errors.Is(err, store.ErrOrganizationsUnavailable) {
		t.Fatalf("capability: %v", err)
	}
	if store.OrganizationsSupported(c) {
		t.Fatal("old plugin reported Organizations support")
	}
	// A plugin with no Organizations RPCs at all fails closed, never empty.
	old := serveWith(t, struct{ storev1.StoreServiceServer }{storev1.UnimplementedStoreServiceServer{}})
	defer old.Close()
	if store.OrganizationsSupported(old) {
		t.Fatal("plugin without the RPC reported support")
	}
	if _, err := old.Organizations().List(ctx, "t", store.OrgPage{}); !errors.Is(err, store.ErrOrganizationsUnavailable) {
		t.Fatalf("list on old plugin: %v", err)
	}
	if _, err := old.Organizations().IsMember(ctx, "t", "o", "u"); !errors.Is(err, store.ErrOrganizationsUnavailable) {
		t.Fatalf("membership on old plugin: %v", err)
	}
	// Stores that do not negotiate are always supported.
	if !store.OrganizationsSupported(memory.New()) {
		t.Fatal("memory store reported unsupported")
	}
}

// A capability version below 1 is refused like an absent RPC.
type zeroOrganizationsPlugin struct{ *Server }

func (zeroOrganizationsPlugin) OrganizationsCapabilities(context.Context, *storev1.PingRequest) (*storev1.OrganizationsCapabilitiesResult, error) {
	return &storev1.OrganizationsCapabilitiesResult{Version: 0}, nil
}

func TestOrganizationsVersionZeroRefused(t *testing.T) {
	c := serveWith(t, zeroOrganizationsPlugin{NewServer(memory.New())})
	defer c.Close()
	if err := c.CheckOrganizationsSupport(context.Background()); !errors.Is(err, store.ErrOrganizationsUnavailable) {
		t.Fatalf("version 0 accepted: %v", err)
	}
}
