package storetest

import (
	"context"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// testEmptyLists pins the policy for list results: an empty list is not an
// error, but a driver may return it as nil or as an empty slice (the plugin
// path may normalize either way), so callers and tests must use len and never
// compare against nil. Nothing here may depend on which one a driver returns.
func testEmptyLists(t *testing.T, newStore Factory) {
	ctx := context.Background()
	s := open(t, newStore)

	tenants, err := s.Tenants().List(ctx)
	mustNoErr(t, err)
	mustEqual(t, len(tenants), 0)

	tn := newTenant("acme")
	mustNoErr(t, s.Tenants().Create(ctx, tn))
	id := tn.ID

	clients, err := s.Clients().List(ctx, id)
	mustNoErr(t, err)
	mustEqual(t, len(clients), 0)

	rss, err := s.ResourceServers().List(ctx, id)
	mustNoErr(t, err)
	mustEqual(t, len(rss), 0)

	grants, total, err := s.ClientGrants().List(ctx, id, store.ClientGrantFilter{}, store.Page{Limit: 10})
	mustNoErr(t, err)
	mustEqual(t, len(grants), 0)
	mustEqual(t, total, 0)

	ugs, err := s.UserGrants().ListByUser(ctx, id, "auth0|nobody")
	mustNoErr(t, err)
	mustEqual(t, len(ugs), 0)

	conns, total, err := s.Connections().List(ctx, id, store.ConnectionFilter{}, store.Page{Limit: 10})
	mustNoErr(t, err)
	mustEqual(t, len(conns), 0)
	mustEqual(t, total, 0)

	ops, err := s.Operators().List(ctx, id)
	mustNoErr(t, err)
	mustEqual(t, len(ops), 0)
}
