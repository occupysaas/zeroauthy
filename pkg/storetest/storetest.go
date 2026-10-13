// Package storetest is the conformance suite for store.Store drivers.
// A driver package calls Run from one of its tests; authors of external
// storage plugins can do the same.
package storetest

import (
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Factory returns a new, empty store. Run closes it when the subtest ends.
type Factory func(t *testing.T) store.Store

// Run executes every conformance test against stores made by newStore.
func Run(t *testing.T, newStore Factory) {
	t.Run("Tenants", func(t *testing.T) { testTenants(t, newStore) })
	t.Run("Clients", func(t *testing.T) { testClients(t, newStore) })
	t.Run("ResourceServers", func(t *testing.T) { testResourceServers(t, newStore) })
	t.Run("ClientGrants", func(t *testing.T) { testClientGrants(t, newStore) })
}

func open(t *testing.T, newStore Factory) store.Store {
	t.Helper()
	s := newStore(t)
	t.Cleanup(func() { _ = s.Close() })
	return s
}
