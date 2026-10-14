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
	t.Run("SigningKeys", func(t *testing.T) { testSigningKeys(t, newStore) })
	t.Run("Connections", func(t *testing.T) { testConnections(t, newStore) })
	t.Run("Users", func(t *testing.T) { testUsers(t, newStore) })
	t.Run("Sessions", func(t *testing.T) { testSessions(t, newStore) })
	t.Run("AuthTransactions", func(t *testing.T) { testAuthTransactions(t, newStore) })
	t.Run("AuthCodes", func(t *testing.T) { testAuthCodes(t, newStore) })
}

func open(t *testing.T, newStore Factory) store.Store {
	t.Helper()
	s := newStore(t)
	t.Cleanup(func() { _ = s.Close() })
	return s
}
