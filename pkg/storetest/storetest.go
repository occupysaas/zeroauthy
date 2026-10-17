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

// Suites maps each conformance suite name to its test function. SQL drivers
// use RunSuites to bring suites up one at a time.
var Suites = map[string]func(t *testing.T, newStore Factory){
	"Tenants":              testTenants,
	"Clients":              testClients,
	"ResourceServers":      testResourceServers,
	"ClientGrants":         testClientGrants,
	"UserGrants":           testUserGrants,
	"SigningKeys":          testSigningKeys,
	"Connections":          testConnections,
	"Users":                testUsers,
	"Sessions":             testSessions,
	"AuthTransactions":     testAuthTransactions,
	"AuthCodes":            testAuthCodes,
	"PushedAuthRequests":   testPushedAuthRequests,
	"RefreshTokens":        testRefreshTokens,
	"PasswordResetTickets": testPasswordResetTickets,
	"Tx":                   testTx,
	"DeviceCodes":          testDeviceCodes,
}

// suiteOrder is the order Run executes the suites in.
var suiteOrder = []string{
	"Tenants", "Clients", "ResourceServers", "ClientGrants", "UserGrants", "SigningKeys",
	"Connections", "Users", "Sessions", "AuthTransactions", "AuthCodes",
	"PushedAuthRequests",
	"RefreshTokens", "PasswordResetTickets", "Tx",
	"DeviceCodes",
}

// Run executes the conformance tests every driver passes against stores made
// by newStore.
func Run(t *testing.T, newStore Factory) {
	RunSuites(t, newStore, suiteOrder...)
}

// RunSuites executes only the named suites. An unknown name fails the test.
func RunSuites(t *testing.T, newStore Factory, names ...string) {
	t.Helper()
	for _, name := range names {
		fn, ok := Suites[name]
		if !ok {
			t.Fatalf("storetest: unknown suite %q", name)
		}
		t.Run(name, func(t *testing.T) { fn(t, newStore) })
	}
}

func open(t *testing.T, newStore Factory) store.Store {
	t.Helper()
	s := newStore(t)
	t.Cleanup(func() { _ = s.Close() })
	return s
}
