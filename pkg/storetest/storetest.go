// Package storetest is the conformance suite for store.Store drivers.
// A driver package calls Run from one of its tests; authors of external
// storage plugins can do the same.
package storetest

import (
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Factory returns a new, empty store. Run closes it when the subtest ends.
type Factory func(t *testing.T) store.Store

// Suites maps each conformance suite name to its test function. SQL drivers
// use RunSuites to bring suites up one at a time.
var Suites = map[string]func(t *testing.T, newStore Factory){
	"ConnectionKeys":              testConnectionKeys,
	"MFA":                         MFA,
	"Phone":                       Phone,
	"Logs":                        testLogs,
	"Events":                      testEvents,
	"RBAC":                        testRBAC,
	"Organizations":               testOrganizations,
	"OrganizationsII":             testOrganizationsII,
	"Actions":                     testActions,
	"ActionsII":                   testActionsII,
	"Tenants":                     testTenants,
	"CustomDomainAttemptLimits":   testCustomDomainAttemptLimits,
	"CustomDomainClaims":          testCustomDomainClaims,
	"CustomDomainCap":             testCustomDomainCap,
	"CustomDomainCAS":             testCustomDomainCAS,
	"CustomDomainDefaultRollback": testCustomDomainDefaultRollback,
	"CustomDomainCascade":         testCustomDomainCascade,
	"TLSAssetCopies":              testTLSAssetCopies,
	"OriginRoundTrip":             testOriginRoundTrip,
	"TLSLeaseFence":               testTLSLeaseFence,
	"Protection":                  testProtection,
	"OIDCClientSettings":          testOIDCClientSettings,
	"ClientAddons":                testClientAddons,
	"SAMLReplay":                  testSAMLReplay,
	"GlobalRevocationState":       testGlobalRevocationState,
	"Clients":                     testClients,
	"ResourceServers":             testResourceServers,
	"ClientGrants":                testClientGrants,
	"UserGrants":                  testUserGrants,
	"SigningKeys":                 testSigningKeys,
	"CustomSigningKeys":           testCustomSigningKeys,
	"Connections":                 testConnections,
	"PasswordHistories":           testPasswordHistories,
	"Users":                       testUsers,
	"UserDelete":                  testUserDelete,
	"UserList":                    testUserList,
	"UserQueryMetadataTypes":      testUserQueryMetadataTypes,
	"SessionExpirySnapshots":      testSessionExpirySnapshots,
	"SAMLSessionParticipants":     testSAMLSessionParticipants,
	"Sessions":                    testSessions,
	"AuthTransactions":            testAuthTransactions,
	"AuthCodes":                   testAuthCodes,
	"PushedAuthRequests":          testPushedAuthRequests,
	"RefreshTokens":               testRefreshTokens,
	"RefreshTokensII":             testRefreshTokensII,
	"DPoP":                        testDPoP,
	"TokenQuotas":                 testTokenQuotas,
	"PasswordResetTickets":        testPasswordResetTickets,
	"EmailVerificationTickets":    testEmailVerificationTickets,
	"Tx":                          testTx,
	"DeviceCodes":                 testDeviceCodes,
	"Operators":                   testOperators,
	"Jobs":                        testJobs,
	"Email":                       testEmail,
	"HostedLogin":                 testHostedLogin,
	"HostedTransition":            testHostedTransition,
	"TenantsDelete":               testTenantsDelete,
	"EmptyLists":                  testEmptyLists,
	"WebAuthn":                    testWebAuthn,
	"Federation":                  testFederation,
	"ClientCredentials":           testClientCredentials,
}

// suiteOrder is the order Run executes the suites in.
var suiteOrder = []string{
	"MFA", "Phone", "WebAuthn",
	"CustomDomainAttemptLimits", "CustomDomainClaims", "CustomDomainCap", "CustomDomainCAS", "CustomDomainDefaultRollback", "CustomDomainCascade", "TLSAssetCopies", "TLSLeaseFence", "OriginRoundTrip",
	"Events", "Logs", "RBAC", "Organizations", "OrganizationsII", "Protection", "Tenants", "Clients", "GlobalRevocationState", "OIDCClientSettings", "ClientAddons", "SAMLReplay", "ResourceServers", "ClientGrants", "UserGrants", "SigningKeys", "CustomSigningKeys",
	"Connections", "PasswordHistories", "Users", "UserDelete", "UserList", "UserQueryMetadataTypes", "Sessions", "SessionExpirySnapshots", "SAMLSessionParticipants", "AuthTransactions", "AuthCodes",
	"PushedAuthRequests",
	"RefreshTokens", "RefreshTokensII", "DPoP", "TokenQuotas", "PasswordResetTickets", "EmailVerificationTickets", "Tx",
	"DeviceCodes", "Operators", "Jobs", "TenantsDelete", "EmptyLists",
	"Email", "HostedLogin", "HostedTransition", "Federation", "ClientCredentials", "Actions", "ActionsII",
}

// Areas groups the suites by the part of zeroauthy they back. Every suite in
// suiteOrder belongs to exactly one area. CI splits a slow driver's Run into
// shards by area; developers can run one area locally:
//
//	ZA_STORETEST_AREAS=oauth go test -run '^TestConformance$' ./internal/store/sqlstore
var Areas = map[string][]string{
	"identity": {"MFA", "Phone", "WebAuthn", "Connections", "PasswordHistories", "Users", "UserDelete", "UserList",
		"UserQueryMetadataTypes", "Sessions", "AuthTransactions", "PasswordResetTickets", "EmailVerificationTickets",
		"HostedLogin", "HostedTransition", "Federation", "SessionExpirySnapshots", "SAMLSessionParticipants"},
	"oauth": {"Clients", "ResourceServers", "ClientGrants", "UserGrants", "SigningKeys", "CustomSigningKeys", "AuthCodes",
		"PushedAuthRequests", "RefreshTokens", "RefreshTokensII", "DPoP", "TokenQuotas", "DeviceCodes", "ClientCredentials",
		"OIDCClientSettings", "GlobalRevocationState", "ClientAddons", "SAMLReplay"},
	"orgs":    {"RBAC", "Organizations", "OrganizationsII"},
	"runtime": {"Events", "Logs", "Jobs", "Email", "Actions", "ActionsII"},
	"tenancy": {"CustomDomainAttemptLimits", "CustomDomainClaims", "CustomDomainCap", "CustomDomainCAS",
		"CustomDomainDefaultRollback", "CustomDomainCascade", "TLSAssetCopies", "TLSLeaseFence", "OriginRoundTrip",
		"Protection", "Tenants", "TenantsDelete", "Operators", "Tx", "EmptyLists"},
}

// Environment variables that limit Run and RunExcept to some areas: a
// comma-separated list of area names. Set at most one of them. A shard that
// sets EnvAreas=x and another that sets EnvSkipAreas=x together run every
// suite exactly once.
const (
	EnvAreas     = "ZA_STORETEST_AREAS"
	EnvSkipAreas = "ZA_STORETEST_SKIP_AREAS"
)

// selectSuites returns the suites the area lists allow, or nil for all of
// them. An unknown area name is an error, so a typo can't silently run
// nothing.
func selectSuites(include, exclude string) (map[string]bool, error) {
	if include != "" && exclude != "" {
		return nil, fmt.Errorf("set only one of %s and %s", EnvAreas, EnvSkipAreas)
	}
	list, keep := include, true
	if exclude != "" {
		list, keep = exclude, false
	}
	if strings.TrimSpace(list) == "" {
		return nil, nil
	}
	named := map[string]bool{}
	for _, area := range strings.Split(list, ",") {
		area = strings.TrimSpace(area)
		suites, ok := Areas[area]
		if !ok {
			known := make([]string, 0, len(Areas))
			for a := range Areas {
				known = append(known, a)
			}
			sort.Strings(known)
			return nil, fmt.Errorf("unknown storetest area %q (known: %s)", area, strings.Join(known, ", "))
		}
		for _, s := range suites {
			named[s] = true
		}
	}
	out := map[string]bool{}
	for _, s := range suiteOrder {
		if named[s] == keep {
			out[s] = true
		}
	}
	return out, nil
}

// envSuites applies EnvAreas and EnvSkipAreas, failing t on a bad value.
func envSuites(t *testing.T) map[string]bool {
	t.Helper()
	include, exclude := os.Getenv(EnvAreas), os.Getenv(EnvSkipAreas)
	sel, err := selectSuites(include, exclude)
	if err != nil {
		t.Fatalf("storetest: %v", err)
	}
	if sel != nil {
		t.Logf("storetest: %s=%q %s=%q: running %d of %d suites", EnvAreas, include, EnvSkipAreas, exclude, len(sel), len(suiteOrder))
	}
	return sel
}

// Run executes the conformance tests every driver passes against stores made
// by newStore, limited to the areas EnvAreas or EnvSkipAreas name.
func Run(t *testing.T, newStore Factory) {
	t.Helper()
	sel := envSuites(t)
	names := slices.DeleteFunc(slices.Clone(suiteOrder), func(n string) bool { return sel != nil && !sel[n] })
	RunSuites(t, newStore, names...)
}

// RunExcept is Run with named suites skipped, limited to the same areas. Each skip reports its reason, so
// a driver that has not implemented a repository yet shows the gap instead of
// passing it.
func RunExcept(t *testing.T, newStore Factory, skip map[string]string) {
	t.Helper()
	sel := envSuites(t)
	for _, name := range suiteOrder {
		if sel != nil && !sel[name] {
			continue
		}
		if reason, ok := skip[name]; ok {
			t.Run(name, func(t *testing.T) { t.Skip(reason) })
			continue
		}
		RunSuites(t, newStore, name)
	}
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
