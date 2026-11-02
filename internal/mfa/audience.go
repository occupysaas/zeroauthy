package mfa

import (
	"context"
	"net/url"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// APIAudience recognizes only active tenant registry hosts. The registry
// exposes canonical hosts and verified custom domains, never pending aliases.
func APIAudience(ctx context.Context, st store.Store, tid, aud string) bool {
	u, err := url.Parse(aud)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/mfa/" || u.RawPath != "" || u.Host == "" || u.Host != tenant.NormalizeHost(u.Host) {
		return false
	}
	t, err := st.Tenants().GetByDomain(ctx, u.Host)
	return err == nil && t.ID == tid
}

// APIResourceServer is a synthetic user API. It is never persisted or listed
// with ordinary resource servers and defines only the three MFA API scopes.
func APIResourceServer(tid, aud string) *store.ResourceServer {
	return &store.ResourceServer{TenantID: tid, Identifier: aud, IsSystem: true, SkipConsentForVerifiableFirstPartyClients: true, Scopes: []store.Scope{{Value: "enroll"}, {Value: "read:authenticators"}, {Value: "remove:authenticators"}}}
}
