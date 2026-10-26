package hostedlogin

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantview"
)

// LocalizedTenant makes a request-local view with authoritative custom text.
// Callers must never mutate the tenant returned by the repository.
func LocalizedTenant(tenant *store.Tenant, config *store.HostedLoginConfig) *store.Tenant {
	return tenantview.Project(tenant, config)
}
