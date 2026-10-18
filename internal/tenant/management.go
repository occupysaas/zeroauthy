package tenant

import "github.com/zeroauthy/zeroauthy/internal/store"

// ManagementAPIIdentifier is the tenant's canonical Management API
// identifier, the audience of its machine-to-machine Management API
// tokens: https://<name>.<baseDomain>/api/v2/, or, without a base domain,
// https://<first entry of Domains>/api/v2/. As on Auth0 it stays on that
// host whichever of the tenant's hosts serves a request (M11). It is ""
// when the tenant has no host at all.
func ManagementAPIIdentifier(t *store.Tenant, baseDomain string) string {
	if t == nil {
		return ""
	}
	switch {
	case baseDomain != "":
		return "https://" + NormalizeHost(t.Name+"."+NormalizeHost(baseDomain)) + "/api/v2/"
	case len(t.Domains) > 0:
		return "https://" + NormalizeHost(t.Domains[0]) + "/api/v2/"
	}
	return ""
}

// Issuers lists the issuers the tenant mints tokens under, one per host it
// answers on: <name>.<baseDomain> when there is a base domain, then each of
// Domains.
func Issuers(t *store.Tenant, baseDomain string) []string {
	var out []string
	if baseDomain != "" {
		out = append(out, "https://"+NormalizeHost(t.Name+"."+NormalizeHost(baseDomain))+"/")
	}
	for _, d := range t.Domains {
		out = append(out, "https://"+NormalizeHost(d)+"/")
	}
	return out
}
