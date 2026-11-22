package mgmt

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const consoleManagementPrefix = "/api/console/tenants/"

// consoleManagement dispatches to the existing Management router after
// authenticating the operator for the named tenant. It uses the tenant's
// canonical origin for handler context without making a network request.
func (cfg Config) consoleManagement(w http.ResponseWriter, r *http.Request, next http.Handler, base tenant.Resolved, path string) {
	name, rawPath, _ := strings.Cut(path, "/")
	if cfg.SystemHost == "" || base.Host != tenant.NormalizeHost(cfg.SystemHost) || !base.Tenant.Reserved || base.Tenant.Name != tenant.SystemName ||
		!tenant.ValidName(name) || name == tenant.SystemName || !strings.HasPrefix(rawPath, "api/v2/") {
		WriteError(w, http.StatusNotFound, "", "Not Found")
		return
	}
	rawPath = "/" + rawPath
	decodedPath, err := url.PathUnescape(rawPath)
	if err != nil {
		WriteError(w, http.StatusNotFound, "", "Not Found")
		return
	}
	caller, err := cfg.authenticate(r, base, name)
	if err != nil {
		Fail(w, err)
		return
	}
	ctx := r.Context()
	target, err := cfg.Store.Tenants().GetByName(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "inexistent_tenant", "The tenant does not exist")
		return
	}
	if err != nil {
		cfg.log().ErrorContext(ctx, "management API: load console target tenant", "err", err)
		WriteError(w, http.StatusInternalServerError, "internal_error", "Internal error")
		return
	}
	host := strings.TrimSuffix(strings.TrimPrefix(tenant.ManagementAPIIdentifier(target, cfg.BaseDomain), "https://"), "/api/v2/")
	if target.Reserved || host == "" {
		WriteError(w, http.StatusNotFound, "", "Not Found")
		return
	}
	ctx = tenant.WithResolved(ctx, tenant.Resolved{Tenant: target, Host: host})
	req := r.Clone(WithCaller(ctx, caller))
	req.URL.Path = decodedPath
	if req.URL.RawPath != "" {
		req.URL.RawPath = rawPath
	}
	req.RequestURI = req.URL.RequestURI()
	next.ServeHTTP(w, req)
}
