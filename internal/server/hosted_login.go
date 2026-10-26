package server

import (
	"net/http"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/hostedlogin"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// hostedPresentation loads a coherent snapshot only for routes that can show
// hosted pages. Protocol response renderers retain their dedicated documents.
func hostedPresentation(st store.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			hosted := strings.HasPrefix(p, "/u/") || strings.HasPrefix(p, "/device/") || p == "/activate" || p == "/authorize" || p == "/v2/logout" || p == "/oidc/logout"
			res, ok := tenant.FromContext(r.Context())
			if !hosted || !ok || res.Tenant == nil || res.Tenant.Reserved {
				next.ServeHTTP(w, r)
				return
			}
			c, err := (hostedlogin.Service{Store: st}).Load(r.Context(), res.Tenant.ID)
			if err != nil {
				view := ui.TenantView(res.Tenant, i18n.ForRequest(res.Tenant, r, ""))
				ui.RenderError(w, http.StatusServiceUnavailable, view, view.L.T(i18n.KeyErrServer))
				return
			}
			res.Tenant = hostedlogin.LocalizedTenant(res.Tenant, c)
			ctx := hostedlogin.WithConfiguration(tenant.WithResolved(r.Context(), res), c)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
