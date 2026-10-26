package tenant

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ErrUnknownTenant means no tenant serves the requested host.
var ErrUnknownTenant = errors.New("tenant: unknown host")

// Resolver finds the tenant through the active registry projection exposed by
// Tenants.GetByDomain. Canonical names must be claimed before serving requests.
// With a base domain, system.<base domain> also reaches the reserved system
// tenant when server.system_host names another host; startup reserves it.
type Resolver struct {
	tenants           store.Tenants
	baseDomain        string
	trustProxyHeaders bool
}

func NewResolver(t store.Tenants, baseDomain string, trustProxyHeaders bool) *Resolver {
	bd := ""
	if baseDomain != "" {
		bd = NormalizeHost(baseDomain)
	}
	return &Resolver{tenants: t, baseDomain: bd, trustProxyHeaders: trustProxyHeaders}
}

func (r *Resolver) Resolve(ctx context.Context, host string) (Resolved, error) {
	h := NormalizeHost(host)
	t, err := r.tenants.GetByDomain(ctx, h)
	if err == nil {
		return Resolved{Tenant: t, Host: h}, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return Resolved{}, err
	}
	if r.baseDomain != "" && h == SystemName+"."+r.baseDomain {
		t, err := r.tenants.GetByName(ctx, SystemName)
		if err == nil && t.Reserved {
			return Resolved{Tenant: t, Host: h}, nil
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return Resolved{}, err
		}
	}
	return Resolved{}, ErrUnknownTenant
}

// Middleware resolves the tenant and stores it in the request context.
// Unknown hosts get a 404 JSON error.
func (r *Resolver) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		host := req.Host
		if r.trustProxyHeaders {
			if fwd := req.Header.Get("X-Forwarded-Host"); fwd != "" {
				host = strings.TrimSpace(strings.Split(fwd, ",")[0])
			}
		}
		res, err := r.Resolve(req.Context(), host)
		switch {
		case errors.Is(err, ErrUnknownTenant):
			w.Header().Set("Cache-Control", "no-store")
			httpx.WriteError(w, http.StatusNotFound, "not_found", "unknown tenant")
			return
		case err != nil:
			w.Header().Set("Cache-Control", "no-store")
			httpx.WriteError(w, http.StatusInternalServerError, "server_error", "internal error")
			return
		}
		next.ServeHTTP(w, req.WithContext(WithResolved(req.Context(), res)))
	})
}
