package tenant

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Resolved is the tenant a request was addressed to and the normalized
// host it used.
type Resolved struct {
	Tenant *store.Tenant
	Host   string
}

// Issuer is the token issuer for this tenant and host. The trailing slash
// is part of the issuer.
func (r Resolved) Issuer() string { return "https://" + r.Host + "/" }

// Origin is the public origin of this request (scheme and host). Browser and
// grant artifacts record it; API identifiers never depend on it.
func (r Resolved) Origin() string { return "https://" + r.Host }

// CanonicalOrigin is the tenant's pinned canonical origin, the meaning of a
// legacy artifact with no recorded origin.
func CanonicalOrigin(t *store.Tenant) string {
	if t == nil || t.CanonicalHost == "" {
		return ""
	}
	return "https://" + t.CanonicalHost
}

// CheckOrigin reports whether an artifact recorded with stored may be used
// on this request's origin (customdomain.CheckOrigin).
func (r Resolved) CheckOrigin(stored string) error {
	return customdomain.CheckOrigin(stored, CanonicalOrigin(r.Tenant), r.Origin())
}

type ctxKey struct{}

// WithResolved returns a context carrying r.
func WithResolved(ctx context.Context, r Resolved) context.Context {
	return context.WithValue(ctx, ctxKey{}, r)
}

// FromContext returns the tenant stored by the resolver middleware.
func FromContext(ctx context.Context) (Resolved, bool) {
	r, ok := ctx.Value(ctxKey{}).(Resolved)
	return r, ok
}
