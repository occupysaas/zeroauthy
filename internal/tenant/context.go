package tenant

import (
	"context"

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
