package tenantview

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Localized returns a request-local tenant with canonical custom text.
// An absent hosted configuration retains the legacy tenant text.
func Localized(ctx context.Context, st store.Store, tenant *store.Tenant) (*store.Tenant, error) {
	if tenant == nil {
		return nil, store.ErrInvalid
	}
	c, err := st.HostedLogins().Get(ctx, tenant.ID)
	if errors.Is(err, store.ErrNotFound) {
		return Project(tenant, nil), nil
	}
	if err != nil {
		return nil, err
	}
	return Project(tenant, c), nil
}

// Project overlays an already loaded configuration without mutating either input.
func Project(tenant *store.Tenant, c *store.HostedLoginConfig) *store.Tenant {
	if tenant == nil {
		return nil
	}
	out := tenant.Clone()
	if c != nil {
		out.CustomText = c.CustomText.Clone()
	}
	return out
}
