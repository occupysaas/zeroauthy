package hostedlogin

import (
	"context"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/brandingrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type Service struct{ Store store.Store }

// Load returns the authoritative configuration. A first read imports legacy
// tenant branding/text exactly once; a concurrent importer wins by CAS.
func (s Service) Load(ctx context.Context, tenantID string) (*store.HostedLoginConfig, error) {
	c, err := s.Store.HostedLogins().Get(ctx, tenantID)
	if err == nil {
		return c, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	tenant, err := s.Store.Tenants().Get(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	c = brandingrules.FromLegacy(tenant)
	if err := s.Store.HostedLogins().Put(ctx, c, 0); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return s.Store.HostedLogins().Get(ctx, tenantID)
		}
		return nil, err
	}
	return s.Store.HostedLogins().Get(ctx, tenantID)
}
