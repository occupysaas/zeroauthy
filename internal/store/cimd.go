package store

import (
	"context"
	"errors"
)

// ErrCIMDUnavailable reports a storage plugin without the cimd.v1
// capability (Plan 41b): it cannot store client external metadata or
// default client grants.
var ErrCIMDUnavailable = errors.New("store: cimd.v1 unavailable")

// CIMDSupporter is implemented by stores that can tell whether they store
// Plan 41b's client and grant fields.
type CIMDSupporter interface{ CheckCIMDSupport(context.Context) error }

// CheckCIMDSupport reports whether s stores Plan 41b's fields. Stores that
// do not implement CIMDSupporter (memory, SQL) support them.
func CheckCIMDSupport(ctx context.Context, s Store) error {
	if capability, ok := s.(CIMDSupporter); ok {
		return capability.CheckCIMDSupport(ctx)
	}
	return nil
}

// ClientNeedsCIMD reports whether writing c needs cimd.v1.
func ClientNeedsCIMD(c *Client) bool { return c != nil && c.External != nil }

// GrantNeedsCIMD reports whether writing g needs cimd.v1.
func GrantNeedsCIMD(g *ClientGrant) bool { return g != nil && g.DefaultFor != "" }

// FindEffectiveClientGrant returns c's own grant for audience and
// subjectType or, for a third-party client without one, the tenant's
// default grant for third-party clients (Plan 41b, LR41b-4: per-client
// grants take precedence). ErrNotFound when neither exists.
func FindEffectiveClientGrant(ctx context.Context, st Store, c *Client, audience, subjectType string) (*ClientGrant, error) {
	g, err := st.ClientGrants().Find(ctx, c.TenantID, c.ClientID, audience, subjectType)
	if err == nil || !errors.Is(err, ErrNotFound) || c.IsFirstParty {
		return g, err
	}
	g, err = st.ClientGrants().Find(ctx, c.TenantID, "", audience, subjectType)
	if err == nil && g.DefaultFor != GrantDefaultForThirdParty {
		return nil, ErrNotFound
	}
	return g, err
}
