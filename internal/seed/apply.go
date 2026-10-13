package seed

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// Apply upserts everything in f. It never deletes.
func Apply(ctx context.Context, st store.Store, f *File, now func() time.Time) error {
	if now == nil {
		now = time.Now
	}
	for _, t := range f.Tenants {
		if err := applyTenant(ctx, st, t, now().UTC()); err != nil {
			return fmt.Errorf("seed: tenant %q: %w", t.Name, err)
		}
	}
	return nil
}

func applyTenant(ctx context.Context, st store.Store, in Tenant, now time.Time) error {
	domains := make([]string, len(in.Domains))
	for i, d := range in.Domains {
		domains[i] = tenant.NormalizeHost(d)
	}
	tn, err := st.Tenants().GetByName(ctx, in.Name)
	switch {
	case errors.Is(err, store.ErrNotFound):
		tn = &store.Tenant{ID: "ten_" + secrets.RandomString(16), Name: in.Name, CreatedAt: now}
		tn.FriendlyName, tn.Domains, tn.DefaultAudience = in.FriendlyName, domains, in.DefaultAudience
		if err := st.Tenants().Create(ctx, tn); err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		tn.FriendlyName, tn.Domains, tn.DefaultAudience = in.FriendlyName, domains, in.DefaultAudience
		if err := st.Tenants().Update(ctx, tn); err != nil {
			return err
		}
	}

	for _, rs := range in.ResourceServers {
		if err := applyResourceServer(ctx, st, tn.ID, rs, now); err != nil {
			return fmt.Errorf("resource server %q: %w", rs.Identifier, err)
		}
	}
	for _, c := range in.Clients {
		if err := applyClient(ctx, st, tn.ID, c, now); err != nil {
			return fmt.Errorf("client %q: %w", c.ClientID, err)
		}
	}
	for _, g := range in.ClientGrants {
		if err := applyClientGrant(ctx, st, tn.ID, g, now); err != nil {
			return fmt.Errorf("client grant %q → %q: %w", g.ClientID, g.Audience, err)
		}
	}
	return nil
}

func applyResourceServer(ctx context.Context, st store.Store, tenantID string, in ResourceServer, now time.Time) error {
	scopes := make([]store.Scope, len(in.Scopes))
	for i, s := range in.Scopes {
		scopes[i] = store.Scope{Value: s.Value, Description: s.Description}
	}
	rs, err := st.ResourceServers().GetByIdentifier(ctx, tenantID, in.Identifier)
	create := errors.Is(err, store.ErrNotFound)
	if err != nil && !create {
		return err
	}
	if create {
		rs = &store.ResourceServer{TenantID: tenantID, ID: "rs_" + secrets.RandomString(24), Identifier: in.Identifier, CreatedAt: now}
	}
	rs.Name, rs.Scopes, rs.SigningAlg = in.Name, scopes, "RS256"
	rs.TokenLifetime, rs.AllowOfflineAccess = in.TokenLifetime, in.AllowOfflineAccess
	if create {
		return st.ResourceServers().Create(ctx, rs)
	}
	return st.ResourceServers().Update(ctx, rs)
}

func applyClient(ctx context.Context, st store.Store, tenantID string, in Client, now time.Time) error {
	c, err := st.Clients().Get(ctx, tenantID, in.ClientID)
	create := errors.Is(err, store.ErrNotFound)
	if err != nil && !create {
		return err
	}
	if create {
		c = &store.Client{TenantID: tenantID, ClientID: in.ClientID, CreatedAt: now}
	}
	c.Name, c.AppType = in.Name, store.AppType(in.AppType)
	c.TokenEndpointAuthMethod = in.TokenEndpointAuthMethod
	c.GrantTypes = slices.Clone(in.GrantTypes)
	c.Callbacks, c.AllowedLogoutURLs = slices.Clone(in.Callbacks), slices.Clone(in.AllowedLogoutURLs)
	c.WebOrigins, c.AllowedOrigins = slices.Clone(in.WebOrigins), slices.Clone(in.AllowedOrigins)

	switch {
	case in.ClientSecret == "":
		c.Secrets = nil
	case !secretMatches(c.Secrets, in.ClientSecret):
		h, err := secrets.Hash(in.ClientSecret)
		if err != nil {
			return err
		}
		c.Secrets = []store.ClientSecret{{Hash: h, CreatedAt: now}}
	}
	if create {
		return st.Clients().Create(ctx, c)
	}
	return st.Clients().Update(ctx, c)
}

func secretMatches(existing []store.ClientSecret, plaintext string) bool {
	for _, s := range existing {
		if ok, err := secrets.Verify(s.Hash, plaintext); err == nil && ok {
			return true
		}
	}
	return false
}

func applyClientGrant(ctx context.Context, st store.Store, tenantID string, in ClientGrant, now time.Time) error {
	g, err := st.ClientGrants().Find(ctx, tenantID, in.ClientID, in.Audience)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return st.ClientGrants().Create(ctx, &store.ClientGrant{
			TenantID: tenantID, ID: "cgr_" + secrets.RandomString(24),
			ClientID: in.ClientID, Audience: in.Audience, Scopes: slices.Clone(in.Scopes), CreatedAt: now,
		})
	case err != nil:
		return err
	default:
		g.Scopes = slices.Clone(in.Scopes)
		return st.ClientGrants().Update(ctx, g)
	}
}
