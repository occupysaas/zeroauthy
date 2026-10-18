// Package tenantsetup holds the tenant set-up steps shared by the seed, the
// system tenant (internal/system) and tenant creation through the system
// API: upserting a tenant and its connections, clients and resource
// servers by their natural keys, and making sure it has signing keys.
//
// Each Upsert loads the entity by its natural key, or starts a new one with
// a generated ID, lets the caller's set function fill it in, and then
// creates or updates it.
package tenantsetup

import (
	"context"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// SigningKeys makes sure the tenant has a current and a next signing key.
func SigningKeys(ctx context.Context, st store.Store, w keys.Wrapper, tenantID string) error {
	if w == nil {
		return errors.New("tenantsetup: a master key wrapper is required for signing keys")
	}
	return keys.NewManager(st.SigningKeys(), w).Ensure(ctx, tenantID)
}

// UpsertTenant finds the tenant by name or starts a new one (ID and
// CreatedAt set), applies set, and stores it. It returns the stored tenant.
func UpsertTenant(ctx context.Context, st store.Store, name string, now time.Time, set func(t *store.Tenant) error) (*store.Tenant, error) {
	tn, err := st.Tenants().GetByName(ctx, name)
	create := errors.Is(err, store.ErrNotFound)
	if err != nil && !create {
		return nil, err
	}
	if create {
		tn = &store.Tenant{ID: "ten_" + secrets.RandomString(16), Name: name, CreatedAt: now}
	}
	if err := set(tn); err != nil {
		return nil, err
	}
	if create {
		err = st.Tenants().Create(ctx, tn)
	} else {
		err = st.Tenants().Update(ctx, tn)
	}
	if err != nil {
		return nil, err
	}
	return tn, nil
}

// UpsertConnection finds the tenant's connection by name or starts a new one
// (ID and CreatedAt set), applies set, and stores it. set sees the final ID,
// so it can seal configuration bound to it.
func UpsertConnection(ctx context.Context, st store.Store, tenantID, name string, now time.Time, set func(c *store.Connection) error) error {
	c, err := st.Connections().GetByName(ctx, tenantID, name)
	create := errors.Is(err, store.ErrNotFound)
	if err != nil && !create {
		return err
	}
	if create {
		c = &store.Connection{TenantID: tenantID, ID: "con_" + secrets.RandomString(16), Name: name, CreatedAt: now}
	}
	if err := set(c); err != nil {
		return err
	}
	if create {
		return st.Connections().Create(ctx, c)
	}
	return st.Connections().Update(ctx, c)
}

// UpsertClient finds the client by ID or starts a new one (CreatedAt set),
// applies set, and stores it. set learns whether the client is new.
func UpsertClient(ctx context.Context, st store.Store, tenantID, clientID string, now time.Time, set func(c *store.Client, created bool) error) error {
	c, err := st.Clients().Get(ctx, tenantID, clientID)
	create := errors.Is(err, store.ErrNotFound)
	if err != nil && !create {
		return err
	}
	if create {
		c = &store.Client{TenantID: tenantID, ClientID: clientID, CreatedAt: now}
	}
	if err := set(c, create); err != nil {
		return err
	}
	if create {
		return st.Clients().Create(ctx, c)
	}
	return st.Clients().Update(ctx, c)
}

// UpsertResourceServer finds the resource server by identifier or starts a
// new one (ID and CreatedAt set), applies set, and stores it.
func UpsertResourceServer(ctx context.Context, st store.Store, tenantID, identifier string, now time.Time, set func(rs *store.ResourceServer) error) error {
	rs, err := st.ResourceServers().GetByIdentifier(ctx, tenantID, identifier)
	create := errors.Is(err, store.ErrNotFound)
	if err != nil && !create {
		return err
	}
	if create {
		rs = &store.ResourceServer{TenantID: tenantID, ID: "rs_" + secrets.RandomString(24), Identifier: identifier, CreatedAt: now}
	}
	if err := set(rs); err != nil {
		return err
	}
	if create {
		return st.ResourceServers().Create(ctx, rs)
	}
	return st.ResourceServers().Update(ctx, rs)
}
