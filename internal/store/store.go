// Package store defines zeroauthy's storage interfaces. Every driver
// (memory, SQL, external plugin) implements Store and must pass the
// conformance suite in pkg/storetest.
//
// Drivers return copies: mutating a value passed to or returned from a
// driver never changes stored state.
package store

import (
	"context"
	"errors"
)

var (
	// ErrNotFound is returned when the requested entity does not exist.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict is returned when a create or update would violate a
	// uniqueness rule.
	ErrConflict = errors.New("store: conflict")
)

// Store aggregates the repositories of one storage backend.
type Store interface {
	Tenants() Tenants
	Clients() Clients
	ResourceServers() ResourceServers
	ClientGrants() ClientGrants
	SigningKeys() SigningKeys
	Ping(ctx context.Context) error
	Close() error
}

// Tenants stores tenants. Tenants are the only entities not scoped by a
// tenant ID.
type Tenants interface {
	// Create stores a new tenant. It returns ErrConflict if the ID, the
	// name, or any of the domains is already used by another tenant.
	Create(ctx context.Context, t *Tenant) error
	Get(ctx context.Context, id string) (*Tenant, error)
	GetByName(ctx context.Context, name string) (*Tenant, error)
	// GetByDomain finds the tenant that lists domain in Domains. Callers
	// pass normalized hosts (see tenant.NormalizeHost).
	GetByDomain(ctx context.Context, domain string) (*Tenant, error)
	// Update replaces the tenant with the same ID. It returns ErrNotFound
	// if absent and ErrConflict if the new name or a domain collides with
	// another tenant.
	Update(ctx context.Context, t *Tenant) error
	// List returns all tenants ordered by Name.
	List(ctx context.Context) ([]*Tenant, error)
}

// Clients stores applications, keyed by (TenantID, ClientID).
type Clients interface {
	// Create returns ErrConflict if the client ID exists in the tenant.
	Create(ctx context.Context, c *Client) error
	Get(ctx context.Context, tenantID, clientID string) (*Client, error)
	// Update returns ErrNotFound if the client does not exist.
	Update(ctx context.Context, c *Client) error
	// Delete returns ErrNotFound if the client does not exist.
	Delete(ctx context.Context, tenantID, clientID string) error
}

// ResourceServers stores APIs, keyed by (TenantID, ID). Identifier is
// unique within a tenant.
type ResourceServers interface {
	// Create returns ErrConflict if the ID or Identifier exists in the tenant.
	Create(ctx context.Context, rs *ResourceServer) error
	Get(ctx context.Context, tenantID, id string) (*ResourceServer, error)
	GetByIdentifier(ctx context.Context, tenantID, identifier string) (*ResourceServer, error)
	// Update returns ErrNotFound if absent and ErrConflict if the new
	// Identifier is used by another resource server in the tenant.
	Update(ctx context.Context, rs *ResourceServer) error
	Delete(ctx context.Context, tenantID, id string) error
}

// ClientGrants stores client_credentials authorizations, keyed by
// (TenantID, ID). (ClientID, Audience) is unique within a tenant.
type ClientGrants interface {
	// Create returns ErrConflict if the ID or (ClientID, Audience) exists.
	Create(ctx context.Context, g *ClientGrant) error
	Find(ctx context.Context, tenantID, clientID, audience string) (*ClientGrant, error)
	// Update replaces the grant with the same ID. ClientID and Audience
	// must not change; drivers return ErrConflict if they do.
	Update(ctx context.Context, g *ClientGrant) error
	Delete(ctx context.Context, tenantID, id string) error
}

// SigningKeys stores signing keys, keyed by (TenantID, KID).
type SigningKeys interface {
	// Create returns ErrConflict if the KID exists in the tenant.
	Create(ctx context.Context, k *SigningKey) error
	// List returns all of a tenant's keys, every status, ordered by
	// CreatedAt then KID.
	List(ctx context.Context, tenantID string) ([]*SigningKey, error)
	// Rotate atomically moves previous→revoked, current→previous and
	// next→current, then stores next, which must have Status KeyNext.
	// If the tenant has no next key it returns ErrNotFound and changes
	// nothing. A duplicate KID returns ErrConflict and changes nothing.
	Rotate(ctx context.Context, tenantID string, next *SigningKey) error
}
