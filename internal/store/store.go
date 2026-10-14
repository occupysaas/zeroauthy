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
	"time"
)

var (
	// ErrNotFound is returned when the requested entity does not exist.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict is returned when a create or update would violate a
	// uniqueness rule.
	ErrConflict = errors.New("store: conflict")
	// ErrAlreadyUsed is returned when a single-use entity was already used.
	ErrAlreadyUsed = errors.New("store: already used")
)

// Store aggregates the repositories of one storage backend.
type Store interface {
	Tenants() Tenants
	Clients() Clients
	ResourceServers() ResourceServers
	ClientGrants() ClientGrants
	SigningKeys() SigningKeys
	Connections() Connections
	Users() Users
	Sessions() Sessions
	AuthTransactions() AuthTransactions
	AuthCodes() AuthCodes
	RefreshTokens() RefreshTokens
	PasswordResetTickets() PasswordResetTickets
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
	// List returns the tenant's clients ordered by ClientID.
	List(ctx context.Context, tenantID string) ([]*Client, error)
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

// Connections stores identity sources, keyed by (TenantID, ID). Name is
// unique within a tenant.
type Connections interface {
	// Create returns ErrConflict if the ID or Name exists in the tenant.
	Create(ctx context.Context, c *Connection) error
	Get(ctx context.Context, tenantID, id string) (*Connection, error)
	GetByName(ctx context.Context, tenantID, name string) (*Connection, error)
	// Update returns ErrNotFound if absent and ErrConflict if the new Name
	// is used by another connection in the tenant.
	Update(ctx context.Context, c *Connection) error
	// List returns the tenant's connections ordered by Name.
	List(ctx context.Context, tenantID string) ([]*Connection, error)
}

// Users stores people, keyed by (TenantID, UserID). Within one connection,
// non-empty Email and non-empty Username values are unique. Callers pass
// lowercase emails and usernames.
type Users interface {
	// Create returns ErrConflict if the UserID exists, or if another user
	// with an identity on the same connection has the same Email or
	// Username.
	Create(ctx context.Context, u *User) error
	Get(ctx context.Context, tenantID, userID string) (*User, error)
	// FindByLogin finds the user with an identity on connection whose
	// Email or Username equals login.
	FindByLogin(ctx context.Context, tenantID, connection, login string) (*User, error)
	// Update replaces the user. ErrNotFound if absent; ErrConflict under
	// the same uniqueness rules as Create.
	Update(ctx context.Context, u *User) error
	// RecordLogin atomically sets LastLogin and increments LoginsCount.
	RecordLogin(ctx context.Context, tenantID, userID string, at time.Time) error
	// SetPasswordHash replaces the password hash of the user's identity on
	// connection and sets UpdatedAt = at. It returns ErrNotFound if the user
	// or the identity is absent.
	SetPasswordHash(ctx context.Context, tenantID, userID, connection, hash string, at time.Time) error
}

// Sessions stores login sessions, keyed by (TenantID, ID). TokenHash is
// unique within a tenant. Changes after creation are narrow atomic
// methods, so concurrent requests cannot overwrite each other's writes.
type Sessions interface {
	// Create returns ErrConflict if the ID or TokenHash exists.
	Create(ctx context.Context, s *LoginSession) error
	GetByTokenHash(ctx context.Context, tenantID, tokenHash string) (*LoginSession, error)
	// Touch sets IdleExpiresAt. It returns ErrNotFound if the session is
	// absent.
	Touch(ctx context.Context, tenantID, id string, idleExpiresAt time.Time) error
	// AddClient appends clientID to ClientIDs unless it is already there.
	// It returns ErrNotFound if the session is absent.
	AddClient(ctx context.Context, tenantID, id, clientID string) error
	// Delete returns ErrNotFound if absent.
	Delete(ctx context.Context, tenantID, id string) error
	// DeleteByUser removes every session of the user in the tenant and
	// returns how many it removed.
	DeleteByUser(ctx context.Context, tenantID, userID string) (int, error)
	// DeleteExpired removes, in every tenant, the sessions whose ExpiresAt
	// or IdleExpiresAt is not after before, and returns how many it removed.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}

// AuthTransactions stores in-progress logins, keyed by (TenantID, ID).
type AuthTransactions interface {
	// Create returns ErrConflict if the ID exists.
	Create(ctx context.Context, t *AuthTransaction) error
	Get(ctx context.Context, tenantID, id string) (*AuthTransaction, error)
	// Delete returns ErrNotFound if absent.
	Delete(ctx context.Context, tenantID, id string) error
	// DeleteExpired removes, in every tenant, the transactions whose
	// ExpiresAt is not after before, and returns how many it removed.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}

// AuthCodes stores authorization codes, keyed by (TenantID, CodeHash).
type AuthCodes interface {
	// Create returns ErrConflict if the CodeHash exists.
	Create(ctx context.Context, c *AuthCode) error
	// Consume atomically marks the code used at `at` and returns it. A
	// code that was already used is a replay: Consume atomically sets its
	// ReplayedAt to `at` unless it is already set (the first replay time is
	// kept) and returns it together with ErrAlreadyUsed, so callers can react
	// to replay. Unknown codes return ErrNotFound.
	Consume(ctx context.Context, tenantID, codeHash string, at time.Time) (*AuthCode, error)
	// Get returns the code without changing it, or ErrNotFound.
	Get(ctx context.Context, tenantID, codeHash string) (*AuthCode, error)
	// DeleteExpired removes, in every tenant, the codes whose ExpiresAt is
	// not after before, used or not, and returns how many it removed.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}

// RefreshTokens stores refresh tokens, keyed by (TenantID, ID). TokenHash
// is unique within a tenant. Rotation and reuse detection happen inside
// Rotate so that drivers can make them atomic.
type RefreshTokens interface {
	// Create returns ErrConflict if the ID or TokenHash exists.
	Create(ctx context.Context, t *RefreshToken) error
	GetByTokenHash(ctx context.Context, tenantID, tokenHash string) (*RefreshToken, error)
	// Rotate atomically exchanges the token oldID for next, which must have
	// the same TenantID and FamilyID (otherwise ErrConflict).
	//   - Absent, or revoked without having been rotated: ErrNotFound,
	//     nothing changes.
	//   - Rotated and revoked: ErrAlreadyUsed, nothing changes.
	//   - next's ID or TokenHash exists: ErrConflict, nothing changes.
	//   - Not rotated yet: sets RotatedAt = at and stores next.
	//   - Already rotated and at is before RotatedAt+leeway (leeway > 0):
	//     stores next and keeps RotatedAt.
	//   - Already rotated otherwise: revokes every token of the family at
	//     `at`, stores nothing, and returns ErrAlreadyUsed.
	Rotate(ctx context.Context, tenantID, oldID string, next *RefreshToken, at time.Time, leeway time.Duration) error
	// Touch sets IdleExpiresAt of a token that is neither revoked nor
	// rotated; otherwise it returns ErrNotFound.
	Touch(ctx context.Context, tenantID, id string, idleExpiresAt time.Time) error
	// RevokeFamily sets RevokedAt = at on every unrevoked token of the
	// family. An unknown family is not an error.
	RevokeFamily(ctx context.Context, tenantID, familyID string, at time.Time) error
	// RevokeByUser sets RevokedAt = at on every unrevoked token of the user
	// in the tenant and returns how many it revoked. Already revoked tokens
	// keep their first RevokedAt.
	RevokeByUser(ctx context.Context, tenantID, userID string, at time.Time) (int, error)
	// DeleteExpired removes, in every tenant, the tokens whose non-zero
	// ExpiresAt or IdleExpiresAt is not after before, and returns how many
	// it removed.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}

// PasswordResetTickets stores password-reset tickets, keyed by
// (TenantID, ID). TokenHash is unique within a tenant.
type PasswordResetTickets interface {
	// Create returns ErrConflict if the ID or TokenHash exists.
	Create(ctx context.Context, t *PasswordResetTicket) error
	GetByTokenHash(ctx context.Context, tenantID, tokenHash string) (*PasswordResetTicket, error)
	// Consume atomically marks the ticket used at `at` and returns it. A
	// ticket that was already used is returned together with
	// ErrAlreadyUsed, and its first UsedAt is kept. Unknown tickets return
	// ErrNotFound.
	Consume(ctx context.Context, tenantID, tokenHash string, at time.Time) (*PasswordResetTicket, error)
	// DeleteExpired removes, in every tenant, the tickets whose ExpiresAt is
	// not after before, used or not, and returns how many it removed.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}
