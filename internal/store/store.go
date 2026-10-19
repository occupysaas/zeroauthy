// Exported through pkg/store; add new names there too.

// Package store defines zeroauthy's storage interfaces. Every driver
// (memory, SQL, external plugin) implements Store and must pass the
// conformance suite in pkg/storetest.
//
// Drivers return copies: mutating a value passed to or returned from a
// driver never changes stored state.
//
// A list method with no matches returns no error and a result of length 0,
// but drivers differ on whether that result is nil or an empty slice (the
// plugin path may normalize either way). Callers must test len and never
// compare a list against nil.
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
	UserGrants() UserGrants
	SigningKeys() SigningKeys
	Connections() Connections
	PasswordHistories() PasswordHistories
	Users() Users
	Sessions() Sessions
	AuthTransactions() AuthTransactions
	AuthCodes() AuthCodes
	PushedAuthRequests() PushedAuthRequests
	DeviceCodes() DeviceCodes
	RefreshTokens() RefreshTokens
	PasswordResetTickets() PasswordResetTickets
	Operators() Operators
	// WithTx runs fn against a transactional view of the store. If fn
	// returns an error, none of its writes persist. Drivers serialize
	// transactions; the memory driver's isolation from concurrent
	// non-transactional writers is best effort (tests and demos only).
	// A nested WithTx call inside fn runs inline and joins the outer transaction.
	WithTx(ctx context.Context, fn func(tx Store) error) error
	Ping(ctx context.Context) error
	Close() error
}

// Tenants stores tenants. Tenants are the only entities not scoped by a
// tenant ID.
type Tenants interface {
	// Create stores a new tenant. It returns ErrConflict if the ID, the
	// name, or any of the domains is already used by another tenant, or if
	// Domains lists a domain more than once.
	Create(ctx context.Context, t *Tenant) error
	Get(ctx context.Context, id string) (*Tenant, error)
	GetByName(ctx context.Context, name string) (*Tenant, error)
	// GetByDomain finds the tenant that lists domain in Domains. Callers
	// pass normalized hosts (see tenant.NormalizeHost).
	GetByDomain(ctx context.Context, domain string) (*Tenant, error)
	// Update replaces the tenant with the same ID. It returns ErrNotFound
	// if absent and ErrConflict if the new name or a domain collides with
	// another tenant, or if Domains lists a domain more than once.
	Update(ctx context.Context, t *Tenant) error
	// List returns all tenants ordered by Name.
	List(ctx context.Context) ([]*Tenant, error)
	// Delete removes the tenant and all of its data: domains, clients,
	// resource servers, grants, signing keys, connections, users, sessions,
	// transactions, codes, pushed requests, device codes, refresh tokens,
	// reset tickets and operators. It returns ErrNotFound if absent. The
	// store does not protect Reserved tenants; callers refuse to delete them.
	Delete(ctx context.Context, id string) error
}

// Operators stores console operators, keyed by (TenantID, UserID), where
// TenantID is the system tenant and UserID one of its users.
type Operators interface {
	Get(ctx context.Context, tenantID, userID string) (*Operator, error)
	// Upsert creates o or replaces the operator with the same key. An
	// existing operator keeps its CreatedAt.
	Upsert(ctx context.Context, o *Operator) error
	// List returns the tenant's operators ordered by UserID.
	List(ctx context.Context, tenantID string) ([]*Operator, error)
	// Delete returns ErrNotFound if absent.
	Delete(ctx context.Context, tenantID, userID string) error
}

// Clients stores applications, keyed by (TenantID, ClientID).
type Clients interface {
	// Create returns ErrConflict if the client ID exists in the tenant.
	Create(ctx context.Context, c *Client) error
	Get(ctx context.Context, tenantID, clientID string) (*Client, error)
	// Update returns ErrNotFound if the client does not exist.
	Update(ctx context.Context, c *Client) error
	// Delete removes the client together with its client grants, user
	// grants and refresh tokens. It returns ErrNotFound if the client does
	// not exist. Connections and login sessions that name the client are
	// left alone.
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
	// Delete removes the resource server together with the client grants,
	// user grants and refresh tokens for its identifier. It returns
	// ErrNotFound if absent.
	Delete(ctx context.Context, tenantID, id string) error
	// List returns the tenant's resource servers ordered by CreatedAt,
	// then ID.
	List(ctx context.Context, tenantID string) ([]*ResourceServer, error)
}

// ClientGrants stores API authorizations of clients, keyed by
// (TenantID, ID). (ClientID, Audience, SubjectType) is unique within a
// tenant.
type ClientGrants interface {
	// Create returns ErrConflict if the ID or (ClientID, Audience, SubjectType) exists.
	Create(ctx context.Context, g *ClientGrant) error
	Find(ctx context.Context, tenantID, clientID, audience, subjectType string) (*ClientGrant, error)
	// Update replaces the grant with the same ID. ClientID, Audience and
	// SubjectType must not change; drivers return ErrConflict if they do.
	Update(ctx context.Context, g *ClientGrant) error
	Delete(ctx context.Context, tenantID, id string) error
	// List returns one page of the tenant's grants that match f, ordered by
	// ID (byte order, so a cursor can name the last ID it returned), and
	// the number of grants that match f before paging. A page past the end
	// is empty.
	List(ctx context.Context, tenantID string, f ClientGrantFilter, p Page) ([]*ClientGrant, int, error)
}

// UserGrants stores consent, keyed by (TenantID, ID). (ClientID, UserID,
// Audience) is unique within a tenant.
type UserGrants interface {
	// Find returns ErrNotFound when the user has no grant for the client
	// and audience.
	Find(ctx context.Context, tenantID, clientID, userID, audience string) (*UserGrant, error)
	// Upsert stores g under its (ClientID, UserID, Audience). If a grant
	// exists, its ID and CreatedAt are kept and Scopes and UpdatedAt are
	// replaced; otherwise g is created as given. It returns the stored grant.
	// Concurrent upserts of one key leave exactly one grant.
	Upsert(ctx context.Context, g *UserGrant) (*UserGrant, error)
	// ListByUser returns the user's grants ordered by ClientID, then Audience.
	ListByUser(ctx context.Context, tenantID, userID string) ([]*UserGrant, error)
	// ListByAudience returns the grants for audience, every user and client,
	// ordered by ID.
	ListByAudience(ctx context.Context, tenantID, audience string) ([]*UserGrant, error)
	// Delete returns ErrNotFound if absent.
	Delete(ctx context.Context, tenantID, id string) error
	// DeleteByUser removes all of the user's grants and returns how many.
	DeleteByUser(ctx context.Context, tenantID, userID string) (int, error)
}

// SigningKeys stores signing keys, keyed by (TenantID, KID).
type SigningKeys interface {
	// Create returns ErrConflict if the KID exists in the tenant, or if
	// k.Status is KeyCurrent or KeyNext and the tenant already has a key
	// with that status.
	Create(ctx context.Context, k *SigningKey) error
	// List returns all of a tenant's keys, every status, ordered by
	// CreatedAt then KID.
	List(ctx context.Context, tenantID string) ([]*SigningKey, error)
	// Rotate atomically moves previous→revoked, current→previous and
	// next→current, then stores next. It returns an error and changes
	// nothing if next.Status is not KeyNext.
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
	// Delete removes the connection and everything that depends on it, in
	// one step: its users (the users with an identity on it) with their
	// sessions, refresh tokens, user grants, password reset tickets and
	// password history; and the tenant's DefaultDirectory when it names the
	// connection. The enabled-clients list goes with the connection. It
	// returns ErrNotFound if the connection is absent.
	Delete(ctx context.Context, tenantID, id string) error
	// List returns one page of the tenant's connections that match f,
	// ordered by Name compared case-insensitively, then ID, and the number
	// that match f before paging. A page past the end is empty.
	List(ctx context.Context, tenantID string, f ConnectionFilter, p Page) ([]*Connection, int, error)
}

// PasswordHistories stores the hashes of the passwords a user had, for a
// connection's password history rule. It is keyed by (TenantID, UserID);
// Connections.Delete and Tenants.Delete remove it.
type PasswordHistories interface {
	// Add stores hash as the user's newest entry, then drops all but the
	// newest keep entries. A keep of zero or less drops them all.
	Add(ctx context.Context, tenantID, userID string, hash []byte, keep int) error
	// List returns the user's stored hashes, newest first.
	List(ctx context.Context, tenantID, userID string) ([][]byte, error)
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
	// FindByEmail returns the users whose Email equals email, on any
	// connection, ordered by UserID. Callers pass the email lowercase.
	FindByEmail(ctx context.Context, tenantID, email string) ([]*User, error)
	// Update replaces the user. ErrNotFound if absent; ErrConflict under
	// the same uniqueness rules as Create. Update never changes LastLogin,
	// LastIP or LoginsCount (only RecordLogin does) and ignores the Version
	// of u: it adds one to the stored Version when Blocked goes from false
	// to true or Email changes, and otherwise leaves it.
	Update(ctx context.Context, u *User) error
	// RecordLogin atomically sets LastLogin and LastIP and increments
	// LoginsCount.
	RecordLogin(ctx context.Context, tenantID, userID string, at time.Time, ip string) error
	// SetPasswordHash replaces the password hash of the user's identity on
	// connection, sets UpdatedAt = at and adds one to Version. It returns
	// ErrNotFound if the user or the identity is absent.
	SetPasswordHash(ctx context.Context, tenantID, userID, connection, hash string, at time.Time) error
	// SetPasswordHashIfEmpty is SetPasswordHash, but atomically does
	// nothing and returns ErrConflict when the identity already has a
	// non-empty hash. ErrNotFound if the user or the identity is absent.
	SetPasswordHashIfEmpty(ctx context.Context, tenantID, userID, connection, hash string, at time.Time) error
	// BumpVersion atomically adds one to Version and returns the new
	// value, or ErrNotFound.
	BumpVersion(ctx context.Context, tenantID, userID string) (int64, error)
	// Delete removes the user and, in the same step, everything that
	// names it: sessions, refresh tokens, user grants, password reset
	// tickets, password history, auth codes and device codes. It returns
	// ErrNotFound if the user is absent.
	Delete(ctx context.Context, tenantID, userID string) error
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
	// or IdleExpiresAt is not after before (a zero time counts as expired),
	// and returns how many it removed.
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

// PushedAuthRequests stores pushed authorization requests, keyed by
// (TenantID, IDHash).
type PushedAuthRequests interface {
	// Create returns ErrConflict if the IDHash exists in the tenant.
	Create(ctx context.Context, p *PushedAuthRequest) error
	// Consume atomically marks the request used at `at` and returns it. A
	// request that was already used is returned together with
	// ErrAlreadyUsed, and its first UsedAt is kept. Unknown requests return
	// ErrNotFound. Expiry is the caller's check.
	Consume(ctx context.Context, tenantID, idHash string, at time.Time) (*PushedAuthRequest, error)
	// Get returns the request without changing it, or ErrNotFound.
	Get(ctx context.Context, tenantID, idHash string) (*PushedAuthRequest, error)
	// DeleteExpired removes, in every tenant, the requests whose ExpiresAt
	// is not after before, used or not, and returns how many it removed.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}

// DeviceCodes stores device authorization requests, keyed by
// (TenantID, DeviceCodeHash). UserCodeHash is unique within a tenant.
type DeviceCodes interface {
	// Create returns ErrConflict if DeviceCodeHash or UserCodeHash exists in the tenant.
	Create(ctx context.Context, d *DeviceCode) error
	Get(ctx context.Context, tenantID, deviceCodeHash string) (*DeviceCode, error)
	GetByUserCode(ctx context.Context, tenantID, userCodeHash string) (*DeviceCode, error)
	// Decide atomically moves a pending code to dec.Status and records the
	// decision. Any other status returns the record and ErrAlreadyUsed.
	// Unknown codes return ErrNotFound. Expiry is the caller's check.
	Decide(ctx context.Context, tenantID, deviceCodeHash string, dec DeviceDecision) (*DeviceCode, error)
	// Poll atomically records a poll at `at`. The rules, in order:
	//  1. consumed: PollInvalid, nothing changes.
	//  2. at is not before ExpiresAt: PollExpired and ExpiredReportedAt is set
	//     if it was nil, else PollInvalid.
	//  3. less than MinPollGap since LastPolledAt: PollSlowDown, LastPolledAt
	//     is not updated.
	//  4. otherwise LastPolledAt = at; pending is PollPending, approved and
	//     denied become consumed and give PollApproved and PollDenied.
	// Unknown codes return ErrNotFound.
	Poll(ctx context.Context, tenantID, deviceCodeHash string, at time.Time) (DevicePoll, error)
	// DeleteExpired removes, in every tenant, the codes whose ExpiresAt is
	// not after before, and returns how many it removed.
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
	// DeleteByUser removes every unused ticket of the user in the tenant and
	// returns how many it removed. Used tickets are kept (until
	// DeleteExpired) so that a replayed link can still be reported as used.
	DeleteByUser(ctx context.Context, tenantID, userID string) (int, error)
	// DeleteExpired removes, in every tenant, the tickets whose ExpiresAt is
	// not after before, used or not, and returns how many it removed.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}
