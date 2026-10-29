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
	// ErrPrecondition is returned when a resource is in use or a storage limit is reached.
	ErrPrecondition = errors.New("store: precondition failed")
	// ErrInvalid is returned for an argument the store refuses to take, such
	// as a negative file chunk number or a job status that is not final.
	ErrInvalid = errors.New("store: invalid argument")
)

// Store aggregates the repositories of one storage backend.
type Store interface {
	RBAC() RBAC
	Organizations() Organizations
	Actions() Actions
	CustomDomains() CustomDomains
	TLSAssets() TLSAssets
	Protection() Protection
	Tenants() Tenants
	Clients() Clients
	ResourceServers() ResourceServers
	ClientGrants() ClientGrants
	UserGrants() UserGrants
	SigningKeys() SigningKeys
	CustomSigningKeys() CustomSigningKeys
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
	EmailVerificationTickets() EmailVerificationTickets
	Operators() Operators
	Jobs() Jobs
	EmailProviders() EmailProviders
	EmailTemplates() EmailTemplates
	EmailNotifications() EmailNotifications
	HostedLogins() HostedLogins
	Federation() Federation
	// WithTx runs fn against a transactional view of the store. If fn
	// returns an error, none of its writes persist. Drivers serialize
	// transactions; the memory driver also excludes outside reads and writes
	// until completion. fn must use its supplied view for reads and writes;
	// synchronous operations through the outer memory store would deadlock.
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
	// reset and verification tickets and operators. It returns ErrNotFound if absent. The
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
	// List returns one page of the tenant's clients that match f, ordered
	// by CreatedAt, then ClientID (byte order), and the number that match f
	// before paging. A zero Page returns every match. A page past the end is
	// empty.
	List(ctx context.Context, tenantID string, f ClientFilter, p Page) ([]*Client, int, error)
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
	// RenameSystem atomically changes only Name on the matching system resource.
	// It never rewrites other fields from a potentially stale snapshot.
	RenameSystem(ctx context.Context, tenantID, identifier, name string) error
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
	// List returns one page of the tenant's grants that match f, ordered by
	// ID (byte order), and the number that match f before paging. A zero
	// Page returns every match. A page past the end is empty.
	List(ctx context.Context, tenantID string, f UserGrantFilter, p Page) ([]*UserGrant, int, error)
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
	Get(ctx context.Context, tenantID, kid string) (*SigningKey, error)
	// Rotate atomically moves current→previous and next→current, retaining
	// every unrevoked previous key, then stores the supplied next key.
	// If the tenant has no next key it returns ErrNotFound and changes
	// nothing. A duplicate KID returns ErrConflict and changes nothing.
	Rotate(ctx context.Context, tenantID string, next *SigningKey) error
	RotateWithResult(ctx context.Context, tenantID string, next *SigningKey, at time.Time) (*SigningKeyRotation, error)
	Revoke(ctx context.Context, tenantID, kid string, at time.Time) (*SigningKey, error)
	SetCertificateIfAbsent(ctx context.Context, tenantID, kid string, der []byte) (*SigningKey, error)
}

// CustomSigningKeys stores a validated public JWKS independently of managed
// signing keys. The repository also prevents ID collisions between the sets.
type CustomSigningKeys interface {
	Get(ctx context.Context, tenantID string) (*CustomSigningKeySet, error)
	Replace(ctx context.Context, set *CustomSigningKeySet) error
	Delete(ctx context.Context, tenantID string) error
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
	// one step: its users (the users whose own identity is on it) with their
	// sessions, refresh tokens, user grants, password reset and email verification
	// tickets and password history; and the tenant's DefaultDirectory when it names the
	// connection. A user with only linked identities on it (D-0043) loses
	// those identities, gains one Version and keeps everything else. The
	// enabled-clients list goes with the connection. It returns
	// ErrNotFound if the connection is absent.
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
	// has one of its logins: the same email or username on the same
	// connection, where each identity logs in with User.IdentityLogin (a
	// linked identity with its ProfileData, see User.LoginKeys).
	Create(ctx context.Context, u *User) error
	Get(ctx context.Context, tenantID, userID string) (*User, error)
	// FindByLogin finds the user with an identity on connection that logs
	// in with login (User.LoginKeys): the user's own Email or Username,
	// or a linked identity's ProfileData email or username, so a linked
	// identity finds its primary user.
	FindByLogin(ctx context.Context, tenantID, connection, login string) (*User, error)
	// FindByIdentity finds the owner of a federated identity through the
	// identity index: connectionID is the immutable connection ID, subject the
	// exact provider subject. ErrNotFound if unowned.
	FindByIdentity(ctx context.Context, tenantID, connectionID, subject string) (*User, error)
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
	// LoginsCount. Callers pass an IP address or "" (httpx.CanonicalIP):
	// never raw header text.
	RecordLogin(ctx context.Context, tenantID, userID string, at time.Time, ip string) error
	// SetPasswordHash replaces the password hash of the user's own (not
	// linked) identity on connection, sets UpdatedAt = at and adds one to
	// Version. It returns ErrNotFound if the user or that identity is
	// absent, also when the user has only a linked identity there.
	SetPasswordHash(ctx context.Context, tenantID, userID, connection, hash string, at time.Time) error
	// SetPasswordHashIfEmpty is SetPasswordHash, but atomically does
	// nothing and returns ErrConflict when the identity already has a
	// non-empty hash. ErrNotFound if the user or the identity is absent.
	SetPasswordHashIfEmpty(ctx context.Context, tenantID, userID, connection, hash string, at time.Time) error
	// BumpVersion atomically adds one to Version and returns the new
	// value, or ErrNotFound.
	BumpVersion(ctx context.Context, tenantID, userID string) (int64, error)
	// GetForUpdate is Get that, inside WithTx, also locks the user until
	// the transaction ends: another transaction's GetForUpdate or write of
	// the user waits for it. Outside a transaction it is Get. Grants use it
	// to mint, and credential changes and revocations lock or write the
	// user first, so the two serialize.
	GetForUpdate(ctx context.Context, tenantID, userID string) (*User, error)
	// UpgradeImportedHash atomically replaces an imported hash: the identity
	// on connection (the user's own or a linked one) whose ImportedHash
	// equals imported gets PasswordHash = hash and an empty ImportedHash,
	// and the user gets UpdatedAt = at and Version + 1. The imported value
	// is the compare-and-swap key: when no identity on connection holds it
	// (including an empty imported), ErrConflict is returned and nothing
	// changes. ErrNotFound if the user does not exist.
	UpgradeImportedHash(ctx context.Context, tenantID, userID, connection, imported, hash string, at time.Time) error
	// Delete removes the user and, in the same step, everything that
	// names it: sessions, refresh tokens, user grants, password reset
	// tickets, email verification tickets, password history, auth codes,
	// device codes and the user's operator row. It returns
	// ErrNotFound if the user is absent.
	Delete(ctx context.Context, tenantID, userID string) error
	// List returns the tenant's users that match q, in the order s, and
	// the number that match before paging. A nil q matches every user. An
	// invalid tree or sort (see UserQuery.Validate and UserSort.Validate)
	// is an error. The semantics are UserQuery's.
	List(ctx context.Context, tenantID string, q *UserQuery, s UserSort, p Page) ([]*User, int, error)
}

// Sessions stores login sessions, keyed by (TenantID, ID). TokenHash is
// unique within a tenant. Changes after creation are narrow atomic
// methods, so concurrent requests cannot overwrite each other's writes.
type Sessions interface {
	// Create returns ErrConflict if the ID or TokenHash exists.
	Create(ctx context.Context, s *LoginSession) error
	GetByTokenHash(ctx context.Context, tenantID, tokenHash string) (*LoginSession, error)
	// Get returns ErrNotFound if the session is absent.
	Get(ctx context.Context, tenantID, id string) (*LoginSession, error)
	// ListByUser returns the user's sessions, newest first (CreatedAt
	// descending, then ID descending, byte order).
	ListByUser(ctx context.Context, tenantID, userID string) ([]*LoginSession, error)
	// Touch records an interaction at `at`: it sets IdleExpiresAt, sets
	// UpdatedAt and LastInteractedAt to at, and sets LastIP and
	// LastUserAgent. It returns ErrNotFound if the session is absent.
	Touch(ctx context.Context, tenantID, id string, at, idleExpiresAt time.Time, ip, userAgent string) error
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
	CompareAndSwapHosted(ctx context.Context, tenantID, id string, expectedRevision int64, next HostedLoginState, now time.Time) error
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
	// Get returns the token whatever its state, or ErrNotFound.
	Get(ctx context.Context, tenantID, id string) (*RefreshToken, error)
	// ListByUser returns the user's live tokens (neither revoked nor
	// rotated), newest first (CreatedAt descending, then ID descending, byte
	// order).
	ListByUser(ctx context.Context, tenantID, userID string) ([]*RefreshToken, error)
	// Revoke sets RevokedAt = at on the token. A token that is already
	// revoked keeps its first RevokedAt; a rotated token is revoked like any
	// other. It returns ErrNotFound if the token is absent.
	Revoke(ctx context.Context, tenantID, id string, at time.Time) error
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
	MarkChallengePassed(ctx context.Context, tenantID, tokenHash string, at time.Time, resultURL string) error
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

// EmailVerificationTickets stores email verification tickets, keyed by
// (TenantID, ID). TokenHash is unique within a tenant. The contracts are
// those of PasswordResetTickets.
type EmailVerificationTickets interface {
	// Create returns ErrConflict if the ID or TokenHash exists.
	Create(ctx context.Context, t *EmailVerificationTicket) error
	GetByTokenHash(ctx context.Context, tenantID, tokenHash string) (*EmailVerificationTicket, error)
	// Consume atomically marks the ticket used at `at` and returns it. A
	// ticket that was already used is returned together with
	// ErrAlreadyUsed, and its first UsedAt is kept. Unknown tickets return
	// ErrNotFound.
	Consume(ctx context.Context, tenantID, tokenHash string, at time.Time) (*EmailVerificationTicket, error)
	// DeleteByUser removes every unused ticket of the user in the tenant and
	// returns how many it removed. Used tickets are kept (until
	// DeleteExpired).
	DeleteByUser(ctx context.Context, tenantID, userID string) (int, error)
	// DeleteExpired removes, in every tenant, the tickets whose ExpiresAt is
	// not after before, used or not, and returns how many it removed.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}

// Jobs stores Management API jobs, keyed by (TenantID, ID), their errors
// and their export files. A worker claims a job with a lease; every write
// the worker makes names its owner and is refused (ErrConflict) once
// another worker holds the lease.
type Jobs interface {
	// Create returns ErrConflict if the ID exists in the tenant.
	Create(ctx context.Context, j *Job) error
	// Get returns ErrNotFound for an absent job. The store keeps no clock:
	// a job past its ExpiresAt is returned until DeleteExpired removes it,
	// and callers compare ExpiresAt with their own clock.
	Get(ctx context.Context, tenantID, id string) (*Job, error)
	// List returns one page of the tenant's jobs, newest first
	// (CreatedAt, then ID, both descending), and the number of them before
	// paging. Input is not loaded.
	List(ctx context.Context, tenantID string, p Page) ([]*Job, int, error)
	// CountActive counts the tenant's jobs of type t that are pending or
	// processing.
	CountActive(ctx context.Context, tenantID string, t JobType) (int, error)
	// Claim atomically picks, in any tenant, the oldest job (CreatedAt, then
	// TenantID, then ID) that is pending with ExpiresAt not before now, or
	// processing with LeaseUntil before now
	// and fewer than JobMaxAttempts attempts, and makes it processing:
	// LeaseOwner = owner, LeaseUntil = now + lease, Attempts + 1,
	// FirstClaimedAt = now if it was zero, UpdatedAt = now. Two concurrent
	// claims never return the same job. ErrNotFound when there is none.
	Claim(ctx context.Context, owner string, now time.Time, lease time.Duration) (*Job, error)
	// Renew moves LeaseUntil to until. ErrConflict when owner does not hold
	// the job's lease (also for a job that is absent or no longer
	// processing).
	Renew(ctx context.Context, tenantID, id, owner string, until time.Time) error
	// Checkpoint sets Progress and Summary and stores errs (Index is
	// unique within a job; a repeated Index is ErrConflict). It is
	// lease-checked like Renew. Callers run it in the same WithTx as the
	// batch's user writes, so both persist or neither.
	Checkpoint(ctx context.Context, tenantID, id, owner string, progress int, s JobSummary, errs []JobError) error
	// Finish sets the final status (JobCompleted or JobFailed; any other is
	// ErrInvalid) and StatusDetails,
	// UpdatedAt = at, clears the lease and Input. Lease-checked like Renew.
	Finish(ctx context.Context, tenantID, id, owner string, st JobStatus, details string, at time.Time) error
	// Errors returns the job's errors in Index order.
	Errors(ctx context.Context, tenantID, id string) ([]JobError, error)
	// AppendFile stores chunk (at most 1 MiB) as chunk number seq of the
	// export file and adds its length to FileSize. A negative seq or a chunk
	// over JobMaxChunk is ErrInvalid. Lease-checked like Renew. A repeated
	// seq is ErrConflict, except seq 0, which starts the file anew: it
	// discards the chunks already stored and sets FileSize to its own
	// length (a worker that restarts an export writes from 0 again).
	AppendFile(ctx context.Context, tenantID, id, owner string, seq int, chunk []byte) error
	// ReadFile calls fn with the export file's chunks in seq order. It
	// returns ErrNotFound for an absent job; fn's error stops the read and
	// is returned.
	ReadFile(ctx context.Context, tenantID, id string, fn func(chunk []byte) error) error
	// DeleteExpired removes, in every tenant, the jobs whose ExpiresAt is
	// before before, with their errors and chunks, and returns how many it
	// removed. It first fails (status failed, Input and lease cleared) the
	// processing jobs that started more than JobMaxRuntime before before
	// (JobDetailTimedOut) and those whose lease ended before before after
	// JobMaxAttempts attempts (JobDetailWorkerLost); those are not counted.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}
