package store

import (
	"context"
	"errors"
	"slices"
	"time"
)

// Directory state of Plan 37c (scim.v1): SCIM configurations and tokens of
// enterprise connections, and directory groups with their members and role
// assignments.

// SCIMMapping maps one Auth0 profile field to one SCIM attribute path.
type SCIMMapping struct {
	Auth0 string `json:"auth0"`
	SCIM  string `json:"scim"`
}

// SCIMConfig is a connection's SCIM configuration; one per connection.
type SCIMConfig struct {
	TenantID, ConnectionID, UserIDAttribute string
	Mapping                                 []SCIMMapping
	CreatedAt, UpdatedAt                    time.Time
}

// Clone returns a deep copy.
func (c *SCIMConfig) Clone() *SCIMConfig {
	if c == nil {
		return nil
	}
	out := *c
	out.Mapping = slices.Clone(c.Mapping)
	return &out
}

// SCIMToken is a SCIM bearer token of one connection. Only the SHA-256 hash
// of the token is stored; ExpiresAt nil means no expiry.
type SCIMToken struct {
	TenantID, ConnectionID, ID, Hash string
	Scopes                           []string
	CreatedAt                        time.Time
	ExpiresAt, LastUsedAt            *time.Time
}

// Clone returns a deep copy.
func (t *SCIMToken) Clone() *SCIMToken {
	if t == nil {
		return nil
	}
	out := *t
	out.Scopes = slices.Clone(t.Scopes)
	out.ExpiresAt, out.LastUsedAt = cloneTime(t.ExpiresAt), cloneTime(t.LastUsedAt)
	return &out
}

// Active reports whether the token has not expired at now.
func (t *SCIMToken) Active(now time.Time) bool { return t.ExpiresAt == nil || now.Before(*t.ExpiresAt) }

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}

// MaxActiveSCIMTokens is Auth0's limit of unexpired tokens per connection.
const MaxActiveSCIMTokens = 2

// Group is a directory group of one connection. Name is unique within the
// connection.
type Group struct {
	TenantID, ID, ConnectionID, Name, ExternalID string
	CreatedAt, UpdatedAt                         time.Time
}

// GroupMember is a user's membership of a group.
type GroupMember struct {
	GroupID, UserID string
	CreatedAt       time.Time
}

// GroupFilter selects groups. Empty fields do not filter. NamePrefix
// matches names case-insensitively by prefix.
type GroupFilter struct {
	ConnectionID, Name, ExternalID, NamePrefix string
	IDs                                        []string
}

// GroupRole is a role assigned to a group, tenant-wide (OrganizationID
// empty) or in one organization.
type GroupRole struct {
	GroupID, RoleID, OrganizationID string
}

// ErrDirectoryUnavailable reports a storage plugin without scim.v1.
var ErrDirectoryUnavailable = errors.New("store: scim.v1 unavailable")

// ErrSCIMTokenLimit reports a token request beyond MaxActiveSCIMTokens.
var ErrSCIMTokenLimit = errors.New("store: SCIM token limit reached")

// DirectorySupporter is implemented by stores that negotiate scim.v1.
type DirectorySupporter interface{ DirectorySupported() bool }

// Directory stores Plan 37c's SCIM and group state, keyed by tenant.
// Pages: offset/limit on lists ordered by CreatedAt then ID; a zero limit
// returns everything.
type Directory interface {
	// CreateSCIMConfig returns ErrConflict if the connection has one.
	CreateSCIMConfig(ctx context.Context, c *SCIMConfig) error
	GetSCIMConfig(ctx context.Context, tenantID, connectionID string) (*SCIMConfig, error)
	// UpdateSCIMConfig returns ErrNotFound if there is none.
	UpdateSCIMConfig(ctx context.Context, c *SCIMConfig) error
	// DeleteSCIMConfig removes the configuration and the connection's
	// tokens; ErrNotFound if there is none.
	DeleteSCIMConfig(ctx context.Context, tenantID, connectionID string) error
	ListSCIMConfigs(ctx context.Context, tenantID string) ([]*SCIMConfig, error)

	// CreateSCIMToken returns ErrSCIMTokenLimit when the connection already
	// has MaxActiveSCIMTokens tokens active at t.CreatedAt.
	CreateSCIMToken(ctx context.Context, t *SCIMToken) error
	ListSCIMTokens(ctx context.Context, tenantID, connectionID string) ([]*SCIMToken, error)
	// DeleteSCIMToken returns ErrNotFound for an unknown token.
	DeleteSCIMToken(ctx context.Context, tenantID, connectionID, id string) error
	// UseSCIMToken finds the tenant's token with this hash, records now as
	// its last use and returns it; ErrNotFound if none (expiry is the
	// caller's check).
	UseSCIMToken(ctx context.Context, tenantID, hash string, now time.Time) (*SCIMToken, error)

	// CreateGroup returns ErrConflict if the ID or the name within the
	// connection exists.
	CreateGroup(ctx context.Context, g *Group) error
	GetGroup(ctx context.Context, tenantID, id string) (*Group, error)
	// UpdateGroup changes name and external ID; ErrNotFound, ErrConflict.
	UpdateGroup(ctx context.Context, g *Group) error
	// DeleteGroup removes the group, its members and role assignments.
	DeleteGroup(ctx context.Context, tenantID, id string) error
	ListGroups(ctx context.Context, tenantID string, f GroupFilter, p Page) ([]*Group, int, error)

	// UpdateGroupMembers removes then adds members (replace drops every
	// other member first). Unknown removals are ignored; re-adding keeps
	// the original membership time. ErrNotFound for an unknown group.
	UpdateGroupMembers(ctx context.Context, tenantID, groupID string, add, remove []string, replace bool, now time.Time) error
	ListGroupMembers(ctx context.Context, tenantID, groupID string, p Page) ([]GroupMember, int, error)
	// ListUserGroups returns the user's memberships, oldest first.
	ListUserGroups(ctx context.Context, tenantID, userID string) ([]GroupMember, error)

	// AddGroupRoles and RemoveGroupRoles change role assignments of a
	// group, tenant-wide or in organizationID. Existing assignments are
	// kept; unknown removals ignored.
	AddGroupRoles(ctx context.Context, tenantID, groupID, organizationID string, roleIDs []string) error
	RemoveGroupRoles(ctx context.Context, tenantID, groupID, organizationID string, roleIDs []string) error
	// ListGroupRoles filters by group and/or role (empty = any) within
	// organizationID ("" = tenant-wide assignments only).
	ListGroupRoles(ctx context.Context, tenantID, groupID, roleID, organizationID string) ([]GroupRole, error)
}

// UnimplementedDirectory fails closed for stores without scim.v1.
type UnimplementedDirectory struct{}

func (UnimplementedDirectory) CreateSCIMConfig(context.Context, *SCIMConfig) error {
	return ErrDirectoryUnavailable
}
func (UnimplementedDirectory) GetSCIMConfig(context.Context, string, string) (*SCIMConfig, error) {
	return nil, ErrDirectoryUnavailable
}
func (UnimplementedDirectory) UpdateSCIMConfig(context.Context, *SCIMConfig) error {
	return ErrDirectoryUnavailable
}
func (UnimplementedDirectory) DeleteSCIMConfig(context.Context, string, string) error {
	return ErrDirectoryUnavailable
}
func (UnimplementedDirectory) ListSCIMConfigs(context.Context, string) ([]*SCIMConfig, error) {
	return nil, ErrDirectoryUnavailable
}
func (UnimplementedDirectory) CreateSCIMToken(context.Context, *SCIMToken) error {
	return ErrDirectoryUnavailable
}
func (UnimplementedDirectory) ListSCIMTokens(context.Context, string, string) ([]*SCIMToken, error) {
	return nil, ErrDirectoryUnavailable
}
func (UnimplementedDirectory) DeleteSCIMToken(context.Context, string, string, string) error {
	return ErrDirectoryUnavailable
}
func (UnimplementedDirectory) UseSCIMToken(context.Context, string, string, time.Time) (*SCIMToken, error) {
	return nil, ErrDirectoryUnavailable
}
func (UnimplementedDirectory) CreateGroup(context.Context, *Group) error {
	return ErrDirectoryUnavailable
}
func (UnimplementedDirectory) GetGroup(context.Context, string, string) (*Group, error) {
	return nil, ErrDirectoryUnavailable
}
func (UnimplementedDirectory) UpdateGroup(context.Context, *Group) error {
	return ErrDirectoryUnavailable
}
func (UnimplementedDirectory) DeleteGroup(context.Context, string, string) error {
	return ErrDirectoryUnavailable
}
func (UnimplementedDirectory) ListGroups(context.Context, string, GroupFilter, Page) ([]*Group, int, error) {
	return nil, 0, ErrDirectoryUnavailable
}
func (UnimplementedDirectory) UpdateGroupMembers(context.Context, string, string, []string, []string, bool, time.Time) error {
	return ErrDirectoryUnavailable
}
func (UnimplementedDirectory) ListGroupMembers(context.Context, string, string, Page) ([]GroupMember, int, error) {
	return nil, 0, ErrDirectoryUnavailable
}
func (UnimplementedDirectory) ListUserGroups(context.Context, string, string) ([]GroupMember, error) {
	return nil, ErrDirectoryUnavailable
}
func (UnimplementedDirectory) AddGroupRoles(context.Context, string, string, string, []string) error {
	return ErrDirectoryUnavailable
}
func (UnimplementedDirectory) RemoveGroupRoles(context.Context, string, string, string, []string) error {
	return ErrDirectoryUnavailable
}
func (UnimplementedDirectory) ListGroupRoles(context.Context, string, string, string, string) ([]GroupRole, error) {
	return nil, ErrDirectoryUnavailable
}

// DirectoryAvailable reports whether s stores Plan 37c's state.
func DirectoryAvailable(s Store) bool {
	if sup, ok := s.(DirectorySupporter); ok {
		return sup.DirectorySupported()
	}
	switch s.Directory().(type) {
	case UnimplementedDirectory, *UnimplementedDirectory:
		return false
	}
	return true
}
