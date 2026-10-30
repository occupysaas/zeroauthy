package store

import (
	"context"
	"errors"
	"time"
)

// ErrOrganizationsUnavailable is returned by stores that do not implement
// Organizations (a remote plugin without the capability, or a driver that has
// not been brought up yet).
var ErrOrganizationsUnavailable = errors.New("store: Organizations capability unavailable")

// OrganizationsSupporter is implemented by remote stores that negotiate
// Organizations support. CheckOrganizationsSupport reports why a plugin lacks
// it; OrganizationsSupported is the cheap, cached predicate for request paths.
type OrganizationsSupporter interface {
	CheckOrganizationsSupport(context.Context) error
	OrganizationsSupported() bool
}

// OrganizationsSupported reports whether st serves Organizations. Stores that
// do not negotiate (memory, SQL) always do; a plugin without the capability
// does not, and callers answer 501 or reject the organization parameter.
func OrganizationsSupported(st Store) bool {
	if s, ok := st.(OrganizationsSupporter); ok {
		return s.OrganizationsSupported()
	}
	return true
}

// Organization is a tenant-scoped group of members (Auth0 Organizations).
// Branding and Metadata are replaced whole by Update. A nil Metadata or
// Branding means unset.
type Organization struct {
	TenantID, ID, Name, DisplayName string
	Branding                        *OrgBranding
	Metadata                        map[string]string
	// ClientAssociation is a read-only list annotation requested through OrgPage.
	ClientAssociation       *OrganizationClient
	ClientAssociationLoaded bool
	// IsAppEntitlementActive gates interactive application association policy.
	IsAppEntitlementActive bool
	// ThirdPartyClientAccess is "block" or "allow".
	ThirdPartyClientAccess string
	CreatedAt, UpdatedAt   time.Time
}

// OrgBranding is an organization's login-page branding.
type OrgBranding struct {
	LogoURL *string
	Colors  *OrgColors
}

// OrgColors holds both colors; a stored Colors always has both set.
type OrgColors struct{ Primary, PageBackground string }

// OrganizationConnection enables a connection for an organization.
type OrganizationConnection struct {
	// Read-only page summary, populated by repository list reads.
	SummaryName, SummaryStrategy           string
	TenantID, OrganizationID, ConnectionID string
	// IsEnabledSet distinguishes legacy omitted bools from intentional false.
	// Stores normalize it to true. New callers disabling a link must set it.
	IsEnabled, IsEnabledSet                                                bool
	ConnectionName, OrganizationAccessLevel, OrganizationMemberAccessLevel string
	AssignMembershipOnLogin                                                bool
	ShowAsButton                                                           bool
	IsSignupEnabled                                                        bool
}

// OrgPage selects a page. Offset mode uses Page and PerPage; checkpoint mode
// (From set or Take non-zero) uses From and Take and ignores Page. Sort is
// "field:1" or "field:-1" for organizations. Invitations support created_at
// ascending/descending, default descending.
type OrgPage struct {
	IncludeClientAssociationFor string
	Page, PerPage               int
	IncludeTotals               bool
	From                        string
	Take                        int
	Sort                        string
}

// OrgResult is one page. Total is set in offset mode; Next is set in
// checkpoint mode only while more items remain.
type OrgResult[T any] struct {
	Items []T
	Total int
	Next  string
}

// OrgLimits are the per-store caps (D-0055). Stores take them from
// orgrules.Limits; OrgLimitSetter lets conformance tests shrink them.
type OrgLimits struct {
	OrganizationsPerTenant     int
	ConnectionsPerOrganization int
	RolesPerMember             int
}

// OrgLimitSetter is implemented by stores whose limits can be overridden,
// for conformance tests that cannot create 10,000 organizations.
type OrgLimitSetter interface{ SetOrgLimits(OrgLimits) }

// Organizations persists organizations, their enabled connections, members
// and member roles. Missing organizations, users, connections and roles are
// ErrNotFound; duplicate names or connections are ErrConflict; limits are
// ErrPrecondition; malformed input is ErrInvalid. Member-role operations for a
// non-member are ErrNotFound. Removing a member keeps the member's role
// assignments; deleting an organization, user, connection or role removes
// the dependent rows.
type Organizations interface {
	Create(ctx context.Context, o *Organization, conns []OrganizationConnection) error
	Get(ctx context.Context, tid, id string) (*Organization, error)
	GetByName(ctx context.Context, tid, name string) (*Organization, error)
	List(ctx context.Context, tid string, p OrgPage) (OrgResult[Organization], error)
	// Update replaces name, display name, branding, metadata and
	// third-party access whole.
	Update(ctx context.Context, o *Organization) error
	Delete(ctx context.Context, tid, id string) error

	Connections(ctx context.Context, tid, orgID string, p OrgPage) (OrgResult[OrganizationConnection], error)
	// In a WithTx view, GetConnection serializes its eligibility read with
	// policy writers until commit, so later member writes use the same policy.
	GetConnection(ctx context.Context, tid, orgID, connID string) (*OrganizationConnection, error)
	// PutConnection creates (create true; ErrConflict if present) or
	// replaces (create false; ErrNotFound if absent) an enabled connection.
	PutConnection(ctx context.Context, c OrganizationConnection, create bool) error
	// DeleteConnection is idempotent for a connection that exists but is
	// not enabled; an unknown organization or connection is ErrNotFound.
	DeleteConnection(ctx context.Context, tid, orgID, connID string) error
	// ConnectionsByConnection lists every organization that enables connID,
	// ordered by organization ID.
	ConnectionsByConnection(ctx context.Context, tid, connID string) ([]OrganizationConnection, error)

	// Members lists member user IDs ordered by user ID.
	Members(ctx context.Context, tid, orgID string, p OrgPage) (OrgResult[string], error)
	// AddMembers adds all or none; an unknown user is ErrNotFound and
	// present members are ignored.
	AddMembers(ctx context.Context, tid, orgID string, userIDs []string) error
	// RemoveMembers is idempotent for non-members.
	RemoveMembers(ctx context.Context, tid, orgID string, userIDs []string) error
	IsMember(ctx context.Context, tid, orgID, userID string) (bool, error)
	UserOrganizations(ctx context.Context, tid, userID string, p OrgPage) (OrgResult[Organization], error)

	// MemberRoles lists role IDs ordered by role ID.
	MemberRoles(ctx context.Context, tid, orgID, userID string, p OrgPage) (OrgResult[string], error)
	ChangeMemberRoles(ctx context.Context, tid, orgID, userID string, add bool, roleIDs []string) error
	// RoleMembers lists the current members holding roleID, ordered by user
	// ID, checkpoint style only.
	RoleMembers(ctx context.Context, tid, orgID, roleID string, p OrgPage) (OrgResult[string], error)
}

// UnimplementedOrganizations fails closed for stores awaiting an
// Organizations implementation.
type UnimplementedOrganizations struct{}

func (UnimplementedOrganizations) Create(context.Context, *Organization, []OrganizationConnection) error {
	return ErrOrganizationsUnavailable
}
func (UnimplementedOrganizations) Get(context.Context, string, string) (*Organization, error) {
	return nil, ErrOrganizationsUnavailable
}
func (UnimplementedOrganizations) GetByName(context.Context, string, string) (*Organization, error) {
	return nil, ErrOrganizationsUnavailable
}
func (UnimplementedOrganizations) List(context.Context, string, OrgPage) (OrgResult[Organization], error) {
	return OrgResult[Organization]{}, ErrOrganizationsUnavailable
}
func (UnimplementedOrganizations) Update(context.Context, *Organization) error {
	return ErrOrganizationsUnavailable
}
func (UnimplementedOrganizations) Delete(context.Context, string, string) error {
	return ErrOrganizationsUnavailable
}
func (UnimplementedOrganizations) Connections(context.Context, string, string, OrgPage) (OrgResult[OrganizationConnection], error) {
	return OrgResult[OrganizationConnection]{}, ErrOrganizationsUnavailable
}
func (UnimplementedOrganizations) GetConnection(context.Context, string, string, string) (*OrganizationConnection, error) {
	return nil, ErrOrganizationsUnavailable
}
func (UnimplementedOrganizations) PutConnection(context.Context, OrganizationConnection, bool) error {
	return ErrOrganizationsUnavailable
}
func (UnimplementedOrganizations) DeleteConnection(context.Context, string, string, string) error {
	return ErrOrganizationsUnavailable
}
func (UnimplementedOrganizations) ConnectionsByConnection(context.Context, string, string) ([]OrganizationConnection, error) {
	return nil, ErrOrganizationsUnavailable
}
func (UnimplementedOrganizations) Members(context.Context, string, string, OrgPage) (OrgResult[string], error) {
	return OrgResult[string]{}, ErrOrganizationsUnavailable
}
func (UnimplementedOrganizations) AddMembers(context.Context, string, string, []string) error {
	return ErrOrganizationsUnavailable
}
func (UnimplementedOrganizations) RemoveMembers(context.Context, string, string, []string) error {
	return ErrOrganizationsUnavailable
}
func (UnimplementedOrganizations) IsMember(context.Context, string, string, string) (bool, error) {
	return false, ErrOrganizationsUnavailable
}
func (UnimplementedOrganizations) UserOrganizations(context.Context, string, string, OrgPage) (OrgResult[Organization], error) {
	return OrgResult[Organization]{}, ErrOrganizationsUnavailable
}
func (UnimplementedOrganizations) MemberRoles(context.Context, string, string, string, OrgPage) (OrgResult[string], error) {
	return OrgResult[string]{}, ErrOrganizationsUnavailable
}
func (UnimplementedOrganizations) ChangeMemberRoles(context.Context, string, string, string, bool, []string) error {
	return ErrOrganizationsUnavailable
}
func (UnimplementedOrganizations) RoleMembers(context.Context, string, string, string, OrgPage) (OrgResult[string], error) {
	return OrgResult[string]{}, ErrOrganizationsUnavailable
}
