package store

import (
	"context"
	"errors"
	"time"
)

var ErrOrganizationsIIUnavailable = errors.New("store: OrganizationsII capability unavailable")

// OrganizationInvitation persists only hashed and wrapped bearer material.
// WrappedTicket carries the sealed ticket/URL response data; ticket_id and
// invitation_url must be recovered from it, never stored as plaintext fields.
type OrganizationInvitation struct {
	TenantID, OrganizationID, ID, ClientID  string
	InviterName, InviteeEmail, ConnectionID string
	Roles                                   []string
	UserMetadata, AppMetadata               map[string]any
	TicketHash                              string
	WrappedTicket                           []byte
	SendInvitationEmail                     bool
	CreatedAt, UpdatedAt, ExpiresAt         time.Time
}

// InvitationReceipt is the durable binding of one acceptance to one login transaction.
type InvitationReceipt struct {
	TenantID, OrganizationID, InvitationID, TransactionID, UserID string
	AcceptedAt                                                    time.Time
}
type OrganizationClient struct {
	TenantID, OrganizationID, ClientID string
	UseForMemberAccess                 bool
}
type OrganizationDiscoveryDomain struct {
	TenantID, OrganizationID, ID, Domain, Status string
	VerificationHost, VerificationTXT            string
	UseForOrganizationDiscovery                  bool
}

// OrganizationsII is storage-only. ConsumeInvitation requires a WithTx view;
// callers validate policy and write membership, roles and metadata in that transaction.
// All references are tenant-scoped. Mutating batches validate fully before writing.
type OrganizationsII interface {
	// CreateInvitation validates all owner references before writing. IDs and
	// ticket hashes are unique within a tenant. Active reads exclude expiry and
	// consumption; DeleteInvitation is idempotent inside an existing organization.
	CreateInvitation(ctx context.Context, in *OrganizationInvitation) error
	GetInvitation(ctx context.Context, tid, orgID, id string) (*OrganizationInvitation, error)
	FindInvitation(ctx context.Context, tid, ticketHash string) (*OrganizationInvitation, error)
	ListInvitations(ctx context.Context, tid, orgID string, p OrgPage) (OrgResult[OrganizationInvitation], error)
	DeleteInvitation(ctx context.Context, tid, orgID, id string) error
	// ConsumeInvitation is allowed only in WithTx, after caller policy checks.
	// now >= expiry and reuse by another transaction return ErrPrecondition.
	// A receipt replay must match tenant, organization, invitation and user exactly.
	ConsumeInvitation(ctx context.Context, tid, orgID, id, transactionID, userID string, now time.Time) (InvitationReceipt, error)
	GetInvitationReceipt(ctx context.Context, tid, transactionID string) (*InvitationReceipt, error)
	// PutClients replaces each named association (upsert), validating the full
	// batch first. HTTP create-vs-patch checks belong in the caller's WithTx.
	PutClients(ctx context.Context, tid, orgID string, clients []OrganizationClient) error
	GetClient(ctx context.Context, tid, orgID, clientID string) (*OrganizationClient, error)
	ListClients(ctx context.Context, tid, orgID string, p OrgPage) (OrgResult[OrganizationClient], error)
	DeleteClients(ctx context.Context, tid, orgID string, clientIDs []string) error
	// Grant associations reference existing client-subject grants, not scope copies.
	// PutClientGrant is idempotent; HTTP create duplicate checks use HasClientGrant
	// in the same WithTx.
	PutClientGrant(ctx context.Context, tid, orgID, grantID string) error
	DeleteClientGrant(ctx context.Context, tid, orgID, grantID string) error
	ListClientGrants(ctx context.Context, tid, orgID string, p OrgPage) (OrgResult[ClientGrant], error)
	GrantOrganizations(ctx context.Context, tid, grantID string, p OrgPage) (OrgResult[Organization], error)
	HasClientGrant(ctx context.Context, tid, orgID, grantID string) (bool, error)
	PutDiscoveryDomain(ctx context.Context, in *OrganizationDiscoveryDomain, create bool) error
	GetDiscoveryDomain(ctx context.Context, tid, orgID, id string) (*OrganizationDiscoveryDomain, error)
	GetDiscoveryDomainByName(ctx context.Context, tid, orgID, domain string) (*OrganizationDiscoveryDomain, error)
	ListDiscoveryDomains(ctx context.Context, tid, orgID string, p OrgPage) (OrgResult[OrganizationDiscoveryDomain], error)
	DeleteDiscoveryDomain(ctx context.Context, tid, orgID, id string) error
	DiscoverOrganizations(ctx context.Context, tid, normalizedDomain string) ([]Organization, error)
}

// UnimplementedOrganizationsII fails closed until a driver supports the capability.
type UnimplementedOrganizationsII struct{}

func (UnimplementedOrganizationsII) CreateInvitation(ctx context.Context, in *OrganizationInvitation) error {
	return ErrOrganizationsIIUnavailable
}
func (UnimplementedOrganizationsII) GetInvitation(ctx context.Context, tid, orgID, id string) (*OrganizationInvitation, error) {
	return nil, ErrOrganizationsIIUnavailable
}
func (UnimplementedOrganizationsII) FindInvitation(ctx context.Context, tid, ticketHash string) (*OrganizationInvitation, error) {
	return nil, ErrOrganizationsIIUnavailable
}
func (UnimplementedOrganizationsII) ListInvitations(ctx context.Context, tid, orgID string, p OrgPage) (OrgResult[OrganizationInvitation], error) {
	return OrgResult[OrganizationInvitation]{}, ErrOrganizationsIIUnavailable
}
func (UnimplementedOrganizationsII) DeleteInvitation(ctx context.Context, tid, orgID, id string) error {
	return ErrOrganizationsIIUnavailable
}
func (UnimplementedOrganizationsII) ConsumeInvitation(ctx context.Context, tid, orgID, id, transactionID, userID string, now time.Time) (InvitationReceipt, error) {
	return InvitationReceipt{}, ErrOrganizationsIIUnavailable
}
func (UnimplementedOrganizationsII) GetInvitationReceipt(ctx context.Context, tid, transactionID string) (*InvitationReceipt, error) {
	return nil, ErrOrganizationsIIUnavailable
}
func (UnimplementedOrganizationsII) PutClients(ctx context.Context, tid, orgID string, clients []OrganizationClient) error {
	return ErrOrganizationsIIUnavailable
}
func (UnimplementedOrganizationsII) GetClient(ctx context.Context, tid, orgID, clientID string) (*OrganizationClient, error) {
	return nil, ErrOrganizationsIIUnavailable
}
func (UnimplementedOrganizationsII) ListClients(ctx context.Context, tid, orgID string, p OrgPage) (OrgResult[OrganizationClient], error) {
	return OrgResult[OrganizationClient]{}, ErrOrganizationsIIUnavailable
}
func (UnimplementedOrganizationsII) DeleteClients(ctx context.Context, tid, orgID string, clientIDs []string) error {
	return ErrOrganizationsIIUnavailable
}
func (UnimplementedOrganizationsII) PutClientGrant(ctx context.Context, tid, orgID, grantID string) error {
	return ErrOrganizationsIIUnavailable
}
func (UnimplementedOrganizationsII) DeleteClientGrant(ctx context.Context, tid, orgID, grantID string) error {
	return ErrOrganizationsIIUnavailable
}
func (UnimplementedOrganizationsII) ListClientGrants(ctx context.Context, tid, orgID string, p OrgPage) (OrgResult[ClientGrant], error) {
	return OrgResult[ClientGrant]{}, ErrOrganizationsIIUnavailable
}
func (UnimplementedOrganizationsII) GrantOrganizations(ctx context.Context, tid, grantID string, p OrgPage) (OrgResult[Organization], error) {
	return OrgResult[Organization]{}, ErrOrganizationsIIUnavailable
}
func (UnimplementedOrganizationsII) HasClientGrant(ctx context.Context, tid, orgID, grantID string) (bool, error) {
	return false, ErrOrganizationsIIUnavailable
}
func (UnimplementedOrganizationsII) PutDiscoveryDomain(ctx context.Context, in *OrganizationDiscoveryDomain, create bool) error {
	return ErrOrganizationsIIUnavailable
}
func (UnimplementedOrganizationsII) GetDiscoveryDomain(ctx context.Context, tid, orgID, id string) (*OrganizationDiscoveryDomain, error) {
	return nil, ErrOrganizationsIIUnavailable
}
func (UnimplementedOrganizationsII) GetDiscoveryDomainByName(ctx context.Context, tid, orgID, domain string) (*OrganizationDiscoveryDomain, error) {
	return nil, ErrOrganizationsIIUnavailable
}
func (UnimplementedOrganizationsII) ListDiscoveryDomains(ctx context.Context, tid, orgID string, p OrgPage) (OrgResult[OrganizationDiscoveryDomain], error) {
	return OrgResult[OrganizationDiscoveryDomain]{}, ErrOrganizationsIIUnavailable
}
func (UnimplementedOrganizationsII) DeleteDiscoveryDomain(ctx context.Context, tid, orgID, id string) error {
	return ErrOrganizationsIIUnavailable
}
func (UnimplementedOrganizationsII) DiscoverOrganizations(ctx context.Context, tid, normalizedDomain string) ([]Organization, error) {
	return nil, ErrOrganizationsIIUnavailable
}
