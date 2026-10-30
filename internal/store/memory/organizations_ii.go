package memory

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type orgIIKey struct{ tenant, org, id string }
type organizationsII struct{ s *Store }

func (s *Store) OrganizationsII() store.OrganizationsII { return organizationsII{s} }

func (r organizationsII) CreateInvitation(_ context.Context, in *store.OrganizationInvitation) error {
	if in == nil || in.TenantID == "" || in.OrganizationID == "" || in.ID == "" || in.ClientID == "" || in.TicketHash == "" || len(in.WrappedTicket) == 0 || in.ExpiresAt.IsZero() {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	s := r.s
	if s.orgs[key{in.TenantID, in.OrganizationID}] == nil || s.clients[key{in.TenantID, in.ClientID}] == nil {
		return store.ErrNotFound
	}
	if in.ConnectionID != "" && s.connections[key{in.TenantID, in.ConnectionID}] == nil {
		return store.ErrNotFound
	}
	for _, id := range in.Roles {
		if s.roles[key{in.TenantID, id}] == nil {
			return store.ErrNotFound
		}
	}
	k := orgIIKey{in.TenantID, in.OrganizationID, in.ID}
	if s.orgInvitations[k] != nil {
		return store.ErrConflict
	}
	for ik, v := range s.orgInvitations {
		if ik.tenant == in.TenantID && (v.ID == in.ID || v.TicketHash == in.TicketHash) {
			return store.ErrConflict
		}
	}
	// A consumed resource ID cannot be repurposed.
	for _, v := range s.orgReceipts {
		if v.TenantID == in.TenantID && v.InvitationID == in.ID {
			return store.ErrConflict
		}
	}
	v := cloneOrgInvitation(in)
	if v.CreatedAt.IsZero() {
		v.CreatedAt = s.now()
	}
	if v.UpdatedAt.IsZero() {
		v.UpdatedAt = v.CreatedAt
	}
	s.orgInvitations[k] = v
	*in = *cloneOrgInvitation(v)
	return nil
}
func (s *Store) activeOrgInvitation(v *store.OrganizationInvitation, now time.Time) bool {
	if v == nil || !now.Before(v.ExpiresAt) {
		return false
	}
	for _, receipt := range s.orgReceipts {
		if receipt.TenantID == v.TenantID && receipt.OrganizationID == v.OrganizationID && receipt.InvitationID == v.ID {
			return false
		}
	}
	return true
}
func (r organizationsII) GetInvitation(_ context.Context, tid, org, id string) (*store.OrganizationInvitation, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	v := r.s.orgInvitations[orgIIKey{tid, org, id}]
	if !r.s.activeOrgInvitation(v, r.s.now()) {
		return nil, store.ErrNotFound
	}
	return cloneOrgInvitation(v), nil
}
func (r organizationsII) FindInvitation(_ context.Context, tid, hash string) (*store.OrganizationInvitation, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	for k, v := range r.s.orgInvitations {
		if k.tenant == tid && v.TicketHash == hash && r.s.activeOrgInvitation(v, r.s.now()) {
			return cloneOrgInvitation(v), nil
		}
	}
	return nil, store.ErrNotFound
}
func iiPage[T any](entries []orgrules.Entry[T], p store.OrgPage, scope string) (store.OrgResult[T], error) {
	orgrules.OrderEntries(entries, false)
	return orgrules.PageEntries(entries, p, scope, false)
}
func (r organizationsII) ListInvitations(_ context.Context, tid, org string, p store.OrgPage) (store.OrgResult[store.OrganizationInvitation], error) {
	r.s.readLock()
	defer r.s.readUnlock()
	if r.s.orgs[key{tid, org}] == nil {
		return store.OrgResult[store.OrganizationInvitation]{}, store.ErrNotFound
	}
	if p.Sort == "" {
		p.Sort = "created_at:-1"
	}
	if p.Sort != "created_at:1" && p.Sort != "created_at:-1" {
		return store.OrgResult[store.OrganizationInvitation]{}, store.ErrInvalid
	}
	var es []orgrules.Entry[store.OrganizationInvitation]
	now := r.s.now()
	for k, v := range r.s.orgInvitations {
		if k.tenant == tid && k.org == org && r.s.activeOrgInvitation(v, now) {
			es = append(es, orgrules.Entry[store.OrganizationInvitation]{ID: v.ID, Sort: fmt.Sprintf("%020d", v.CreatedAt.UnixNano()), Item: *cloneOrgInvitation(v)})
		}
	}
	desc := p.Sort == "created_at:-1"
	orgrules.OrderEntries(es, desc)
	return orgrules.PageEntries(es, p, orgScope("ii-invites", tid, org), desc)
}
func (r organizationsII) DeleteInvitation(_ context.Context, tid, org, id string) error {
	r.s.lock()
	defer r.s.unlock()
	if r.s.orgs[key{tid, org}] == nil {
		return store.ErrNotFound
	}
	delete(r.s.orgInvitations, orgIIKey{tid, org, id})
	return nil
}
func (r organizationsII) ConsumeInvitation(_ context.Context, tid, org, id, transaction, user string, now time.Time) (store.InvitationReceipt, error) {
	if !r.s.tx {
		return store.InvitationReceipt{}, store.ErrPrecondition
	}
	if transaction == "" || user == "" || now.IsZero() {
		return store.InvitationReceipt{}, store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	s := r.s
	if receipt := s.orgReceipts[key{tid, transaction}]; receipt != nil {
		if receipt.OrganizationID == org && receipt.InvitationID == id && receipt.UserID == user {
			return *receipt, nil
		}
		return store.InvitationReceipt{}, store.ErrPrecondition
	}
	if s.orgs[key{tid, org}] == nil || s.users[key{tid, user}] == nil {
		return store.InvitationReceipt{}, store.ErrNotFound
	}
	v := s.orgInvitations[orgIIKey{tid, org, id}]
	if !s.activeOrgInvitation(v, now) {
		return store.InvitationReceipt{}, store.ErrPrecondition
	}
	out := store.InvitationReceipt{TenantID: tid, OrganizationID: org, InvitationID: id, TransactionID: transaction, UserID: user, AcceptedAt: now}
	s.orgReceipts[key{tid, transaction}] = &out
	return out, nil
}
func (r organizationsII) GetInvitationReceipt(_ context.Context, tid, transaction string) (*store.InvitationReceipt, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	v := r.s.orgReceipts[key{tid, transaction}]
	if v == nil {
		return nil, store.ErrNotFound
	}
	return cloneValue(v), nil
}

func (r organizationsII) PutClients(_ context.Context, tid, org string, clients []store.OrganizationClient) error {
	if len(clients) == 0 {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	if r.s.orgs[key{tid, org}] == nil {
		return store.ErrNotFound
	}
	seen := map[string]bool{}
	for _, c := range clients {
		if c.ClientID == "" {
			return store.ErrInvalid
		}
		if (c.TenantID != "" && c.TenantID != tid) || (c.OrganizationID != "" && c.OrganizationID != org) {
			return store.ErrNotFound
		}
		if seen[c.ClientID] {
			return store.ErrConflict
		}
		seen[c.ClientID] = true
		if r.s.clients[key{tid, c.ClientID}] == nil {
			return store.ErrNotFound
		}
	}
	for _, c := range clients {
		c.TenantID = tid
		c.OrganizationID = org
		r.s.orgClients[orgIIKey{tid, org, c.ClientID}] = &c
	}
	return nil
}
func (r organizationsII) GetClient(_ context.Context, tid, org, client string) (*store.OrganizationClient, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	v := r.s.orgClients[orgIIKey{tid, org, client}]
	if v == nil {
		return nil, store.ErrNotFound
	}
	return cloneValue(v), nil
}
func (r organizationsII) ListClients(_ context.Context, tid, org string, p store.OrgPage) (store.OrgResult[store.OrganizationClient], error) {
	r.s.readLock()
	defer r.s.readUnlock()
	if r.s.orgs[key{tid, org}] == nil {
		return store.OrgResult[store.OrganizationClient]{}, store.ErrNotFound
	}
	var es []orgrules.Entry[store.OrganizationClient]
	for k, v := range r.s.orgClients {
		if k.tenant == tid && k.org == org {
			es = append(es, orgrules.Entry[store.OrganizationClient]{ID: v.ClientID, Item: *v})
		}
	}
	return iiPage(es, p, orgScope("ii-clients", tid, org))
}
func (r organizationsII) DeleteClients(_ context.Context, tid, org string, clients []string) error {
	if len(clients) == 0 {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	if r.s.orgs[key{tid, org}] == nil {
		return store.ErrNotFound
	}
	for _, id := range clients {
		if r.s.clients[key{tid, id}] == nil {
			return store.ErrNotFound
		}
	}
	for _, id := range clients {
		delete(r.s.orgClients, orgIIKey{tid, org, id})
	}
	return nil
}
func (r organizationsII) PutClientGrant(_ context.Context, tid, org, grant string) error {
	r.s.lock()
	defer r.s.unlock()
	g := r.s.clientGrants[key{tid, grant}]
	if r.s.orgs[key{tid, org}] == nil || g == nil || r.s.clients[key{tid, g.ClientID}] == nil {
		return store.ErrNotFound
	}
	if g.SubjectType != store.SubjectTypeClient {
		return store.ErrInvalid
	}
	r.s.orgGrants[orgIIKey{tid, org, grant}] = true
	return nil
}
func (r organizationsII) DeleteClientGrant(_ context.Context, tid, org, grant string) error {
	r.s.lock()
	defer r.s.unlock()
	if r.s.orgs[key{tid, org}] == nil || r.s.clientGrants[key{tid, grant}] == nil {
		return store.ErrNotFound
	}
	delete(r.s.orgGrants, orgIIKey{tid, org, grant})
	return nil
}
func (r organizationsII) HasClientGrant(_ context.Context, tid, org, grant string) (bool, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	if r.s.orgs[key{tid, org}] == nil {
		return false, store.ErrNotFound
	}
	return r.s.clientGrants[key{tid, grant}] != nil && r.s.orgGrants[orgIIKey{tid, org, grant}], nil
}
func (r organizationsII) ListClientGrants(_ context.Context, tid, org string, p store.OrgPage) (store.OrgResult[store.ClientGrant], error) {
	r.s.readLock()
	defer r.s.readUnlock()
	if r.s.orgs[key{tid, org}] == nil {
		return store.OrgResult[store.ClientGrant]{}, store.ErrNotFound
	}
	var es []orgrules.Entry[store.ClientGrant]
	for k := range r.s.orgGrants {
		if k.tenant == tid && k.org == org {
			if g := r.s.clientGrants[key{tid, k.id}]; g != nil {
				es = append(es, orgrules.Entry[store.ClientGrant]{ID: g.ID, Item: *cloneClientGrant(g)})
			}
		}
	}
	return iiPage(es, p, orgScope("ii-grants", tid, org))
}
func (r organizationsII) GrantOrganizations(_ context.Context, tid, grant string, p store.OrgPage) (store.OrgResult[store.Organization], error) {
	r.s.readLock()
	defer r.s.readUnlock()
	if r.s.clientGrants[key{tid, grant}] == nil {
		return store.OrgResult[store.Organization]{}, store.ErrNotFound
	}
	var orgs []*store.Organization
	for k := range r.s.orgGrants {
		if k.tenant == tid && k.id == grant {
			if o := r.s.orgs[key{tid, k.org}]; o != nil {
				orgs = append(orgs, o)
			}
		}
	}
	return pageOrgs(orgs, p, orgScope("ii-grant-orgs", tid, grant))
}
func (r organizationsII) PutDiscoveryDomain(_ context.Context, in *store.OrganizationDiscoveryDomain, create bool) error {
	if in == nil || in.TenantID == "" || in.OrganizationID == "" || in.ID == "" || in.Domain == "" {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	s := r.s
	if s.orgs[key{in.TenantID, in.OrganizationID}] == nil {
		return store.ErrNotFound
	}
	k := orgIIKey{in.TenantID, in.OrganizationID, in.ID}
	old := s.orgDomains[k]
	if create && old != nil {
		return store.ErrConflict
	}
	if !create && old == nil {
		return store.ErrNotFound
	}
	for dk, v := range s.orgDomains {
		if dk.tenant == k.tenant && dk.org == k.org && dk.id != k.id && v.Domain == in.Domain {
			return store.ErrConflict
		}
	}
	// Domain syntax, normalization and lifecycle validation belong to orgrules/mgmt.
	s.orgDomains[k] = cloneValue(in)
	return nil
}
func (r organizationsII) GetDiscoveryDomain(_ context.Context, tid, org, id string) (*store.OrganizationDiscoveryDomain, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	v := r.s.orgDomains[orgIIKey{tid, org, id}]
	if v == nil {
		return nil, store.ErrNotFound
	}
	return cloneValue(v), nil
}
func (r organizationsII) GetDiscoveryDomainByName(_ context.Context, tid, org, domain string) (*store.OrganizationDiscoveryDomain, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	for k, v := range r.s.orgDomains {
		if k.tenant == tid && k.org == org && v.Domain == domain {
			return cloneValue(v), nil
		}
	}
	return nil, store.ErrNotFound
}
func (r organizationsII) ListDiscoveryDomains(_ context.Context, tid, org string, p store.OrgPage) (store.OrgResult[store.OrganizationDiscoveryDomain], error) {
	r.s.readLock()
	defer r.s.readUnlock()
	if r.s.orgs[key{tid, org}] == nil {
		return store.OrgResult[store.OrganizationDiscoveryDomain]{}, store.ErrNotFound
	}
	var es []orgrules.Entry[store.OrganizationDiscoveryDomain]
	for k, v := range r.s.orgDomains {
		if k.tenant == tid && k.org == org {
			es = append(es, orgrules.Entry[store.OrganizationDiscoveryDomain]{ID: v.ID, Item: *v})
		}
	}
	return iiPage(es, p, orgScope("ii-domains", tid, org))
}
func (r organizationsII) DeleteDiscoveryDomain(_ context.Context, tid, org, id string) error {
	r.s.lock()
	defer r.s.unlock()
	if r.s.orgs[key{tid, org}] == nil {
		return store.ErrNotFound
	}
	if r.s.orgDomains[orgIIKey{tid, org, id}] == nil {
		return store.ErrNotFound
	}
	delete(r.s.orgDomains, orgIIKey{tid, org, id})
	return nil
}
func (r organizationsII) DiscoverOrganizations(_ context.Context, tid, domain string) ([]store.Organization, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	out := []store.Organization{}
	seen := map[string]bool{}
	for k, v := range r.s.orgDomains {
		if k.tenant == tid && v.Domain == domain && v.Status == "verified" && v.UseForOrganizationDiscovery && !seen[k.org] {
			if o := r.s.orgs[key{tid, k.org}]; o != nil {
				out = append(out, *cloneOrg(o))
				seen[k.org] = true
			}
		}
	}
	slices.SortFunc(out, func(a, b store.Organization) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

type orgIICleanup struct {
	org, client, grant, role, user string
	all                            bool
}

// cleanupOrgII removes dependent rows; only an explicit all selector purges a
// tenant. Role deletion revokes invites instead of dropping a promised role.
// Receipts survive invitation deletion for replay safety.
func (s *Store) cleanupOrgII(tid string, match orgIICleanup) {
	org, client, grant, role, user, all := match.org, match.client, match.grant, match.role, match.user, match.all
	// Removing a receipt owner must also destroy its consumed invitation: merely
	// deleting the receipt would reactivate a retained ticket.
	if user != "" {
		for _, receipt := range s.orgReceipts {
			if receipt.TenantID == tid && receipt.UserID == user {
				delete(s.orgInvitations, orgIIKey{tid, receipt.OrganizationID, receipt.InvitationID})
			}
		}
	}
	for k, v := range s.orgInvitations {
		if k.tenant == tid && (all || org != "" && k.org == org || client != "" && v.ClientID == client || role != "" && slices.Contains(v.Roles, role)) {
			delete(s.orgInvitations, k)
		}
	}
	for k, v := range s.orgReceipts {
		if k.tenant == tid && (all || org != "" && v.OrganizationID == org || user != "" && v.UserID == user) {
			delete(s.orgReceipts, k)
		}
	}
	for k := range s.orgClients {
		if k.tenant == tid && (all || org != "" && k.org == org || client != "" && k.id == client) {
			delete(s.orgClients, k)
		}
	}
	for k := range s.orgGrants {
		if k.tenant == tid && (all || org != "" && k.org == org || grant != "" && k.id == grant) {
			delete(s.orgGrants, k)
		}
	}
	for k := range s.orgDomains {
		if k.tenant == tid && (all || org != "" && k.org == org) {
			delete(s.orgDomains, k)
		}
	}
}
