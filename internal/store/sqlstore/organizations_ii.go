package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type organizationsII struct{ s *Store }

func (s *Store) OrganizationsII() store.OrganizationsII { return organizationsII{s} }

// All policy-dependent reads in a caller transaction take the same tenant lock
// as writers, before reading any dependent row. It remains held through commit.
func (r organizationsII) readLock(ctx context.Context, tid string) error {
	if r.s.tx != nil {
		return r.s.lockRBAC(ctx, tid)
	}
	return nil
}
func (r organizationsII) atomic(ctx context.Context, tid string, fn func(organizationsII) error) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := tx.lockRBAC(ctx, tid); err != nil {
			return err
		}
		return fn(organizationsII{tx})
	})
}
func (r organizationsII) exists(ctx context.Context, table, col, tid, id string) error {
	var one int
	err := r.s.queryRow(ctx, `SELECT 1 FROM `+table+` WHERE tenant_id=? AND `+col+`=?`, tid, id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}
func iiNotFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}
func iiPage[T any](es []orgrules.Entry[T], p store.OrgPage, scope string) (store.OrgResult[T], error) {
	orgrules.OrderEntries(es, false)
	return orgrules.PageEntries(es, p, scope, false)
}
func (r organizationsII) org(ctx context.Context, tid, id string) error {
	return (organizations{r.s}).orgExists(ctx, tid, id)
}

func (r organizationsII) CreateInvitation(ctx context.Context, in *store.OrganizationInvitation) error {
	if in == nil || in.TenantID == "" || in.OrganizationID == "" || in.ID == "" || in.ClientID == "" || in.TicketHash == "" || len(in.WrappedTicket) == 0 || in.ExpiresAt.IsZero() {
		return store.ErrInvalid
	}
	v := *in
	if v.CreatedAt.IsZero() {
		v.CreatedAt = now()
	}
	if v.UpdatedAt.IsZero() {
		v.UpdatedAt = v.CreatedAt
	}
	payload, err := toJSON(v)
	if err != nil {
		return err
	}
	err = r.atomic(ctx, v.TenantID, func(t organizationsII) error {
		if err := t.org(ctx, v.TenantID, v.OrganizationID); err != nil {
			return err
		}
		if err := t.exists(ctx, "clients", "client_id", v.TenantID, v.ClientID); err != nil {
			return err
		}
		if v.ConnectionID != "" {
			if err := t.exists(ctx, "connections", "id", v.TenantID, v.ConnectionID); err != nil {
				return err
			}
		}
		for _, id := range v.Roles {
			if err := t.exists(ctx, "rbac_roles", "id", v.TenantID, id); err != nil {
				return err
			}
		}
		var n int
		if err := t.s.queryRow(ctx, `SELECT COUNT(*) FROM organization_invitation_receipts WHERE tenant_id=? AND invitation_id=?`, v.TenantID, v.ID).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return store.ErrConflict
		}
		var conn any
		if v.ConnectionID != "" {
			conn = v.ConnectionID
		}
		if _, err := t.s.exec(ctx, `INSERT INTO organization_invitations (tenant_id,organization_id,id,client_id,connection_id,ticket_hash,expires_at,created_at,payload) VALUES (?,?,?,?,?,?,?,?,?)`, v.TenantID, v.OrganizationID, v.ID, v.ClientID, conn, v.TicketHash, micros(v.ExpiresAt), micros(v.CreatedAt), payload); err != nil {
			return t.s.conflict(err)
		}
		seen := map[string]bool{}
		for _, id := range v.Roles {
			if seen[id] {
				continue
			}
			seen[id] = true
			if _, err := t.s.exec(ctx, `INSERT INTO organization_invitation_roles (tenant_id,invitation_id,role_id) VALUES (?,?,?)`, v.TenantID, v.ID, id); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil { // Round-trip detaches nested input maps, slices and wrapped bytes.
		_ = fromJSON(payload, in)
	}
	return err
}

const iiActive = ` AND NOT EXISTS (SELECT 1 FROM organization_invitation_receipts r WHERE r.tenant_id=i.tenant_id AND r.invitation_id=i.id)`

func (r organizationsII) invitation(ctx context.Context, tid, where string, args ...any) (*store.OrganizationInvitation, error) {
	if err := r.readLock(ctx, tid); err != nil {
		return nil, err
	}
	var payload string
	err := r.s.queryRow(ctx, `SELECT i.payload FROM organization_invitations i WHERE i.tenant_id=? AND `+where+iiActive, append([]any{tid}, args...)...).Scan(&payload)
	if err != nil {
		return nil, iiNotFound(err)
	}
	var v store.OrganizationInvitation
	if err := fromJSON(payload, &v); err != nil {
		return nil, err
	}
	return &v, nil
}
func (r organizationsII) GetInvitation(ctx context.Context, tid, org, id string) (*store.OrganizationInvitation, error) {
	v, err := r.invitation(ctx, tid, `i.organization_id=? AND i.id=?`, org, id)
	if err == nil && !r.s.iiNow().Before(v.ExpiresAt) {
		return nil, store.ErrNotFound
	}
	return v, err
}
func (r organizationsII) FindInvitation(ctx context.Context, tid, hash string) (*store.OrganizationInvitation, error) {
	v, err := r.invitation(ctx, tid, `i.ticket_hash=?`, hash)
	if err == nil && !r.s.iiNow().Before(v.ExpiresAt) {
		return nil, store.ErrNotFound
	}
	return v, err
}
func (r organizationsII) ListInvitations(ctx context.Context, tid, org string, p store.OrgPage) (store.OrgResult[store.OrganizationInvitation], error) {
	var out store.OrgResult[store.OrganizationInvitation]
	if err := r.readLock(ctx, tid); err != nil {
		return out, err
	}
	if err := r.org(ctx, tid, org); err != nil {
		return out, err
	}
	if p.Sort == "" {
		p.Sort = "created_at:-1"
	}
	if p.Sort != "created_at:1" && p.Sort != "created_at:-1" {
		return out, store.ErrInvalid
	}
	rows, err := r.s.query(ctx, `SELECT i.payload FROM organization_invitations i WHERE i.tenant_id=? AND i.organization_id=?`+iiActive, tid, org)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	var es []orgrules.Entry[store.OrganizationInvitation]
	clock := r.s.iiNow()
	for rows.Next() {
		var payload string
		var v store.OrganizationInvitation
		if err := rows.Scan(&payload); err != nil {
			return out, err
		}
		if err := fromJSON(payload, &v); err != nil {
			return out, err
		}
		if clock.Before(v.ExpiresAt) {
			es = append(es, orgrules.Entry[store.OrganizationInvitation]{ID: v.ID, Sort: fmt.Sprintf("%020d", v.CreatedAt.UnixNano()), Item: v})
		}
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	desc := p.Sort == "created_at:-1"
	orgrules.OrderEntries(es, desc)
	return orgrules.PageEntries(es, p, orgrules.Scope("ii-invites", tid, org), desc)
}
func (r organizationsII) DeleteInvitation(ctx context.Context, tid, org, id string) error {
	return r.atomic(ctx, tid, func(t organizationsII) error {
		if err := t.org(ctx, tid, org); err != nil {
			return err
		}
		_, err := t.s.exec(ctx, `DELETE FROM organization_invitations WHERE tenant_id=? AND organization_id=? AND id=?`, tid, org, id)
		return err
	})
}
func (r organizationsII) ConsumeInvitation(ctx context.Context, tid, org, id, transaction, user string, clock time.Time) (store.InvitationReceipt, error) {
	var out store.InvitationReceipt
	if r.s.tx == nil {
		return out, store.ErrPrecondition
	}
	if transaction == "" || user == "" || clock.IsZero() {
		return out, store.ErrInvalid
	}
	// Do not open an autonomous transaction: consumption, policy, membership and
	// role changes belong to the caller's WithTx and roll back together.
	if err := r.s.lockRBAC(ctx, tid); err != nil {
		return out, err
	}
	receipt, err := r.GetInvitationReceipt(ctx, tid, transaction)
	if err == nil {
		if receipt.OrganizationID == org && receipt.InvitationID == id && receipt.UserID == user {
			return *receipt, nil
		}
		return out, store.ErrPrecondition
	}
	if !errors.Is(err, store.ErrNotFound) {
		return out, err
	}
	if err := r.org(ctx, tid, org); err != nil {
		return out, err
	}
	if err := r.exists(ctx, "users", "user_id", tid, user); err != nil {
		return out, err
	}
	v, err := r.invitation(ctx, tid, `i.organization_id=? AND i.id=?`, org, id)
	if errors.Is(err, store.ErrNotFound) {
		return out, store.ErrPrecondition
	}
	if err != nil {
		return out, err
	}
	if !clock.Before(v.ExpiresAt) {
		return out, store.ErrPrecondition
	}
	out = store.InvitationReceipt{TenantID: tid, OrganizationID: org, InvitationID: id, TransactionID: transaction, UserID: user, AcceptedAt: fromMicros(micros(clock))}
	_, err = r.s.exec(ctx, `INSERT INTO organization_invitation_receipts (tenant_id,organization_id,invitation_id,transaction_id,user_id,accepted_at) VALUES (?,?,?,?,?,?)`, tid, org, id, transaction, user, micros(clock))
	return out, err
}
func (r organizationsII) GetInvitationReceipt(ctx context.Context, tid, transaction string) (*store.InvitationReceipt, error) {
	if err := r.readLock(ctx, tid); err != nil {
		return nil, err
	}
	var v store.InvitationReceipt
	var accepted int64
	err := r.s.queryRow(ctx, `SELECT tenant_id,organization_id,invitation_id,transaction_id,user_id,accepted_at FROM organization_invitation_receipts WHERE tenant_id=? AND transaction_id=?`, tid, transaction).Scan(&v.TenantID, &v.OrganizationID, &v.InvitationID, &v.TransactionID, &v.UserID, &accepted)
	if err != nil {
		return nil, iiNotFound(err)
	}
	v.AcceptedAt = fromMicros(accepted)
	return &v, nil
}

func (r organizationsII) PutClients(ctx context.Context, tid, org string, clients []store.OrganizationClient) error {
	if len(clients) == 0 {
		return store.ErrInvalid
	}
	return r.atomic(ctx, tid, func(t organizationsII) error {
		if err := t.org(ctx, tid, org); err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, c := range clients {
			if c.ClientID == "" {
				return store.ErrInvalid
			}
			if c.TenantID != "" && c.TenantID != tid || c.OrganizationID != "" && c.OrganizationID != org {
				return store.ErrNotFound
			}
			if seen[c.ClientID] {
				return store.ErrConflict
			}
			seen[c.ClientID] = true
			if err := t.exists(ctx, "clients", "client_id", tid, c.ClientID); err != nil {
				return err
			}
		}
		for _, c := range clients {
			if _, err := t.s.exec(ctx, `DELETE FROM organization_clients WHERE tenant_id=? AND organization_id=? AND client_id=?`, tid, org, c.ClientID); err != nil {
				return err
			}
			if _, err := t.s.exec(ctx, `INSERT INTO organization_clients (tenant_id,organization_id,client_id,use_for_member_access) VALUES (?,?,?,?)`, tid, org, c.ClientID, c.UseForMemberAccess); err != nil {
				return err
			}
		}
		return nil
	})
}
func (r organizationsII) GetClient(ctx context.Context, tid, org, client string) (*store.OrganizationClient, error) {
	if err := r.readLock(ctx, tid); err != nil {
		return nil, err
	}
	v := store.OrganizationClient{TenantID: tid, OrganizationID: org, ClientID: client}
	err := r.s.queryRow(ctx, `SELECT use_for_member_access FROM organization_clients WHERE tenant_id=? AND organization_id=? AND client_id=?`, tid, org, client).Scan(&v.UseForMemberAccess)
	if err != nil {
		return nil, iiNotFound(err)
	}
	return &v, nil
}
func (r organizationsII) ListClients(ctx context.Context, tid, org string, p store.OrgPage) (store.OrgResult[store.OrganizationClient], error) {
	var out store.OrgResult[store.OrganizationClient]
	if err := r.readLock(ctx, tid); err != nil {
		return out, err
	}
	if err := r.org(ctx, tid, org); err != nil {
		return out, err
	}
	rows, err := r.s.query(ctx, `SELECT client_id,use_for_member_access FROM organization_clients WHERE tenant_id=? AND organization_id=?`, tid, org)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	var es []orgrules.Entry[store.OrganizationClient]
	for rows.Next() {
		v := store.OrganizationClient{TenantID: tid, OrganizationID: org}
		if err := rows.Scan(&v.ClientID, &v.UseForMemberAccess); err != nil {
			return out, err
		}
		es = append(es, orgrules.Entry[store.OrganizationClient]{ID: v.ClientID, Item: v})
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	return iiPage(es, p, orgrules.Scope("ii-clients", tid, org))
}
func (r organizationsII) DeleteClients(ctx context.Context, tid, org string, clients []string) error {
	if len(clients) == 0 {
		return store.ErrInvalid
	}
	return r.atomic(ctx, tid, func(t organizationsII) error {
		if err := t.org(ctx, tid, org); err != nil {
			return err
		}
		for _, id := range clients {
			if err := t.exists(ctx, "clients", "client_id", tid, id); err != nil {
				return err
			}
		}
		for _, id := range clients {
			if _, err := t.s.exec(ctx, `DELETE FROM organization_clients WHERE tenant_id=? AND organization_id=? AND client_id=?`, tid, org, id); err != nil {
				return err
			}
		}
		return nil
	})
}
func (r organizationsII) PutClientGrant(ctx context.Context, tid, org, grant string) error {
	return r.atomic(ctx, tid, func(t organizationsII) error {
		if err := t.org(ctx, tid, org); err != nil {
			return err
		}
		g, err := scanClientGrant(t.s.queryRow(ctx, `SELECT `+clientGrantCols+` FROM client_grants WHERE tenant_id=? AND id=?`, tid, grant))
		if err != nil {
			return iiNotFound(err)
		}
		if err := t.exists(ctx, "clients", "client_id", tid, g.ClientID); err != nil {
			return err
		}
		if g.SubjectType != store.SubjectTypeClient {
			return store.ErrInvalid
		}
		return (organizations{t.s}).insertIgnore(ctx, `organization_client_grants (tenant_id,organization_id,grant_id) VALUES (?,?,?)`, tid, org, grant)
	})
}
func (r organizationsII) DeleteClientGrant(ctx context.Context, tid, org, grant string) error {
	return r.atomic(ctx, tid, func(t organizationsII) error {
		if err := t.org(ctx, tid, org); err != nil {
			return err
		}
		if err := t.exists(ctx, "client_grants", "id", tid, grant); err != nil {
			return err
		}
		_, err := t.s.exec(ctx, `DELETE FROM organization_client_grants WHERE tenant_id=? AND organization_id=? AND grant_id=?`, tid, org, grant)
		return err
	})
}
func (r organizationsII) HasClientGrant(ctx context.Context, tid, org, grant string) (bool, error) {
	if err := r.readLock(ctx, tid); err != nil {
		return false, err
	}
	if err := r.org(ctx, tid, org); err != nil {
		return false, err
	}
	var n int
	err := r.s.queryRow(ctx, `SELECT COUNT(*) FROM organization_client_grants WHERE tenant_id=? AND organization_id=? AND grant_id=?`, tid, org, grant).Scan(&n)
	return n > 0, err
}
func (r organizationsII) ListClientGrants(ctx context.Context, tid, org string, p store.OrgPage) (store.OrgResult[store.ClientGrant], error) {
	var out store.OrgResult[store.ClientGrant]
	if err := r.readLock(ctx, tid); err != nil {
		return out, err
	}
	if err := r.org(ctx, tid, org); err != nil {
		return out, err
	}
	rows, err := r.s.query(ctx, `SELECT `+clientGrantCols+` FROM client_grants WHERE tenant_id=? AND id IN (SELECT grant_id FROM organization_client_grants WHERE tenant_id=? AND organization_id=?)`, tid, tid, org)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	var es []orgrules.Entry[store.ClientGrant]
	for rows.Next() {
		g, err := scanClientGrant(rows)
		if err != nil {
			return out, err
		}
		es = append(es, orgrules.Entry[store.ClientGrant]{ID: g.ID, Item: *g})
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	return iiPage(es, p, orgrules.Scope("ii-grants", tid, org))
}
func (r organizationsII) GrantOrganizations(ctx context.Context, tid, grant string, p store.OrgPage) (store.OrgResult[store.Organization], error) {
	var out store.OrgResult[store.Organization]
	if err := r.readLock(ctx, tid); err != nil {
		return out, err
	}
	if err := r.exists(ctx, "client_grants", "id", tid, grant); err != nil {
		return out, err
	}
	return (organizations{r.s}).pageOrgs(ctx, p, orgrules.Scope("ii-grant-orgs", tid, grant), `tenant_id=? AND id IN (SELECT organization_id FROM organization_client_grants WHERE tenant_id=? AND grant_id=?)`, tid, tid, grant)
}

func (r organizationsII) PutDiscoveryDomain(ctx context.Context, in *store.OrganizationDiscoveryDomain, create bool) error {
	if in == nil || in.TenantID == "" || in.OrganizationID == "" || in.ID == "" || in.Domain == "" {
		return store.ErrInvalid
	}
	payload, err := toJSON(in)
	if err != nil {
		return err
	}
	return r.atomic(ctx, in.TenantID, func(t organizationsII) error {
		if err := t.org(ctx, in.TenantID, in.OrganizationID); err != nil {
			return err
		}
		_, err := t.GetDiscoveryDomain(ctx, in.TenantID, in.OrganizationID, in.ID)
		if create && err == nil {
			return store.ErrConflict
		}
		if !create && errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if !create {
			if _, err := t.s.exec(ctx, `DELETE FROM organization_discovery_domains WHERE tenant_id=? AND organization_id=? AND id=?`, in.TenantID, in.OrganizationID, in.ID); err != nil {
				return err
			}
		}
		_, err = t.s.exec(ctx, `INSERT INTO organization_discovery_domains (tenant_id,organization_id,id,domain,status,use_for_organization_discovery,payload) VALUES (?,?,?,?,?,?,?)`, in.TenantID, in.OrganizationID, in.ID, in.Domain, in.Status, in.UseForOrganizationDiscovery, payload)
		return t.s.conflict(err)
	})
}
func (r organizationsII) domain(ctx context.Context, tid, org, col, value string) (*store.OrganizationDiscoveryDomain, error) {
	if err := r.readLock(ctx, tid); err != nil {
		return nil, err
	}
	var payload string
	err := r.s.queryRow(ctx, `SELECT payload FROM organization_discovery_domains WHERE tenant_id=? AND organization_id=? AND `+col+`=?`, tid, org, value).Scan(&payload)
	if err != nil {
		return nil, iiNotFound(err)
	}
	var v store.OrganizationDiscoveryDomain
	if err := fromJSON(payload, &v); err != nil {
		return nil, err
	}
	return &v, nil
}
func (r organizationsII) GetDiscoveryDomain(ctx context.Context, tid, org, id string) (*store.OrganizationDiscoveryDomain, error) {
	return r.domain(ctx, tid, org, "id", id)
}
func (r organizationsII) GetDiscoveryDomainByName(ctx context.Context, tid, org, domain string) (*store.OrganizationDiscoveryDomain, error) {
	return r.domain(ctx, tid, org, "domain", domain)
}
func (r organizationsII) ListDiscoveryDomains(ctx context.Context, tid, org string, p store.OrgPage) (store.OrgResult[store.OrganizationDiscoveryDomain], error) {
	var out store.OrgResult[store.OrganizationDiscoveryDomain]
	if err := r.readLock(ctx, tid); err != nil {
		return out, err
	}
	if err := r.org(ctx, tid, org); err != nil {
		return out, err
	}
	rows, err := r.s.query(ctx, `SELECT payload FROM organization_discovery_domains WHERE tenant_id=? AND organization_id=?`, tid, org)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	var es []orgrules.Entry[store.OrganizationDiscoveryDomain]
	for rows.Next() {
		var payload string
		var v store.OrganizationDiscoveryDomain
		if err := rows.Scan(&payload); err != nil {
			return out, err
		}
		if err := fromJSON(payload, &v); err != nil {
			return out, err
		}
		es = append(es, orgrules.Entry[store.OrganizationDiscoveryDomain]{ID: v.ID, Item: v})
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	return iiPage(es, p, orgrules.Scope("ii-domains", tid, org))
}
func (r organizationsII) DeleteDiscoveryDomain(ctx context.Context, tid, org, id string) error {
	return r.atomic(ctx, tid, func(t organizationsII) error {
		if err := t.org(ctx, tid, org); err != nil {
			return err
		}
		res, err := t.s.exec(ctx, `DELETE FROM organization_discovery_domains WHERE tenant_id=? AND organization_id=? AND id=?`, tid, org, id)
		if err != nil {
			return err
		}
		return expectRow(res)
	})
}
func (r organizationsII) DiscoverOrganizations(ctx context.Context, tid, domain string) ([]store.Organization, error) {
	if err := r.readLock(ctx, tid); err != nil {
		return nil, err
	}
	orgs, err := (organizations{r.s}).queryOrgs(ctx, `SELECT `+orgCols+` FROM organizations WHERE tenant_id=? AND id IN (SELECT organization_id FROM organization_discovery_domains WHERE tenant_id=? AND domain=? AND status='verified' AND use_for_organization_discovery=true) ORDER BY id`+r.s.d.byteOrder, tid, tid, domain)
	if err != nil {
		return nil, err
	}
	out := make([]store.Organization, 0, len(orgs))
	for _, o := range orgs {
		out = append(out, *o)
	}
	return out, nil
}

func (s *Store) policyWrite(ctx context.Context, tid string, fn func(*Store) error) error {
	return s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := tx.lockRBAC(ctx, tid); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		return fn(tx)
	})
}

func (s *Store) iiNow() time.Time {
	if s.orgIIClock != nil {
		return s.orgIIClock()
	}
	return time.Now().UTC()
}

// policyRead permits historical standalone fixtures without a tenant row, while
// every real tenant takes the common writer boundary before dependent reads.
func (s *Store) policyRead(ctx context.Context, tid string) error {
	if s.tx == nil {
		return nil
	}
	err := s.lockRBAC(ctx, tid)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}
