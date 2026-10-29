package grpcstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc"
)

func organizationInvitationToPB(v *store.OrganizationInvitation) (*storev1.OrganizationInvitationMsg, error) {
	if v == nil {
		return nil, nil
	}
	out := &storev1.OrganizationInvitationMsg{}
	out.TenantId = v.TenantID
	out.OrganizationId = v.OrganizationID
	out.Id = v.ID
	out.ClientId = v.ClientID
	out.InviterName = v.InviterName
	out.InviteeEmail = v.InviteeEmail
	out.ConnectionId = v.ConnectionID
	out.Roles = stringsToPB(v.Roles)
	bUserMetadata, err := json.Marshal(v.UserMetadata)
	if err != nil {
		return nil, fmt.Errorf("invalid invitation metadata: %w", store.ErrInvalid)
	}
	out.UserMetadataJson = bUserMetadata
	bAppMetadata, err := json.Marshal(v.AppMetadata)
	if err != nil {
		return nil, fmt.Errorf("invalid invitation metadata: %w", store.ErrInvalid)
	}
	out.AppMetadataJson = bAppMetadata
	out.TicketHash = v.TicketHash
	out.WrappedTicket = append([]byte(nil), v.WrappedTicket...)
	out.SendInvitationEmail = v.SendInvitationEmail
	out.CreatedAt = tsToPB(v.CreatedAt)
	out.UpdatedAt = tsToPB(v.UpdatedAt)
	out.ExpiresAt = tsToPB(v.ExpiresAt)
	return out, nil
}
func organizationInvitationFromPB(v *storev1.OrganizationInvitationMsg) (*store.OrganizationInvitation, error) {
	if v == nil {
		return nil, nil
	}
	out := &store.OrganizationInvitation{}
	if err := checkTS(v.CreatedAt, v.UpdatedAt, v.ExpiresAt); err != nil {
		return nil, err
	}
	out.TenantID = v.TenantId
	out.OrganizationID = v.OrganizationId
	out.ID = v.Id
	out.ClientID = v.ClientId
	out.InviterName = v.InviterName
	out.InviteeEmail = v.InviteeEmail
	out.ConnectionID = v.ConnectionId
	out.Roles = stringsFromPB(v.Roles)
	if len(v.UserMetadataJson) > 0 {
		if err := json.Unmarshal(v.UserMetadataJson, &out.UserMetadata); err != nil {
			return nil, fmt.Errorf("invalid invitation metadata: %w", store.ErrInvalid)
		}
	}
	if len(v.AppMetadataJson) > 0 {
		if err := json.Unmarshal(v.AppMetadataJson, &out.AppMetadata); err != nil {
			return nil, fmt.Errorf("invalid invitation metadata: %w", store.ErrInvalid)
		}
	}
	out.TicketHash = v.TicketHash
	out.WrappedTicket = append([]byte(nil), v.WrappedTicket...)
	out.SendInvitationEmail = v.SendInvitationEmail
	out.CreatedAt = tsFromPB(v.CreatedAt)
	out.UpdatedAt = tsFromPB(v.UpdatedAt)
	out.ExpiresAt = tsFromPB(v.ExpiresAt)
	return out, nil
}
func invitationReceiptToPB(v *store.InvitationReceipt) (*storev1.InvitationReceiptMsg, error) {
	if v == nil {
		return nil, nil
	}
	out := &storev1.InvitationReceiptMsg{}
	out.TenantId = v.TenantID
	out.OrganizationId = v.OrganizationID
	out.InvitationId = v.InvitationID
	out.TransactionId = v.TransactionID
	out.UserId = v.UserID
	out.AcceptedAt = tsToPB(v.AcceptedAt)
	return out, nil
}
func invitationReceiptFromPB(v *storev1.InvitationReceiptMsg) (*store.InvitationReceipt, error) {
	if v == nil {
		return nil, nil
	}
	out := &store.InvitationReceipt{}
	if err := checkTS(v.AcceptedAt); err != nil {
		return nil, err
	}
	out.TenantID = v.TenantId
	out.OrganizationID = v.OrganizationId
	out.InvitationID = v.InvitationId
	out.TransactionID = v.TransactionId
	out.UserID = v.UserId
	out.AcceptedAt = tsFromPB(v.AcceptedAt)
	return out, nil
}
func organizationClientToPB(v *store.OrganizationClient) (*storev1.OrganizationClientMsg, error) {
	if v == nil {
		return nil, nil
	}
	out := &storev1.OrganizationClientMsg{}
	out.TenantId = v.TenantID
	out.OrganizationId = v.OrganizationID
	out.ClientId = v.ClientID
	out.UseForMemberAccess = v.UseForMemberAccess
	return out, nil
}
func organizationClientFromPB(v *storev1.OrganizationClientMsg) (*store.OrganizationClient, error) {
	if v == nil {
		return nil, nil
	}
	out := &store.OrganizationClient{}
	out.TenantID = v.TenantId
	out.OrganizationID = v.OrganizationId
	out.ClientID = v.ClientId
	out.UseForMemberAccess = v.UseForMemberAccess
	return out, nil
}
func organizationDiscoveryDomainToPB(v *store.OrganizationDiscoveryDomain) (*storev1.OrganizationDiscoveryDomainMsg, error) {
	if v == nil {
		return nil, nil
	}
	out := &storev1.OrganizationDiscoveryDomainMsg{}
	out.TenantId = v.TenantID
	out.OrganizationId = v.OrganizationID
	out.Id = v.ID
	out.Domain = v.Domain
	out.Status = v.Status
	out.VerificationHost = v.VerificationHost
	out.VerificationTxt = v.VerificationTXT
	out.UseForOrganizationDiscovery = v.UseForOrganizationDiscovery
	return out, nil
}
func organizationDiscoveryDomainFromPB(v *storev1.OrganizationDiscoveryDomainMsg) (*store.OrganizationDiscoveryDomain, error) {
	if v == nil {
		return nil, nil
	}
	out := &store.OrganizationDiscoveryDomain{}
	out.TenantID = v.TenantId
	out.OrganizationID = v.OrganizationId
	out.ID = v.Id
	out.Domain = v.Domain
	out.Status = v.Status
	out.VerificationHost = v.VerificationHost
	out.VerificationTXT = v.VerificationTxt
	out.UseForOrganizationDiscovery = v.UseForOrganizationDiscovery
	return out, nil
}

const organizationsIICapability = 1

type clientOrganizationsII struct{ c *Client }

func (c *Client) OrganizationsII() store.OrganizationsII { return clientOrganizationsII{c} }
func (c *Client) CheckOrganizationsIISupport(ctx context.Context) error {
	v, err := c.rpc.OrganizationsIICapabilities(ctx, &storev1.PingRequest{})
	if err != nil {
		err = rpcErr("OrganizationsII capability", capabilityError(err, store.ErrOrganizationsIIUnavailable))
		if errors.Is(err, store.ErrOrganizationsIIUnavailable) {
			c.orgIICap.v.Store(2)
		}
		return err
	}
	if err = errFromPB(v.Error); err != nil {
		if errors.Is(err, store.ErrOrganizationsIIUnavailable) {
			c.orgIICap.v.Store(2)
		}
		return err
	}
	if v.Version < organizationsIICapability {
		c.orgIICap.v.Store(2)
		return store.ErrOrganizationsIIUnavailable
	}
	c.orgIICap.v.Store(1)
	return nil
}
func (c *Client) OrganizationsIISupported() bool {
	switch c.orgIICap.v.Load() {
	case 1:
		return true
	case 2:
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.CheckOrganizationsIISupport(ctx) == nil
}

// Check every active write/II operation: a reconnect can replace the plugin
// with a different capability version. Only the cheap predicate uses the cache.
func (c *Client) requireOrganizationsII(ctx context.Context) error {
	return c.CheckOrganizationsIISupport(ctx)
}
func (s *Server) OrganizationsIICapabilities(ctx context.Context, _ *storev1.PingRequest) (*storev1.OrganizationsCapabilitiesResult, error) {
	if c, ok := s.st.(store.OrganizationsIISupporter); ok {
		if err := c.CheckOrganizationsIISupport(ctx); err != nil {
			return &storev1.OrganizationsCapabilitiesResult{Error: errToPB(err)}, nil
		}
	}
	// No repository access here: an outer memory store is locked while a remote
	// transaction exists. The explicit unavailable repository is the backing
	// store's declaration; implementation-specific failures remain operation errors.
	switch s.st.OrganizationsII().(type) {
	case store.UnimplementedOrganizationsII, *store.UnimplementedOrganizationsII:
		return &storev1.OrganizationsCapabilitiesResult{Version: 0}, nil
	}
	return &storev1.OrganizationsCapabilitiesResult{Version: organizationsIICapability}, nil
}

func orgIICall(c *Client, ctx context.Context, q *storev1.OrganizationsIIRequest, rpc func(context.Context, *storev1.OrganizationsIIRequest, ...grpc.CallOption) (*storev1.OrganizationsIIResponse, error)) (*storev1.OrganizationsIIResponse, error) {
	if err := c.requireOrganizationsII(ctx); err != nil {
		return nil, err
	}
	q.TxId = c.txID
	v, err := rpc(ctx, q)
	if err != nil {
		err = capabilityError(err, store.ErrOrganizationsIIUnavailable)
		if errors.Is(err, store.ErrOrganizationsIIUnavailable) {
			c.orgIICap.v.Store(2)
		}
		return nil, rpcErr("OrganizationsII", err)
	}
	if err = errFromPB(v.Error); err != nil {
		return nil, err
	}
	return v, nil
}
func (s *Server) orgIIServe(tx string, out *storev1.OrganizationsIIResponse, fn func(store.OrganizationsII) error) *storev1.OrganizationsIIResponse {
	out.Error = errToPB(s.with(tx, func(st store.Store) error { return fn(st.OrganizationsII()) }))
	return out
}

func (o clientOrganizationsII) CreateInvitation(ctx context.Context, in *store.OrganizationInvitation) error {
	pb, err := organizationInvitationToPB(in)
	if err != nil {
		return err
	}
	v, err := orgIICall(o.c, ctx, &storev1.OrganizationsIIRequest{Invitation: pb}, o.c.rpc.OrganizationsIICreateInvitation)
	_ = v
	return err
}
func (s *Server) OrganizationsIICreateInvitation(ctx context.Context, q *storev1.OrganizationsIIRequest) (*storev1.OrganizationsIIResponse, error) {
	out := &storev1.OrganizationsIIResponse{}
	return s.orgIIServe(q.TxId, out, func(o store.OrganizationsII) error {
		in, err := organizationInvitationFromPB(q.Invitation)
		if err != nil {
			return err
		}
		if in == nil {
			return store.ErrInvalid
		}
		return o.CreateInvitation(ctx, in)
	}), nil
}

func (o clientOrganizationsII) GetInvitation(ctx context.Context, tid, orgID, id string) (*store.OrganizationInvitation, error) {
	v, err := orgIICall(o.c, ctx, &storev1.OrganizationsIIRequest{TenantId: tid, OrganizationId: orgID, Id: id}, o.c.rpc.OrganizationsIIGetInvitation)
	if err != nil {
		return nil, err
	}
	x, err := organizationInvitationFromPB(v.Invitation)
	return x, err
}
func (s *Server) OrganizationsIIGetInvitation(ctx context.Context, q *storev1.OrganizationsIIRequest) (*storev1.OrganizationsIIResponse, error) {
	out := &storev1.OrganizationsIIResponse{}
	return s.orgIIServe(q.TxId, out, func(o store.OrganizationsII) error {
		v, err := o.GetInvitation(ctx, q.TenantId, q.OrganizationId, q.Id)
		if err != nil {
			return err
		}
		out.Invitation, err = organizationInvitationToPB(v)
		return err
	}), nil
}

func (o clientOrganizationsII) FindInvitation(ctx context.Context, tid, ticketHash string) (*store.OrganizationInvitation, error) {
	v, err := orgIICall(o.c, ctx, &storev1.OrganizationsIIRequest{TenantId: tid, TicketHash: ticketHash}, o.c.rpc.OrganizationsIIFindInvitation)
	if err != nil {
		return nil, err
	}
	x, err := organizationInvitationFromPB(v.Invitation)
	return x, err
}
func (s *Server) OrganizationsIIFindInvitation(ctx context.Context, q *storev1.OrganizationsIIRequest) (*storev1.OrganizationsIIResponse, error) {
	out := &storev1.OrganizationsIIResponse{}
	return s.orgIIServe(q.TxId, out, func(o store.OrganizationsII) error {
		v, err := o.FindInvitation(ctx, q.TenantId, q.TicketHash)
		if err != nil {
			return err
		}
		out.Invitation, err = organizationInvitationToPB(v)
		return err
	}), nil
}

func (o clientOrganizationsII) ListInvitations(ctx context.Context, tid, orgID string, p store.OrgPage) (store.OrgResult[store.OrganizationInvitation], error) {
	v, err := orgIICall(o.c, ctx, &storev1.OrganizationsIIRequest{TenantId: tid, OrganizationId: orgID, Page: orgPageToPB(p)}, o.c.rpc.OrganizationsIIListInvitations)
	if err != nil {
		return store.OrgResult[store.OrganizationInvitation]{}, err
	}
	items := make([]store.OrganizationInvitation, 0, len(v.Invitations))
	for _, pb := range v.Invitations {
		x, e := organizationInvitationFromPB(pb)
		if e != nil {
			return store.OrgResult[store.OrganizationInvitation]{}, e
		}
		if x == nil {
			return store.OrgResult[store.OrganizationInvitation]{}, store.ErrInvalid
		}
		items = append(items, *x)
	}
	return store.OrgResult[store.OrganizationInvitation]{Items: items, Total: int(v.Total), Next: v.Next}, nil
}
func (s *Server) OrganizationsIIListInvitations(ctx context.Context, q *storev1.OrganizationsIIRequest) (*storev1.OrganizationsIIResponse, error) {
	out := &storev1.OrganizationsIIResponse{}
	return s.orgIIServe(q.TxId, out, func(o store.OrganizationsII) error {
		v, err := o.ListInvitations(ctx, q.TenantId, q.OrganizationId, orgPageFromPB(q.Page))
		if err != nil {
			return err
		}
		out.Total = int64(v.Total)
		out.Next = v.Next
		for _, x := range v.Items {
			pb, e := organizationInvitationToPB(&x)
			if e != nil {
				return e
			}
			out.Invitations = append(out.Invitations, pb)
		}
		return nil
	}), nil
}

func (o clientOrganizationsII) DeleteInvitation(ctx context.Context, tid, orgID, id string) error {
	v, err := orgIICall(o.c, ctx, &storev1.OrganizationsIIRequest{TenantId: tid, OrganizationId: orgID, Id: id}, o.c.rpc.OrganizationsIIDeleteInvitation)
	_ = v
	return err
}
func (s *Server) OrganizationsIIDeleteInvitation(ctx context.Context, q *storev1.OrganizationsIIRequest) (*storev1.OrganizationsIIResponse, error) {
	out := &storev1.OrganizationsIIResponse{}
	return s.orgIIServe(q.TxId, out, func(o store.OrganizationsII) error {
		return o.DeleteInvitation(ctx, q.TenantId, q.OrganizationId, q.Id)
	}), nil
}

func (o clientOrganizationsII) ConsumeInvitation(ctx context.Context, tid, orgID, id, transactionID, userID string, now time.Time) (store.InvitationReceipt, error) {
	v, err := orgIICall(o.c, ctx, &storev1.OrganizationsIIRequest{TenantId: tid, OrganizationId: orgID, Id: id, TransactionId: transactionID, UserId: userID, Now: tsToPB(now)}, o.c.rpc.OrganizationsIIConsumeInvitation)
	if err != nil {
		return store.InvitationReceipt{}, err
	}
	x, err := invitationReceiptFromPB(v.Receipt)
	if err != nil {
		return store.InvitationReceipt{}, err
	}
	if x == nil {
		return store.InvitationReceipt{}, store.ErrInvalid
	}
	return *x, nil
}
func (s *Server) OrganizationsIIConsumeInvitation(ctx context.Context, q *storev1.OrganizationsIIRequest) (*storev1.OrganizationsIIResponse, error) {
	out := &storev1.OrganizationsIIResponse{}
	return s.orgIIServe(q.TxId, out, func(o store.OrganizationsII) error {
		if err := checkTS(q.Now); err != nil {
			return err
		}
		v, err := o.ConsumeInvitation(ctx, q.TenantId, q.OrganizationId, q.Id, q.TransactionId, q.UserId, tsFromPB(q.Now))
		if err != nil {
			return err
		}
		out.Receipt, err = invitationReceiptToPB(&v)
		return err
	}), nil
}

func (o clientOrganizationsII) GetInvitationReceipt(ctx context.Context, tid, transactionID string) (*store.InvitationReceipt, error) {
	v, err := orgIICall(o.c, ctx, &storev1.OrganizationsIIRequest{TenantId: tid, TransactionId: transactionID}, o.c.rpc.OrganizationsIIGetInvitationReceipt)
	if err != nil {
		return nil, err
	}
	x, err := invitationReceiptFromPB(v.Receipt)
	return x, err
}
func (s *Server) OrganizationsIIGetInvitationReceipt(ctx context.Context, q *storev1.OrganizationsIIRequest) (*storev1.OrganizationsIIResponse, error) {
	out := &storev1.OrganizationsIIResponse{}
	return s.orgIIServe(q.TxId, out, func(o store.OrganizationsII) error {
		v, err := o.GetInvitationReceipt(ctx, q.TenantId, q.TransactionId)
		if err != nil {
			return err
		}
		out.Receipt, err = invitationReceiptToPB(v)
		return err
	}), nil
}

func (o clientOrganizationsII) PutClients(ctx context.Context, tid, orgID string, clients []store.OrganizationClient) error {
	pb := make([]*storev1.OrganizationClientMsg, 0, len(clients))
	for _, x := range clients {
		v, _ := organizationClientToPB(&x)
		pb = append(pb, v)
	}
	v, err := orgIICall(o.c, ctx, &storev1.OrganizationsIIRequest{TenantId: tid, OrganizationId: orgID, Clients: pb}, o.c.rpc.OrganizationsIIPutClients)
	_ = v
	return err
}
func (s *Server) OrganizationsIIPutClients(ctx context.Context, q *storev1.OrganizationsIIRequest) (*storev1.OrganizationsIIResponse, error) {
	out := &storev1.OrganizationsIIResponse{}
	return s.orgIIServe(q.TxId, out, func(o store.OrganizationsII) error {
		in := make([]store.OrganizationClient, 0, len(q.Clients))
		for _, pb := range q.Clients {
			x, e := organizationClientFromPB(pb)
			if e != nil {
				return e
			}
			if x == nil {
				return store.ErrInvalid
			}
			in = append(in, *x)
		}
		return o.PutClients(ctx, q.TenantId, q.OrganizationId, in)
	}), nil
}

func (o clientOrganizationsII) GetClient(ctx context.Context, tid, orgID, clientID string) (*store.OrganizationClient, error) {
	v, err := orgIICall(o.c, ctx, &storev1.OrganizationsIIRequest{TenantId: tid, OrganizationId: orgID, ClientId: clientID}, o.c.rpc.OrganizationsIIGetClient)
	if err != nil {
		return nil, err
	}
	x, err := organizationClientFromPB(v.Client)
	return x, err
}
func (s *Server) OrganizationsIIGetClient(ctx context.Context, q *storev1.OrganizationsIIRequest) (*storev1.OrganizationsIIResponse, error) {
	out := &storev1.OrganizationsIIResponse{}
	return s.orgIIServe(q.TxId, out, func(o store.OrganizationsII) error {
		v, err := o.GetClient(ctx, q.TenantId, q.OrganizationId, q.ClientId)
		if err != nil {
			return err
		}
		out.Client, err = organizationClientToPB(v)
		return err
	}), nil
}

func (o clientOrganizationsII) ListClients(ctx context.Context, tid, orgID string, p store.OrgPage) (store.OrgResult[store.OrganizationClient], error) {
	v, err := orgIICall(o.c, ctx, &storev1.OrganizationsIIRequest{TenantId: tid, OrganizationId: orgID, Page: orgPageToPB(p)}, o.c.rpc.OrganizationsIIListClients)
	if err != nil {
		return store.OrgResult[store.OrganizationClient]{}, err
	}
	items := make([]store.OrganizationClient, 0, len(v.Clients))
	for _, pb := range v.Clients {
		x, e := organizationClientFromPB(pb)
		if e != nil {
			return store.OrgResult[store.OrganizationClient]{}, e
		}
		if x == nil {
			return store.OrgResult[store.OrganizationClient]{}, store.ErrInvalid
		}
		items = append(items, *x)
	}
	return store.OrgResult[store.OrganizationClient]{Items: items, Total: int(v.Total), Next: v.Next}, nil
}
func (s *Server) OrganizationsIIListClients(ctx context.Context, q *storev1.OrganizationsIIRequest) (*storev1.OrganizationsIIResponse, error) {
	out := &storev1.OrganizationsIIResponse{}
	return s.orgIIServe(q.TxId, out, func(o store.OrganizationsII) error {
		v, err := o.ListClients(ctx, q.TenantId, q.OrganizationId, orgPageFromPB(q.Page))
		if err != nil {
			return err
		}
		out.Total = int64(v.Total)
		out.Next = v.Next
		for _, x := range v.Items {
			pb, e := organizationClientToPB(&x)
			if e != nil {
				return e
			}
			out.Clients = append(out.Clients, pb)
		}
		return nil
	}), nil
}

func (o clientOrganizationsII) DeleteClients(ctx context.Context, tid, orgID string, clientIDs []string) error {
	v, err := orgIICall(o.c, ctx, &storev1.OrganizationsIIRequest{TenantId: tid, OrganizationId: orgID, Ids: clientIDs}, o.c.rpc.OrganizationsIIDeleteClients)
	_ = v
	return err
}
func (s *Server) OrganizationsIIDeleteClients(ctx context.Context, q *storev1.OrganizationsIIRequest) (*storev1.OrganizationsIIResponse, error) {
	out := &storev1.OrganizationsIIResponse{}
	return s.orgIIServe(q.TxId, out, func(o store.OrganizationsII) error {
		return o.DeleteClients(ctx, q.TenantId, q.OrganizationId, q.Ids)
	}), nil
}

func (o clientOrganizationsII) PutClientGrant(ctx context.Context, tid, orgID, grantID string) error {
	v, err := orgIICall(o.c, ctx, &storev1.OrganizationsIIRequest{TenantId: tid, OrganizationId: orgID, GrantId: grantID}, o.c.rpc.OrganizationsIIPutClientGrant)
	_ = v
	return err
}
func (s *Server) OrganizationsIIPutClientGrant(ctx context.Context, q *storev1.OrganizationsIIRequest) (*storev1.OrganizationsIIResponse, error) {
	out := &storev1.OrganizationsIIResponse{}
	return s.orgIIServe(q.TxId, out, func(o store.OrganizationsII) error {
		return o.PutClientGrant(ctx, q.TenantId, q.OrganizationId, q.GrantId)
	}), nil
}

func (o clientOrganizationsII) DeleteClientGrant(ctx context.Context, tid, orgID, grantID string) error {
	v, err := orgIICall(o.c, ctx, &storev1.OrganizationsIIRequest{TenantId: tid, OrganizationId: orgID, GrantId: grantID}, o.c.rpc.OrganizationsIIDeleteClientGrant)
	_ = v
	return err
}
func (s *Server) OrganizationsIIDeleteClientGrant(ctx context.Context, q *storev1.OrganizationsIIRequest) (*storev1.OrganizationsIIResponse, error) {
	out := &storev1.OrganizationsIIResponse{}
	return s.orgIIServe(q.TxId, out, func(o store.OrganizationsII) error {
		return o.DeleteClientGrant(ctx, q.TenantId, q.OrganizationId, q.GrantId)
	}), nil
}

func (o clientOrganizationsII) ListClientGrants(ctx context.Context, tid, orgID string, p store.OrgPage) (store.OrgResult[store.ClientGrant], error) {
	v, err := orgIICall(o.c, ctx, &storev1.OrganizationsIIRequest{TenantId: tid, OrganizationId: orgID, Page: orgPageToPB(p)}, o.c.rpc.OrganizationsIIListClientGrants)
	if err != nil {
		return store.OrgResult[store.ClientGrant]{}, err
	}
	items := make([]store.ClientGrant, 0, len(v.Grants))
	for _, pb := range v.Grants {
		x, e := clientGrantFromPB(pb)
		if e != nil {
			return store.OrgResult[store.ClientGrant]{}, e
		}
		if x == nil {
			return store.OrgResult[store.ClientGrant]{}, store.ErrInvalid
		}
		items = append(items, *x)
	}
	return store.OrgResult[store.ClientGrant]{Items: items, Total: int(v.Total), Next: v.Next}, nil
}
func (s *Server) OrganizationsIIListClientGrants(ctx context.Context, q *storev1.OrganizationsIIRequest) (*storev1.OrganizationsIIResponse, error) {
	out := &storev1.OrganizationsIIResponse{}
	return s.orgIIServe(q.TxId, out, func(o store.OrganizationsII) error {
		v, err := o.ListClientGrants(ctx, q.TenantId, q.OrganizationId, orgPageFromPB(q.Page))
		if err != nil {
			return err
		}
		out.Total = int64(v.Total)
		out.Next = v.Next
		for _, x := range v.Items {
			pb, e := clientGrantToPB(&x)
			if e != nil {
				return e
			}
			out.Grants = append(out.Grants, pb)
		}
		return nil
	}), nil
}

func (o clientOrganizationsII) GrantOrganizations(ctx context.Context, tid, grantID string, p store.OrgPage) (store.OrgResult[store.Organization], error) {
	v, err := orgIICall(o.c, ctx, &storev1.OrganizationsIIRequest{TenantId: tid, GrantId: grantID, Page: orgPageToPB(p)}, o.c.rpc.OrganizationsIIGrantOrganizations)
	if err != nil {
		return store.OrgResult[store.Organization]{}, err
	}
	items := make([]store.Organization, 0, len(v.Organizations))
	for _, pb := range v.Organizations {
		x := orgFromPB(pb)
		if x == nil {
			return store.OrgResult[store.Organization]{}, store.ErrInvalid
		}
		items = append(items, *x)
	}
	return store.OrgResult[store.Organization]{Items: items, Total: int(v.Total), Next: v.Next}, nil
}
func (s *Server) OrganizationsIIGrantOrganizations(ctx context.Context, q *storev1.OrganizationsIIRequest) (*storev1.OrganizationsIIResponse, error) {
	out := &storev1.OrganizationsIIResponse{}
	return s.orgIIServe(q.TxId, out, func(o store.OrganizationsII) error {
		v, err := o.GrantOrganizations(ctx, q.TenantId, q.GrantId, orgPageFromPB(q.Page))
		if err != nil {
			return err
		}
		out.Total = int64(v.Total)
		out.Next = v.Next
		for _, x := range v.Items {
			pb := orgToPB(&x)
			out.Organizations = append(out.Organizations, pb)
		}
		return nil
	}), nil
}

func (o clientOrganizationsII) HasClientGrant(ctx context.Context, tid, orgID, grantID string) (bool, error) {
	v, err := orgIICall(o.c, ctx, &storev1.OrganizationsIIRequest{TenantId: tid, OrganizationId: orgID, GrantId: grantID}, o.c.rpc.OrganizationsIIHasClientGrant)
	if err != nil {
		return false, err
	}
	return v.Flag, nil
}
func (s *Server) OrganizationsIIHasClientGrant(ctx context.Context, q *storev1.OrganizationsIIRequest) (*storev1.OrganizationsIIResponse, error) {
	out := &storev1.OrganizationsIIResponse{}
	return s.orgIIServe(q.TxId, out, func(o store.OrganizationsII) error {
		v, err := o.HasClientGrant(ctx, q.TenantId, q.OrganizationId, q.GrantId)
		if err != nil {
			return err
		}
		out.Flag = v
		return nil
	}), nil
}

func (o clientOrganizationsII) PutDiscoveryDomain(ctx context.Context, in *store.OrganizationDiscoveryDomain, create bool) error {
	pb, err := organizationDiscoveryDomainToPB(in)
	if err != nil {
		return err
	}
	v, err := orgIICall(o.c, ctx, &storev1.OrganizationsIIRequest{DiscoveryDomain: pb, Create: create}, o.c.rpc.OrganizationsIIPutDiscoveryDomain)
	_ = v
	return err
}
func (s *Server) OrganizationsIIPutDiscoveryDomain(ctx context.Context, q *storev1.OrganizationsIIRequest) (*storev1.OrganizationsIIResponse, error) {
	out := &storev1.OrganizationsIIResponse{}
	return s.orgIIServe(q.TxId, out, func(o store.OrganizationsII) error {
		in, err := organizationDiscoveryDomainFromPB(q.DiscoveryDomain)
		if err != nil {
			return err
		}
		if in == nil {
			return store.ErrInvalid
		}
		return o.PutDiscoveryDomain(ctx, in, q.Create)
	}), nil
}

func (o clientOrganizationsII) GetDiscoveryDomain(ctx context.Context, tid, orgID, id string) (*store.OrganizationDiscoveryDomain, error) {
	v, err := orgIICall(o.c, ctx, &storev1.OrganizationsIIRequest{TenantId: tid, OrganizationId: orgID, Id: id}, o.c.rpc.OrganizationsIIGetDiscoveryDomain)
	if err != nil {
		return nil, err
	}
	x, err := organizationDiscoveryDomainFromPB(v.DiscoveryDomain)
	return x, err
}
func (s *Server) OrganizationsIIGetDiscoveryDomain(ctx context.Context, q *storev1.OrganizationsIIRequest) (*storev1.OrganizationsIIResponse, error) {
	out := &storev1.OrganizationsIIResponse{}
	return s.orgIIServe(q.TxId, out, func(o store.OrganizationsII) error {
		v, err := o.GetDiscoveryDomain(ctx, q.TenantId, q.OrganizationId, q.Id)
		if err != nil {
			return err
		}
		out.DiscoveryDomain, err = organizationDiscoveryDomainToPB(v)
		return err
	}), nil
}

func (o clientOrganizationsII) GetDiscoveryDomainByName(ctx context.Context, tid, orgID, domain string) (*store.OrganizationDiscoveryDomain, error) {
	v, err := orgIICall(o.c, ctx, &storev1.OrganizationsIIRequest{TenantId: tid, OrganizationId: orgID, Domain: domain}, o.c.rpc.OrganizationsIIGetDiscoveryDomainByName)
	if err != nil {
		return nil, err
	}
	x, err := organizationDiscoveryDomainFromPB(v.DiscoveryDomain)
	return x, err
}
func (s *Server) OrganizationsIIGetDiscoveryDomainByName(ctx context.Context, q *storev1.OrganizationsIIRequest) (*storev1.OrganizationsIIResponse, error) {
	out := &storev1.OrganizationsIIResponse{}
	return s.orgIIServe(q.TxId, out, func(o store.OrganizationsII) error {
		v, err := o.GetDiscoveryDomainByName(ctx, q.TenantId, q.OrganizationId, q.Domain)
		if err != nil {
			return err
		}
		out.DiscoveryDomain, err = organizationDiscoveryDomainToPB(v)
		return err
	}), nil
}

func (o clientOrganizationsII) ListDiscoveryDomains(ctx context.Context, tid, orgID string, p store.OrgPage) (store.OrgResult[store.OrganizationDiscoveryDomain], error) {
	v, err := orgIICall(o.c, ctx, &storev1.OrganizationsIIRequest{TenantId: tid, OrganizationId: orgID, Page: orgPageToPB(p)}, o.c.rpc.OrganizationsIIListDiscoveryDomains)
	if err != nil {
		return store.OrgResult[store.OrganizationDiscoveryDomain]{}, err
	}
	items := make([]store.OrganizationDiscoveryDomain, 0, len(v.DiscoveryDomains))
	for _, pb := range v.DiscoveryDomains {
		x, e := organizationDiscoveryDomainFromPB(pb)
		if e != nil {
			return store.OrgResult[store.OrganizationDiscoveryDomain]{}, e
		}
		if x == nil {
			return store.OrgResult[store.OrganizationDiscoveryDomain]{}, store.ErrInvalid
		}
		items = append(items, *x)
	}
	return store.OrgResult[store.OrganizationDiscoveryDomain]{Items: items, Total: int(v.Total), Next: v.Next}, nil
}
func (s *Server) OrganizationsIIListDiscoveryDomains(ctx context.Context, q *storev1.OrganizationsIIRequest) (*storev1.OrganizationsIIResponse, error) {
	out := &storev1.OrganizationsIIResponse{}
	return s.orgIIServe(q.TxId, out, func(o store.OrganizationsII) error {
		v, err := o.ListDiscoveryDomains(ctx, q.TenantId, q.OrganizationId, orgPageFromPB(q.Page))
		if err != nil {
			return err
		}
		out.Total = int64(v.Total)
		out.Next = v.Next
		for _, x := range v.Items {
			pb, e := organizationDiscoveryDomainToPB(&x)
			if e != nil {
				return e
			}
			out.DiscoveryDomains = append(out.DiscoveryDomains, pb)
		}
		return nil
	}), nil
}

func (o clientOrganizationsII) DeleteDiscoveryDomain(ctx context.Context, tid, orgID, id string) error {
	v, err := orgIICall(o.c, ctx, &storev1.OrganizationsIIRequest{TenantId: tid, OrganizationId: orgID, Id: id}, o.c.rpc.OrganizationsIIDeleteDiscoveryDomain)
	_ = v
	return err
}
func (s *Server) OrganizationsIIDeleteDiscoveryDomain(ctx context.Context, q *storev1.OrganizationsIIRequest) (*storev1.OrganizationsIIResponse, error) {
	out := &storev1.OrganizationsIIResponse{}
	return s.orgIIServe(q.TxId, out, func(o store.OrganizationsII) error {
		return o.DeleteDiscoveryDomain(ctx, q.TenantId, q.OrganizationId, q.Id)
	}), nil
}

func (o clientOrganizationsII) DiscoverOrganizations(ctx context.Context, tid, normalizedDomain string) ([]store.Organization, error) {
	v, err := orgIICall(o.c, ctx, &storev1.OrganizationsIIRequest{TenantId: tid, Domain: normalizedDomain}, o.c.rpc.OrganizationsIIDiscoverOrganizations)
	if err != nil {
		return nil, err
	}
	items := make([]store.Organization, 0, len(v.Organizations))
	for _, pb := range v.Organizations {
		x := orgFromPB(pb)
		if x == nil {
			return nil, store.ErrInvalid
		}
		items = append(items, *x)
	}
	return items, nil
}
func (s *Server) OrganizationsIIDiscoverOrganizations(ctx context.Context, q *storev1.OrganizationsIIRequest) (*storev1.OrganizationsIIResponse, error) {
	out := &storev1.OrganizationsIIResponse{}
	return s.orgIIServe(q.TxId, out, func(o store.OrganizationsII) error {
		v, err := o.DiscoverOrganizations(ctx, q.TenantId, q.Domain)
		if err != nil {
			return err
		}
		for _, x := range v {
			pb := orgToPB(&x)
			out.Organizations = append(out.Organizations, pb)
		}
		return nil
	}), nil
}
