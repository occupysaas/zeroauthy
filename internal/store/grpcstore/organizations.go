package grpcstore

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc"
)

// organizationsCapability is the capability version this client and server speak.
const organizationsCapability = 1

// orgCapState caches a definitive capability answer, shared by a client and
// the transaction clients derived from it. Transient failures are not cached.
type orgCapState struct{ v atomic.Int32 } // 0 unknown, 1 supported, 2 unsupported

type clientOrganizations struct{ c *Client }

// Organizations returns the plugin-backed repository. A plugin without the
// RPCs yields store.ErrOrganizationsUnavailable, never an empty result.
func (c *Client) Organizations() store.Organizations { return clientOrganizations{c} }

// CheckOrganizationsSupport probes the plugin's Organizations capability.
// A definitive answer is cached for OrganizationsSupported.
func (c *Client) CheckOrganizationsSupport(ctx context.Context) error {
	v, err := c.rpc.OrganizationsCapabilities(ctx, &storev1.PingRequest{})
	if err != nil {
		err = fmt.Errorf("storage plugin Organizations: %w", capabilityError(err, store.ErrOrganizationsUnavailable))
		c.cacheOrgCapability(err)
		return err
	}
	if err := errFromPB(v.GetError()); err != nil {
		return err
	}
	if v.Version < organizationsCapability {
		err = fmt.Errorf("storage plugin Organizations: capability %d required (plugin provides %d); upgrade the storage plugin: %w", organizationsCapability, v.Version, store.ErrOrganizationsUnavailable)
		c.cacheOrgCapability(err)
		return err
	}
	c.orgCap.v.Store(1)
	return nil
}

func (c *Client) cacheOrgCapability(err error) {
	if isOrgUnavailable(err) {
		c.orgCap.v.Store(2)
	}
}

// OrganizationsSupported reports whether the plugin serves Organizations,
// probing once on first use.
func (c *Client) OrganizationsSupported() bool {
	switch c.orgCap.v.Load() {
	case 1:
		return true
	case 2:
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.CheckOrganizationsSupport(ctx) == nil
}

func (s *Server) OrganizationsCapabilities(context.Context, *storev1.PingRequest) (*storev1.OrganizationsCapabilitiesResult, error) {
	return &storev1.OrganizationsCapabilitiesResult{Version: organizationsCapability}, nil
}

func orgToPB(o *store.Organization) *storev1.OrganizationMsg {
	if o == nil {
		return nil
	}
	pb := &storev1.OrganizationMsg{TenantId: o.TenantID, Id: o.ID, Name: o.Name, DisplayName: o.DisplayName,
		IsAppEntitlementActive: o.IsAppEntitlementActive, Metadata: stringMapToPB(o.Metadata), ThirdPartyClientAccess: o.ThirdPartyClientAccess,
		CreatedAt: tsToPB(o.CreatedAt), UpdatedAt: tsToPB(o.UpdatedAt)}
	if b := o.Branding; b != nil {
		pb.Branding = &storev1.OrganizationBrandingMsg{LogoUrl: cloneString(b.LogoURL)}
		if b.Colors != nil {
			pb.Branding.Colors = &storev1.OrganizationColorsMsg{Primary: b.Colors.Primary, PageBackground: b.Colors.PageBackground}
		}
	}
	return pb
}

func orgFromPB(pb *storev1.OrganizationMsg) *store.Organization {
	if pb == nil {
		return nil
	}
	o := &store.Organization{TenantID: pb.TenantId, ID: pb.Id, Name: pb.Name, DisplayName: pb.DisplayName,
		IsAppEntitlementActive: pb.IsAppEntitlementActive, Metadata: stringMapFromPB(pb.Metadata), ThirdPartyClientAccess: pb.ThirdPartyClientAccess,
		CreatedAt: tsFromPB(pb.CreatedAt), UpdatedAt: tsFromPB(pb.UpdatedAt)}
	if b := pb.Branding; b != nil {
		o.Branding = &store.OrgBranding{LogoURL: cloneString(b.LogoUrl)}
		if b.Colors != nil {
			o.Branding.Colors = &store.OrgColors{Primary: b.Colors.Primary, PageBackground: b.Colors.PageBackground}
		}
	}
	return o
}

func cloneString(s *string) *string {
	if s == nil {
		return nil
	}
	v := *s
	return &v
}

func orgConnToPB(c store.OrganizationConnection) *storev1.OrganizationConnectionMsg {
	p := &storev1.OrganizationConnectionMsg{TenantId: c.TenantID, OrganizationId: c.OrganizationID, ConnectionId: c.ConnectionID, AssignMembershipOnLogin: c.AssignMembershipOnLogin, ShowAsButton: c.ShowAsButton, IsSignupEnabled: c.IsSignupEnabled, ConnectionName: c.ConnectionName, OrganizationAccessLevel: c.OrganizationAccessLevel, OrganizationMemberAccessLevel: c.OrganizationMemberAccessLevel}
	if c.IsEnabledSet {
		v := c.IsEnabled
		p.IsEnabled = &v
	}
	return p
}
func orgConnFromPB(c *storev1.OrganizationConnectionMsg) store.OrganizationConnection {
	// Preserve omission on writes. Persisted modern rows carry optional presence;
	// old server reads are normalized by the client read boundary below.
	return store.OrganizationConnection{TenantID: c.GetTenantId(), OrganizationID: c.GetOrganizationId(), ConnectionID: c.GetConnectionId(), AssignMembershipOnLogin: c.GetAssignMembershipOnLogin(), ShowAsButton: c.GetShowAsButton(), IsSignupEnabled: c.GetIsSignupEnabled(), IsEnabled: c.GetIsEnabled(), IsEnabledSet: c != nil && c.IsEnabled != nil, ConnectionName: c.GetConnectionName(), OrganizationAccessLevel: c.GetOrganizationAccessLevel(), OrganizationMemberAccessLevel: c.GetOrganizationMemberAccessLevel()}
}
func orgConnReadFromPB(c *storev1.OrganizationConnectionMsg) store.OrganizationConnection {
	out := orgConnFromPB(c)
	if !out.IsEnabledSet {
		out.IsEnabled = true
		out.IsEnabledSet = true
	}
	if out.OrganizationAccessLevel == "" {
		out.OrganizationAccessLevel = "none"
	}
	if out.OrganizationMemberAccessLevel == "" {
		out.OrganizationMemberAccessLevel = "limited"
	}
	return out
}
func orgConnActiveII(c store.OrganizationConnection) bool {
	return (c.IsEnabledSet && !c.IsEnabled) || c.ConnectionName != "" || (c.OrganizationAccessLevel != "" && c.OrganizationAccessLevel != "none") || (c.OrganizationMemberAccessLevel != "" && c.OrganizationMemberAccessLevel != "limited")
}

func orgConnsToPB(cs []store.OrganizationConnection) []*storev1.OrganizationConnectionMsg {
	out := make([]*storev1.OrganizationConnectionMsg, 0, len(cs))
	for _, c := range cs {
		out = append(out, orgConnToPB(c))
	}
	return out
}

func orgConnsFromPB(cs []*storev1.OrganizationConnectionMsg) []store.OrganizationConnection {
	out := make([]store.OrganizationConnection, 0, len(cs))
	for _, c := range cs {
		out = append(out, orgConnFromPB(c))
	}
	return out
}

func orgPageToPB(p store.OrgPage) *storev1.OrganizationPageMsg {
	return &storev1.OrganizationPageMsg{Page: int64(p.Page), PerPage: int64(p.PerPage), IncludeTotals: p.IncludeTotals,
		From: p.From, Take: int64(p.Take), Sort: p.Sort}
}

func orgPageFromPB(p *storev1.OrganizationPageMsg) store.OrgPage {
	return store.OrgPage{Page: int(p.GetPage()), PerPage: int(p.GetPerPage()), IncludeTotals: p.GetIncludeTotals(),
		From: p.GetFrom(), Take: int(p.GetTake()), Sort: p.GetSort()}
}

func isOrgUnavailable(err error) bool {
	return err != nil && errors.Is(err, store.ErrOrganizationsUnavailable)
}

// orgCall performs one Organizations RPC and maps the outcome. An RPC the
// plugin lacks reads as store.ErrOrganizationsUnavailable and is cached.
func orgCall(c *Client, op string, q *storev1.OrganizationsRequest,
	rpc func(context.Context, *storev1.OrganizationsRequest, ...grpc.CallOption) (*storev1.OrganizationsResponse, error),
	ctx context.Context) (*storev1.OrganizationsResponse, error) {
	q.TxId = c.txID
	v, err := rpc(ctx, q)
	if err != nil {
		err = fmt.Errorf("storage plugin Organizations: %s: %w", op, capabilityError(err, store.ErrOrganizationsUnavailable))
		c.cacheOrgCapability(err)
		return nil, err
	}
	if err := errFromPB(v.GetError()); err != nil {
		return nil, err
	}
	return v, nil
}

// orgServe runs fn against the (possibly transactional) backing store and
// reports its error in the response.
func (srv *Server) orgServe(txID string, out *storev1.OrganizationsResponse, fn func(store.Organizations) error) *storev1.OrganizationsResponse {
	err := srv.with(txID, func(s store.Store) error { return fn(s.Organizations()) })
	out.Error = errToPB(err)
	return out
}

func orgListToPB[T any](r store.OrgResult[T], out *storev1.OrganizationsResponse, add func(T)) {
	out.Total, out.Next = int64(r.Total), r.Next
	for _, it := range r.Items {
		add(it)
	}
}

func (o clientOrganizations) Create(ctx context.Context, org *store.Organization, conns []store.OrganizationConnection) error {
	active := org != nil && org.IsAppEntitlementActive
	for _, c := range conns {
		active = active || orgConnActiveII(c)
	}
	if active {
		if err := o.c.requireOrganizationsII(ctx); err != nil {
			return err
		}
	}
	_, err := orgCall(o.c, "Create", &storev1.OrganizationsRequest{Organization: orgToPB(org), Connections: orgConnsToPB(conns)}, o.c.rpc.OrganizationsCreate, ctx)
	return err
}
func (srv *Server) OrganizationsCreate(ctx context.Context, q *storev1.OrganizationsRequest) (*storev1.OrganizationsResponse, error) {
	return srv.orgServe(q.TxId, &storev1.OrganizationsResponse{}, func(o store.Organizations) error {
		in := orgFromPB(q.Organization)
		if in == nil {
			return fmt.Errorf("%w: organization required", store.ErrInvalid)
		}
		return o.Create(ctx, in, orgConnsFromPB(q.Connections))
	}), nil
}

func (o clientOrganizations) Get(ctx context.Context, tid, id string) (*store.Organization, error) {
	v, err := orgCall(o.c, "Get", &storev1.OrganizationsRequest{TenantId: tid, OrganizationId: id}, o.c.rpc.OrganizationsGet, ctx)
	if err != nil {
		return nil, err
	}
	return orgFromPB(v.Organization), nil
}
func (srv *Server) OrganizationsGet(ctx context.Context, q *storev1.OrganizationsRequest) (*storev1.OrganizationsResponse, error) {
	out := &storev1.OrganizationsResponse{}
	return srv.orgServe(q.TxId, out, func(o store.Organizations) error {
		v, err := o.Get(ctx, q.TenantId, q.OrganizationId)
		out.Organization = orgToPB(v)
		return err
	}), nil
}

func (o clientOrganizations) GetByName(ctx context.Context, tid, name string) (*store.Organization, error) {
	v, err := orgCall(o.c, "GetByName", &storev1.OrganizationsRequest{TenantId: tid, Name: name}, o.c.rpc.OrganizationsGetByName, ctx)
	if err != nil {
		return nil, err
	}
	return orgFromPB(v.Organization), nil
}
func (srv *Server) OrganizationsGetByName(ctx context.Context, q *storev1.OrganizationsRequest) (*storev1.OrganizationsResponse, error) {
	out := &storev1.OrganizationsResponse{}
	return srv.orgServe(q.TxId, out, func(o store.Organizations) error {
		v, err := o.GetByName(ctx, q.TenantId, q.Name)
		out.Organization = orgToPB(v)
		return err
	}), nil
}

func (o clientOrganizations) orgList(ctx context.Context, op string, q *storev1.OrganizationsRequest,
	rpc func(context.Context, *storev1.OrganizationsRequest, ...grpc.CallOption) (*storev1.OrganizationsResponse, error)) (store.OrgResult[store.Organization], error) {
	out := store.OrgResult[store.Organization]{Items: []store.Organization{}}
	v, err := orgCall(o.c, op, q, rpc, ctx)
	if err != nil {
		return out, err
	}
	out.Total, out.Next = int(v.Total), v.Next
	for _, x := range v.Organizations {
		out.Items = append(out.Items, *orgFromPB(x))
	}
	return out, nil
}
func (o clientOrganizations) List(ctx context.Context, tid string, p store.OrgPage) (store.OrgResult[store.Organization], error) {
	return o.orgList(ctx, "List", &storev1.OrganizationsRequest{TenantId: tid, Page: orgPageToPB(p)}, o.c.rpc.OrganizationsList)
}
func orgsToResponse(out *storev1.OrganizationsResponse) func(store.Organization) {
	return func(x store.Organization) { out.Organizations = append(out.Organizations, orgToPB(&x)) }
}
func (srv *Server) OrganizationsList(ctx context.Context, q *storev1.OrganizationsRequest) (*storev1.OrganizationsResponse, error) {
	out := &storev1.OrganizationsResponse{}
	return srv.orgServe(q.TxId, out, func(o store.Organizations) error {
		r, err := o.List(ctx, q.TenantId, orgPageFromPB(q.Page))
		orgListToPB(r, out, orgsToResponse(out))
		return err
	}), nil
}

func (o clientOrganizations) Update(ctx context.Context, org *store.Organization) error {
	if org != nil && org.IsAppEntitlementActive {
		if err := o.c.requireOrganizationsII(ctx); err != nil {
			return err
		}
	}
	_, err := orgCall(o.c, "Update", &storev1.OrganizationsRequest{Organization: orgToPB(org)}, o.c.rpc.OrganizationsUpdate, ctx)
	return err
}
func (srv *Server) OrganizationsUpdate(ctx context.Context, q *storev1.OrganizationsRequest) (*storev1.OrganizationsResponse, error) {
	return srv.orgServe(q.TxId, &storev1.OrganizationsResponse{}, func(o store.Organizations) error {
		in := orgFromPB(q.Organization)
		if in == nil {
			return fmt.Errorf("%w: organization required", store.ErrInvalid)
		}
		return o.Update(ctx, in)
	}), nil
}

func (o clientOrganizations) Delete(ctx context.Context, tid, id string) error {
	_, err := orgCall(o.c, "Delete", &storev1.OrganizationsRequest{TenantId: tid, OrganizationId: id}, o.c.rpc.OrganizationsDelete, ctx)
	return err
}
func (srv *Server) OrganizationsDelete(ctx context.Context, q *storev1.OrganizationsRequest) (*storev1.OrganizationsResponse, error) {
	return srv.orgServe(q.TxId, &storev1.OrganizationsResponse{}, func(o store.Organizations) error {
		return o.Delete(ctx, q.TenantId, q.OrganizationId)
	}), nil
}

func (o clientOrganizations) Connections(ctx context.Context, tid, orgID string, p store.OrgPage) (store.OrgResult[store.OrganizationConnection], error) {
	out := store.OrgResult[store.OrganizationConnection]{Items: []store.OrganizationConnection{}}
	v, err := orgCall(o.c, "Connections", &storev1.OrganizationsRequest{TenantId: tid, OrganizationId: orgID, Page: orgPageToPB(p)}, o.c.rpc.OrganizationsConnections, ctx)
	if err != nil {
		return out, err
	}
	out.Total, out.Next = int(v.Total), v.Next
	for _, pb := range v.Connections {
		out.Items = append(out.Items, orgConnReadFromPB(pb))
	}
	return out, nil
}
func (srv *Server) OrganizationsConnections(ctx context.Context, q *storev1.OrganizationsRequest) (*storev1.OrganizationsResponse, error) {
	out := &storev1.OrganizationsResponse{}
	return srv.orgServe(q.TxId, out, func(o store.Organizations) error {
		r, err := o.Connections(ctx, q.TenantId, q.OrganizationId, orgPageFromPB(q.Page))
		orgListToPB(r, out, func(c store.OrganizationConnection) { out.Connections = append(out.Connections, orgConnToPB(c)) })
		return err
	}), nil
}

func (o clientOrganizations) GetConnection(ctx context.Context, tid, orgID, connID string) (*store.OrganizationConnection, error) {
	v, err := orgCall(o.c, "GetConnection", &storev1.OrganizationsRequest{TenantId: tid, OrganizationId: orgID, ConnectionId: connID}, o.c.rpc.OrganizationsGetConnection, ctx)
	if err != nil {
		return nil, err
	}
	c := orgConnReadFromPB(v.Connection)
	return &c, nil
}
func (srv *Server) OrganizationsGetConnection(ctx context.Context, q *storev1.OrganizationsRequest) (*storev1.OrganizationsResponse, error) {
	out := &storev1.OrganizationsResponse{}
	return srv.orgServe(q.TxId, out, func(o store.Organizations) error {
		c, err := o.GetConnection(ctx, q.TenantId, q.OrganizationId, q.ConnectionId)
		if c != nil {
			out.Connection = orgConnToPB(*c)
		}
		return err
	}), nil
}

func (o clientOrganizations) PutConnection(ctx context.Context, c store.OrganizationConnection, create bool) error {
	if orgConnActiveII(c) {
		if err := o.c.requireOrganizationsII(ctx); err != nil {
			return err
		}
	}
	_, err := orgCall(o.c, "PutConnection", &storev1.OrganizationsRequest{Connection: orgConnToPB(c), Flag: create}, o.c.rpc.OrganizationsPutConnection, ctx)
	return err
}
func (srv *Server) OrganizationsPutConnection(ctx context.Context, q *storev1.OrganizationsRequest) (*storev1.OrganizationsResponse, error) {
	return srv.orgServe(q.TxId, &storev1.OrganizationsResponse{}, func(o store.Organizations) error {
		return o.PutConnection(ctx, orgConnFromPB(q.Connection), q.Flag)
	}), nil
}

func (o clientOrganizations) DeleteConnection(ctx context.Context, tid, orgID, connID string) error {
	_, err := orgCall(o.c, "DeleteConnection", &storev1.OrganizationsRequest{TenantId: tid, OrganizationId: orgID, ConnectionId: connID}, o.c.rpc.OrganizationsDeleteConnection, ctx)
	return err
}
func (srv *Server) OrganizationsDeleteConnection(ctx context.Context, q *storev1.OrganizationsRequest) (*storev1.OrganizationsResponse, error) {
	return srv.orgServe(q.TxId, &storev1.OrganizationsResponse{}, func(o store.Organizations) error {
		return o.DeleteConnection(ctx, q.TenantId, q.OrganizationId, q.ConnectionId)
	}), nil
}

func (o clientOrganizations) ConnectionsByConnection(ctx context.Context, tid, connID string) ([]store.OrganizationConnection, error) {
	v, err := orgCall(o.c, "ConnectionsByConnection", &storev1.OrganizationsRequest{TenantId: tid, ConnectionId: connID}, o.c.rpc.OrganizationsConnectionsByConnection, ctx)
	if err != nil {
		return nil, err
	}
	out := make([]store.OrganizationConnection, 0, len(v.Connections))
	for _, pb := range v.Connections {
		out = append(out, orgConnReadFromPB(pb))
	}
	return out, nil
}
func (srv *Server) OrganizationsConnectionsByConnection(ctx context.Context, q *storev1.OrganizationsRequest) (*storev1.OrganizationsResponse, error) {
	out := &storev1.OrganizationsResponse{}
	return srv.orgServe(q.TxId, out, func(o store.Organizations) error {
		cs, err := o.ConnectionsByConnection(ctx, q.TenantId, q.ConnectionId)
		out.Connections = orgConnsToPB(cs)
		return err
	}), nil
}

// orgIDs runs a paged RPC that returns string IDs.
func (o clientOrganizations) orgIDs(ctx context.Context, op string, q *storev1.OrganizationsRequest,
	rpc func(context.Context, *storev1.OrganizationsRequest, ...grpc.CallOption) (*storev1.OrganizationsResponse, error)) (store.OrgResult[string], error) {
	out := store.OrgResult[string]{Items: []string{}}
	v, err := orgCall(o.c, op, q, rpc, ctx)
	if err != nil {
		return out, err
	}
	out.Total, out.Next = int(v.Total), v.Next
	out.Items = append(out.Items, v.Ids...)
	return out, nil
}
func idsToResponse(out *storev1.OrganizationsResponse) func(string) {
	return func(id string) { out.Ids = append(out.Ids, id) }
}

func (o clientOrganizations) Members(ctx context.Context, tid, orgID string, p store.OrgPage) (store.OrgResult[string], error) {
	return o.orgIDs(ctx, "Members", &storev1.OrganizationsRequest{TenantId: tid, OrganizationId: orgID, Page: orgPageToPB(p)}, o.c.rpc.OrganizationsMembers)
}
func (srv *Server) OrganizationsMembers(ctx context.Context, q *storev1.OrganizationsRequest) (*storev1.OrganizationsResponse, error) {
	out := &storev1.OrganizationsResponse{}
	return srv.orgServe(q.TxId, out, func(o store.Organizations) error {
		r, err := o.Members(ctx, q.TenantId, q.OrganizationId, orgPageFromPB(q.Page))
		orgListToPB(r, out, idsToResponse(out))
		return err
	}), nil
}

func (o clientOrganizations) AddMembers(ctx context.Context, tid, orgID string, userIDs []string) error {
	_, err := orgCall(o.c, "AddMembers", &storev1.OrganizationsRequest{TenantId: tid, OrganizationId: orgID, Ids: userIDs}, o.c.rpc.OrganizationsAddMembers, ctx)
	return err
}
func (srv *Server) OrganizationsAddMembers(ctx context.Context, q *storev1.OrganizationsRequest) (*storev1.OrganizationsResponse, error) {
	return srv.orgServe(q.TxId, &storev1.OrganizationsResponse{}, func(o store.Organizations) error {
		return o.AddMembers(ctx, q.TenantId, q.OrganizationId, q.Ids)
	}), nil
}

func (o clientOrganizations) RemoveMembers(ctx context.Context, tid, orgID string, userIDs []string) error {
	_, err := orgCall(o.c, "RemoveMembers", &storev1.OrganizationsRequest{TenantId: tid, OrganizationId: orgID, Ids: userIDs}, o.c.rpc.OrganizationsRemoveMembers, ctx)
	return err
}
func (srv *Server) OrganizationsRemoveMembers(ctx context.Context, q *storev1.OrganizationsRequest) (*storev1.OrganizationsResponse, error) {
	return srv.orgServe(q.TxId, &storev1.OrganizationsResponse{}, func(o store.Organizations) error {
		return o.RemoveMembers(ctx, q.TenantId, q.OrganizationId, q.Ids)
	}), nil
}

func (o clientOrganizations) IsMember(ctx context.Context, tid, orgID, userID string) (bool, error) {
	v, err := orgCall(o.c, "IsMember", &storev1.OrganizationsRequest{TenantId: tid, OrganizationId: orgID, UserId: userID}, o.c.rpc.OrganizationsIsMember, ctx)
	if err != nil {
		return false, err
	}
	return v.Flag, nil
}
func (srv *Server) OrganizationsIsMember(ctx context.Context, q *storev1.OrganizationsRequest) (*storev1.OrganizationsResponse, error) {
	out := &storev1.OrganizationsResponse{}
	return srv.orgServe(q.TxId, out, func(o store.Organizations) error {
		ok, err := o.IsMember(ctx, q.TenantId, q.OrganizationId, q.UserId)
		out.Flag = ok
		return err
	}), nil
}

func (o clientOrganizations) UserOrganizations(ctx context.Context, tid, userID string, p store.OrgPage) (store.OrgResult[store.Organization], error) {
	return o.orgList(ctx, "UserOrganizations", &storev1.OrganizationsRequest{TenantId: tid, UserId: userID, Page: orgPageToPB(p)}, o.c.rpc.OrganizationsUserOrganizations)
}
func (srv *Server) OrganizationsUserOrganizations(ctx context.Context, q *storev1.OrganizationsRequest) (*storev1.OrganizationsResponse, error) {
	out := &storev1.OrganizationsResponse{}
	return srv.orgServe(q.TxId, out, func(o store.Organizations) error {
		r, err := o.UserOrganizations(ctx, q.TenantId, q.UserId, orgPageFromPB(q.Page))
		orgListToPB(r, out, orgsToResponse(out))
		return err
	}), nil
}

func (o clientOrganizations) MemberRoles(ctx context.Context, tid, orgID, userID string, p store.OrgPage) (store.OrgResult[string], error) {
	return o.orgIDs(ctx, "MemberRoles", &storev1.OrganizationsRequest{TenantId: tid, OrganizationId: orgID, UserId: userID, Page: orgPageToPB(p)}, o.c.rpc.OrganizationsMemberRoles)
}
func (srv *Server) OrganizationsMemberRoles(ctx context.Context, q *storev1.OrganizationsRequest) (*storev1.OrganizationsResponse, error) {
	out := &storev1.OrganizationsResponse{}
	return srv.orgServe(q.TxId, out, func(o store.Organizations) error {
		r, err := o.MemberRoles(ctx, q.TenantId, q.OrganizationId, q.UserId, orgPageFromPB(q.Page))
		orgListToPB(r, out, idsToResponse(out))
		return err
	}), nil
}

func (o clientOrganizations) ChangeMemberRoles(ctx context.Context, tid, orgID, userID string, add bool, roleIDs []string) error {
	_, err := orgCall(o.c, "ChangeMemberRoles", &storev1.OrganizationsRequest{TenantId: tid, OrganizationId: orgID, UserId: userID, Flag: add, Ids: roleIDs}, o.c.rpc.OrganizationsChangeMemberRoles, ctx)
	return err
}
func (srv *Server) OrganizationsChangeMemberRoles(ctx context.Context, q *storev1.OrganizationsRequest) (*storev1.OrganizationsResponse, error) {
	return srv.orgServe(q.TxId, &storev1.OrganizationsResponse{}, func(o store.Organizations) error {
		return o.ChangeMemberRoles(ctx, q.TenantId, q.OrganizationId, q.UserId, q.Flag, q.Ids)
	}), nil
}

func (o clientOrganizations) RoleMembers(ctx context.Context, tid, orgID, roleID string, p store.OrgPage) (store.OrgResult[string], error) {
	return o.orgIDs(ctx, "RoleMembers", &storev1.OrganizationsRequest{TenantId: tid, OrganizationId: orgID, RoleId: roleID, Page: orgPageToPB(p)}, o.c.rpc.OrganizationsRoleMembers)
}
func (srv *Server) OrganizationsRoleMembers(ctx context.Context, q *storev1.OrganizationsRequest) (*storev1.OrganizationsResponse, error) {
	out := &storev1.OrganizationsResponse{}
	return srv.orgServe(q.TxId, out, func(o store.Organizations) error {
		r, err := o.RoleMembers(ctx, q.TenantId, q.OrganizationId, q.RoleId, orgPageFromPB(q.Page))
		orgListToPB(r, out, idsToResponse(out))
		return err
	}), nil
}
