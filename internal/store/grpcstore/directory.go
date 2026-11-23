package grpcstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Plan 37c (scim.v1): store.Directory over one DirectoryCall RPC. method is
// the Go method name; args and result are the JSON of dirArgs and dirResult
// (store types encode with their Go field names).

type dirArgs struct {
	TenantID, ConnectionID, ID, Hash, GroupID, RoleID, OrganizationID string `json:",omitempty"`
	Config                                                            *store.SCIMConfig
	Token                                                             *store.SCIMToken
	Group                                                             *store.Group
	Filter                                                            store.GroupFilter
	Page                                                              store.Page
	Add, Remove, Roles                                                []string `json:",omitempty"`
	Replace                                                           bool     `json:",omitempty"`
	Now                                                               time.Time
}

type dirResult struct {
	Config  *store.SCIMConfig   `json:",omitempty"`
	Configs []*store.SCIMConfig `json:",omitempty"`
	Token   *store.SCIMToken    `json:",omitempty"`
	Tokens  []*store.SCIMToken  `json:",omitempty"`
	Group   *store.Group        `json:",omitempty"`
	Groups  []*store.Group      `json:",omitempty"`
	Members []store.GroupMember `json:",omitempty"`
	Roles   []store.GroupRole   `json:",omitempty"`
	Total   int                 `json:",omitempty"`
	// SelfService is the result of a SelfService.* method.
	SelfService json.RawMessage `json:",omitempty"`
}

type clientDirectory struct{ c *Client }

func (c *Client) Directory() store.Directory {
	if c.dirCap.v.Load() == 2 {
		return store.UnimplementedDirectory{}
	}
	return clientDirectory{c}
}

// CheckDirectorySupport latches a definite scim.v1 answer.
func (c *Client) CheckDirectorySupport(ctx context.Context) error {
	switch c.dirCap.v.Load() {
	case 1:
		return nil
	case 2:
		return store.ErrDirectoryUnavailable
	}
	v, err := c.rpc.DirectoryCapabilities(ctx, &storev1.PingRequest{})
	if err != nil {
		err = rpcErr("scim.v1 capability", capabilityError(err, store.ErrDirectoryUnavailable))
	} else {
		err = errFromPB(v.GetError())
		if err == nil && v.GetVersion() < 1 {
			err = store.ErrDirectoryUnavailable
		}
	}
	if errors.Is(err, store.ErrDirectoryUnavailable) {
		c.dirCap.v.Store(2)
	} else if err == nil {
		c.dirCap.v.CompareAndSwap(0, 1)
	}
	if c.dirCap.v.Load() == 2 {
		return store.ErrDirectoryUnavailable
	}
	return err
}

func (c *Client) DirectorySupported() bool {
	switch c.dirCap.v.Load() {
	case 1:
		return true
	case 2:
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.CheckDirectorySupport(ctx) == nil
}

func (d clientDirectory) call(ctx context.Context, method string, a dirArgs) (dirResult, error) {
	var out dirResult
	if err := d.c.CheckDirectorySupport(ctx); err != nil {
		return out, err
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return out, err
	}
	r, err := d.c.rpc.DirectoryCall(ctx, &storev1.DirectoryCallRequest{TxId: d.c.txID, Method: method, Args: raw})
	if err != nil {
		return out, rpcErr("DirectoryCall "+method, err)
	}
	if e := errFromPB(r.GetError()); e != nil {
		return out, e
	}
	if len(r.GetResult()) > 0 {
		if err := json.Unmarshal(r.GetResult(), &out); err != nil {
			return out, fmt.Errorf("DirectoryCall %s: decode result: %w", method, err)
		}
	}
	return out, nil
}

func (d clientDirectory) CreateSCIMConfig(ctx context.Context, c *store.SCIMConfig) error {
	_, err := d.call(ctx, "CreateSCIMConfig", dirArgs{Config: c})
	return err
}
func (d clientDirectory) GetSCIMConfig(ctx context.Context, tid, conn string) (*store.SCIMConfig, error) {
	r, err := d.call(ctx, "GetSCIMConfig", dirArgs{TenantID: tid, ConnectionID: conn})
	return r.Config, err
}
func (d clientDirectory) UpdateSCIMConfig(ctx context.Context, c *store.SCIMConfig) error {
	_, err := d.call(ctx, "UpdateSCIMConfig", dirArgs{Config: c})
	return err
}
func (d clientDirectory) DeleteSCIMConfig(ctx context.Context, tid, conn string) error {
	_, err := d.call(ctx, "DeleteSCIMConfig", dirArgs{TenantID: tid, ConnectionID: conn})
	return err
}
func (d clientDirectory) ListSCIMConfigs(ctx context.Context, tid string) ([]*store.SCIMConfig, error) {
	r, err := d.call(ctx, "ListSCIMConfigs", dirArgs{TenantID: tid})
	if err == nil && r.Configs == nil {
		r.Configs = []*store.SCIMConfig{}
	}
	return r.Configs, err
}
func (d clientDirectory) CreateSCIMToken(ctx context.Context, t *store.SCIMToken) error {
	_, err := d.call(ctx, "CreateSCIMToken", dirArgs{Token: t})
	return err
}
func (d clientDirectory) ListSCIMTokens(ctx context.Context, tid, conn string) ([]*store.SCIMToken, error) {
	r, err := d.call(ctx, "ListSCIMTokens", dirArgs{TenantID: tid, ConnectionID: conn})
	if err == nil && r.Tokens == nil {
		r.Tokens = []*store.SCIMToken{}
	}
	return r.Tokens, err
}
func (d clientDirectory) DeleteSCIMToken(ctx context.Context, tid, conn, id string) error {
	_, err := d.call(ctx, "DeleteSCIMToken", dirArgs{TenantID: tid, ConnectionID: conn, ID: id})
	return err
}
func (d clientDirectory) UseSCIMToken(ctx context.Context, tid, hash string, now time.Time) (*store.SCIMToken, error) {
	r, err := d.call(ctx, "UseSCIMToken", dirArgs{TenantID: tid, Hash: hash, Now: now})
	return r.Token, err
}
func (d clientDirectory) CreateGroup(ctx context.Context, g *store.Group) error {
	_, err := d.call(ctx, "CreateGroup", dirArgs{Group: g})
	return err
}
func (d clientDirectory) GetGroup(ctx context.Context, tid, id string) (*store.Group, error) {
	r, err := d.call(ctx, "GetGroup", dirArgs{TenantID: tid, ID: id})
	return r.Group, err
}
func (d clientDirectory) UpdateGroup(ctx context.Context, g *store.Group) error {
	_, err := d.call(ctx, "UpdateGroup", dirArgs{Group: g})
	return err
}
func (d clientDirectory) DeleteGroup(ctx context.Context, tid, id string) error {
	_, err := d.call(ctx, "DeleteGroup", dirArgs{TenantID: tid, ID: id})
	return err
}
func (d clientDirectory) ListGroups(ctx context.Context, tid string, f store.GroupFilter, p store.Page) ([]*store.Group, int, error) {
	r, err := d.call(ctx, "ListGroups", dirArgs{TenantID: tid, Filter: f, Page: p})
	return r.Groups, r.Total, err
}
func (d clientDirectory) UpdateGroupMembers(ctx context.Context, tid, gid string, add, remove []string, replace bool, now time.Time) error {
	_, err := d.call(ctx, "UpdateGroupMembers", dirArgs{TenantID: tid, GroupID: gid, Add: add, Remove: remove, Replace: replace, Now: now})
	return err
}
func (d clientDirectory) ListGroupMembers(ctx context.Context, tid, gid string, p store.Page) ([]store.GroupMember, int, error) {
	r, err := d.call(ctx, "ListGroupMembers", dirArgs{TenantID: tid, GroupID: gid, Page: p})
	return r.Members, r.Total, err
}
func (d clientDirectory) ListUserGroups(ctx context.Context, tid, uid string) ([]store.GroupMember, error) {
	r, err := d.call(ctx, "ListUserGroups", dirArgs{TenantID: tid, ID: uid})
	if err == nil && r.Members == nil {
		r.Members = []store.GroupMember{}
	}
	return r.Members, err
}
func (d clientDirectory) AddGroupRoles(ctx context.Context, tid, gid, org string, roles []string) error {
	_, err := d.call(ctx, "AddGroupRoles", dirArgs{TenantID: tid, GroupID: gid, OrganizationID: org, Roles: roles})
	return err
}
func (d clientDirectory) RemoveGroupRoles(ctx context.Context, tid, gid, org string, roles []string) error {
	_, err := d.call(ctx, "RemoveGroupRoles", dirArgs{TenantID: tid, GroupID: gid, OrganizationID: org, Roles: roles})
	return err
}
func (d clientDirectory) ListGroupRoles(ctx context.Context, tid, gid, role, org string) ([]store.GroupRole, error) {
	r, err := d.call(ctx, "ListGroupRoles", dirArgs{TenantID: tid, GroupID: gid, RoleID: role, OrganizationID: org})
	if err == nil && r.Roles == nil {
		r.Roles = []store.GroupRole{}
	}
	return r.Roles, err
}

// DirectoryCapabilities answers scim.v1 for the backing store.
func (s *Server) DirectoryCapabilities(_ context.Context, _ *storev1.PingRequest) (*storev1.EventsCapabilitiesResult, error) {
	if !store.DirectoryAvailable(s.st) {
		return &storev1.EventsCapabilitiesResult{}, nil
	}
	if store.SelfServiceAvailable(s.st) {
		return &storev1.EventsCapabilitiesResult{Version: 2}, nil
	}
	return &storev1.EventsCapabilitiesResult{Version: 1}, nil
}

// DirectoryCall dispatches one store.Directory method.
func (s *Server) DirectoryCall(ctx context.Context, r *storev1.DirectoryCallRequest) (*storev1.DirectoryCallResult, error) {
	var a dirArgs
	if err := json.Unmarshal(r.GetArgs(), &a); err != nil {
		return nil, status.Error(codes.InvalidArgument, "DirectoryCall: malformed arguments")
	}
	var out dirResult
	err := s.with(r.GetTxId(), func(st store.Store) (e error) {
		d := st.Directory()
		switch r.GetMethod() {
		case "CreateSCIMConfig":
			e = d.CreateSCIMConfig(ctx, a.Config)
		case "GetSCIMConfig":
			out.Config, e = d.GetSCIMConfig(ctx, a.TenantID, a.ConnectionID)
		case "UpdateSCIMConfig":
			e = d.UpdateSCIMConfig(ctx, a.Config)
		case "DeleteSCIMConfig":
			e = d.DeleteSCIMConfig(ctx, a.TenantID, a.ConnectionID)
		case "ListSCIMConfigs":
			out.Configs, e = d.ListSCIMConfigs(ctx, a.TenantID)
		case "CreateSCIMToken":
			e = d.CreateSCIMToken(ctx, a.Token)
		case "ListSCIMTokens":
			out.Tokens, e = d.ListSCIMTokens(ctx, a.TenantID, a.ConnectionID)
		case "DeleteSCIMToken":
			e = d.DeleteSCIMToken(ctx, a.TenantID, a.ConnectionID, a.ID)
		case "UseSCIMToken":
			out.Token, e = d.UseSCIMToken(ctx, a.TenantID, a.Hash, a.Now)
		case "CreateGroup":
			e = d.CreateGroup(ctx, a.Group)
		case "GetGroup":
			out.Group, e = d.GetGroup(ctx, a.TenantID, a.ID)
		case "UpdateGroup":
			e = d.UpdateGroup(ctx, a.Group)
		case "DeleteGroup":
			e = d.DeleteGroup(ctx, a.TenantID, a.ID)
		case "ListGroups":
			out.Groups, out.Total, e = d.ListGroups(ctx, a.TenantID, a.Filter, a.Page)
		case "UpdateGroupMembers":
			e = d.UpdateGroupMembers(ctx, a.TenantID, a.GroupID, a.Add, a.Remove, a.Replace, a.Now)
		case "ListGroupMembers":
			out.Members, out.Total, e = d.ListGroupMembers(ctx, a.TenantID, a.GroupID, a.Page)
		case "ListUserGroups":
			out.Members, e = d.ListUserGroups(ctx, a.TenantID, a.ID)
		case "AddGroupRoles":
			e = d.AddGroupRoles(ctx, a.TenantID, a.GroupID, a.OrganizationID, a.Roles)
		case "RemoveGroupRoles":
			e = d.RemoveGroupRoles(ctx, a.TenantID, a.GroupID, a.OrganizationID, a.Roles)
		case "ListGroupRoles":
			out.Roles, e = d.ListGroupRoles(ctx, a.TenantID, a.GroupID, a.RoleID, a.OrganizationID)
		default:
			if method, ok := strings.CutPrefix(r.GetMethod(), selfServicePrefix); ok && store.SelfServiceAvailable(st) {
				return serveSelfService(ctx, st.SelfService(), method, r.GetArgs(), &out.SelfService)
			}
			return status.Error(codes.Unimplemented, "DirectoryCall: unknown method")
		}
		return e
	})
	if st, ok := status.FromError(err); ok && st.Code() == codes.Unimplemented {
		return nil, err
	}
	raw, encErr := json.Marshal(out)
	if encErr != nil {
		return nil, encodeFault(encErr)
	}
	return &storev1.DirectoryCallResult{Error: errToPB(err), Result: raw}, nil
}
