package grpcstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Plan 42b: store.MyOrgStore over the MyOrgCall RPC (method = Go method
// name, JSON arguments and results), available when MyOrgCapabilities
// answers version 1.

type myOrgArgs struct {
	TenantID, ClientID, RoleID string `json:",omitempty"`
	OrgID, DomainID, Domain    string `json:",omitempty"`
	Visible                    bool
	Config                     *store.MyOrgClientConfig
	CreatedAt                  time.Time `json:",omitzero"`
}

type myOrgResult struct {
	Config *store.MyOrgClientConfig `json:",omitempty"`
	Roles  []string                 `json:",omitempty"`
	Claims map[string]time.Time     `json:",omitempty"`
}

// CheckMyOrgSupport reports whether the plugin implements my_org.v1. A
// definite answer is cached; transient probe errors are retried.
func (c *Client) CheckMyOrgSupport(ctx context.Context) error {
	switch c.myOrgCap.v.Load() {
	case 1:
		return nil
	case 2:
		return store.ErrMyOrgUnavailable
	}
	result, err := c.rpc.MyOrgCapabilities(ctx, &storev1.PingRequest{})
	if err != nil {
		err = rpcErr("my_org.v1 capability", capabilityError(err, store.ErrMyOrgUnavailable))
	} else {
		err = errFromPB(result.GetError())
		if err == nil && result.GetVersion() < 1 {
			err = store.ErrMyOrgUnavailable
		}
	}
	if errors.Is(err, store.ErrMyOrgUnavailable) {
		c.myOrgCap.v.Store(2)
	} else if err == nil {
		c.myOrgCap.v.CompareAndSwap(0, 1)
	}
	if c.myOrgCap.v.Load() == 2 {
		return store.ErrMyOrgUnavailable
	}
	return err
}

func (c *Client) myOrgCall(ctx context.Context, method string, a myOrgArgs) (myOrgResult, error) {
	var out myOrgResult
	if err := c.CheckMyOrgSupport(ctx); err != nil {
		return out, err
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return out, err
	}
	r, err := c.rpc.MyOrgCall(ctx, &storev1.MyOrgCallRequest{TxId: c.txID, Method: method, Args: raw})
	if err != nil {
		return out, rpcErr("MyOrgCall "+method, err)
	}
	if len(r.GetResult()) > 0 {
		if err := json.Unmarshal(r.GetResult(), &out); err != nil {
			return out, fmt.Errorf("MyOrgCall %s: decode result: %w", method, err)
		}
	}
	return out, errFromPB(r.GetError())
}

func (c *Client) PutMyOrgClientConfig(ctx context.Context, cfg *store.MyOrgClientConfig) error {
	_, err := c.myOrgCall(ctx, "PutMyOrgClientConfig", myOrgArgs{Config: cfg})
	return err
}
func (c *Client) GetMyOrgClientConfig(ctx context.Context, tid, cid string) (*store.MyOrgClientConfig, error) {
	r, err := c.myOrgCall(ctx, "GetMyOrgClientConfig", myOrgArgs{TenantID: tid, ClientID: cid})
	if err != nil {
		return nil, err
	}
	return r.Config, nil
}
func (c *Client) DeleteMyOrgClientConfig(ctx context.Context, tid, cid string) error {
	_, err := c.myOrgCall(ctx, "DeleteMyOrgClientConfig", myOrgArgs{TenantID: tid, ClientID: cid})
	return err
}
func (c *Client) SetMyOrgRoleVisible(ctx context.Context, tid, rid string, visible bool) error {
	_, err := c.myOrgCall(ctx, "SetMyOrgRoleVisible", myOrgArgs{TenantID: tid, RoleID: rid, Visible: visible})
	return err
}
func (c *Client) ListMyOrgVisibleRoles(ctx context.Context, tid string) ([]string, error) {
	r, err := c.myOrgCall(ctx, "ListMyOrgVisibleRoles", myOrgArgs{TenantID: tid})
	if err != nil {
		return nil, err
	}
	if r.Roles == nil {
		r.Roles = []string{}
	}
	return r.Roles, nil
}

func (c *Client) PutDomainClaim(ctx context.Context, tid, org, id string, created time.Time) error {
	_, err := c.myOrgCall(ctx, "PutDomainClaim", myOrgArgs{TenantID: tid, OrgID: org, DomainID: id, CreatedAt: created})
	return err
}
func (c *Client) DomainClaims(ctx context.Context, tid, org string) (map[string]time.Time, error) {
	r, err := c.myOrgCall(ctx, "DomainClaims", myOrgArgs{TenantID: tid, OrgID: org})
	if err != nil {
		return nil, err
	}
	if r.Claims == nil {
		r.Claims = map[string]time.Time{}
	}
	return r.Claims, nil
}
func (c *Client) VerifiedDomainOrganizations(ctx context.Context, tid, domain string) ([]string, error) {
	r, err := c.myOrgCall(ctx, "VerifiedDomainOrganizations", myOrgArgs{TenantID: tid, Domain: domain})
	if err != nil {
		return nil, err
	}
	if r.Roles == nil {
		r.Roles = []string{}
	}
	return r.Roles, nil
}
func (c *Client) DeleteDomainClaim(ctx context.Context, tid, org, id string) error {
	_, err := c.myOrgCall(ctx, "DeleteDomainClaim", myOrgArgs{TenantID: tid, OrgID: org, DomainID: id})
	return err
}

// MyOrgCapabilities answers my_org.v1 for the backing store.
func (s *Server) MyOrgCapabilities(ctx context.Context, _ *storev1.PingRequest) (*storev1.EventsCapabilitiesResult, error) {
	if _, err := store.MyOrg(ctx, s.st); err != nil {
		if errors.Is(err, store.ErrMyOrgUnavailable) {
			return &storev1.EventsCapabilitiesResult{}, nil
		}
		return nil, status.Error(codes.Unavailable, "my_org.v1 backing store probe failed")
	}
	return &storev1.EventsCapabilitiesResult{Version: 1}, nil
}

// MyOrgCall serves the store.MyOrgStore methods.
func (s *Server) MyOrgCall(ctx context.Context, q *storev1.MyOrgCallRequest) (*storev1.MyOrgCallResult, error) {
	var a myOrgArgs
	if err := json.Unmarshal(q.Args, &a); err != nil {
		return nil, status.Error(codes.InvalidArgument, "MyOrgCall: malformed arguments")
	}
	var r myOrgResult
	err := s.with(q.TxId, func(st store.Store) error {
		repo, err := store.MyOrg(ctx, st)
		if err != nil {
			return err
		}
		switch q.Method {
		case "PutMyOrgClientConfig":
			if a.Config == nil {
				return store.ErrInvalid
			}
			return repo.PutMyOrgClientConfig(ctx, a.Config)
		case "GetMyOrgClientConfig":
			r.Config, err = repo.GetMyOrgClientConfig(ctx, a.TenantID, a.ClientID)
		case "DeleteMyOrgClientConfig":
			return repo.DeleteMyOrgClientConfig(ctx, a.TenantID, a.ClientID)
		case "SetMyOrgRoleVisible":
			return repo.SetMyOrgRoleVisible(ctx, a.TenantID, a.RoleID, a.Visible)
		case "ListMyOrgVisibleRoles":
			r.Roles, err = repo.ListMyOrgVisibleRoles(ctx, a.TenantID)
		case "PutDomainClaim":
			return repo.PutDomainClaim(ctx, a.TenantID, a.OrgID, a.DomainID, a.CreatedAt)
		case "DomainClaims":
			r.Claims, err = repo.DomainClaims(ctx, a.TenantID, a.OrgID)
		case "VerifiedDomainOrganizations":
			r.Roles, err = repo.VerifiedDomainOrganizations(ctx, a.TenantID, a.Domain)
		case "DeleteDomainClaim":
			return repo.DeleteDomainClaim(ctx, a.TenantID, a.OrgID, a.DomainID)
		default:
			return status.Error(codes.Unimplemented, "MyOrgCall: unknown method")
		}
		return err
	})
	if st, ok := status.FromError(err); ok && err != nil && st.Code() == codes.Unimplemented {
		return nil, err
	}
	out := &storev1.MyOrgCallResult{Error: errToPB(err)}
	if err == nil {
		enc, e := json.Marshal(r)
		if e != nil {
			return nil, e
		}
		out.Result = enc
	}
	return out, nil
}
