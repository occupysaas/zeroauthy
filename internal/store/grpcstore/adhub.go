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

// Plan 38a: store.ADHubStore over the ADHubCall RPC (method = Go method
// name, JSON arguments and results), available when ADHubCapabilities
// answers version 1.

type adArgs struct {
	TenantID, ConnectionID, SessionID, TicketHash string `json:",omitempty"`
	Provisioning                                  *store.ADProvisioning
	Session                                       *store.ADHubSession
	Time                                          time.Time
	Limit                                         int
}

type adResult struct {
	Provisioning *store.ADProvisioning `json:",omitempty"`
	Sessions     []*store.ADHubSession `json:",omitempty"`
	Count        int                   `json:",omitempty"`
}

// CheckADHubSupport reports whether the plugin implements ad_hub.v1. A
// definite answer is cached; transient probe errors are retried.
func (c *Client) CheckADHubSupport(ctx context.Context) error {
	switch c.adCap.v.Load() {
	case 1:
		return nil
	case 2:
		return store.ErrADHubUnavailable
	}
	result, err := c.rpc.ADHubCapabilities(ctx, &storev1.PingRequest{})
	if err != nil {
		err = rpcErr("ad_hub.v1 capability", capabilityError(err, store.ErrADHubUnavailable))
	} else {
		err = errFromPB(result.GetError())
		if err == nil && result.GetVersion() < 1 {
			err = store.ErrADHubUnavailable
		}
	}
	if errors.Is(err, store.ErrADHubUnavailable) {
		c.adCap.v.Store(2)
	} else if err == nil {
		c.adCap.v.CompareAndSwap(0, 1)
	}
	if c.adCap.v.Load() == 2 {
		return store.ErrADHubUnavailable
	}
	return err
}

func (c *Client) adCall(ctx context.Context, method string, a adArgs) (adResult, error) {
	var out adResult
	if err := c.CheckADHubSupport(ctx); err != nil {
		return out, err
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return out, err
	}
	r, err := c.rpc.ADHubCall(ctx, &storev1.ADHubCallRequest{TxId: c.txID, Method: method, Args: raw})
	if err != nil {
		return out, rpcErr("ADHubCall "+method, err)
	}
	if len(r.GetResult()) > 0 {
		if err := json.Unmarshal(r.GetResult(), &out); err != nil {
			return out, fmt.Errorf("ADHubCall %s: decode result: %w", method, err)
		}
	}
	return out, errFromPB(r.GetError())
}

func (c *Client) CreateADProvisioning(ctx context.Context, p *store.ADProvisioning) error {
	_, err := c.adCall(ctx, "CreateADProvisioning", adArgs{Provisioning: p})
	return err
}
func (c *Client) GetADProvisioning(ctx context.Context, tid, cid string) (*store.ADProvisioning, error) {
	r, err := c.adCall(ctx, "GetADProvisioning", adArgs{TenantID: tid, ConnectionID: cid})
	if err != nil {
		return nil, err
	}
	return r.Provisioning, nil
}
func (c *Client) FindADProvisioning(ctx context.Context, tid, hash string) (*store.ADProvisioning, error) {
	r, err := c.adCall(ctx, "FindADProvisioning", adArgs{TenantID: tid, TicketHash: hash})
	if err != nil {
		return nil, err
	}
	return r.Provisioning, nil
}
func (c *Client) PutADHubSession(ctx context.Context, s *store.ADHubSession) error {
	_, err := c.adCall(ctx, "PutADHubSession", adArgs{Session: s})
	return err
}
func (c *Client) DeleteADHubSession(ctx context.Context, tid, cid, sid string) error {
	_, err := c.adCall(ctx, "DeleteADHubSession", adArgs{TenantID: tid, ConnectionID: cid, SessionID: sid})
	return err
}
func (c *Client) ListADHubSessions(ctx context.Context, tid, cid string, seenAfter time.Time) ([]*store.ADHubSession, error) {
	r, err := c.adCall(ctx, "ListADHubSessions", adArgs{TenantID: tid, ConnectionID: cid, Time: seenAfter})
	if err != nil {
		return nil, err
	}
	if r.Sessions == nil {
		r.Sessions = []*store.ADHubSession{}
	}
	return r.Sessions, nil
}
func (c *Client) PurgeADHubSessions(ctx context.Context, before time.Time, limit int) (int, error) {
	r, err := c.adCall(ctx, "PurgeADHubSessions", adArgs{Time: before, Limit: limit})
	return r.Count, err
}

// ADHubCapabilities answers ad_hub.v1 for the backing store.
func (s *Server) ADHubCapabilities(ctx context.Context, _ *storev1.PingRequest) (*storev1.EventsCapabilitiesResult, error) {
	if _, err := store.ADHub(ctx, s.st); err != nil {
		if errors.Is(err, store.ErrADHubUnavailable) {
			return &storev1.EventsCapabilitiesResult{}, nil
		}
		return nil, status.Error(codes.Unavailable, "ad_hub.v1 backing store probe failed")
	}
	return &storev1.EventsCapabilitiesResult{Version: 1}, nil
}

// ADHubCall serves the store.ADHubStore methods.
func (s *Server) ADHubCall(ctx context.Context, q *storev1.ADHubCallRequest) (*storev1.ADHubCallResult, error) {
	var a adArgs
	if err := json.Unmarshal(q.Args, &a); err != nil {
		return nil, status.Error(codes.InvalidArgument, "ADHubCall: malformed arguments")
	}
	var r adResult
	err := s.with(q.TxId, func(st store.Store) error {
		repo, err := store.ADHub(ctx, st)
		if err != nil {
			return err
		}
		switch q.Method {
		case "CreateADProvisioning":
			if a.Provisioning == nil {
				return store.ErrInvalid
			}
			return repo.CreateADProvisioning(ctx, a.Provisioning)
		case "GetADProvisioning":
			r.Provisioning, err = repo.GetADProvisioning(ctx, a.TenantID, a.ConnectionID)
		case "FindADProvisioning":
			r.Provisioning, err = repo.FindADProvisioning(ctx, a.TenantID, a.TicketHash)
		case "PutADHubSession":
			if a.Session == nil {
				return store.ErrInvalid
			}
			return repo.PutADHubSession(ctx, a.Session)
		case "DeleteADHubSession":
			return repo.DeleteADHubSession(ctx, a.TenantID, a.ConnectionID, a.SessionID)
		case "ListADHubSessions":
			r.Sessions, err = repo.ListADHubSessions(ctx, a.TenantID, a.ConnectionID, a.Time)
		case "PurgeADHubSessions":
			r.Count, err = repo.PurgeADHubSessions(ctx, a.Time, a.Limit)
		default:
			return status.Error(codes.Unimplemented, "ADHubCall: unknown method")
		}
		return err
	})
	if st, ok := status.FromError(err); ok && err != nil && st.Code() == codes.Unimplemented {
		return nil, err
	}
	out := &storev1.ADHubCallResult{Error: errToPB(err)}
	if err == nil {
		enc, e := json.Marshal(r)
		if e != nil {
			return nil, e
		}
		out.Result = enc
	}
	return out, nil
}
