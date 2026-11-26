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

// Plan 41c: store.CIBAStore over the CIBACall RPC (method = Go method
// name, JSON arguments and results), available when CIBACapabilities
// answers version 1.

type cibaArgs struct {
	TenantID, IDHash, TicketHash, ClientID string `json:",omitempty"`
	Request                                *store.CIBARequest
	Decision                               *store.CIBADecision
	At                                     time.Time `json:",omitzero"`
}

type cibaResult struct {
	Request *store.CIBARequest `json:",omitempty"`
	Poll    store.CIBAPoll
	Count   int
}

// CheckCIBASupport reports whether the plugin implements ciba.v1. A
// definite answer is cached; transient probe errors are retried.
func (c *Client) CheckCIBASupport(ctx context.Context) error {
	switch c.cibaCap.v.Load() {
	case 1:
		return nil
	case 2:
		return store.ErrCIBAUnavailable
	}
	result, err := c.rpc.CIBACapabilities(ctx, &storev1.PingRequest{})
	if err != nil {
		err = rpcErr("ciba.v1 capability", capabilityError(err, store.ErrCIBAUnavailable))
	} else {
		err = errFromPB(result.GetError())
		if err == nil && result.GetVersion() < 1 {
			err = store.ErrCIBAUnavailable
		}
	}
	if errors.Is(err, store.ErrCIBAUnavailable) {
		c.cibaCap.v.Store(2)
	} else if err == nil {
		c.cibaCap.v.CompareAndSwap(0, 1)
	}
	if c.cibaCap.v.Load() == 2 {
		return store.ErrCIBAUnavailable
	}
	return err
}

func (c *Client) cibaCall(ctx context.Context, method string, a cibaArgs) (cibaResult, error) {
	var out cibaResult
	if err := c.CheckCIBASupport(ctx); err != nil {
		return out, err
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return out, err
	}
	r, err := c.rpc.CIBACall(ctx, &storev1.CIBACallRequest{TxId: c.txID, Method: method, Args: raw})
	if err != nil {
		return out, rpcErr("CIBACall "+method, err)
	}
	if len(r.GetResult()) > 0 {
		if err := json.Unmarshal(r.GetResult(), &out); err != nil {
			return out, fmt.Errorf("CIBACall %s: decode result: %w", method, err)
		}
	}
	return out, errFromPB(r.GetError())
}

func (c *Client) CreateCIBARequest(ctx context.Context, r *store.CIBARequest) error {
	_, err := c.cibaCall(ctx, "CreateCIBARequest", cibaArgs{Request: r})
	return err
}
func (c *Client) GetCIBARequest(ctx context.Context, tid, idHash string) (*store.CIBARequest, error) {
	r, err := c.cibaCall(ctx, "GetCIBARequest", cibaArgs{TenantID: tid, IDHash: idHash})
	return r.Request, err
}
func (c *Client) GetCIBARequestByTicket(ctx context.Context, tid, ticketHash string) (*store.CIBARequest, error) {
	r, err := c.cibaCall(ctx, "GetCIBARequestByTicket", cibaArgs{TenantID: tid, TicketHash: ticketHash})
	return r.Request, err
}
func (c *Client) DecideCIBARequest(ctx context.Context, tid, idHash string, dec store.CIBADecision) (*store.CIBARequest, error) {
	r, err := c.cibaCall(ctx, "DecideCIBARequest", cibaArgs{TenantID: tid, IDHash: idHash, Decision: &dec})
	return r.Request, err
}
func (c *Client) PollCIBARequest(ctx context.Context, tid, idHash, clientID string, at time.Time) (store.CIBAPoll, *store.CIBARequest, error) {
	r, err := c.cibaCall(ctx, "PollCIBARequest", cibaArgs{TenantID: tid, IDHash: idHash, ClientID: clientID, At: at})
	if err != nil {
		return 0, nil, err
	}
	return r.Poll, r.Request, nil
}
func (c *Client) CountPendingCIBARequests(ctx context.Context, tid string, now time.Time) (int, error) {
	r, err := c.cibaCall(ctx, "CountPendingCIBARequests", cibaArgs{TenantID: tid, At: now})
	return r.Count, err
}
func (c *Client) DeleteExpiredCIBARequests(ctx context.Context, before time.Time) (int, error) {
	r, err := c.cibaCall(ctx, "DeleteExpiredCIBARequests", cibaArgs{At: before})
	return r.Count, err
}

// CIBACapabilities answers ciba.v1 for the backing store.
func (s *Server) CIBACapabilities(ctx context.Context, _ *storev1.PingRequest) (*storev1.EventsCapabilitiesResult, error) {
	if _, err := store.CIBA(ctx, s.st); err != nil {
		if errors.Is(err, store.ErrCIBAUnavailable) {
			return &storev1.EventsCapabilitiesResult{}, nil
		}
		return nil, status.Error(codes.Unavailable, "ciba.v1 backing store probe failed")
	}
	return &storev1.EventsCapabilitiesResult{Version: 1}, nil
}

// CIBACall serves the store.CIBAStore methods.
func (s *Server) CIBACall(ctx context.Context, q *storev1.CIBACallRequest) (*storev1.CIBACallResult, error) {
	var a cibaArgs
	if err := json.Unmarshal(q.Args, &a); err != nil {
		return nil, status.Error(codes.InvalidArgument, "CIBACall: malformed arguments")
	}
	var r cibaResult
	err := s.with(q.TxId, func(st store.Store) error {
		repo, err := store.CIBA(ctx, st)
		if err != nil {
			return err
		}
		switch q.Method {
		case "CreateCIBARequest":
			if a.Request == nil {
				return store.ErrInvalid
			}
			return repo.CreateCIBARequest(ctx, a.Request)
		case "GetCIBARequest":
			r.Request, err = repo.GetCIBARequest(ctx, a.TenantID, a.IDHash)
		case "GetCIBARequestByTicket":
			r.Request, err = repo.GetCIBARequestByTicket(ctx, a.TenantID, a.TicketHash)
		case "DecideCIBARequest":
			if a.Decision == nil {
				return store.ErrInvalid
			}
			r.Request, err = repo.DecideCIBARequest(ctx, a.TenantID, a.IDHash, *a.Decision)
		case "PollCIBARequest":
			r.Poll, r.Request, err = repo.PollCIBARequest(ctx, a.TenantID, a.IDHash, a.ClientID, a.At)
		case "CountPendingCIBARequests":
			r.Count, err = repo.CountPendingCIBARequests(ctx, a.TenantID, a.At)
		case "DeleteExpiredCIBARequests":
			r.Count, err = repo.DeleteExpiredCIBARequests(ctx, a.At)
		default:
			return status.Error(codes.Unimplemented, "CIBACall: unknown method")
		}
		return err
	})
	if st, ok := status.FromError(err); ok && err != nil && st.Code() == codes.Unimplemented {
		return nil, err
	}
	out := &storev1.CIBACallResult{Error: errToPB(err)}
	enc, e := json.Marshal(r)
	if e != nil {
		return nil, e
	}
	out.Result = enc
	return out, nil
}
