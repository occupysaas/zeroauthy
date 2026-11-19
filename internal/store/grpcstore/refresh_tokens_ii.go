package grpcstore

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/zeroauthy/zeroauthy/internal/store"
	pb "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

const (
	refreshUnknown int32 = iota
	refreshLegacy
	refreshSupported
	refreshLost
)

type refreshCapability struct {
	probe sync.Mutex
	state atomic.Int32
}

func (c *Client) CheckRefreshTokensIISupport(ctx context.Context) error {
	cap := c.refreshCap
	if cap.state.Load() == refreshUnknown {
		cap.probe.Lock()
		defer cap.probe.Unlock()
		if cap.state.Load() == refreshUnknown {
			r, err := c.rpc.RefreshTokensIICapabilities(ctx, &pb.PingRequest{})
			if err != nil {
				err = rpcErr("RefreshTokensIICapabilities", capabilityError(err, store.ErrRefreshTokensIIUnavailable))
			} else {
				err = errFromPB(r.GetError())
				if err == nil && r.GetVersion() < 1 {
					err = store.ErrRefreshTokensIIUnavailable
				}
			}
			switch {
			case errors.Is(err, store.ErrRefreshTokensIISupportLost):
				cap.state.Store(refreshLost)
			case errors.Is(err, store.ErrRefreshTokensIIUnavailable):
				cap.state.Store(refreshLegacy)
			case err != nil:
				return err
			default:
				cap.state.Store(refreshSupported)
			}
		}
	}
	switch cap.state.Load() {
	case refreshSupported:
		return nil
	case refreshLegacy:
		return store.ErrRefreshTokensIIUnavailable
	default:
		return store.ErrRefreshTokensIISupportLost
	}
}

// An operation failing after positive negotiation never reclassifies the
// connection as initially legacy. Both sentinel classifications remain
// available on operation errors; only the probe determines fallback policy.
func (c *Client) refreshOperationError(err error) error {
	if errors.Is(err, store.ErrRefreshTokensIISupportLost) || errors.Is(err, store.ErrRefreshTokensIIUnavailable) {
		c.refreshCap.state.CompareAndSwap(refreshSupported, refreshLost)
		if c.refreshCap.state.Load() == refreshLost {
			return errors.Join(store.ErrRefreshTokensIISupportLost, store.ErrRefreshTokensIIUnavailable)
		}
	}
	return err
}

func (c *Client) requireRefreshII(ctx context.Context) error {
	return c.refreshOperationError(c.CheckRefreshTokensIISupport(ctx))
}

func (c *Client) refreshResult(op string, r result, err error) error {
	if err != nil {
		err = rpcErr(op, capabilityError(err, store.ErrRefreshTokensIIUnavailable))
	} else {
		err = errFromPB(r.GetError())
	}
	return c.refreshOperationError(err)
}

func (s *Server) RefreshTokensIICapabilities(ctx context.Context, q *pb.PingRequest) (*pb.EventsCapabilitiesResult, error) {
	err := store.CheckRefreshTokensIISupport(ctx, s.st)
	if err != nil && !errors.Is(err, store.ErrRefreshTokensIIUnavailable) && !errors.Is(err, store.ErrRefreshTokensIISupportLost) {
		return nil, refreshBackendError(err)
	}
	return &pb.EventsCapabilitiesResult{Version: 1, Error: errToPB(err)}, nil
}

// Keep transport/context faults out of the domain-error protobuf envelope.
func refreshBackendError(err error) error {
	if errors.Is(err, store.ErrRefreshTokensIIUnavailable) || errors.Is(err, store.ErrRefreshTokensIISupportLost) {
		return status.Error(codes.Unimplemented, "refresh_tokens_ii.v1 unavailable")
	}
	if st, ok := status.FromError(err); ok {
		return st.Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return status.FromContextError(err).Err()
	}
	return status.Error(codes.Unavailable, "refresh_tokens_ii.v1 backing store probe failed")
}

func (c *Client) writeRefreshII(ctx context.Context, q *pb.RefreshIIWrite) error {
	if err := c.requireRefreshII(ctx); err != nil {
		return err
	}
	q.TxId = c.txID
	r, err := c.rpc.RefreshTokensIIWrite(ctx, q)
	return c.refreshResult("RefreshTokensIIWrite", r, err)
}

func (s *Server) RefreshTokensIIWrite(ctx context.Context, q *pb.RefreshIIWrite) (*pb.Result, error) {
	return withRefreshII(s, ctx, q, (*Server).refreshTokensIIWrite)
}

func (s *Server) refreshTokensIIWrite(ctx context.Context, q *pb.RefreshIIWrite) (*pb.Result, error) {
	switch v := q.Record.(type) {
	case *pb.RefreshIIWrite_Tenant:
		req := &pb.TenantWrite{TxId: q.TxId, Value: v.Tenant}
		if q.Update {
			return s.TenantsUpdate(ctx, req)
		}
		return s.TenantsCreate(ctx, req)
	case *pb.RefreshIIWrite_Client:
		req := &pb.ClientWrite{TxId: q.TxId, Value: v.Client}
		if q.Update {
			return s.ClientsUpdate(ctx, req)
		}
		return s.ClientsCreate(ctx, req)
	case *pb.RefreshIIWrite_Api:
		req := &pb.ResourceServerWrite{TxId: q.TxId, Value: v.Api}
		if q.Update {
			return s.ResourceServersUpdate(ctx, req)
		}
		return s.ResourceServersCreate(ctx, req)
	case *pb.RefreshIIWrite_Session:
		req := &pb.SessionWrite{TxId: q.TxId, Value: v.Session}
		if q.Update {
			break
		}
		return s.SessionsCreate(ctx, req)
	case *pb.RefreshIIWrite_Transaction:
		req := &pb.AuthTransactionWrite{TxId: q.TxId, Value: v.Transaction}
		if q.Update {
			break
		}
		return s.AuthTransactionsCreate(ctx, req)
	case *pb.RefreshIIWrite_Code:
		req := &pb.AuthCodeWrite{TxId: q.TxId, Value: v.Code}
		if q.Update {
			break
		}
		return s.AuthCodesCreate(ctx, req)
	case *pb.RefreshIIWrite_Token:
		req := &pb.RefreshTokenWrite{TxId: q.TxId, Value: v.Token}
		if q.Update {
			break
		}
		return s.RefreshTokensCreate(ctx, req)

	case *pb.RefreshIIWrite_Organization:
		if v.Organization == nil {
			break
		}
		v.Organization.TxId = q.TxId
		call := s.OrganizationsCreate
		if q.Update {
			call = s.OrganizationsUpdate
		}
		r, err := call(ctx, v.Organization)
		return &pb.Result{Error: r.GetError()}, err
	}
	return &pb.Result{Error: errToPB(store.ErrInvalid)}, nil
}

func needsRefreshII(t *store.RefreshToken) bool {
	return t != nil && (t.DPoPJKT != "" || t.ParentID != "" || (t.Access != "" && t.Access != "offline") || t.Device != nil || t.Metadata != nil || t.LastExchangedAt != nil)
}

func (r clientRefreshTokens) ConvertNonRotating(ctx context.Context, tid, id string, next *store.RefreshToken) error {
	return r.convert(ctx, tid, id, next, time.Time{}, 0, false)
}

func (r clientRefreshTokens) ConvertRotating(ctx context.Context, tid, id string, next *store.RefreshToken, at time.Time, leeway time.Duration) error {
	return r.convert(ctx, tid, id, next, at, leeway, true)
}

func (r clientRefreshTokens) convert(ctx context.Context, tid, id string, next *store.RefreshToken, at time.Time, leeway time.Duration, rotating bool) error {
	if err := r.c.requireRefreshII(ctx); err != nil {
		return err
	}
	v, err := refreshTokenToPB(next)
	if err != nil {
		return err
	}
	q := &pb.RefreshTokensRotateRequest{TxId: r.c.txID, TenantId: tid, OldId: id, Next: v, At: tsToPB(at), Leeway: durationpb.New(leeway)}
	call := r.c.rpc.RefreshTokensConvertNonRotating
	if rotating {
		call = r.c.rpc.RefreshTokensConvertRotating
	}
	res, err := call(ctx, q)
	return r.c.refreshResult("refresh token conversion", res, err)
}

func (s *Server) RefreshTokensIIRotate(ctx context.Context, q *pb.RefreshTokensRotateRequest) (*pb.Result, error) {
	return withRefreshII(s, ctx, q, (*Server).RefreshTokensRotate)
}

func (s *Server) RefreshTokensConvertNonRotating(ctx context.Context, q *pb.RefreshTokensRotateRequest) (*pb.Result, error) {
	return withRefreshII(s, ctx, q, (*Server).refreshTokensConvertNonRotating)
}

func (s *Server) refreshTokensConvertNonRotating(ctx context.Context, q *pb.RefreshTokensRotateRequest) (*pb.Result, error) {
	if err := checkTS(q.At); err != nil {
		return &pb.Result{Error: errToPB(err)}, nil
	}
	next, err := refreshTokenFromPB(q.Next)
	if err != nil {
		return &pb.Result{Error: errToPB(err)}, nil
	}
	return exec(s, q.TxId, func(st store.Store) error {
		return st.RefreshTokens().ConvertNonRotating(ctx, q.TenantId, q.OldId, next)
	}), nil
}

func (s *Server) RefreshTokensConvertRotating(ctx context.Context, q *pb.RefreshTokensRotateRequest) (*pb.Result, error) {
	return withRefreshII(s, ctx, q, (*Server).refreshTokensConvertRotating)
}

func (s *Server) refreshTokensConvertRotating(ctx context.Context, q *pb.RefreshTokensRotateRequest) (*pb.Result, error) {
	if err := checkTS(q.At); err != nil {
		return &pb.Result{Error: errToPB(err)}, nil
	}
	next, err := refreshTokenFromPB(q.Next)
	if err != nil {
		return &pb.Result{Error: errToPB(err)}, nil
	}
	return exec(s, q.TxId, func(st store.Store) error {
		return st.RefreshTokens().ConvertRotating(ctx, q.TenantId, q.OldId, next, tsFromPB(q.At), q.Leeway.AsDuration())
	}), nil
}

func (r clientRefreshTokens) RevokeByUserClient(ctx context.Context, tid, user, client, audience string, at time.Time) (int, error) {
	if err := r.c.requireRefreshII(ctx); err != nil {
		return 0, err
	}
	res, err := r.c.rpc.RefreshTokensRevokeByUserClient(ctx, &pb.RefreshIIRequest{TxId: r.c.txID, TenantId: tid, UserId: user, ClientId: client, Audience: audience, At: tsToPB(at)})
	if err = r.c.refreshResult("RefreshTokensRevokeByUserClient", res, err); err != nil {
		return 0, err
	}
	return int(res.Count), nil
}

func (s *Server) RefreshTokensRevokeByUserClient(ctx context.Context, q *pb.RefreshIIRequest) (*pb.CountResult, error) {
	return withRefreshII(s, ctx, q, (*Server).refreshTokensRevokeByUserClient)
}

func (s *Server) refreshTokensRevokeByUserClient(ctx context.Context, q *pb.RefreshIIRequest) (*pb.CountResult, error) {
	if err := checkTS(q.At); err != nil {
		return &pb.CountResult{Error: errToPB(err)}, nil
	}
	return count(s, q.TxId, func(st store.Store) (int, error) {
		return st.RefreshTokens().RevokeByUserClient(ctx, q.TenantId, q.UserId, q.ClientId, q.Audience, tsFromPB(q.At))
	}), nil
}

func (r clientRefreshTokens) RevokeBySession(ctx context.Context, tid, id string, at time.Time) (int, error) {
	if err := r.c.requireRefreshII(ctx); err != nil {
		return 0, err
	}
	res, err := r.c.rpc.RefreshTokensRevokeBySession(ctx, &pb.RefreshIIRequest{TxId: r.c.txID, TenantId: tid, Id: id, At: tsToPB(at)})
	if err = r.c.refreshResult("RefreshTokensRevokeBySession", res, err); err != nil {
		return 0, err
	}
	return int(res.Count), nil
}

func (s *Server) RefreshTokensRevokeBySession(ctx context.Context, q *pb.RefreshIIRequest) (*pb.CountResult, error) {
	return withRefreshII(s, ctx, q, (*Server).refreshTokensRevokeBySession)
}

func (s *Server) refreshTokensRevokeBySession(ctx context.Context, q *pb.RefreshIIRequest) (*pb.CountResult, error) {
	if err := checkTS(q.At); err != nil {
		return &pb.CountResult{Error: errToPB(err)}, nil
	}
	return count(s, q.TxId, func(st store.Store) (int, error) {
		return st.RefreshTokens().RevokeBySession(ctx, q.TenantId, q.Id, tsFromPB(q.At))
	}), nil
}

func (r clientRefreshTokens) RecordExchange(ctx context.Context, tid, id, ip, ua string, at time.Time) error {
	if err := r.c.requireRefreshII(ctx); err != nil {
		return err
	}
	res, err := r.c.rpc.RefreshTokensRecordExchange(ctx, &pb.RefreshIIRequest{TxId: r.c.txID, TenantId: tid, Id: id, Ip: ip, UserAgent: ua, At: tsToPB(at)})
	if err = r.c.refreshResult("RefreshTokensRecordExchange", res, err); err != nil {
		return err
	}
	return nil
}

func (s *Server) RefreshTokensRecordExchange(ctx context.Context, q *pb.RefreshIIRequest) (*pb.Result, error) {
	return withRefreshII(s, ctx, q, (*Server).refreshTokensRecordExchange)
}

func (s *Server) refreshTokensRecordExchange(ctx context.Context, q *pb.RefreshIIRequest) (*pb.Result, error) {
	if err := checkTS(q.At); err != nil {
		return &pb.Result{Error: errToPB(err)}, nil
	}
	return exec(s, q.TxId, func(st store.Store) error {
		return st.RefreshTokens().RecordExchange(ctx, q.TenantId, q.Id, q.Ip, q.UserAgent, tsFromPB(q.At))
	}), nil
}

func (r clientRefreshTokens) UpdateMetadata(ctx context.Context, tid, id string, md map[string]string) (*store.RefreshToken, error) {
	if err := r.c.requireRefreshII(ctx); err != nil {
		return nil, err
	}
	res, err := r.c.rpc.RefreshTokensUpdateMetadata(ctx, &pb.RefreshIIRequest{TxId: r.c.txID, TenantId: tid, Id: id, Metadata: stringMapToPB(md)})
	if err = r.c.refreshResult("RefreshTokensUpdateMetadata", res, err); err != nil {
		return nil, err
	}
	return refreshTokenFromPB(res.Value)
}

func (s *Server) RefreshTokensUpdateMetadata(ctx context.Context, q *pb.RefreshIIRequest) (*pb.RefreshTokenResult, error) {
	return withRefreshII(s, ctx, q, (*Server).refreshTokensUpdateMetadata)
}

func (s *Server) refreshTokensUpdateMetadata(ctx context.Context, q *pb.RefreshIIRequest) (*pb.RefreshTokenResult, error) {
	v, e, err := one(s, q.TxId, func(st store.Store) (*store.RefreshToken, error) {
		return st.RefreshTokens().UpdateMetadata(ctx, q.TenantId, q.Id, stringMapFromPB(q.Metadata))
	}, refreshTokenToPB)
	return &pb.RefreshTokenResult{Value: v, Error: e}, err
}

func (r clientSessions) UpdateMetadata(ctx context.Context, tid, id string, md map[string]string) (*store.LoginSession, error) {
	if err := r.c.requireRefreshII(ctx); err != nil {
		return nil, err
	}
	res, err := r.c.rpc.SessionsUpdateMetadata(ctx, &pb.RefreshIIRequest{TxId: r.c.txID, TenantId: tid, Id: id, Metadata: stringMapToPB(md)})
	if err = r.c.refreshResult("SessionsUpdateMetadata", res, err); err != nil {
		return nil, err
	}
	return sessionFromPB(res.Value)
}

func (s *Server) SessionsUpdateMetadata(ctx context.Context, q *pb.RefreshIIRequest) (*pb.SessionResult, error) {
	return withRefreshII(s, ctx, q, (*Server).sessionsUpdateMetadata)
}

func (s *Server) sessionsUpdateMetadata(ctx context.Context, q *pb.RefreshIIRequest) (*pb.SessionResult, error) {
	v, e, err := one(s, q.TxId, func(st store.Store) (*store.LoginSession, error) {
		return st.Sessions().UpdateMetadata(ctx, q.TenantId, q.Id, stringMapFromPB(q.Metadata))
	}, sessionToPB)
	return &pb.SessionResult{Value: v, Error: e}, err
}

func (r clientRefreshTokens) ListByUserPage(ctx context.Context, tid, user, client, from string, take int) ([]*store.RefreshToken, string, error) {
	if err := r.c.requireRefreshII(ctx); err != nil {
		return nil, "", err
	}
	if take < 1 || take > 100 {
		return nil, "", store.ErrInvalid
	}
	res, err := r.c.rpc.RefreshTokensListByUserPage(ctx, &pb.RefreshIIRequest{TxId: r.c.txID, TenantId: tid, UserId: user, ClientId: client, From: from, Take: int32(take)})
	if err = r.c.refreshResult("RefreshTokensListByUserPage", res, err); err != nil {
		return nil, "", err
	}
	out, err := decList("RefreshTokensListByUserPage", nil, nil, res.Values, refreshTokenFromPB)
	return out, res.Next, err
}

func (s *Server) RefreshTokensListByUserPage(ctx context.Context, q *pb.RefreshIIRequest) (*pb.RefreshTokenPage, error) {
	return withRefreshII(s, ctx, q, (*Server).refreshTokensListByUserPage)
}

func (s *Server) refreshTokensListByUserPage(ctx context.Context, q *pb.RefreshIIRequest) (*pb.RefreshTokenPage, error) {
	var cursor string
	vs, e, err := many(s, q.TxId, func(st store.Store) ([]*store.RefreshToken, error) {
		v, next, err := st.RefreshTokens().ListByUserPage(ctx, q.TenantId, q.UserId, q.ClientId, q.From, int(q.Take))
		cursor = next
		return v, err
	}, refreshTokenToPB)
	return &pb.RefreshTokenPage{Error: e, Next: cursor, Values: vs}, err
}
