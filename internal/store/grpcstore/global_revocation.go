package grpcstore

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"time"
)

func (c *Client) UseGlobalRevocationJTI(ctx context.Context, tid, connection, jti string, exp, now time.Time) error {
	if err := c.CheckOIDCLogoutSupport(ctx); err != nil {
		return err
	}
	r, err := c.rpc.OIDCLogoutUseGlobalJTI(ctx, &storev1.GlobalRevocationJTIRequest{TxId: c.txID, TenantId: tid, ConnectionId: connection, Jti: jti, ExpiresAt: tsToPB(exp), Now: tsToPB(now)})
	return do("OIDCLogoutUseGlobalJTI", r, err)
}
func (c *Client) PurgeGlobalRevocationJTIs(ctx context.Context, before time.Time, limit int) (int, error) {
	if err := c.CheckOIDCLogoutSupport(ctx); err != nil {
		return 0, err
	}
	r, err := c.rpc.OIDCLogoutPurgeGlobalJTIs(ctx, &storev1.ClientCredentialsPurgeRequest{TxId: c.txID, Before: tsToPB(before), Limit: int64(limit)})
	if err != nil {
		return 0, rpcErr("OIDCLogoutPurgeGlobalJTIs", err)
	}
	return int(r.GetCount()), errFromPB(r.GetError())
}
func (c *Client) FindByFederatedEmail(ctx context.Context, tid, connection, email string) (*store.User, error) {
	if err := c.CheckOIDCLogoutSupport(ctx); err != nil {
		return nil, err
	}
	r, err := c.rpc.OIDCLogoutFindByEmail(ctx, &storev1.UsersFindByIdentityRequest{TxId: c.txID, Key: fedKeyToPB(store.FederatedIdentityKey{TenantID: tid, ConnectionID: connection, Subject: email})})
	return decOne("OIDCLogoutFindByEmail", err, r.GetError(), r.GetValue(), userFromPB)
}
func (s *Server) OIDCLogoutUseGlobalJTI(ctx context.Context, q *storev1.GlobalRevocationJTIRequest) (*storev1.Result, error) {
	return exec(s, q.TxId, func(st store.Store) error {
		repo, ok := st.(store.GlobalRevocationStore)
		if !ok {
			return store.ErrOIDCLogoutUnavailable
		}
		if err := checkTS(q.ExpiresAt, q.Now); err != nil {
			return err
		}
		return repo.UseGlobalRevocationJTI(ctx, q.TenantId, q.ConnectionId, q.Jti, tsFromPB(q.ExpiresAt), tsFromPB(q.Now))
	}), nil
}
func (s *Server) OIDCLogoutPurgeGlobalJTIs(ctx context.Context, q *storev1.ClientCredentialsPurgeRequest) (*storev1.CountResult, error) {
	out := &storev1.CountResult{}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		repo, ok := st.(store.GlobalRevocationStore)
		if !ok {
			return store.ErrOIDCLogoutUnavailable
		}
		n, err := repo.PurgeGlobalRevocationJTIs(ctx, tsFromPB(q.Before), int(q.Limit))
		out.Count = int64(n)
		return err
	}))
	return out, nil
}
func (s *Server) OIDCLogoutFindByEmail(ctx context.Context, q *storev1.UsersFindByIdentityRequest) (*storev1.UserResult, error) {
	k := fedKeyFromPB(q.Key)
	v, e, err := one(s, q.TxId, func(st store.Store) (*store.User, error) {
		repo, ok := st.(store.GlobalRevocationStore)
		if !ok {
			return nil, store.ErrOIDCLogoutUnavailable
		}
		return repo.FindByFederatedEmail(ctx, k.TenantID, k.ConnectionID, k.Subject)
	}, userToPB)
	return &storev1.UserResult{Error: e, Value: v}, err
}
