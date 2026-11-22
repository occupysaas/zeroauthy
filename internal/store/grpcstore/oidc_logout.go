package grpcstore

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"
)

func (c *Client) CheckOIDCLogoutSupport(ctx context.Context) error {
	switch c.oidcCap.v.Load() {
	case 1:
		return nil
	case 2:
		return store.ErrOIDCLogoutUnavailable
	}
	result, err := c.rpc.OIDCLogoutCapabilities(ctx, &storev1.PingRequest{})
	if err != nil {
		err = rpcErr("oidc_logout.v1 capability", capabilityError(err, store.ErrOIDCLogoutUnavailable))
	} else {
		err = errFromPB(result.GetError())
		if err == nil && result.GetVersion() < 1 {
			err = store.ErrOIDCLogoutUnavailable
		}
	}
	if errors.Is(err, store.ErrOIDCLogoutUnavailable) {
		c.oidcCap.v.Store(2)
	} else if err == nil {
		c.oidcCap.v.CompareAndSwap(0, 1)
	}
	if c.oidcCap.v.Load() == 2 {
		return store.ErrOIDCLogoutUnavailable
	}
	return err
}

func (s *Server) OIDCLogoutCapabilities(ctx context.Context, _ *storev1.PingRequest) (*storev1.EventsCapabilitiesResult, error) {
	if _, explicit := s.st.(store.OIDCLogoutSupporter); !explicit {
		_, global := s.st.(store.GlobalRevocationStore)
		_, expiry := s.st.Sessions().(store.SessionExpiryLister)
		_, organizations := s.st.Sessions().(store.SessionOrganizationRecorder)
		if !global || !expiry || !organizations {
			return &storev1.EventsCapabilitiesResult{}, nil
		}
	}
	if err := store.CheckOIDCLogoutSupport(ctx, s.st); err != nil {
		if errors.Is(err, store.ErrOIDCLogoutUnavailable) {
			return &storev1.EventsCapabilitiesResult{}, nil
		}
		return nil, status.Error(codes.Unavailable, "oidc_logout.v1 backing store probe failed")
	}
	return &storev1.EventsCapabilitiesResult{Version: 1}, nil
}

func (a clientSessions) ListExpired(ctx context.Context, before time.Time, limit int) ([]*store.LoginSession, error) {
	if err := a.c.CheckOIDCLogoutSupport(ctx); err != nil {
		return nil, err
	}
	result, err := a.c.rpc.OIDCLogoutSessionsListExpired(ctx, &storev1.RefreshIIPurgeRequest{Before: tsToPB(before), Limit: int64(limit), TxId: a.c.txID})
	return decList("OIDCLogoutSessionsListExpired", err, result.GetError(), result.GetValues(), sessionFromPB)
}
func (s *Server) OIDCLogoutSessionsListExpired(ctx context.Context, q *storev1.RefreshIIPurgeRequest) (*storev1.SessionList, error) {
	values, e, err := many(s, q.TxId, func(st store.Store) ([]*store.LoginSession, error) {
		repo, ok := st.Sessions().(store.SessionExpiryLister)
		if !ok {
			return nil, store.ErrOIDCLogoutUnavailable
		}
		return repo.ListExpired(ctx, tsFromPB(q.Before), int(q.Limit))
	}, sessionToPB)
	if err != nil {
		return nil, err
	}
	return &storev1.SessionList{Error: e, Values: values}, nil
}

func (a clientSessions) RecordClientOrganization(ctx context.Context, tid, id, clientID, orgID string) error {
	if err := a.c.CheckOIDCLogoutSupport(ctx); err != nil {
		return err
	}
	result, err := a.c.rpc.OIDCLogoutSessionOrganization(ctx, &storev1.SessionsAddClientRequest{TxId: a.c.txID, TenantId: tid, Id: id, ClientId: clientID, OrganizationId: orgID})
	return do("OIDCLogoutSessionOrganization", result, err)
}
func (s *Server) OIDCLogoutSessionOrganization(ctx context.Context, q *storev1.SessionsAddClientRequest) (*storev1.Result, error) {
	return exec(s, q.TxId, func(st store.Store) error {
		repo, ok := st.Sessions().(store.SessionOrganizationRecorder)
		if !ok {
			return store.ErrOIDCLogoutUnavailable
		}
		return repo.RecordClientOrganization(ctx, q.TenantId, q.Id, q.ClientId, q.OrganizationId)
	}), nil
}
