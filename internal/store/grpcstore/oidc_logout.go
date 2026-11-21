package grpcstore

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	if err := store.CheckOIDCLogoutSupport(ctx, s.st); err != nil {
		if errors.Is(err, store.ErrOIDCLogoutUnavailable) {
			return &storev1.EventsCapabilitiesResult{}, nil
		}
		return nil, status.Error(codes.Unavailable, "oidc_logout.v1 backing store probe failed")
	}
	return &storev1.EventsCapabilitiesResult{Version: 1}, nil
}
