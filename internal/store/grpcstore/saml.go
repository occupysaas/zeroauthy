package grpcstore

import (
	"context"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CheckSAMLSupport reports whether the plugin implements saml.v1 (Plan 37a).
// A definite answer is cached; transient probe errors are retried.
func (c *Client) CheckSAMLSupport(ctx context.Context) error {
	switch c.samlCap.v.Load() {
	case 1:
		return nil
	case 2:
		return store.ErrSAMLUnavailable
	}
	result, err := c.rpc.SAMLCapabilities(ctx, &storev1.PingRequest{})
	if err != nil {
		err = rpcErr("saml.v1 capability", capabilityError(err, store.ErrSAMLUnavailable))
	} else {
		err = errFromPB(result.GetError())
		if err == nil && result.GetVersion() < 1 {
			err = store.ErrSAMLUnavailable
		}
	}
	if errors.Is(err, store.ErrSAMLUnavailable) {
		c.samlCap.v.Store(2)
	} else if err == nil {
		c.samlCap.v.CompareAndSwap(0, 1)
	}
	if c.samlCap.v.Load() == 2 {
		return store.ErrSAMLUnavailable
	}
	return err
}

// SAMLCapabilities answers saml.v1 for the backing store.
func (s *Server) SAMLCapabilities(ctx context.Context, _ *storev1.PingRequest) (*storev1.EventsCapabilitiesResult, error) {
	if err := store.CheckSAMLSupport(ctx, s.st); err != nil {
		if errors.Is(err, store.ErrSAMLUnavailable) {
			return &storev1.EventsCapabilitiesResult{}, nil
		}
		return nil, status.Error(codes.Unavailable, "saml.v1 backing store probe failed")
	}
	return &storev1.EventsCapabilitiesResult{Version: 1}, nil
}
