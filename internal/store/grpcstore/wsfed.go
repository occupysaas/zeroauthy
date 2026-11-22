package grpcstore

import (
	"context"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CheckWSFedSupport reports whether the plugin implements wsfed.v1 (Plan
// 37b): it stores client_aliases, unique per tenant, and form_template. A
// definite answer is cached; transient probe errors are retried.
func (c *Client) CheckWSFedSupport(ctx context.Context) error {
	switch c.wsfedCap.v.Load() {
	case 1:
		return nil
	case 2:
		return store.ErrWSFedUnavailable
	}
	result, err := c.rpc.WSFedCapabilities(ctx, &storev1.PingRequest{})
	if err != nil {
		err = rpcErr("wsfed.v1 capability", capabilityError(err, store.ErrWSFedUnavailable))
	} else {
		err = errFromPB(result.GetError())
		if err == nil && result.GetVersion() < 1 {
			err = store.ErrWSFedUnavailable
		}
	}
	if errors.Is(err, store.ErrWSFedUnavailable) {
		c.wsfedCap.v.Store(2)
	} else if err == nil {
		c.wsfedCap.v.CompareAndSwap(0, 1)
	}
	if c.wsfedCap.v.Load() == 2 {
		return store.ErrWSFedUnavailable
	}
	return err
}

// WSFedCapabilities answers wsfed.v1 for the backing store.
func (s *Server) WSFedCapabilities(ctx context.Context, _ *storev1.PingRequest) (*storev1.EventsCapabilitiesResult, error) {
	if err := store.CheckWSFedSupport(ctx, s.st); err != nil {
		if errors.Is(err, store.ErrWSFedUnavailable) {
			return &storev1.EventsCapabilitiesResult{}, nil
		}
		return nil, status.Error(codes.Unavailable, "wsfed.v1 backing store probe failed")
	}
	return &storev1.EventsCapabilitiesResult{Version: 1}, nil
}
