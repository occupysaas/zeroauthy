package grpcstore

import (
	"context"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CheckCIMDSupport reports whether the plugin implements cimd.v1 (Plan
// 41b): it stores client external metadata, unique per tenant, and
// default client grants. A
// definite answer is cached; transient probe errors are retried.
func (c *Client) CheckCIMDSupport(ctx context.Context) error {
	switch c.cimdCap.v.Load() {
	case 1:
		return nil
	case 2:
		return store.ErrCIMDUnavailable
	}
	result, err := c.rpc.CIMDCapabilities(ctx, &storev1.PingRequest{})
	if err != nil {
		err = rpcErr("cimd.v1 capability", capabilityError(err, store.ErrCIMDUnavailable))
	} else {
		err = errFromPB(result.GetError())
		if err == nil && result.GetVersion() < 1 {
			err = store.ErrCIMDUnavailable
		}
	}
	if errors.Is(err, store.ErrCIMDUnavailable) {
		c.cimdCap.v.Store(2)
	} else if err == nil {
		c.cimdCap.v.CompareAndSwap(0, 1)
	}
	if c.cimdCap.v.Load() == 2 {
		return store.ErrCIMDUnavailable
	}
	return err
}

// CIMDCapabilities answers cimd.v1 for the backing store.
func (s *Server) CIMDCapabilities(ctx context.Context, _ *storev1.PingRequest) (*storev1.EventsCapabilitiesResult, error) {
	if err := store.CheckCIMDSupport(ctx, s.st); err != nil {
		if errors.Is(err, store.ErrCIMDUnavailable) {
			return &storev1.EventsCapabilitiesResult{}, nil
		}
		return nil, status.Error(codes.Unavailable, "cimd.v1 backing store probe failed")
	}
	return &storev1.EventsCapabilitiesResult{Version: 1}, nil
}
