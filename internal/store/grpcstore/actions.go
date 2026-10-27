package grpcstore

import "github.com/zeroauthy/zeroauthy/internal/store"

// Actions is unsupported until the gRPC protocol lands; it fails closed.
func (c *Client) Actions() store.Actions { return store.UnimplementedActions{} }
