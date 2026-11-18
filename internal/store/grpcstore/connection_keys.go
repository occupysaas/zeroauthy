package grpcstore

import "github.com/zeroauthy/zeroauthy/internal/store"

func (s *Client) ConnectionKeys() store.ConnectionKeys { return store.UnimplementedConnectionKeys{} }
