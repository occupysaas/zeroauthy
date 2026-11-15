package grpcstore

import "github.com/zeroauthy/zeroauthy/internal/store"

// ClientCredentials is answered as unavailable until Plan 35 Task 5.
func (c *Client) ClientCredentials() store.ClientCredentials {
	return store.UnimplementedClientCredentials{}
}
