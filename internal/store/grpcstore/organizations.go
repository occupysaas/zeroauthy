package grpcstore

import "github.com/zeroauthy/zeroauthy/internal/store"

// Organizations is unavailable until the driver implements it.
func (c *Client) Organizations() store.Organizations { return store.UnimplementedOrganizations{} }
