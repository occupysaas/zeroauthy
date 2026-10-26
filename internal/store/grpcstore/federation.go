package grpcstore

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Federation is implemented by Plan 24 Task 3; until then the repository
// reports itself unavailable and social login cannot start.
func (c *Client) Federation() store.Federation { return store.UnimplementedFederation{} }

func (a clientUsers) FindByIdentity(context.Context, string, string, string) (*store.User, error) {
	return nil, store.ErrFederationUnavailable
}
