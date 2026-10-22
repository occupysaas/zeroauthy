package grpcstore

import "github.com/zeroauthy/zeroauthy/internal/store"

// Protection is explicitly unavailable until the durable Task 4 adapter lands.
func (c *Client) Protection() store.Protection { return store.UnimplementedProtection{} }
