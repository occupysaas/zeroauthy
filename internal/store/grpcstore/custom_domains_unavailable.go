package grpcstore

import "github.com/zeroauthy/zeroauthy/internal/store"

// CustomDomains reports the missing capability explicitly until this driver
// implements registry persistence. It must never fall back to tenant aliases.
func (c *Client) CustomDomains() store.CustomDomains { return store.UnimplementedCustomDomains{} }
func (c *Client) TLSAssets() store.TLSAssets         { return store.UnimplementedTLSAssets{} }
