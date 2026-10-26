package sqlstore

import "github.com/zeroauthy/zeroauthy/internal/store"

// CustomDomains reports the missing capability explicitly until this driver
// implements registry persistence. It must never fall back to tenant aliases.
func (s *Store) CustomDomains() store.CustomDomains { return store.UnimplementedCustomDomains{} }
func (s *Store) TLSAssets() store.TLSAssets         { return store.UnimplementedTLSAssets{} }
