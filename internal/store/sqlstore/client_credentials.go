package sqlstore

import "github.com/zeroauthy/zeroauthy/internal/store"

// ClientCredentials is answered as unavailable until Plan 35 Task 4.
func (s *Store) ClientCredentials() store.ClientCredentials {
	return store.UnimplementedClientCredentials{}
}
