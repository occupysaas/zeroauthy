package sqlstore

import "github.com/zeroauthy/zeroauthy/internal/store"

func (s *Store) ConnectionKeys() store.ConnectionKeys { return store.UnimplementedConnectionKeys{} }
