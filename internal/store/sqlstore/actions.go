package sqlstore

import "github.com/zeroauthy/zeroauthy/internal/store"

// Actions is unsupported until the SQL repository lands; it fails closed.
func (s *Store) Actions() store.Actions { return store.UnimplementedActions{} }
