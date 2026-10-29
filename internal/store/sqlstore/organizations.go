package sqlstore

import "github.com/zeroauthy/zeroauthy/internal/store"

// Organizations is unavailable until the driver implements it.
func (s *Store) Organizations() store.Organizations { return store.UnimplementedOrganizations{} }
