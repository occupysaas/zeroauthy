// Package memory is an in-memory store.Store for tests and demos. All data
// is lost when the process exits.
package memory

import (
	"context"
	"sync"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Store is safe for concurrent use. One RWMutex guards all maps, so
// multi-entity operations such as key rotation are trivially atomic.
type Store struct {
	mu      sync.RWMutex
	tenants map[string]*store.Tenant // by ID
}

// New returns an empty store.
func New() *Store {
	return &Store{
		tenants: map[string]*store.Tenant{},
	}
}

func (s *Store) Tenants() store.Tenants     { return tenants{s} }
func (s *Store) Ping(context.Context) error { return nil }
func (s *Store) Close() error               { return nil }

var _ store.Store = (*Store)(nil)
