// Package memory is an in-memory store.Store for tests and demos. All data
// is lost when the process exits.
package memory

import (
	"context"
	"sync"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// key addresses a tenant-scoped entity.
type key struct{ tenant, id string }

// Store is safe for concurrent use. One RWMutex guards all maps, so
// multi-entity operations such as key rotation are trivially atomic.
type Store struct {
	mu              sync.RWMutex
	tenants         map[string]*store.Tenant      // by ID
	clients         map[key]*store.Client         // by (tenant, client ID)
	resourceServers map[key]*store.ResourceServer // by (tenant, ID)
	clientGrants    map[key]*store.ClientGrant    // by (tenant, ID)
	signingKeys     map[key]*store.SigningKey     // by (tenant, KID)
	connections     map[key]*store.Connection     // by (tenant, ID)
	users           map[key]*store.User           // by (tenant, UserID)
}

// New returns an empty store.
func New() *Store {
	return &Store{
		tenants:         map[string]*store.Tenant{},
		clients:         map[key]*store.Client{},
		resourceServers: map[key]*store.ResourceServer{},
		clientGrants:    map[key]*store.ClientGrant{},
		signingKeys:     map[key]*store.SigningKey{},
		connections:     map[key]*store.Connection{},
		users:           map[key]*store.User{},
	}
}

func (s *Store) Tenants() store.Tenants                 { return tenants{s} }
func (s *Store) Clients() store.Clients                 { return clients{s} }
func (s *Store) ResourceServers() store.ResourceServers { return resourceServers{s} }
func (s *Store) ClientGrants() store.ClientGrants       { return clientGrants{s} }
func (s *Store) SigningKeys() store.SigningKeys         { return signingKeys{s} }
func (s *Store) Connections() store.Connections         { return connections{s} }
func (s *Store) Users() store.Users                     { return users{s} }
func (s *Store) Ping(context.Context) error             { return nil }
func (s *Store) Close() error                           { return nil }

var _ store.Store = (*Store)(nil)
