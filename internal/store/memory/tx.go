package memory

import (
	"context"
	"maps"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// WithTx snapshots every map, runs fn against the same store, and restores
// the snapshot if fn fails. Transactions are serialized by txMu. Writers that
// are not inside a transaction are not isolated (memory is for tests/demos).
func (s *Store) WithTx(ctx context.Context, fn func(store.Store) error) error {
	s.txMu.Lock()
	defer s.txMu.Unlock()
	snap := s.snapshot()
	if err := fn(s); err != nil {
		s.restore(snap)
		return err
	}
	return nil
}

// snapshot deep-copies every map.
func (s *Store) snapshot() *Store {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &Store{
		tenants:         cloneMap(s.tenants, cloneTenant),
		clients:         cloneMap(s.clients, cloneClient),
		resourceServers: cloneMap(s.resourceServers, cloneResourceServer),
		clientGrants:    cloneMap(s.clientGrants, cloneClientGrant),
		signingKeys:     cloneMap(s.signingKeys, cloneSigningKey),
		connections:     cloneMap(s.connections, cloneConnection),
		users:           cloneMap(s.users, cloneUser),
		sessions:        cloneMap(s.sessions, cloneSession),
		transactions:    cloneMap(s.transactions, cloneAuthTransaction),
		authCodes:       cloneMap(s.authCodes, cloneAuthCode),
		refreshTokens:   cloneMap(s.refreshTokens, cloneRefreshToken),
		resetTickets:    cloneMap(s.resetTickets, cloneResetTicket),
	}
}

// restore reassigns every map from snap.
func (s *Store) restore(snap *Store) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tenants, s.clients, s.resourceServers = snap.tenants, snap.clients, snap.resourceServers
	s.clientGrants, s.signingKeys, s.connections = snap.clientGrants, snap.signingKeys, snap.connections
	s.users, s.sessions, s.transactions = snap.users, snap.sessions, snap.transactions
	s.authCodes, s.refreshTokens, s.resetTickets = snap.authCodes, snap.refreshTokens, snap.resetTickets
}

func cloneMap[K comparable, V any](m map[K]*V, clone func(*V) *V) map[K]*V {
	out := make(map[K]*V, len(m))
	for k, v := range maps.All(m) {
		out[k] = clone(v)
	}
	return out
}
