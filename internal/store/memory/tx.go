package memory

import (
	"context"
	"maps"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// WithTx snapshots every map, runs fn, and restores the snapshot unless fn
// returns nil (including when fn panics or calls runtime.Goexit, e.g. via
// t.Fatal). Transactions are serialized by txMu. fn receives a txStore, so a
// nested WithTx runs inline like it does in the SQL drivers. Writers that are
// not inside a transaction are not isolated (memory is for tests/demos).
func (s *Store) WithTx(ctx context.Context, fn func(store.Store) error) error {
	s.txMu.Lock()
	defer s.txMu.Unlock()
	snap := s.snapshot()
	committed := false
	defer func() {
		if !committed {
			s.restore(snap)
		}
	}()
	err := fn(txStore{s})
	committed = err == nil
	return err
}

// txStore is the store handed to a transaction body. Its WithTx joins the
// enclosing transaction instead of locking txMu again, like a savepoint in
// the SQL drivers: an error or panic from fn undoes fn's writes only, and the
// enclosing transaction continues.
type txStore struct{ *Store }

func (t txStore) WithTx(_ context.Context, fn func(store.Store) error) error {
	snap := t.snapshot()
	ok := false
	defer func() {
		if !ok {
			t.restore(snap)
		}
	}()
	err := fn(t)
	ok = err == nil
	return err
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
		userGrants:      cloneMap(s.userGrants, cloneUserGrant),
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
	s.userGrants = snap.userGrants
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
