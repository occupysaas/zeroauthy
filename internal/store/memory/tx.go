package memory

import (
	"bytes"
	"context"
	"maps"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/protectionstate"
)

// WithTx snapshots every map, runs fn, and restores the snapshot unless fn
// returns nil (including when fn panics or calls runtime.Goexit, e.g. via
// t.Fatal). Transactions are serialized by txMu, and so are writes made
// outside any transaction, so a restore never undoes another caller's
// write. fn receives a view of the store whose writes skip txMu; a nested
// WithTx on it joins the enclosing transaction like a savepoint in the SQL
// drivers: an error or panic from fn undoes fn's writes only, and the
// enclosing transaction continues. fn must use the store it is given: a
// write through the outer store would wait for the transaction to end.
func (s *Store) WithTx(ctx context.Context, fn func(store.Store) error) error {
	if s.tx {
		return s.savepoint(fn)
	}
	s.txMu.Lock()
	defer s.txMu.Unlock()
	return s.savepoint(fn)
}

// savepoint runs fn against the transaction view and restores the maps it
// changed unless fn returns nil. The caller holds txMu.
func (s *Store) savepoint(fn func(store.Store) error) error {
	snap := s.snapshot()
	ok := false
	defer func() {
		if !ok {
			s.restore(snap)
		}
	}()
	err := fn(&Store{state: s.state, tx: true})
	ok = err == nil
	return err
}

// snapshot deep-copies every map.
func (s *Store) snapshot() *state {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &state{
		protection:         cloneMap(s.protection, func(p *protectionstate.State) *protectionstate.State { return p.Clone() }),
		proofs:             maps.Clone(s.proofs),
		tenants:            cloneMap(s.tenants, cloneTenant),
		clients:            cloneMap(s.clients, cloneClient),
		resourceServers:    cloneMap(s.resourceServers, cloneResourceServer),
		clientGrants:       cloneMap(s.clientGrants, cloneClientGrant),
		userGrants:         cloneMap(s.userGrants, cloneUserGrant),
		signingKeys:        cloneMap(s.signingKeys, cloneSigningKey),
		customSigningKeys:  cloneMap(s.customSigningKeys, cloneCustomSigningKeySet),
		connections:        cloneMap(s.connections, cloneConnection),
		passwordHistories:  clonePasswordHistories(s.passwordHistories),
		users:              cloneMap(s.users, cloneUser),
		sessions:           cloneMap(s.sessions, cloneSession),
		transactions:       cloneMap(s.transactions, cloneAuthTransaction),
		authCodes:          cloneMap(s.authCodes, cloneAuthCode),
		pushedAuthRequests: cloneMap(s.pushedAuthRequests, clonePushedAuthRequest),
		deviceCodes:        cloneMap(s.deviceCodes, cloneDeviceCode),
		refreshTokens:      cloneMap(s.refreshTokens, cloneRefreshToken),
		resetTickets:       cloneMap(s.resetTickets, cloneResetTicket),
		verifyTickets:      cloneMap(s.verifyTickets, cloneVerifyTicket),
		operators:          cloneMap(s.operators, cloneOperator),
		jobs:               cloneMap(s.jobs, cloneJob),
		jobErrors:          cloneJobErrorMap(s.jobErrors),
		jobFiles:           cloneJobFiles(s.jobFiles),
	}
}

// restore reassigns every map from snap.
func (s *Store) restore(snap *state) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.protection, s.proofs = snap.protection, snap.proofs
	s.tenants, s.clients, s.resourceServers = snap.tenants, snap.clients, snap.resourceServers
	s.clientGrants, s.signingKeys, s.connections = snap.clientGrants, snap.signingKeys, snap.connections
	s.customSigningKeys = snap.customSigningKeys
	s.userGrants = snap.userGrants
	s.users, s.sessions, s.transactions = snap.users, snap.sessions, snap.transactions
	s.authCodes, s.refreshTokens, s.resetTickets = snap.authCodes, snap.refreshTokens, snap.resetTickets
	s.pushedAuthRequests, s.deviceCodes = snap.pushedAuthRequests, snap.deviceCodes
	s.verifyTickets = snap.verifyTickets
	s.operators, s.passwordHistories = snap.operators, snap.passwordHistories
	s.jobs, s.jobErrors, s.jobFiles = snap.jobs, snap.jobErrors, snap.jobFiles
}

func cloneMap[K comparable, V any](m map[K]*V, clone func(*V) *V) map[K]*V {
	out := make(map[K]*V, len(m))
	for k, v := range maps.All(m) {
		out[k] = clone(v)
	}
	return out
}

func clonePasswordHistories(m map[key][][]byte) map[key][][]byte {
	out := make(map[key][][]byte, len(m))
	for k, h := range m {
		c := make([][]byte, len(h))
		for i, b := range h {
			c[i] = bytes.Clone(b)
		}
		out[k] = c
	}
	return out
}

func cloneJobErrorMap(m map[key][]store.JobError) map[key][]store.JobError {
	out := make(map[key][]store.JobError, len(m))
	for k, errs := range m {
		out[k] = cloneJobErrors(errs)
	}
	return out
}

func cloneJobFiles(m map[key]jobFile) map[key]jobFile {
	out := make(map[key]jobFile, len(m))
	for k, f := range m {
		out[k] = cloneJobFile(f)
	}
	return out
}
