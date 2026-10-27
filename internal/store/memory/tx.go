package memory

import (
	"bytes"
	"context"
	"maps"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/protectionstate"
)

// WithTx snapshots every map, runs fn, and restores the snapshot unless fn
// returns nil (including when fn panics or calls runtime.Goexit, e.g. via
// t.Fatal). txMu excludes external readers and writers until final lease
// validation and any rollback finish. fn receives a view of the store whose
// reads and writes skip txMu; a nested
// WithTx on it joins the enclosing transaction like a savepoint in the SQL
// drivers: an error or panic from fn undoes fn's writes only, and the
// enclosing transaction continues. fn must use the store it is given for both
// reads and writes: operations through the outer store wait for the transaction
// to end, so calling them synchronously from fn would deadlock.
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
	view := &Store{state: s.state, tx: true, checkedLeases: map[string]store.TLSLease{}}
	err := fn(view)
	if err == nil {
		s.mu.Lock()
		for _, l := range view.checkedLeases {
			if !(tlsAssets{view}).valid(l) {
				err = store.ErrConflict
				break
			}
		}
		s.mu.Unlock()
	}
	if err == nil && s.tx {
		for k, l := range view.checkedLeases {
			s.checkedLeases[k] = l
		}
	}
	ok = err == nil
	return err
}

// snapshot deep-copies every map.
func (s *Store) snapshot() *state {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &state{
		actions: cloneMap(s.actions, cloneAction), actionVersions: cloneMap(s.actionVersions, cloneActionVersion), builds: cloneMap(s.builds, cloneBuild),
		artifacts: cloneArtifacts(s.artifacts), bindings: cloneBindingLists(s.bindings), executions: cloneMap(s.executions, cloneExecution), continues: cloneMap(s.continues, cloneContinue),
		roles: cloneMap(s.roles, cloneRole), rolePermissions: maps.Clone(s.rolePermissions), userPermissions: maps.Clone(s.userPermissions), roleMembers: maps.Clone(s.roleMembers),
		customDomains:          cloneMap(s.customDomains, (*store.CustomDomain).Clone),
		hostBindings:           cloneMap(s.hostBindings, func(h *store.HostBinding) *store.HostBinding { c := *h; return &c }),
		domainDefaults:         maps.Clone(s.domainDefaults),
		domainAttempts:         maps.Clone(s.domainAttempts),
		tenantAttempts:         cloneAttemptTimes(s.tenantAttempts),
		tlsAssets:              cloneMap(s.tlsAssets, (*store.TLSAsset).Clone),
		tlsLeases:              cloneMap(s.tlsLeases, func(l *store.TLSLease) *store.TLSLease { c := *l; return &c }),
		protection:             cloneMap(s.protection, func(p *protectionstate.State) *protectionstate.State { return p.Clone() }),
		proofs:                 maps.Clone(s.proofs),
		tenants:                cloneMap(s.tenants, cloneTenant),
		clients:                cloneMap(s.clients, cloneClient),
		resourceServers:        cloneMap(s.resourceServers, cloneResourceServer),
		clientGrants:           cloneMap(s.clientGrants, cloneClientGrant),
		userGrants:             cloneMap(s.userGrants, cloneUserGrant),
		signingKeys:            cloneMap(s.signingKeys, cloneSigningKey),
		customSigningKeys:      cloneMap(s.customSigningKeys, cloneCustomSigningKeySet),
		connections:            cloneMap(s.connections, cloneConnection),
		passwordHistories:      clonePasswordHistories(s.passwordHistories),
		users:                  cloneMap(s.users, cloneUser),
		sessions:               cloneMap(s.sessions, cloneSession),
		transactions:           cloneMap(s.transactions, cloneAuthTransaction),
		authCodes:              cloneMap(s.authCodes, cloneAuthCode),
		pushedAuthRequests:     cloneMap(s.pushedAuthRequests, clonePushedAuthRequest),
		deviceCodes:            cloneMap(s.deviceCodes, cloneDeviceCode),
		refreshTokens:          cloneMap(s.refreshTokens, cloneRefreshToken),
		resetTickets:           cloneMap(s.resetTickets, cloneResetTicket),
		verifyTickets:          cloneMap(s.verifyTickets, cloneVerifyTicket),
		operators:              cloneMap(s.operators, cloneOperator),
		jobs:                   cloneMap(s.jobs, cloneJob),
		jobErrors:              cloneJobErrorMap(s.jobErrors),
		jobFiles:               cloneJobFiles(s.jobFiles),
		hostedLogins:           cloneMap(s.hostedLogins, func(c *store.HostedLoginConfig) *store.HostedLoginConfig { return c.Clone() }),
		emailProviders:         cloneMap(s.emailProviders, cloneEmailProvider),
		emailProviderRevisions: maps.Clone(s.emailProviderRevisions),
		emailTemplates:         cloneMap(s.emailTemplates, cloneEmailTemplate),
		emailNotifications:     maps.Clone(s.emailNotifications),
		fedAttempts:            cloneMap(s.fedAttempts, (*store.FederationAttempt).Clone),
		fedIdentities:          maps.Clone(s.fedIdentities),
		fedTokens:              cloneFedTokens(s.fedTokens),
	}
}

// restore reassigns every map from snap.
func (s *Store) restore(snap *state) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.actions, s.actionVersions, s.builds, s.artifacts = snap.actions, snap.actionVersions, snap.builds, snap.artifacts
	s.bindings, s.executions, s.continues = snap.bindings, snap.executions, snap.continues
	s.roles, s.rolePermissions, s.userPermissions, s.roleMembers = snap.roles, snap.rolePermissions, snap.userPermissions, snap.roleMembers
	s.customDomains, s.hostBindings, s.domainDefaults = snap.customDomains, snap.hostBindings, snap.domainDefaults
	s.domainAttempts, s.tenantAttempts = snap.domainAttempts, snap.tenantAttempts
	s.tlsAssets, s.tlsLeases = snap.tlsAssets, snap.tlsLeases
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
	s.hostedLogins = snap.hostedLogins
	s.emailProviders, s.emailProviderRevisions = snap.emailProviders, snap.emailProviderRevisions
	s.emailTemplates, s.emailNotifications = snap.emailTemplates, snap.emailNotifications
	s.fedAttempts, s.fedIdentities, s.fedTokens = snap.fedAttempts, snap.fedIdentities, snap.fedTokens
}

func cloneFedTokens(m map[fedKey][]byte) map[fedKey][]byte {
	out := make(map[fedKey][]byte, len(m))
	for k, v := range m {
		out[k] = bytes.Clone(v)
	}
	return out
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

func cloneAttemptTimes(m map[string][]time.Time) map[string][]time.Time {
	out := make(map[string][]time.Time, len(m))
	for k, v := range m {
		out[k] = slices.Clone(v)
	}
	return out
}
