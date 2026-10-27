// Package memory is an in-memory store.Store for tests and demos. All data
// is lost when the process exits.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/protectionstate"
)

// key addresses a tenant-scoped entity.
type key struct{ tenant, id string }

// Store is safe for concurrent use. One RWMutex guards all maps, so
// multi-entity operations such as key rotation are trivially atomic. A
// transaction body gets a view of the same state with tx set.
type Store struct {
	*state
	// tx marks a transaction's view: its reads and writes already hold txMu.
	tx            bool
	checkedLeases map[string]store.TLSLease
}

// state is the data of a Store and its locks. txMu isolates transactions from
// ordinary reads and writes, so uncommitted state is never externally visible
// and rollback never undoes a write that is not its own. Ordinary readers share
// txMu's read lock and mu's read lock, so independent reads can run together.
type state struct {
	roles                  map[key]*store.Role
	rolePermissions        map[permissionEdge]bool
	userPermissions        map[permissionEdge]bool
	roleMembers            map[memberEdge]bool
	now                    func() time.Time
	customDomains          map[key]*store.CustomDomain
	hostBindings           map[string]*store.HostBinding
	domainDefaults         map[string]string
	domainAttempts         map[key]time.Time
	tenantAttempts         map[string][]time.Time
	tlsAssets              map[string]*store.TLSAsset
	tlsLeases              map[string]*store.TLSLease
	protection             map[string]*protectionstate.State
	proofs                 map[string]time.Time
	txMu                   sync.RWMutex
	mu                     sync.RWMutex
	tenants                map[string]*store.Tenant               // by ID
	clients                map[key]*store.Client                  // by (tenant, client ID)
	resourceServers        map[key]*store.ResourceServer          // by (tenant, ID)
	clientGrants           map[key]*store.ClientGrant             // by (tenant, ID)
	userGrants             map[key]*store.UserGrant               // by (tenant, ID)
	signingKeys            map[key]*store.SigningKey              // by (tenant, KID)
	customSigningKeys      map[string]*store.CustomSigningKeySet  // by tenant
	connections            map[key]*store.Connection              // by (tenant, ID)
	passwordHistories      map[key][][]byte                       // by (tenant, UserID), oldest first
	users                  map[key]*store.User                    // by (tenant, UserID)
	sessions               map[key]*store.LoginSession            // by (tenant, ID)
	transactions           map[key]*store.AuthTransaction         // by (tenant, ID)
	authCodes              map[key]*store.AuthCode                // by (tenant, CodeHash)
	pushedAuthRequests     map[key]*store.PushedAuthRequest       // by (tenant, IDHash)
	deviceCodes            map[key]*store.DeviceCode              // by (tenant, DeviceCodeHash)
	refreshTokens          map[key]*store.RefreshToken            // by (tenant, ID)
	resetTickets           map[key]*store.PasswordResetTicket     // by (tenant, ID)
	verifyTickets          map[key]*store.EmailVerificationTicket // by (tenant, ID)
	operators              map[key]*store.Operator                // by (tenant, UserID)
	jobs                   map[key]*store.Job                     // by (tenant, ID)
	jobErrors              map[key][]store.JobError               // by (tenant, job ID), by Index
	jobFiles               map[key]jobFile                        // by (tenant, job ID)
	hostedLogins           map[string]*store.HostedLoginConfig
	emailProviders         map[string]*store.EmailProvider
	emailProviderRevisions map[string]int64
	emailTemplates         map[key]*store.EmailTemplate
	emailNotifications     map[emailClaimKey]store.EmailNotification
	fedAttempts            map[key]*store.FederationAttempt // by (tenant, StateHash)
	fedIdentities          map[fedKey]string                // owner UserID
	fedTokens              map[fedKey][]byte                // sealed token records
}

// NewWithClock returns an empty store whose storage time (attempt budgets,
// due lists and lease expiry) comes from now, for deterministic tests.
func NewWithClock(now func() time.Time) *Store {
	s := New()
	s.now = now
	return s
}

// New returns an empty store.
func New() *Store {
	return &Store{state: &state{
		roles: map[key]*store.Role{}, rolePermissions: map[permissionEdge]bool{}, userPermissions: map[permissionEdge]bool{}, roleMembers: map[memberEdge]bool{},
		now:            time.Now,
		customDomains:  map[key]*store.CustomDomain{},
		hostBindings:   map[string]*store.HostBinding{},
		domainDefaults: map[string]string{},
		domainAttempts: map[key]time.Time{},
		tenantAttempts: map[string][]time.Time{},
		tlsAssets:      map[string]*store.TLSAsset{},
		tlsLeases:      map[string]*store.TLSLease{},
		protection:     map[string]*protectionstate.State{}, proofs: map[string]time.Time{},
		tenants:                map[string]*store.Tenant{},
		clients:                map[key]*store.Client{},
		resourceServers:        map[key]*store.ResourceServer{},
		clientGrants:           map[key]*store.ClientGrant{},
		userGrants:             map[key]*store.UserGrant{},
		signingKeys:            map[key]*store.SigningKey{},
		customSigningKeys:      map[string]*store.CustomSigningKeySet{},
		connections:            map[key]*store.Connection{},
		passwordHistories:      map[key][][]byte{},
		users:                  map[key]*store.User{},
		sessions:               map[key]*store.LoginSession{},
		transactions:           map[key]*store.AuthTransaction{},
		authCodes:              map[key]*store.AuthCode{},
		pushedAuthRequests:     map[key]*store.PushedAuthRequest{},
		deviceCodes:            map[key]*store.DeviceCode{},
		refreshTokens:          map[key]*store.RefreshToken{},
		resetTickets:           map[key]*store.PasswordResetTicket{},
		verifyTickets:          map[key]*store.EmailVerificationTicket{},
		operators:              map[key]*store.Operator{},
		jobs:                   map[key]*store.Job{},
		jobErrors:              map[key][]store.JobError{},
		jobFiles:               map[key]jobFile{},
		hostedLogins:           map[string]*store.HostedLoginConfig{},
		emailProviders:         map[string]*store.EmailProvider{},
		emailProviderRevisions: map[string]int64{},
		emailTemplates:         map[key]*store.EmailTemplate{},
		emailNotifications:     map[emailClaimKey]store.EmailNotification{},
		fedAttempts:            map[key]*store.FederationAttempt{},
		fedIdentities:          map[fedKey]string{},
		fedTokens:              map[fedKey][]byte{},
	}}
}

// lock takes the write lock. Outside a transaction it first takes txMu,
// so the write waits for a running transaction and is not lost when that
// transaction restores its snapshot.
func (s *Store) lock() {
	if !s.tx {
		s.txMu.Lock()
	}
	s.mu.Lock()
}

func (s *Store) unlock() {
	s.mu.Unlock()
	if !s.tx {
		s.txMu.Unlock()
	}
}

// readLock waits for any external transaction before accessing shared maps.
// Transaction-local reads skip the gate already held by their WithTx caller.
// Lock ordering matches writes: txMu before mu, release in reverse order.
func (s *Store) readLock() {
	if !s.tx {
		s.txMu.RLock()
	}
	s.mu.RLock()
}

func (s *Store) readUnlock() {
	s.mu.RUnlock()
	if !s.tx {
		s.txMu.RUnlock()
	}
}

func (s *Store) Tenants() store.Tenants                           { return tenants{s} }
func (s *Store) Clients() store.Clients                           { return clients{s} }
func (s *Store) ResourceServers() store.ResourceServers           { return resourceServers{s} }
func (s *Store) ClientGrants() store.ClientGrants                 { return clientGrants{s} }
func (s *Store) UserGrants() store.UserGrants                     { return userGrants{s} }
func (s *Store) SigningKeys() store.SigningKeys                   { return signingKeys{s} }
func (s *Store) Connections() store.Connections                   { return connections{s} }
func (s *Store) PasswordHistories() store.PasswordHistories       { return passwordHistories{s} }
func (s *Store) Users() store.Users                               { return users{s} }
func (s *Store) Sessions() store.Sessions                         { return sessions{s} }
func (s *Store) AuthTransactions() store.AuthTransactions         { return authTransactions{s} }
func (s *Store) AuthCodes() store.AuthCodes                       { return authCodes{s} }
func (s *Store) PushedAuthRequests() store.PushedAuthRequests     { return pushedAuthRequests{s} }
func (s *Store) DeviceCodes() store.DeviceCodes                   { return deviceCodes{s} }
func (s *Store) RefreshTokens() store.RefreshTokens               { return refreshTokens{s} }
func (s *Store) PasswordResetTickets() store.PasswordResetTickets { return resetTickets{s} }
func (s *Store) EmailVerificationTickets() store.EmailVerificationTickets {
	return verifyTickets{s}
}
func (s *Store) Operators() store.Operators                   { return operators{s} }
func (s *Store) Jobs() store.Jobs                             { return jobs{s} }
func (s *Store) EmailProviders() store.EmailProviders         { return emailProviders{s} }
func (s *Store) EmailTemplates() store.EmailTemplates         { return emailTemplates{s} }
func (s *Store) EmailNotifications() store.EmailNotifications { return emailNotifications{s} }
func (s *Store) Ping(context.Context) error                   { return nil }
func (s *Store) Close() error                                 { return nil }

var _ store.Store = (*Store)(nil)
