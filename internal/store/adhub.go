package store

import (
	"bytes"
	"context"
	"errors"
	"time"
)

// StrategyAD is the AD/LDAP connection strategy (Plan 38a).
const StrategyAD = "ad"

// ErrADHubUnavailable reports a storage plugin without the ad_hub.v1
// capability (Plan 38a): it cannot store AD/LDAP provisioning tickets or
// connector sessions.
var ErrADHubUnavailable = errors.New("store: ad_hub.v1 unavailable")

// ADProvisioning is an ad connection's provisioning state: the ticket the
// AD/LDAP Connector is installed with and the key zeroauthy signs hub
// requests with. One per connection, created with it (LR38a-4).
type ADProvisioning struct {
	TenantID, ConnectionID string
	// TicketHash is the lowercase hex SHA-256 of the ticket; tickets are
	// looked up by it.
	TicketHash string
	// TicketSealed and SigningKeySealed are sealed to the tenant and
	// connection (internal/adhub).
	TicketSealed, SigningKeySealed []byte
	CreatedAt                      time.Time
}

// Clone returns a deep copy.
func (p *ADProvisioning) Clone() *ADProvisioning {
	if p == nil {
		return nil
	}
	out := *p
	out.TicketSealed = bytes.Clone(p.TicketSealed)
	out.SigningKeySealed = bytes.Clone(p.SigningKeySealed)
	return &out
}

// ADHubSession records a connector socket authenticated on one replica.
// Rows are refreshed while the socket is open and deleted when it closes;
// rows not seen recently belong to replicas that stopped.
type ADHubSession struct {
	TenantID, ConnectionID, SessionID string
	// ReplicaID names the replica holding the socket; ReplicaURL is its
	// internal forwarding endpoint (empty on a single replica).
	ReplicaID, ReplicaURL string
	// CertThumbprint is the SHA-1 thumbprint of the certificate the
	// connector authenticated with.
	CertThumbprint string
	AgentIP        string
	ConnectedAt    time.Time
	LastSeenAt     time.Time
}

// Clone returns a copy.
func (s *ADHubSession) Clone() *ADHubSession {
	if s == nil {
		return nil
	}
	out := *s
	return &out
}

// ADHubStore stores AD/LDAP provisioning and connector sessions (ad_hub.v1).
// Deleting a connection or tenant deletes its rows.
type ADHubStore interface {
	// CreateADProvisioning stores p; ErrConflict if the connection already
	// has one or the ticket hash is taken in the tenant.
	CreateADProvisioning(ctx context.Context, p *ADProvisioning) error
	GetADProvisioning(ctx context.Context, tenantID, connectionID string) (*ADProvisioning, error)
	// FindADProvisioning finds the provisioning of a ticket hash.
	FindADProvisioning(ctx context.Context, tenantID, ticketHash string) (*ADProvisioning, error)
	// PutADHubSession creates or replaces a session by its key.
	PutADHubSession(ctx context.Context, s *ADHubSession) error
	// DeleteADHubSession removes a session; absent sessions are not an error.
	DeleteADHubSession(ctx context.Context, tenantID, connectionID, sessionID string) error
	// ListADHubSessions returns the connection's sessions seen after
	// seenAfter, most recently connected first.
	ListADHubSessions(ctx context.Context, tenantID, connectionID string, seenAfter time.Time) ([]*ADHubSession, error)
	// PurgeADHubSessions deletes up to limit sessions last seen before before.
	PurgeADHubSessions(ctx context.Context, before time.Time, limit int) (int, error)
}

// ADHubSupporter is implemented by stores that can tell whether they store
// AD/LDAP state.
type ADHubSupporter interface{ CheckADHubSupport(context.Context) error }

// ADHub returns s's ADHubStore after checking the capability.
func ADHub(ctx context.Context, s Store) (ADHubStore, error) {
	if capability, ok := s.(ADHubSupporter); ok {
		if err := capability.CheckADHubSupport(ctx); err != nil {
			return nil, err
		}
	}
	repo, ok := s.(ADHubStore)
	if !ok {
		return nil, ErrADHubUnavailable
	}
	return repo, nil
}
