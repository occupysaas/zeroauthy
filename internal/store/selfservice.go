package store

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

// Self-service SSO state of Plan 37c Phase B (scim.v1 capability version 2):
// self-service profiles with their custom text, SSO tickets and connection
// profiles. The Auth0 members of a profile or connection profile live in Doc
// (validated JSON); Name is kept apart for uniqueness. Only the SHA-256 hash
// of a ticket's token is stored.

// SelfServiceProfile is a self-service SSO profile.
type SelfServiceProfile struct {
	TenantID, ID, Name   string
	Doc                  json.RawMessage
	CreatedAt, UpdatedAt time.Time
}

// SSOTicket is a self-service SSO ticket of a profile. Doc is the validated
// ticket request. A ticket can be used until ExpiresAt, unless revoked or
// consumed (UsedAt: the assistant completed). ConnectionID is the one
// connection the ticket may change: the request's connection_id, or the
// connection the assistant created (BindTicketConnection).
type SSOTicket struct {
	TenantID, ID, ProfileID, Hash, ConnectionID string
	Doc                                         json.RawMessage
	CreatedAt, ExpiresAt                        time.Time
	RevokedAt, UsedAt                           *time.Time
}

// Usable reports whether the ticket can still be used at now.
func (t *SSOTicket) Usable(now time.Time) bool {
	return t.RevokedAt == nil && t.UsedAt == nil && now.Before(t.ExpiresAt)
}

// ConnectionProfile is a template for connections created by SSO tickets.
type ConnectionProfile struct {
	TenantID, ID, Name   string
	Doc                  json.RawMessage
	CreatedAt, UpdatedAt time.Time
}

func cloneRaw(r json.RawMessage) json.RawMessage { return slices.Clone(r) }

// Clone returns a deep copy.
func (p *SelfServiceProfile) Clone() *SelfServiceProfile {
	out := *p
	out.Doc = cloneRaw(p.Doc)
	return &out
}

// Clone returns a deep copy.
func (t *SSOTicket) Clone() *SSOTicket {
	out := *t
	out.Doc = cloneRaw(t.Doc)
	out.RevokedAt, out.UsedAt = cloneTime(t.RevokedAt), cloneTime(t.UsedAt)
	return &out
}

// Clone returns a deep copy.
func (p *ConnectionProfile) Clone() *ConnectionProfile {
	out := *p
	out.Doc = cloneRaw(p.Doc)
	return &out
}

// ErrSelfServiceUnavailable: the storage plugin lacks scim.v1 version 2.
var ErrSelfServiceUnavailable = errors.New("store: self-service SSO is not supported by this storage plugin")

// SelfService is Plan 37c Phase B storage.
type SelfService interface {
	// CreateProfile returns ErrConflict if the ID or the name exists.
	CreateProfile(ctx context.Context, p *SelfServiceProfile) error
	GetProfile(ctx context.Context, tenantID, id string) (*SelfServiceProfile, error)
	// UpdateProfile replaces name and document; ErrNotFound, ErrConflict.
	UpdateProfile(ctx context.Context, p *SelfServiceProfile) error
	// DeleteProfile removes the profile, its custom text and its tickets;
	// ErrNotFound.
	DeleteProfile(ctx context.Context, tenantID, id string) error
	// ListProfiles lists oldest first.
	ListProfiles(ctx context.Context, tenantID string, p Page) ([]*SelfServiceProfile, int, error)

	// GetCustomText returns nil when nothing is set.
	GetCustomText(ctx context.Context, tenantID, profileID, language, page string) (json.RawMessage, error)
	// SetCustomText replaces the page's text; ErrNotFound for an unknown
	// profile.
	SetCustomText(ctx context.Context, tenantID, profileID, language, page string, text json.RawMessage) error

	// CreateTicket returns ErrNotFound for an unknown profile.
	CreateTicket(ctx context.Context, t *SSOTicket) error
	GetTicketByHash(ctx context.Context, tenantID, hash string) (*SSOTicket, error)
	// RevokeTicket records now as the revocation time; revoking again keeps
	// the first time. ErrNotFound for an unknown ticket of the profile.
	RevokeTicket(ctx context.Context, tenantID, profileID, id string, now time.Time) error
	// UseTicket consumes a usable ticket; ErrPrecondition when it is
	// revoked, used or expired at now.
	UseTicket(ctx context.Context, tenantID, id string, now time.Time) error
	// BindTicketConnection records the connection a ticket created. It
	// succeeds when the ticket has no connection or already this one, and
	// returns ErrPrecondition for another one; ErrNotFound for an unknown
	// ticket.
	BindTicketConnection(ctx context.Context, tenantID, id, connectionID string) error

	// CreateConnectionProfile returns ErrConflict if the ID or name exists.
	CreateConnectionProfile(ctx context.Context, p *ConnectionProfile) error
	GetConnectionProfile(ctx context.Context, tenantID, id string) (*ConnectionProfile, error)
	UpdateConnectionProfile(ctx context.Context, p *ConnectionProfile) error
	DeleteConnectionProfile(ctx context.Context, tenantID, id string) error
	// ListConnectionProfiles lists oldest first.
	ListConnectionProfiles(ctx context.Context, tenantID string, p Page) ([]*ConnectionProfile, int, error)
}

// SelfServiceSupporter reports scim.v1 version 2.
type SelfServiceSupporter interface{ SelfServiceSupported() bool }

// SelfServiceAvailable reports whether st stores self-service SSO state.
func SelfServiceAvailable(st Store) bool {
	if s, ok := st.(SelfServiceSupporter); ok {
		return s.SelfServiceSupported()
	}
	return false
}

// UnimplementedSelfService fails closed.
type UnimplementedSelfService struct{}

func (UnimplementedSelfService) CreateProfile(context.Context, *SelfServiceProfile) error {
	return ErrSelfServiceUnavailable
}
func (UnimplementedSelfService) GetProfile(context.Context, string, string) (*SelfServiceProfile, error) {
	return nil, ErrSelfServiceUnavailable
}
func (UnimplementedSelfService) UpdateProfile(context.Context, *SelfServiceProfile) error {
	return ErrSelfServiceUnavailable
}
func (UnimplementedSelfService) DeleteProfile(context.Context, string, string) error {
	return ErrSelfServiceUnavailable
}
func (UnimplementedSelfService) ListProfiles(context.Context, string, Page) ([]*SelfServiceProfile, int, error) {
	return nil, 0, ErrSelfServiceUnavailable
}
func (UnimplementedSelfService) GetCustomText(context.Context, string, string, string, string) (json.RawMessage, error) {
	return nil, ErrSelfServiceUnavailable
}
func (UnimplementedSelfService) SetCustomText(context.Context, string, string, string, string, json.RawMessage) error {
	return ErrSelfServiceUnavailable
}
func (UnimplementedSelfService) CreateTicket(context.Context, *SSOTicket) error {
	return ErrSelfServiceUnavailable
}
func (UnimplementedSelfService) GetTicketByHash(context.Context, string, string) (*SSOTicket, error) {
	return nil, ErrSelfServiceUnavailable
}
func (UnimplementedSelfService) RevokeTicket(context.Context, string, string, string, time.Time) error {
	return ErrSelfServiceUnavailable
}
func (UnimplementedSelfService) UseTicket(context.Context, string, string, time.Time) error {
	return ErrSelfServiceUnavailable
}
func (UnimplementedSelfService) BindTicketConnection(context.Context, string, string, string) error {
	return ErrSelfServiceUnavailable
}
func (UnimplementedSelfService) CreateConnectionProfile(context.Context, *ConnectionProfile) error {
	return ErrSelfServiceUnavailable
}
func (UnimplementedSelfService) GetConnectionProfile(context.Context, string, string) (*ConnectionProfile, error) {
	return nil, ErrSelfServiceUnavailable
}
func (UnimplementedSelfService) UpdateConnectionProfile(context.Context, *ConnectionProfile) error {
	return ErrSelfServiceUnavailable
}
func (UnimplementedSelfService) DeleteConnectionProfile(context.Context, string, string) error {
	return ErrSelfServiceUnavailable
}
func (UnimplementedSelfService) ListConnectionProfiles(context.Context, string, Page) ([]*ConnectionProfile, int, error) {
	return nil, 0, ErrSelfServiceUnavailable
}
