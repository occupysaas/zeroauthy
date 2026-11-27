package store

import (
	"context"
	"errors"
	"slices"
	"time"
)

// ErrCIBAUnavailable reports a storage plugin without the ciba.v1
// capability (Plan 41c): it cannot store backchannel authentication
// requests.
var ErrCIBAUnavailable = errors.New("store: ciba.v1 unavailable")

// CIBAStatus is a backchannel authentication request's state.
type CIBAStatus string

const (
	CIBAPending  CIBAStatus = "pending"
	CIBAApproved CIBAStatus = "approved"
	CIBADenied   CIBAStatus = "denied"
	// CIBAConsumed is an approved request whose tokens were issued.
	CIBAConsumed CIBAStatus = "consumed"
)

// CIBAPendingWindow is how long after its expiry a pending request still
// counts towards the tenant's pending limit (Auth0: up to 24 hours), and
// when the sweeper may remove it.
const CIBAPendingWindow = 24 * time.Hour

// CIBARequest is a backchannel authentication request (OpenID CIBA, poll
// mode).
type CIBARequest struct {
	// Origin pins the issuer/host of /bc-authorize.
	Origin   string
	TenantID string
	// IDHash is secrets.HashToken(auth_req_id); TicketHash the hash of the
	// approval link's single-use value. Both unique in the tenant.
	IDHash, TicketHash string
	ClientID           string
	// UserID is the hinted user; empty for a request that is never
	// delivered (unknown user or no verified email, LR41c-7).
	UserID         string
	Scopes         []string
	Audience       string
	BindingMessage string
	Status         CIBAStatus
	// Set by DecideCIBARequest(approved).
	GrantedScopes []string
	ActionEffects []byte
	AuthTime      time.Time
	MFAAt         time.Time
	// Interval is the poll interval in seconds; each slow_down adds 5.
	Interval     int
	LastPolledAt *time.Time
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

// Clone returns a deep copy.
func (r *CIBARequest) Clone() *CIBARequest {
	if r == nil {
		return nil
	}
	out := *r
	out.Scopes = slices.Clone(r.Scopes)
	out.GrantedScopes = slices.Clone(r.GrantedScopes)
	out.ActionEffects = slices.Clone(r.ActionEffects)
	if r.LastPolledAt != nil {
		t := *r.LastPolledAt
		out.LastPolledAt = &t
	}
	return &out
}

// CIBADecision is the user's answer.
type CIBADecision struct {
	Status        CIBAStatus // CIBAApproved or CIBADenied
	GrantedScopes []string
	ActionEffects []byte
	AuthTime      time.Time
	MFAAt         time.Time
}

// CIBAPoll is the outcome of a poll.
type CIBAPoll int

const (
	CIBAPollPending CIBAPoll = iota
	CIBAPollSlowDown
	CIBAPollApproved
	CIBAPollDenied
	CIBAPollExpired
	CIBAPollInvalid
)

// CIBAPollGap is the slow_down step: each poll inside the interval adds it.
const CIBAPollGap = 5

// CIBAStore stores backchannel authentication requests (ciba.v1).
// Deleting a client or tenant deletes its requests.
type CIBAStore interface {
	// CreateCIBARequest returns ErrConflict when IDHash or TicketHash
	// exists in the tenant.
	CreateCIBARequest(ctx context.Context, r *CIBARequest) error
	GetCIBARequest(ctx context.Context, tenantID, idHash string) (*CIBARequest, error)
	GetCIBARequestByTicket(ctx context.Context, tenantID, ticketHash string) (*CIBARequest, error)
	// DecideCIBARequest atomically moves a pending request to dec.Status
	// and records the decision; any other status returns ErrAlreadyUsed.
	// Expiry is the caller's check.
	DecideCIBARequest(ctx context.Context, tenantID, idHash string, dec CIBADecision) (*CIBARequest, error)
	// PollCIBARequest atomically records a poll by clientID at `at`:
	//  1. unknown, or another client's request: ErrNotFound, nothing changes;
	//  2. consumed: CIBAPollInvalid;
	//  3. at is not before ExpiresAt: CIBAPollExpired (pending or denied);
	//  4. less than Interval seconds since LastPolledAt: CIBAPollSlowDown,
	//     Interval grows by CIBAPollGap, LastPolledAt is unchanged;
	//  5. otherwise LastPolledAt = at; pending gives CIBAPollPending,
	//     denied CIBAPollDenied, approved becomes consumed and gives
	//     CIBAPollApproved with the record (once).
	PollCIBARequest(ctx context.Context, tenantID, idHash, clientID string, at time.Time) (CIBAPoll, *CIBARequest, error)
	// CountPendingCIBARequests counts the tenant's pending requests whose
	// ExpiresAt is after now minus CIBAPendingWindow.
	CountPendingCIBARequests(ctx context.Context, tenantID string, now time.Time) (int, error)
	// DeleteExpiredCIBARequests removes, in every tenant, requests whose
	// ExpiresAt is not after before, and returns how many.
	DeleteExpiredCIBARequests(ctx context.Context, before time.Time) (int, error)
}

// CIBASupporter is implemented by stores that can tell whether they store
// CIBA requests.
type CIBASupporter interface{ CheckCIBASupport(context.Context) error }

// CIBA returns s's CIBAStore after checking the capability.
func CIBA(ctx context.Context, s Store) (CIBAStore, error) {
	if capability, ok := s.(CIBASupporter); ok {
		if err := capability.CheckCIBASupport(ctx); err != nil {
			return nil, err
		}
	}
	repo, ok := s.(CIBAStore)
	if !ok {
		return nil, ErrCIBAUnavailable
	}
	return repo, nil
}

// PollCIBA applies PollCIBARequest's rules 2–5 to r at `at`, mutating it,
// for drivers that hold the record (memory, SQL inside a transaction).
func PollCIBA(r *CIBARequest, at time.Time) CIBAPoll {
	switch {
	case r.Status == CIBAConsumed:
		return CIBAPollInvalid
	case !at.Before(r.ExpiresAt) && r.Status != CIBAApproved:
		return CIBAPollExpired
	case r.LastPolledAt != nil && at.Sub(*r.LastPolledAt) < time.Duration(r.Interval)*time.Second:
		r.Interval += CIBAPollGap
		return CIBAPollSlowDown
	}
	t := at
	r.LastPolledAt = &t
	switch r.Status {
	case CIBAApproved:
		r.Status = CIBAConsumed
		return CIBAPollApproved
	case CIBADenied:
		return CIBAPollDenied
	}
	return CIBAPollPending
}
