package store

import (
	"context"
	"errors"
	"maps"
	"slices"
	"time"
)

var ErrCustomDomainRepositoryUnavailable = errors.New("store: custom domain repository unavailable; upgrade the storage driver")

// CustomDomain is private persistence state, not a public API response. API
// consumers must construct an explicit public DTO; proof/key hashes, generation,
// lifecycle and worker diagnostics must never be copied into that response.
type CustomDomain struct {
	TenantID, ID, Domain, Type, Source, OriginHost                     string
	Generation, Revision                                               int64
	Status, TLSPolicy, CustomClientIPHeader, RelyingPartyIdentifier    string
	CustomClientIPHeaderNull                                           bool
	DomainMetadata                                                     map[string]string
	VerificationMethod, ProofRecordName, ProofRecordValue, ProofStatus string
	ProofToken                                                         []byte
	ProofCreatedAt                                                     time.Time
	ProofVerifiedAt, LastProofCheckAt, ProofFailureSince               *time.Time
	Lifecycle                                                          string
	NextAttemptAt                                                      *time.Time
	AttemptCount                                                       int
	LastFailure                                                        string
	ProxyKeyHash                                                       []byte
	ActiveCertificateKey                                               string
	CreatedAt, UpdatedAt                                               time.Time
}

// Clone owns every mutable member, including optional timestamps.
func (d *CustomDomain) Clone() *CustomDomain {
	if d == nil {
		return nil
	}
	c := *d
	c.DomainMetadata = maps.Clone(d.DomainMetadata)
	c.ProofToken = slices.Clone(d.ProofToken)
	c.ProxyKeyHash = slices.Clone(d.ProxyKeyHash)
	for _, p := range []**time.Time{&c.ProofVerifiedAt, &c.LastProofCheckAt, &c.ProofFailureSince, &c.NextAttemptAt} {
		if *p != nil {
			v := **p
			*p = &v
		}
	}
	return &c
}

const (
	HostCanonical = "canonical"
	HostOperator  = "operator"
	HostPublic    = "public"
	HostOrigin    = "origin"
)

// HostBinding is a globally unique normalized hostname claim. Pending public
// names are claimed with Active=false; origin names never become browser origins.
type HostBinding struct {
	Host, TenantID, DomainID string
	Generation               int64
	Kind                     string
	Active                   bool
}

// CustomDomains returns copies. All list methods use deterministic key ordering;
// List includes every tenant row, leaving public filtering/projection to service.
// ListDue uses storage time, including equality at the due instant.
// Domain/default/projection writes must share a service transaction.
type CustomDomains interface {
	Get(ctx context.Context, tenantID, id string) (*CustomDomain, error)
	List(ctx context.Context, tenantID string) ([]*CustomDomain, error)
	ListDue(ctx context.Context, limit int) ([]*CustomDomain, error)
	// Create uses expected revision zero and assigns the first positive revision.
	Create(ctx context.Context, row *CustomDomain) error
	// Update increments the revision only on a successful CAS.
	Update(ctx context.Context, row *CustomDomain, expectedRevision int64) error
	Delete(ctx context.Context, tenantID, id string, expectedRevision int64) error
	GetHost(ctx context.Context, host string) (*HostBinding, error)
	// PutHost creates a unique claim or updates only the same tenant/domain owner.
	PutHost(ctx context.Context, row *HostBinding) error
	DeleteHost(ctx context.Context, host, tenantID, domainID string) error
	// GetDefault returns an empty ID for the canonical host.
	GetDefault(ctx context.Context, tenantID string) (string, error)
	SetDefault(ctx context.Context, tenantID, domainID string) error
	// AdmitAttempt atomically enforces one domain attempt per 30s and twenty
	// tenant attempts per minute using storage time. Zero admits; a positive
	// duration refuses with Retry-After, without partially mutating counters.
	AdmitAttempt(ctx context.Context, tenantID, domainID string) (time.Duration, error)
}

// UnimplementedCustomDomains fails explicitly until a driver implements the
// capability. It never silently falls back to unverified host routing.
type UnimplementedCustomDomains struct{}

func (UnimplementedCustomDomains) Get(context.Context, string, string) (*CustomDomain, error) {
	return nil, ErrCustomDomainRepositoryUnavailable
}
func (UnimplementedCustomDomains) List(context.Context, string) ([]*CustomDomain, error) {
	return nil, ErrCustomDomainRepositoryUnavailable
}
func (UnimplementedCustomDomains) ListDue(context.Context, int) ([]*CustomDomain, error) {
	return nil, ErrCustomDomainRepositoryUnavailable
}
func (UnimplementedCustomDomains) Create(context.Context, *CustomDomain) error {
	return ErrCustomDomainRepositoryUnavailable
}
func (UnimplementedCustomDomains) Update(context.Context, *CustomDomain, int64) error {
	return ErrCustomDomainRepositoryUnavailable
}
func (UnimplementedCustomDomains) Delete(context.Context, string, string, int64) error {
	return ErrCustomDomainRepositoryUnavailable
}
func (UnimplementedCustomDomains) GetHost(context.Context, string) (*HostBinding, error) {
	return nil, ErrCustomDomainRepositoryUnavailable
}
func (UnimplementedCustomDomains) PutHost(context.Context, *HostBinding) error {
	return ErrCustomDomainRepositoryUnavailable
}
func (UnimplementedCustomDomains) DeleteHost(context.Context, string, string, string) error {
	return ErrCustomDomainRepositoryUnavailable
}
func (UnimplementedCustomDomains) GetDefault(context.Context, string) (string, error) {
	return "", ErrCustomDomainRepositoryUnavailable
}
func (UnimplementedCustomDomains) SetDefault(context.Context, string, string) error {
	return ErrCustomDomainRepositoryUnavailable
}
func (UnimplementedCustomDomains) AdmitAttempt(context.Context, string, string) (time.Duration, error) {
	return 0, ErrCustomDomainRepositoryUnavailable
}
