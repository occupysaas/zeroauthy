package customdomain

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/hostname"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var (
	// ErrManagedUnavailable: this deployment does not issue certificates.
	ErrManagedUnavailable = errors.New("customdomain: managed certificates are not enabled on this deployment")
	// ErrOriginTLSUnavailable: self-managed proxies need origin TLS deployment.
	ErrOriginTLSUnavailable = errors.New("customdomain: self-managed domains need a configured origin namespace with TLS")
	// ErrNotReady: the operation needs a currently usable domain (409).
	ErrNotReady = errors.New("customdomain: the custom domain is not ready")
	// ErrDomainUnavailable: an explicitly selected origin cannot be used now (503).
	ErrDomainUnavailable = errors.New("customdomain: the selected custom domain is unavailable")
)

// RateLimitError refuses a verification attempt; RetryAfter is positive.
type RateLimitError struct{ RetryAfter time.Duration }

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("customdomain: too many verification attempts; retry after %s", e.RetryAfter)
}

// ServiceConfig is deployment policy; it never holds provider credentials.
type ServiceConfig struct {
	BaseDomain, SystemHost, OriginDomain string
	ManagedEnabled, OriginTLSReady       bool
}

// Service owns API domain proof and lifecycle. DNS I/O always happens outside
// store transactions; every transition re-reads and CASes the row.
type Service struct {
	st       store.Store
	resolver DNSResolver
	cfg      ServiceConfig
	clock    func() time.Time
	random   io.Reader
}

func NewService(st store.Store, resolver DNSResolver, cfg ServiceConfig, clock func() time.Time, random io.Reader) *Service {
	return &Service{st: st, resolver: resolver, cfg: cfg, clock: clock, random: random}
}

// VerifyResult carries the plaintext proxy key only for the call that created it.
type VerifyResult struct {
	Domain      *store.CustomDomain
	CNAMEAPIKey string
}

// Reserved is the namespace API-owned names may not occupy.
func (s *Service) Reserved() ReservedNames {
	return ReservedNames{SystemHost: s.cfg.SystemHost, BaseDomain: s.cfg.BaseDomain, OriginSuffix: s.cfg.OriginDomain}
}

func (s *Service) randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(s.random, b); err != nil {
		return nil, err
	}
	return b, nil
}

func (s *Service) nextAttempt(now time.Time, d time.Duration) (*time.Time, error) {
	j, err := jitter(d, s.random)
	if err != nil {
		return nil, err
	}
	t := now.Add(j)
	return &t, nil
}

// Create allocates the proof and the private origin alias, and claims both
// names globally (inactive) in one transaction with the row.
func (s *Service) Create(ctx context.Context, tenantID string, in CreateInput) (*store.CustomDomain, error) {
	switch in.Type {
	case TypeManaged:
		if !s.cfg.ManagedEnabled {
			return nil, ErrManagedUnavailable
		}
	case TypeSelfManaged:
		if !s.cfg.OriginTLSReady || s.cfg.OriginDomain == "" {
			return nil, ErrOriginTLSUnavailable
		}
	default:
		return nil, invalid("unsupported domain type")
	}
	now := s.clock()
	id, err := s.randomBytes(8)
	if err != nil {
		return nil, err
	}
	token, err := s.randomBytes(32)
	if err != nil {
		return nil, err
	}
	d := &store.CustomDomain{
		TenantID: tenantID, ID: "cd_" + hex.EncodeToString(id), Domain: in.Domain, Type: in.Type, Source: SourceAPI,
		Generation: 1, Status: StatusPending, TLSPolicy: in.TLSPolicy.Value,
		CustomClientIPHeader: in.CustomClientIPHeader.Value, CustomClientIPHeaderNull: in.CustomClientIPHeader.Null,
		RelyingPartyIdentifier: in.RelyingPartyIdentifier.Value, DomainMetadata: in.DomainMetadata.Value,
		VerificationMethod: "txt", ProofRecordName: ProofRecordPrefix + in.Domain, ProofStatus: ProofPending,
		ProofToken: token, ProofCreatedAt: now, ProofFailureSince: &now, Lifecycle: LifecycleProofPending,
		CreatedAt: now, UpdatedAt: now,
	}
	d.ProofRecordValue = ProofValue(d)
	if d.NextAttemptAt, err = s.nextAttempt(now, retryDelay(1)); err != nil {
		return nil, err
	}
	if s.cfg.OriginDomain != "" {
		label, err := s.randomBytes(8)
		if err != nil {
			return nil, err
		}
		suffix, err := hostname.NormalizeOperatorHost(s.cfg.OriginDomain)
		if err != nil {
			return nil, err
		}
		d.OriginHost = "cd-" + hex.EncodeToString(label) + "." + suffix
	}
	err = s.st.WithTx(ctx, func(tx store.Store) error {
		existing, err := tx.CustomDomains().List(ctx, tenantID)
		if err != nil {
			return err
		}
		if err := ValidateDomainCount(len(existing)); err != nil {
			return err
		}
		if err := tx.CustomDomains().Create(ctx, d); err != nil {
			return err
		}
		for _, h := range s.bindings(d, false) {
			if err := tx.CustomDomains().PutHost(ctx, h); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (s *Service) bindings(d *store.CustomDomain, active bool) []*store.HostBinding {
	out := []*store.HostBinding{{Host: d.Domain, TenantID: d.TenantID, DomainID: d.ID, Generation: d.Generation, Kind: store.HostPublic, Active: active}}
	if d.OriginHost != "" {
		out = append(out, &store.HostBinding{Host: d.OriginHost, TenantID: d.TenantID, DomainID: d.ID, Generation: d.Generation, Kind: store.HostOrigin, Active: active})
	}
	return out
}

// Get returns a copy of the tenant's domain.
func (s *Service) Get(ctx context.Context, tenantID, id string) (*store.CustomDomain, error) {
	return s.st.CustomDomains().Get(ctx, tenantID, id)
}

// Update applies public settings only; omitted fields are preserved.
func (s *Service) Update(ctx context.Context, tenantID, id string, in PatchInput) (*store.CustomDomain, error) {
	var out *store.CustomDomain
	err := s.st.WithTx(ctx, func(tx store.Store) error {
		d, err := tx.CustomDomains().Get(ctx, tenantID, id)
		if err != nil {
			return err
		}
		if in.TLSPolicy.Present {
			d.TLSPolicy = in.TLSPolicy.Value
		}
		if in.CustomClientIPHeader.Present {
			d.CustomClientIPHeader, d.CustomClientIPHeaderNull = in.CustomClientIPHeader.Value, in.CustomClientIPHeader.Null
		}
		if in.DomainMetadata.Present {
			d.DomainMetadata = in.DomainMetadata.Value
		}
		if in.RelyingPartyIdentifier.Present {
			d.RelyingPartyIdentifier = in.RelyingPartyIdentifier.Value
		}
		d.UpdatedAt = s.clock()
		if err := tx.CustomDomains().Update(ctx, d, d.Revision); err != nil {
			return err
		}
		out = d
		return nil
	})
	return out, err
}

// Delete removes serving eligibility, claims, assets and a default pointer to
// it atomically; the repository cascade owns those records.
func (s *Service) Delete(ctx context.Context, tenantID, id string) error {
	return s.st.WithTx(ctx, func(tx store.Store) error {
		d, err := tx.CustomDomains().Get(ctx, tenantID, id)
		if err != nil {
			return err
		}
		return tx.CustomDomains().Delete(ctx, tenantID, id, d.Revision)
	})
}

type proofOutcome int

const (
	proofMatched   proofOutcome = iota
	proofMissing                // a definite answer without the expected value
	proofUncertain              // resolver failure; never revokes ownership by itself
)

// prove performs the bounded DNS check; it must never run inside a transaction.
func (s *Service) prove(ctx context.Context, d *store.CustomDomain) (proofOutcome, string) {
	values, err := s.resolver.LookupTXT(ctx, d.ProofRecordName)
	switch {
	case err == nil:
		want := []byte(ProofValue(d))
		for _, v := range values {
			if subtle.ConstantTimeCompare([]byte(v), want) == 1 {
				return proofMatched, ""
			}
		}
		return proofMissing, "the verification TXT record does not contain the expected value"
	case errors.Is(err, ErrDNSNotFound):
		return proofMissing, "the verification TXT record was not found"
	case errors.Is(err, ErrDNSLimit):
		return proofMissing, "the verification DNS lookup exceeded its limits"
	}
	return proofUncertain, "the verification DNS lookup failed"
}

// serving reports states an explicit verify must not disturb.
func serving(d *store.CustomDomain) bool {
	switch d.Lifecycle {
	case LifecycleActive, LifecycleRenewalError, LifecycleIssuing:
		return true
	}
	return false
}

// Verify is the explicit verification call. A self-managed domain becomes ready
// here only, and the first winner alone receives the plaintext proxy key after
// its hash and ready state commit. Failure restarts the retry schedule.
func (s *Service) Verify(ctx context.Context, tenantID, id string) (VerifyResult, error) {
	d, err := s.st.CustomDomains().Get(ctx, tenantID, id)
	if err != nil {
		return VerifyResult{}, err
	}
	if serving(d) {
		return VerifyResult{Domain: d}, nil
	}
	retry, err := s.st.CustomDomains().AdmitAttempt(ctx, tenantID, id)
	if err != nil {
		return VerifyResult{}, err
	}
	if retry > 0 {
		return VerifyResult{}, &RateLimitError{RetryAfter: retry}
	}
	outcome, reason := s.prove(ctx, d)
	var key string
	err = s.st.WithTx(ctx, func(tx store.Store) error {
		cur, err := tx.CustomDomains().Get(ctx, tenantID, id)
		if err != nil {
			return err
		}
		if cur.Generation != d.Generation {
			return store.ErrConflict
		}
		if serving(cur) {
			d = cur // another verification won; never reissue its key
			return nil
		}
		now := s.clock()
		cur.LastProofCheckAt, cur.UpdatedAt = &now, now
		if outcome == proofMatched {
			if err := s.proved(ctx, tx, cur, now, &key); err != nil {
				return err
			}
		} else {
			// Manual verification restarts the schedule with the same proof.
			if cur.ProofVerifiedAt == nil {
				cur.ProofFailureSince = &now
			}
			if cur.Lifecycle == LifecycleFailed {
				cur.Lifecycle = LifecycleProofPending
			}
			cur.Status, cur.ProofStatus, cur.AttemptCount, cur.LastFailure = StatusPending, ProofPending, 0, reason
			if cur.NextAttemptAt, err = s.nextAttempt(now, retryDelay(1)); err != nil {
				return err
			}
		}
		if err := tx.CustomDomains().Update(ctx, cur, cur.Revision); err != nil {
			return err
		}
		d = cur
		return nil
	})
	if err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{Domain: d, CNAMEAPIKey: key}, nil
}

// proved records a successful explicit proof. Managed domains only queue
// certificate work; they are not ready until a certificate is active. A
// self-managed key is generated once; reactivation after suspension keeps it.
func (s *Service) proved(ctx context.Context, tx store.Store, d *store.CustomDomain, now time.Time, key *string) error {
	d.ProofStatus, d.ProofVerifiedAt, d.ProofFailureSince = ProofVerified, &now, nil
	d.AttemptCount, d.LastFailure = 0, ""
	if d.Type == TypeManaged {
		d.Lifecycle, d.Status, d.NextAttemptAt = LifecycleIssuing, StatusPending, &now
		return nil
	}
	if d.ProxyKeyHash == nil {
		raw, err := s.randomBytes(32)
		if err != nil {
			return err
		}
		*key = base64.RawURLEncoding.EncodeToString(raw)
		d.ProxyKeyHash = HashProxyKey(*key)
	}
	return s.activate(ctx, tx, d, now)
}

func (s *Service) activate(ctx context.Context, tx store.Store, d *store.CustomDomain, now time.Time) error {
	d.Lifecycle, d.Status, d.ProofStatus = LifecycleActive, StatusReady, ProofVerified
	var err error
	if d.NextAttemptAt, err = s.nextAttempt(now, recheckEvery); err != nil {
		return err
	}
	return s.setActive(ctx, tx, d, true)
}

func (s *Service) setActive(ctx context.Context, tx store.Store, d *store.CustomDomain, active bool) error {
	for _, h := range s.bindings(d, active) {
		if err := tx.CustomDomains().PutHost(ctx, h); err != nil {
			return err
		}
	}
	return refreshProjection(ctx, tx, d.TenantID)
}

// refreshProjection rewrites Tenant.Domains so it lists exactly the active
// registry aliases: storage re-appends active public names and keeps
// privileged aliases, while inactive public and origin names drop out.
func refreshProjection(ctx context.Context, tx store.Store, tenantID string) error {
	t, err := tx.Tenants().Get(ctx, tenantID)
	if err != nil {
		return err
	}
	keep := t.Domains[:0]
	for _, host := range t.Domains {
		h, err := tx.CustomDomains().GetHost(ctx, host)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err == nil && (h.Kind == store.HostPublic || h.Kind == store.HostOrigin) {
			continue
		}
		keep = append(keep, host)
	}
	t.Domains = keep
	return tx.Tenants().Update(ctx, t)
}

// CheckDue runs the background proof schedule for due domains this service
// owns: initial proof retries, suspended re-proof and self-managed 24h
// ownership rechecks. Issuing/renewing managed domains belong to the
// certificate worker. Background work never creates a self-managed key.
func (s *Service) CheckDue(ctx context.Context) error {
	due, err := s.st.CustomDomains().ListDue(ctx, 100)
	if err != nil {
		return err
	}
	var errs []error
	for _, d := range due {
		if !s.ownsBackground(d) {
			continue
		}
		outcome, reason := s.prove(ctx, d)
		err := s.st.WithTx(ctx, func(tx store.Store) error {
			cur, err := tx.CustomDomains().Get(ctx, d.TenantID, d.ID)
			if errors.Is(err, store.ErrNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
			if cur.Revision != d.Revision {
				return nil // changed while we looked; the next pass decides
			}
			if err := s.background(ctx, tx, cur, outcome, reason); err != nil {
				return err
			}
			return tx.CustomDomains().Update(ctx, cur, cur.Revision)
		})
		if err != nil && !errors.Is(err, store.ErrConflict) {
			errs = append(errs, fmt.Errorf("custom domain %s/%s: %w", d.TenantID, d.ID, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Service) ownsBackground(d *store.CustomDomain) bool {
	switch d.Lifecycle {
	case LifecycleProofPending, LifecycleSuspended:
		return true
	case LifecycleActive, LifecycleRenewalError:
		return d.Type == TypeSelfManaged
	}
	return false
}

func (s *Service) background(ctx context.Context, tx store.Store, d *store.CustomDomain, outcome proofOutcome, reason string) error {
	now := s.clock()
	d.LastProofCheckAt, d.UpdatedAt = &now, now
	var err error
	switch {
	case outcome == proofMatched && d.Lifecycle == LifecycleProofPending && d.Type == TypeSelfManaged:
		// Ownership is proven, but only an explicit verify may activate and
		// return the one-time key.
		d.ProofStatus, d.ProofVerifiedAt, d.ProofFailureSince = ProofVerified, &now, nil
		d.AttemptCount, d.LastFailure, d.NextAttemptAt = 0, "", nil
		return nil
	case outcome == proofMatched && d.Lifecycle == LifecycleProofPending:
		var none string
		return s.proved(ctx, tx, d, now, &none)
	case outcome == proofMatched && d.Lifecycle == LifecycleSuspended:
		d.ProofVerifiedAt, d.ProofFailureSince, d.AttemptCount, d.LastFailure = &now, nil, 0, ""
		if d.Type == TypeManaged {
			// Re-proven; the certificate worker re-checks its certificate.
			d.Lifecycle, d.ProofStatus, d.NextAttemptAt = LifecycleIssuing, ProofVerified, &now
			return nil
		}
		return s.activate(ctx, tx, d, now) // established key: nothing is reissued
	case outcome == proofMatched:
		d.ProofFailureSince, d.AttemptCount, d.LastFailure = nil, 0, ""
		d.NextAttemptAt, err = s.nextAttempt(now, recheckEvery)
		return err
	}
	d.AttemptCount++
	d.LastFailure = reason
	switch d.Lifecycle {
	case LifecycleProofPending:
		if d.ProofFailureSince == nil {
			d.ProofFailureSince = &now
		}
		if !now.Before(d.ProofFailureSince.Add(initialPause)) {
			d.Lifecycle, d.Status, d.ProofStatus, d.NextAttemptAt = LifecycleFailed, StatusFailed, ProofFailed, nil
			return nil
		}
	case LifecycleActive, LifecycleRenewalError:
		// Resolver outages are uncertainty: they neither start nor complete the
		// continuous-loss window, which only definite missing answers advance.
		if outcome == proofMissing {
			if d.ProofFailureSince == nil {
				d.ProofFailureSince = &now
			}
			if !now.Before(d.ProofFailureSince.Add(lossGrace)) {
				d.Lifecycle, d.Status, d.ProofStatus = LifecycleSuspended, StatusPending, ProofPending
				if err := s.setActive(ctx, tx, d, false); err != nil {
					return err
				}
			}
		}
	}
	// AttemptCount failures have happened; creation already used the first delay.
	d.NextAttemptAt, err = s.nextAttempt(now, retryDelay(d.AttemptCount+1))
	return err
}

// Default returns the configured default domain pointer, or nil for canonical.
// The pointer is retained while the domain is temporarily unusable.
func (s *Service) Default(ctx context.Context, tenantID string) (*store.CustomDomain, error) {
	id, err := s.st.CustomDomains().GetDefault(ctx, tenantID)
	if err != nil || id == "" {
		return nil, err
	}
	return s.st.CustomDomains().Get(ctx, tenantID, id)
}

// SetDefault selects a usable same-tenant API domain, or the canonical host
// (which clears the pointer and returns nil). It never picks implicitly.
func (s *Service) SetDefault(ctx context.Context, tenantID, host string) (*store.CustomDomain, error) {
	name, err := hostname.NormalizeOperatorHost(host)
	if err != nil {
		return nil, invalid("domain is not a valid host")
	}
	var out *store.CustomDomain
	err = s.st.WithTx(ctx, func(tx store.Store) error {
		t, err := tx.Tenants().Get(ctx, tenantID)
		if err != nil {
			return err
		}
		if t.CanonicalHost != "" && name == t.CanonicalHost {
			return tx.CustomDomains().SetDefault(ctx, tenantID, "")
		}
		d, err := s.byHost(ctx, tx, tenantID, name)
		if err != nil {
			return err
		}
		if !Usable(d) {
			return ErrNotReady
		}
		out = d
		return tx.CustomDomains().SetDefault(ctx, tenantID, d.ID)
	})
	return out, err
}

func (s *Service) byHost(ctx context.Context, st store.Store, tenantID, host string) (*store.CustomDomain, error) {
	h, err := st.CustomDomains().GetHost(ctx, host)
	if err != nil {
		return nil, err
	}
	if h.TenantID != tenantID || h.Kind != store.HostPublic {
		return nil, store.ErrNotFound
	}
	return st.CustomDomains().Get(ctx, tenantID, h.DomainID)
}

// NotificationOrigin picks the public host for a new user-facing link: an
// explicit selection must be the canonical host or a usable same-tenant domain
// (else ErrDomainUnavailable, 503); otherwise a usable default, else canonical.
func (s *Service) NotificationOrigin(ctx context.Context, tenantID, explicit string) (string, error) {
	t, err := s.st.Tenants().Get(ctx, tenantID)
	if err != nil {
		return "", err
	}
	if explicit != "" {
		// The canonical host may be a legacy operator host with a port.
		name, err := hostname.NormalizeOperatorHost(strings.TrimSpace(explicit))
		if err != nil {
			return "", ErrDomainUnavailable
		}
		if name == t.CanonicalHost {
			return name, nil
		}
		d, err := s.byHost(ctx, s.st, tenantID, name)
		if errors.Is(err, store.ErrNotFound) || err == nil && !Usable(d) {
			return "", ErrDomainUnavailable
		}
		if err != nil {
			return "", err
		}
		return d.Domain, nil
	}
	d, err := s.Default(ctx, tenantID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	if Usable(d) {
		return d.Domain, nil
	}
	return t.CanonicalHost, nil
}
