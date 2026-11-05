// Package rpid resolves the WebAuthn relying party ID and origin for a
// request host (Plan 33b §3.2, R1, R2): the canonical host uses itself, a
// verified custom domain its relying_party_identifier or itself, and an
// operator alias Tenant.DomainRPIDs[host] or itself. A stored RP ID that
// WebAuthn cannot use fails closed; it is never silently replaced.
package rpid

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/hostname"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

// Kind is the request host's role.
type Kind string

const (
	KindCanonical Kind = "canonical"
	KindCustom    Kind = "custom"
	KindOperator  Kind = "operator"
)

// ErrInvalid is returned for an RP ID the rules refuse; its message is fixed.
var ErrInvalid = errors.New("relying party identifier must be the host or a non-public-suffix ancestor it may share")

// Result is the effective RP ID and origin for one request host. Valid is
// false when the stored RP ID cannot be used; ceremonies then fail closed.
type Result struct {
	RPID, Origin string
	Kind         Kind
	Valid        bool
	Problem      string
}

// Policy holds the deployment inputs. RestrictShared is
// security.webauthn.restrict_shared_rp_ids.
type Policy struct {
	BaseDomain, SystemHost, OriginSuffix string
	RestrictShared                       bool
	Store                                store.Store
	Log                                  *slog.Logger
}

// splitHost lowercases the host, drops a trailing dot and separates a port.
func splitHost(raw string) (host, port string) {
	host = strings.ToLower(raw)
	if h, p, err := net.SplitHostPort(host); err == nil {
		host, port = h, p
	}
	return strings.TrimSuffix(host, "."), port
}

// For resolves res.Host.
func (p Policy) For(ctx context.Context, res tenant.Resolved) (Result, error) {
	host, port := splitHost(res.Host)
	r := Result{RPID: host, Origin: "https://" + host, Kind: KindCanonical, Valid: true}
	if port != "" {
		r.Origin += ":" + port
	}
	if res.Tenant == nil {
		return r, nil
	}
	// A nondefault port identifies a distinct operator alias even when its
	// hostname equals the canonical host. Strip the port only for the RP ID.
	if tenant.NormalizeHost(res.Host) == tenant.NormalizeHost(res.Tenant.CanonicalHost) {
		return r, nil
	}
	binding, err := p.binding(ctx, tenant.NormalizeHost(res.Host))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return r, err
	}
	stored := ""
	switch {
	case binding != nil && binding.TenantID == res.Tenant.ID && binding.Kind == store.HostPublic && binding.Active:
		r.Kind = KindCustom
		d, err := p.Store.CustomDomains().Get(ctx, res.Tenant.ID, binding.DomainID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return r, err
		}
		if d != nil && d.Status == "ready" {
			stored = d.RelyingPartyIdentifier
		} else {
			return p.invalid(ctx, res, r), nil
		}
	case binding != nil && binding.TenantID == res.Tenant.ID && binding.Kind == store.HostOperator && binding.Active:
		r.Kind = KindOperator
		stored = res.Tenant.DomainRPIDs[binding.Host]
	default:
		return p.invalid(ctx, res, r), nil
	}
	if stored != "" {
		r.RPID = stored
	}
	if err := p.Validate(ctx, res.Tenant.ID, host, r.RPID); err != nil {
		if !errors.Is(err, ErrInvalid) {
			return r, err
		}
		return p.invalid(ctx, res, r), nil
	}
	return r, nil
}

func (p Policy) invalid(ctx context.Context, res tenant.Resolved, r Result) Result {
	r.Valid, r.Problem = false, ErrInvalid.Error()
	log := p.Log
	if log == nil {
		log = slog.Default()
	}
	log.WarnContext(ctx, "unusable WebAuthn relying party ID; ceremonies fail closed", "tenant", res.Tenant.ID, "host", res.Host)
	return r
}

func (p Policy) binding(ctx context.Context, host string) (*store.HostBinding, error) {
	if p.Store == nil {
		return nil, store.ErrNotFound
	}
	return p.Store.CustomDomains().GetHost(ctx, host)
}

// covers reports whether rp equals name or is an ancestor of it.
func covers(rp, name string) bool {
	name, _ = splitHost(name)
	return name != "" && (name == rp || strings.HasSuffix(name, "."+rp))
}

// Validate applies WebAuthn's rule (the host or a registrable ancestor, not
// a public suffix, at most 255 bytes) and, with RestrictShared, refuses RP
// IDs covering the deployment's hosts or another tenant's host (R1).
func (p Policy) Validate(ctx context.Context, tenantID, host, rpID string) error {
	host, _ = splitHost(host)
	if len(rpID) > webauthnrules.Limits.RPIDMax {
		return ErrInvalid
	}
	rp, err := hostname.NormalizeDNSName(rpID)
	if err != nil || rp != rpID || !covers(rp, host) {
		return ErrInvalid
	}
	if !p.RestrictShared {
		return nil
	}
	for _, own := range []string{p.BaseDomain, p.SystemHost, p.OriginSuffix} {
		if covers(rp, own) {
			return ErrInvalid
		}
	}
	if p.Store != nil {
		tenants, err := p.Store.WebAuthn().HostTenantsUnder(ctx, rp, 16)
		if err != nil {
			return err
		}
		for _, tid := range tenants {
			if tid != tenantID {
				return ErrInvalid
			}
		}
	}
	return nil
}
