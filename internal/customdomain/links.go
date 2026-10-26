package customdomain

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/hostname"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ErrOriginMismatch: an artifact was presented on a public origin other than
// the one it was created for.
var ErrOriginMismatch = errors.New("customdomain: artifact belongs to another origin")

// CheckOrigin compares an artifact's stored origin with the request's. A
// legacy empty origin means the pinned canonical origin, never whichever host
// presents it first. Callers check before any consume, rotation, revocation
// or other state change.
func CheckOrigin(storedOrigin, canonicalOrigin, requestOrigin string) error {
	if storedOrigin == "" {
		storedOrigin = canonicalOrigin
	}
	if storedOrigin == "" || storedOrigin != requestOrigin {
		return ErrOriginMismatch
	}
	return nil
}

// SelectNotificationOrigin picks the host for a new user-facing link: an
// explicit selection must be the canonical host or a usable same-tenant
// domain (else ErrDomainUnavailable, 503); otherwise a usable default, else
// canonical. Request Host never participates.
func SelectNotificationOrigin(ctx context.Context, st store.Store, tenantID, explicitHost string) (string, error) {
	return selectNotificationOrigin(ctx, st, tenantID, explicitHost, time.Now())
}
func selectNotificationOrigin(ctx context.Context, st store.Store, tenantID, explicitHost string, now time.Time) (string, error) {
	t, err := st.Tenants().Get(ctx, tenantID)
	if err != nil {
		return "", err
	}
	if explicitHost != "" {
		// The canonical host may be a legacy operator host with a port.
		name, err := hostname.NormalizeOperatorHost(strings.TrimSpace(explicitHost))
		if err != nil {
			return "", ErrDomainUnavailable
		}
		if name == t.CanonicalHost {
			return name, nil
		}
		d, err := domainByHost(ctx, st, tenantID, name)
		if errors.Is(err, store.ErrNotFound) {
			return "", ErrDomainUnavailable
		}
		if err == nil {
			var usable bool
			usable, err = ServingUsable(ctx, st, d, now)
			if err == nil && !usable {
				return "", ErrDomainUnavailable
			}
		}
		if err != nil {
			return "", err
		}
		return d.Domain, nil
	}
	id, err := st.CustomDomains().GetDefault(ctx, tenantID)
	if err != nil {
		return "", err
	}
	if id != "" {
		d, err := st.CustomDomains().Get(ctx, tenantID, id)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return "", err
		}
		if err == nil {
			usable, err := ServingUsable(ctx, st, d, now)
			if err != nil {
				return "", err
			}
			if usable {
				return d.Domain, nil
			}
		}
	}
	return t.CanonicalHost, nil
}

// OriginUsable rechecks, just before an asynchronous side effect, that a
// selected host is still the tenant's canonical host or a usable domain of
// the same tenant. It never substitutes another host.
func OriginUsable(ctx context.Context, st store.Store, tenantID, host string) error {
	t, err := st.Tenants().Get(ctx, tenantID)
	if err != nil {
		return err
	}
	if host != "" && host == t.CanonicalHost {
		return nil
	}
	d, err := domainByHost(ctx, st, tenantID, host)
	if errors.Is(err, store.ErrNotFound) {
		return ErrDomainUnavailable
	}
	if err == nil {
		usable, e := ServingUsable(ctx, st, d, time.Now())
		if e != nil {
			return e
		}
		if !usable {
			return ErrDomainUnavailable
		}
	}
	return err
}

// PublicDomain is the template context of a request or link served on an
// API custom domain: the public name and its metadata only, never origin
// aliases, proofs, keys or certificates. Nil for canonical/operator hosts.
type PublicDomain struct {
	Domain   string
	Metadata map[string]string
}

// PublicContext returns the public custom domain context for host, or nil.
func PublicContext(ctx context.Context, st store.Store, tenantID, host string) (*PublicDomain, error) {
	d, err := domainByHost(ctx, st, tenantID, host)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return publicOf(d), nil
}

func domainByHost(ctx context.Context, st store.Store, tenantID, host string) (*store.CustomDomain, error) {
	h, err := st.CustomDomains().GetHost(ctx, host)
	if errors.Is(err, store.ErrInvalid) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if h.TenantID != tenantID || h.Kind != store.HostPublic {
		return nil, store.ErrNotFound
	}
	return st.CustomDomains().Get(ctx, tenantID, h.DomainID)
}

type publicDomainKey struct{}

// WithPublicDomain records the admitted request's public domain context.
func WithPublicDomain(ctx context.Context, pd *PublicDomain) context.Context {
	return context.WithValue(ctx, publicDomainKey{}, pd)
}

// PublicDomainFromContext is the request's public custom domain context, or
// nil on canonical and operator hosts.
func PublicDomainFromContext(ctx context.Context) *PublicDomain {
	pd, _ := ctx.Value(publicDomainKey{}).(*PublicDomain)
	return pd
}

func publicOf(d *store.CustomDomain) *PublicDomain {
	md := make(map[string]string, len(d.DomainMetadata))
	for k, v := range d.DomainMetadata {
		md[k] = v
	}
	return &PublicDomain{Domain: d.Domain, Metadata: md}
}

// ServingUsable additionally checks the active managed certificate at the
// instant of use, independent of worker availability and retry schedules.
func ServingUsable(ctx context.Context, st store.Store, d *store.CustomDomain, now time.Time) (bool, error) {
	if !Usable(d) {
		return false, nil
	}
	if d.Type != TypeManaged {
		return true, nil
	}
	if d.ActiveCertificateKey == "" {
		return false, nil
	}
	asset, err := st.TLSAssets().Get(ctx, d.ActiveCertificateKey)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return asset.Kind == store.TLSAssetCertificate && asset.TenantID == d.TenantID && asset.DomainID == d.ID && asset.Generation == d.Generation && !now.Before(asset.PublicData.NotBefore) && now.Before(asset.PublicData.NotAfter), nil
}
