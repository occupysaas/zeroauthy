package cimd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/dcr"
	"github.com/zeroauthy/zeroauthy/internal/ratelimit"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantrules"
)

var (
	// ErrInvalid reports a document that fails validation; the Outcome
	// carries the violations.
	ErrInvalid = errors.New("cimd: the metadata document is invalid")
	// ErrDynamicConflict reports a register call for a URL whose client a
	// user's flow created (Auth0's 409).
	ErrDynamicConflict = errors.New("cimd: a dynamically registered client already exists with this external_client_id")
	// ErrUnavailable reports a client whose document could not be
	// refreshed past its hard expiry (R41-7).
	ErrUnavailable = errors.New("cimd: the metadata document is unavailable")
	// ErrRateLimited reports an unknown URL beyond the tenant's dynamic
	// registration rate.
	ErrRateLimited = errors.New("cimd: too many dynamic registrations")
)

// maxCredentials bounds the keys a CIMD client holds (the JWKS limit).
const maxCredentials = maxJWKSKeys

// Registrar creates, updates and refreshes CIMD clients.
type Registrar struct {
	Store   store.Store
	Fetcher *Fetcher
	Now     func() time.Time

	limitOnce sync.Once
	limiter   *ratelimit.Limiter
}

// limiterFor is the per-tenant limit on dynamic registrations at the
// authorization server: dcr.Rate, as /oidc/register.
func (r *Registrar) limiterFor() *ratelimit.Limiter {
	r.limitOnce.Do(func() { r.limiter = ratelimit.NewLimiter(dcr.Rate, 10000).WithClock(r.now) })
	return r.limiter
}

func (r *Registrar) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Outcome is the result of a registration.
type Outcome struct {
	Client     *store.Client
	Created    bool
	Mapped     Mapped
	Validation Validation
}

// Lookup returns the tenant's client registered with url, or nil.
func Lookup(ctx context.Context, st store.Store, tenantID, url string) (*store.Client, error) {
	cs, _, err := st.Clients().List(ctx, tenantID, store.ClientFilter{ExternalClientID: url}, store.Page{Limit: 1})
	if err != nil || len(cs) == 0 {
		return nil, err
	}
	return cs[0], nil
}

// Register fetches url and creates or updates its client as createdBy
// (store.ExternalCreatedByAdmin or ExternalCreatedByClient). permit is
// called with whether the call creates, before anything is fetched or
// written; its error is returned as is. Concurrent calls for one URL make
// one client: a create that loses the race updates the winner.
func (r *Registrar) Register(ctx context.Context, tn *store.Tenant, url, createdBy string, permit func(create bool) error) (Outcome, error) {
	if err := CheckURL(url); err != nil {
		return Outcome{}, fmt.Errorf("%w: %v", ErrRetrieval, err)
	}
	existing, err := Lookup(ctx, r.Store, tn.ID, url)
	if err != nil {
		return Outcome{}, err
	}
	if existing != nil && createdBy == store.ExternalCreatedByAdmin && existing.External.CreatedBy == store.ExternalCreatedByClient {
		return Outcome{}, ErrDynamicConflict
	}
	if permit != nil {
		if err := permit(existing == nil); err != nil {
			return Outcome{}, err
		}
	}
	doc, err := r.Fetcher.Fetch(ctx, url)
	if err != nil {
		return Outcome{}, err
	}
	mapped, v := r.Fetcher.Evaluate(ctx, doc)
	out := Outcome{Mapped: mapped, Validation: v}
	if !v.Valid {
		return out, ErrInvalid
	}
	for range 2 {
		if existing == nil {
			c := &store.Client{TenantID: tn.ID, ClientID: dcr.NewClientID(), CreatedAt: r.now(), Origin: store.OriginAPI}
			err = r.write(ctx, tn, c, mapped, doc.MaxAge, createdBy, true)
			if err == nil {
				out.Client, out.Created = c, true
				return out, nil
			}
			if !errors.Is(err, store.ErrConflict) {
				return out, err
			}
			// Another call registered the URL first: update its client.
			if existing, err = Lookup(ctx, r.Store, tn.ID, url); err != nil {
				return out, err
			}
			if existing == nil {
				return out, store.ErrConflict
			}
			if permit != nil {
				if err := permit(false); err != nil {
					return Outcome{}, err
				}
			}
			continue
		}
		by := existing.External.CreatedBy
		if createdBy == store.ExternalCreatedByAdmin {
			by = createdBy
		}
		err = r.write(ctx, tn, existing, mapped, doc.MaxAge, by, false)
		out.Client = existing
		return out, err
	}
	return out, store.ErrConflict
}

// Refresh refetches c's document when its cache expired. A good document
// replaces the client's mapped fields and credentials; a failed or invalid
// one marks the client unavailable and keeps it usable until HardExpiry
// after the last good fetch, then ErrUnavailable. It returns the client to
// use.
func (r *Registrar) Refresh(ctx context.Context, tn *store.Tenant, c *store.Client) (*store.Client, error) {
	now := r.now()
	ext := c.External
	if ext == nil || ext.Type != store.ExternalMetadataCIMD {
		return c, nil
	}
	if now.Before(ext.ExpiresAt) {
		return c, nil
	}
	doc, err := r.Fetcher.Fetch(ctx, ext.ClientID)
	if err == nil {
		mapped, v := r.Fetcher.Evaluate(ctx, doc)
		if v.Valid {
			fresh := *c
			if werr := r.write(ctx, tn, &fresh, mapped, doc.MaxAge, ext.CreatedBy, false); werr != nil {
				return nil, werr
			}
			return &fresh, nil
		}
		err = fmt.Errorf("%w: %s", ErrInvalid, strings.Join(v.Violations, "; "))
	}
	if now.After(ext.FetchedAt.Add(HardExpiry)) {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if ext.Status != store.ExternalStatusUnavailable {
		marked := *c
		next := *ext
		next.Status = store.ExternalStatusUnavailable
		marked.External = &next
		if uerr := r.Store.Clients().Update(ctx, &marked); uerr != nil {
			return nil, uerr
		}
		return &marked, nil
	}
	return c, nil
}

// write applies mapped to c and stores it with its credentials in one
// transaction: the client's credentials are replaced by the document's.
func (r *Registrar) write(ctx context.Context, tn *store.Tenant, c *store.Client, m Mapped, maxAge time.Duration, createdBy string, create bool) error {
	firstParty := false
	pkj := m.TokenEndpointAuthMethod == store.AuthMethodPrivateKeyJWT
	method := m.TokenEndpointAuthMethod
	if pkj {
		method = store.AuthMethodClientSecretPost // placeholder, cleared below
	}
	spec := clientrules.Spec{
		Name: m.Name, AppType: m.AppType, TokenEndpointAuthMethod: method,
		GrantTypes: m.GrantTypes, Callbacks: m.Callbacks, AllowedOrigins: dcr.CallbackOrigins(m.Callbacks),
		IsFirstParty: &firstParty, ThirdPartySecurityMode: store.SecurityModeStrict, // LR41b-8
	}
	if errs := clientrules.Normalize(&spec, tn.PushedAuthorizationRequestsSupported); len(errs) > 0 {
		return fmt.Errorf("%w: %v", ErrInvalid, errors.Join(errs...))
	}
	clientrules.Apply(c, &spec)
	c.Secrets = nil
	if pkj {
		c.TokenEndpointAuthMethod = ""
	}
	now := r.now()
	c.External = &store.ClientExternalMetadata{Type: store.ExternalMetadataCIMD, CreatedBy: createdBy, ClientID: m.ExternalClientID,
		Status: store.ExternalStatusAvailable, FetchedAt: now, ExpiresAt: now.Add(maxAge)}
	return r.Store.WithTx(ctx, func(tx store.Store) error {
		if err := store.CheckCIMDSupport(ctx, tx); err != nil {
			return err
		}
		c.PrivateKeyJWTCredentials = nil
		if create {
			if err := tx.Clients().Create(ctx, c); err != nil {
				return err
			}
		} else {
			old, err := tx.ClientCredentials().List(ctx, c.TenantID, c.ClientID)
			if err != nil && !errors.Is(err, store.ErrClientCredentialsUnavailable) {
				return err
			}
			for _, cred := range old {
				if err := tx.ClientCredentials().Delete(ctx, c.TenantID, c.ClientID, cred.ID); err != nil {
					return err
				}
			}
		}
		if pkj {
			c.PrivateKeyJWTCredentials = []string{}
			for _, k := range m.Credentials {
				cred := &store.ClientCredential{TenantID: c.TenantID, ClientID: c.ClientID, ID: "cred_" + secrets.RandomString(22),
					Type: "public_key", KID: k.KID, Alg: k.Alg, PublicKeyDER: k.DER, Thumbprint: k.Thumbprint, CreatedAt: now, UpdatedAt: now}
				if err := tx.ClientCredentials().Create(ctx, cred, maxCredentials); err != nil {
					return err
				}
				c.PrivateKeyJWTCredentials = append(c.PrivateKeyJWTCredentials, cred.ID)
			}
		}
		// Deleting credentials edits the stored client; write c last.
		return tx.Clients().Update(ctx, c)
	})
}

// Resolve maps a client_id from an authorization request to the client ID
// to use (LR41b-6). When the tenant accepts Client ID Metadata Documents
// and clientID is such a URL, it is the internal ID of the client
// registered with it: refreshed when its cache expired, or created (as
// created_by client) when the tenant allows dynamic registration. Any
// other clientID is returned unchanged. An unknown URL without dynamic
// registration is also returned unchanged, so the lookup that follows
// fails as for any unknown client.
func (r *Registrar) Resolve(ctx context.Context, tn *store.Tenant, clientID string) (string, error) {
	if r == nil || !tenantrules.ClientIDMetadataDocuments(tn) || !IsCandidate(clientID) {
		return clientID, nil
	}
	c, err := Lookup(ctx, r.Store, tn.ID, clientID)
	if err != nil {
		return "", err
	}
	if c == nil {
		if !tenantrules.ClientIDMetadataDocumentRegistration(tn) {
			return clientID, nil
		}
		if !r.limiterFor().Allow(tn.ID).Allowed {
			return "", ErrRateLimited
		}
		out, err := r.Register(ctx, tn, clientID, store.ExternalCreatedByClient, nil)
		if err != nil {
			return "", err
		}
		return out.Client.ClientID, nil
	}
	if _, err := r.Refresh(ctx, tn, c); err != nil {
		return "", err
	}
	return c.ClientID, nil
}
