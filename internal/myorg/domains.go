package myorg

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Domains (Phase B, D-0221): the organization's discovery domains
// (LR42b-15), verified through DNS (LR42b-16); claims made here expire
// after claimTTL unless verified (LR42b-17).

const (
	claimTTL        = 7 * 24 * time.Hour
	verifyTimeout   = 5 * time.Second
	verificationPfx = "_zeroauthy-org."
	domainEventOK   = "my_organization_api_domain_succeeded"
	domainEventFail = "my_organization_api_domain_failed"
)

var domainName = regexp.MustCompile(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9])$`)

// normalizeDomain validates a domain name and lowercases it.
func normalizeDomain(field, v string) (string, *Problem) {
	if len(v) == 0 || len(v) > 253 || !domainName.MatchString(v) {
		return "", badRequest("invalid_body", "domain is not a valid domain name.", ValidationError{Detail: "domain is not a valid domain name.", Field: field, Pointer: "/" + field, Source: "body"})
	}
	return strings.ToLower(v), nil
}

func domainView(d *store.OrganizationDiscoveryDomain, associated bool) map[string]any {
	assoc := "unassociated"
	if associated {
		assoc = "associated"
	}
	return map[string]any{"id": d.ID, "org_id": d.OrganizationID, "domain": d.Domain, "status": d.Status,
		"verification_txt": d.VerificationTXT, "verification_host": d.VerificationHost, "identity_provider_association": assoc}
}

// expireClaims deletes the organization's unverified domains claimed here
// more than claimTTL ago (LR42b-17).
func (h *Handlers) expireClaims(ctx context.Context, c *Caller) error {
	repo, err := store.MyOrg(ctx, h.Store)
	if err != nil {
		return err
	}
	claims, err := repo.DomainClaims(ctx, c.TenantID, c.Org.ID)
	if err != nil {
		return err
	}
	for id, at := range claims {
		if h.now().Sub(at) <= claimTTL {
			continue
		}
		d, err := h.Store.OrganizationsII().GetDiscoveryDomain(ctx, c.TenantID, c.Org.ID, id)
		switch {
		case errors.Is(err, store.ErrNotFound):
			err = repo.DeleteDomainClaim(ctx, c.TenantID, c.Org.ID, id)
		case err == nil && d.Status != "verified":
			err = h.Store.OrganizationsII().DeleteDiscoveryDomain(ctx, c.TenantID, c.Org.ID, id)
			if errors.Is(err, store.ErrNotFound) {
				err = nil
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// domain is the organization's domain domain_id, after expiry.
func (h *Handlers) domain(r *http.Request, c *Caller) (*store.OrganizationDiscoveryDomain, error) {
	if err := h.expireClaims(r.Context(), c); err != nil {
		return nil, err
	}
	id := chi.URLParam(r, "domain_id")
	if !strings.HasPrefix(id, "ord_") && !strings.HasPrefix(id, "dd_") || len(id) > 64 {
		return nil, notFound("The domain does not exist.")
	}
	d, err := h.Store.OrganizationsII().GetDiscoveryDomain(r.Context(), c.TenantID, c.Org.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("The domain does not exist.")
	}
	return d, err
}

// associated reports which domain names the organization's identity
// providers have. Without the Management API there are no providers to
// read, so none.
func (h *Handlers) associated(ctx context.Context, c *Caller) (map[string]bool, error) {
	out := map[string]bool{}
	if h.Writes == nil {
		return out, nil
	}
	held, err := h.linkedDomains(ctx, c)
	for d := range held {
		out[d] = true
	}
	return out, err
}

func (h *Handlers) domainFail(w http.ResponseWriter, r *http.Request, c *Caller, what string, err error) {
	h.event(r, c, domainEventFail)
	h.fail(w, r, what, err)
}

func (h *Handlers) listDomains(w http.ResponseWriter, r *http.Request, c *Caller) {
	p, prob := page(r)
	if prob != nil {
		h.domainFail(w, r, c, "list domains", prob)
		return
	}
	p.IncludeTotals = false
	if err := h.expireClaims(r.Context(), c); err != nil {
		h.domainFail(w, r, c, "list domains", err)
		return
	}
	res, err := h.Store.OrganizationsII().ListDiscoveryDomains(r.Context(), c.TenantID, c.Org.ID, p)
	if err != nil {
		h.domainFail(w, r, c, "list domains", err)
		return
	}
	assoc, err := h.associated(r.Context(), c)
	if err != nil {
		h.domainFail(w, r, c, "list domains", err)
		return
	}
	items := make([]map[string]any, 0, len(res.Items))
	for i := range res.Items {
		items = append(items, domainView(&res.Items[i], assoc[res.Items[i].Domain]))
	}
	out := map[string]any{"organization_domains": items}
	if res.Next != "" {
		out["next"] = res.Next
	}
	h.event(r, c, domainEventOK)
	writeJSON(w, r, http.StatusOK, out)
}

func (h *Handlers) createDomain(w http.ResponseWriter, r *http.Request, c *Caller) {
	var in struct {
		Domain string `json:"domain"`
	}
	if p := decode(r, &in); p != nil {
		h.domainFail(w, r, c, "create domain", p)
		return
	}
	name, p := normalizeDomain("domain", in.Domain)
	if p != nil {
		h.domainFail(w, r, c, "create domain", p)
		return
	}
	ctx := r.Context()
	if err := h.expireClaims(ctx, c); err != nil {
		h.domainFail(w, r, c, "create domain", err)
		return
	}
	d := &store.OrganizationDiscoveryDomain{TenantID: c.TenantID, OrganizationID: c.Org.ID, ID: "ord_" + secrets.RandomString(22), Domain: name,
		Status: "pending", VerificationHost: verificationPfx + name, VerificationTXT: secrets.RandomString(32)}
	err := h.Store.WithTx(ctx, func(tx store.Store) error {
		repo, err := store.MyOrg(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.OrganizationsII().GetDiscoveryDomainByName(ctx, c.TenantID, c.Org.ID, name); err == nil {
			return conflict("domain_exists", "The organization already has this domain.")
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		owners, err := repo.VerifiedDomainOrganizations(ctx, c.TenantID, name)
		if err != nil {
			return err
		}
		if len(owners) > 0 {
			return conflict("domain_exists", "Another organization has verified this domain.")
		}
		if err := tx.OrganizationsII().PutDiscoveryDomain(ctx, d, true); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return conflict("domain_exists", "The organization already has this domain.")
			}
			return err
		}
		return repo.PutDomainClaim(ctx, c.TenantID, c.Org.ID, d.ID, h.now())
	})
	if err != nil {
		h.domainFail(w, r, c, "create domain", err)
		return
	}
	h.event(r, c, domainEventOK)
	writeJSON(w, r, http.StatusCreated, domainView(d, false))
}

func (h *Handlers) getDomain(w http.ResponseWriter, r *http.Request, c *Caller) {
	d, err := h.domain(r, c)
	if err != nil {
		h.domainFail(w, r, c, "get domain", err)
		return
	}
	assoc, err := h.associated(r.Context(), c)
	if err != nil {
		h.domainFail(w, r, c, "get domain", err)
		return
	}
	h.event(r, c, domainEventOK)
	writeJSON(w, r, http.StatusOK, domainView(d, assoc[d.Domain]))
}

func (h *Handlers) deleteDomain(w http.ResponseWriter, r *http.Request, c *Caller) {
	d, err := h.domain(r, c)
	if err == nil && h.Writes != nil {
		// The organization's identity providers lose the domain (LR42b-19).
		err = h.unlinkDomain(r.Context(), c, d.Domain)
	}
	if err == nil {
		err = h.Store.OrganizationsII().DeleteDiscoveryDomain(r.Context(), c.TenantID, c.Org.ID, d.ID)
	}
	if err != nil {
		h.domainFail(w, r, c, "delete domain", err)
		return
	}
	h.event(r, c, domainEventOK)
	w.WriteHeader(http.StatusNoContent)
}

// verifyDomain looks up the TXT record (LR42b-16): a match verifies the
// domain unless another organization verified it first; no match or no
// record fails it; a resolver error leaves it and answers 503.
func (h *Handlers) verifyDomain(w http.ResponseWriter, r *http.Request, c *Caller) {
	d, err := h.domain(r, c)
	if err != nil {
		h.domainFail(w, r, c, "verify domain", err)
		return
	}
	unavailable := problem(http.StatusServiceUnavailable, "dns_unavailable", "Service Unavailable", "The domain's DNS records could not be read; try again later.")
	if h.DNS == nil {
		h.domainFail(w, r, c, "verify domain", unavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), verifyTimeout)
	values, err := h.DNS.LookupTXT(ctx, d.VerificationHost)
	cancel()
	switch {
	case errors.Is(err, customdomain.ErrDNSNotFound):
		values = nil
	case err != nil:
		h.log().WarnContext(r.Context(), "my org: domain verification lookup failed", "domain_id", d.ID, "err", err)
		h.domainFail(w, r, c, "verify domain", unavailable)
		return
	}
	status := "failed"
	if slices.Contains(values, d.VerificationTXT) {
		status = "verified"
	}
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		if status == "verified" {
			repo, err := store.MyOrg(r.Context(), tx)
			if err != nil {
				return err
			}
			owners, err := repo.VerifiedDomainOrganizations(r.Context(), c.TenantID, d.Domain)
			if err != nil {
				return err
			}
			if slices.ContainsFunc(owners, func(o string) bool { return o != c.Org.ID }) {
				status = "failed"
			}
		}
		d.Status = status
		return tx.OrganizationsII().PutDiscoveryDomain(r.Context(), d, false)
	})
	if err != nil {
		h.domainFail(w, r, c, "verify domain", err)
		return
	}
	assoc, _ := h.associated(r.Context(), c)
	if status == "verified" {
		h.event(r, c, domainEventOK)
	} else {
		h.event(r, c, domainEventFail)
	}
	writeJSON(w, r, http.StatusAccepted, domainView(d, assoc[d.Domain]))
}
