package mgmt

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func discoveryDomainView(d *store.OrganizationDiscoveryDomain) map[string]any {
	return map[string]any{"id": d.ID, "domain": d.Domain, "status": d.Status, "verification_host": d.VerificationHost, "verification_txt": d.VerificationTXT, "use_for_organization_discovery": d.UseForOrganizationDiscovery}
}
func readDiscoveryDomain(r *http.Request, d *store.OrganizationDiscoveryDomain, create bool) error {
	if err := noClientQuery(r); err != nil {
		return err
	}
	body, err := decodeObject(r)
	if err != nil {
		return err
	}
	if create {
		if _, ok := body["domain"]; !ok {
			return badBody("domain is required")
		}
	}
	for k, v := range body {
		if isNull(v) {
			return badBody("%s cannot be null", k)
		}
		switch k {
		case "domain":
			if !create || decodeString(v, &d.Domain) != nil {
				return badBody("invalid domain")
			}
			d.Domain, err = orglogin.NormalizeDiscoveryDomain(d.Domain)
			if err != nil {
				return badBody("invalid domain")
			}
		case "status":
			if decodeString(v, &d.Status) != nil || (d.Status != "pending" && d.Status != "verified") || create && d.Status != "pending" {
				return badBody("invalid status")
			}
		case "use_for_organization_discovery":
			if decodeStrict(v, &d.UseForOrganizationDiscovery) != nil {
				return badBody("use_for_organization_discovery must be boolean")
			}
		default:
			return badBody("unknown property %s", k)
		}
	}
	return nil
}
func (h *Handlers) ListOrganizationDiscoveryDomains(w http.ResponseWriter, r *http.Request, id string) {
	if !h.organizationClientParent(w, r, id) {
		return
	}
	p := store.OrgPage{Take: 50}
	q := r.URL.Query()
	for k, v := range q {
		if (k != "from" && k != "take") || len(v) != 1 {
			Fail(w, badQuery("unsupported or repeated query parameter"))
			return
		}
	}
	p.From = q.Get("from")
	if q.Has("take") {
		n, err := strconv.Atoi(q.Get("take"))
		if err != nil || n < 1 || n > 100 {
			Fail(w, badQuery("take must be from 1 to 100"))
			return
		}
		p.Take = n
	}
	res, err := h.Store.OrganizationsII().ListDiscoveryDomains(r.Context(), resolved(r).ID, id, p)
	if errors.Is(err, store.ErrInvalid) {
		Fail(w, &Error{Status: 400, Code: "invalid_paging", Message: "Invalid checkpoint"})
		return
	}
	if err != nil {
		h.orgIIError(w, r, err)
		return
	}
	items := make([]map[string]any, 0, len(res.Items))
	for _, d := range res.Items {
		items = append(items, discoveryDomainView(&d))
	}
	out := map[string]any{"domains": items}
	if res.Next != "" {
		out["next"] = res.Next
	}
	writeJSON(w, 200, out)
}
func (h *Handlers) CreateOrganizationDiscoveryDomain(w http.ResponseWriter, r *http.Request, id string) {
	if !h.organizationClientParent(w, r, id) {
		return
	}
	d := &store.OrganizationDiscoveryDomain{TenantID: resolved(r).ID, OrganizationID: id, ID: "dd_" + secrets.RandomString(24), Status: "pending", UseForOrganizationDiscovery: true}
	if err := readDiscoveryDomain(r, d, true); err != nil {
		Fail(w, err)
		return
	}
	d.VerificationHost = "_zeroauthy-org." + d.Domain
	d.VerificationTXT = secrets.RandomString(32)
	if err := h.Store.OrganizationsII().PutDiscoveryDomain(r.Context(), d, true); err != nil {
		h.orgIIError(w, r, err)
		return
	}
	h.audit(r, "create organization discovery domain", "id", id, "domain_id", d.ID)
	writeJSON(w, 201, discoveryDomainView(d))
}
func (h *Handlers) getDiscoveryDomain(w http.ResponseWriter, r *http.Request, id, key string, byName bool) {
	if !h.organizationClientParent(w, r, id) {
		return
	}
	if err := noClientQuery(r); err != nil {
		Fail(w, err)
		return
	}
	var d *store.OrganizationDiscoveryDomain
	var err error
	if byName {
		key, err = orglogin.NormalizeDiscoveryDomain(key)
		if err != nil {
			Fail(w, &Error{Status: 400, Code: "invalid_uri", Message: "Invalid domain name"})
			return
		}
		d, err = h.Store.OrganizationsII().GetDiscoveryDomainByName(r.Context(), resolved(r).ID, id, key)
	} else {
		d, err = h.Store.OrganizationsII().GetDiscoveryDomain(r.Context(), resolved(r).ID, id, key)
	}
	if err != nil {
		h.orgIIError(w, r, err)
		return
	}
	writeJSON(w, 200, discoveryDomainView(d))
}
func (h *Handlers) GetOrganizationDiscoveryDomain(w http.ResponseWriter, r *http.Request, id, key string) {
	h.getDiscoveryDomain(w, r, id, key, false)
}
func (h *Handlers) GetOrganizationDiscoveryDomainByName(w http.ResponseWriter, r *http.Request, id, key string) {
	h.getDiscoveryDomain(w, r, id, key, true)
}
func (h *Handlers) UpdateOrganizationDiscoveryDomain(w http.ResponseWriter, r *http.Request, id, key string) {
	if !h.organizationClientParent(w, r, id) {
		return
	}
	var out *store.OrganizationDiscoveryDomain
	err := h.Store.WithTx(r.Context(), func(tx store.Store) error {
		if _, err := invitationOrg(r, tx, id); err != nil {
			return err
		}
		d, err := tx.OrganizationsII().GetDiscoveryDomain(r.Context(), resolved(r).ID, id, key)
		if err != nil {
			return err
		}
		if err := readDiscoveryDomain(r, d, false); err != nil {
			return err
		}
		// Status changes are administrator attestations, never a network DNS check.
		if err := tx.OrganizationsII().PutDiscoveryDomain(r.Context(), d, false); err != nil {
			return err
		}
		out = d
		return nil
	})
	if err != nil {
		h.orgIIError(w, r, err)
		return
	}
	h.audit(r, "update organization discovery domain", "id", id, "domain_id", key)
	writeJSON(w, 200, discoveryDomainView(out))
}
func (h *Handlers) DeleteOrganizationDiscoveryDomain(w http.ResponseWriter, r *http.Request, id, key string) {
	if !h.organizationClientParent(w, r, id) {
		return
	}
	if err := noClientQuery(r); err != nil {
		Fail(w, err)
		return
	}
	if err := h.Store.OrganizationsII().DeleteDiscoveryDomain(r.Context(), resolved(r).ID, id, key); err != nil {
		h.orgIIError(w, r, err)
		return
	}
	h.audit(r, "delete organization discovery domain", "id", id, "domain_id", key)
	w.WriteHeader(204)
}
