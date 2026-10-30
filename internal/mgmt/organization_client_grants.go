package mgmt

import (
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/http"
)

func (h *Handlers) ListOrganizationClientGrants(w http.ResponseWriter, r *http.Request, id string) {
	if _, ok := h.orgs(w); !ok {
		return
	}
	if !h.organizationClientParent(w, r, id) {
		return
	}
	if !organizationGrantNoBody(w, r) {
		return
	}
	p, _, err := orgQuery(r, "page", "per_page", "include_totals")
	if err != nil {
		Fail(w, err)
		return
	}
	result, err := h.Store.OrganizationsII().ListClientGrants(r.Context(), resolved(r).ID, id, p)
	if err != nil {
		h.orgIIError(w, r, err)
		return
	}
	grants := make([]*store.ClientGrant, len(result.Items))
	for i := range result.Items {
		grants[i] = &result.Items[i]
	}
	out := clientGrantViews(grants)
	if p.IncludeTotals {
		writeJSON(w, 200, map[string]any{"client_grants": out, "start": p.Page * p.PerPage, "limit": p.PerPage, "total": result.Total})
		return
	}
	writeJSON(w, 200, out)
}
func (h *Handlers) AssociateOrganizationClientGrant(w http.ResponseWriter, r *http.Request, id string) {
	if !h.organizationClientParent(w, r, id) {
		return
	}
	if err := noClientQuery(r); err != nil {
		Fail(w, err)
		return
	}
	body, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	var grantID string
	if len(body) != 1 || isNull(body["grant_id"]) || decodeString(body["grant_id"], &grantID) != nil || !clientGrantID.MatchString(grantID) {
		Fail(w, badBody("grant_id is required and must be a grant ID"))
		return
	}
	var grant *store.ClientGrant
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		if _, err := invitationOrg(r, tx, id); err != nil {
			return err
		}
		g, err := findClientGrant(r, tx, resolved(r).ID, grantID)
		if errors.Is(err, errClientGrantNotFound) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		if g.SubjectType != store.SubjectTypeClient {
			return badBody("organization associations require a client-subject grant")
		}
		exists, err := tx.OrganizationsII().HasClientGrant(r.Context(), resolved(r).ID, id, grantID)
		if err != nil {
			return err
		}
		if exists {
			return store.ErrConflict
		}
		if err := tx.OrganizationsII().PutClientGrant(r.Context(), resolved(r).ID, id, grantID); err != nil {
			return err
		}
		grant = g
		return nil
	})
	if err != nil {
		h.orgIIError(w, r, err)
		return
	}
	h.audit(r, "associate organization client grant", "id", id, "grant_id", grantID)
	writeJSON(w, 201, clientGrantView(grant))
}
func (h *Handlers) DeleteOrganizationClientGrant(w http.ResponseWriter, r *http.Request, id, grantID string) {
	if !h.organizationClientParent(w, r, id) {
		return
	}
	if err := noClientQuery(r); err != nil {
		Fail(w, err)
		return
	}
	if r.Body != nil && r.ContentLength != 0 {
		Fail(w, badBody("this operation accepts no body"))
		return
	}
	if !clientGrantID.MatchString(grantID) {
		Fail(w, errBadGrantID)
		return
	}
	err := h.Store.WithTx(r.Context(), func(tx store.Store) error {
		if _, err := invitationOrg(r, tx, id); err != nil {
			return err
		}
		if _, err := findClientGrant(r, tx, resolved(r).ID, grantID); err != nil {
			if errors.Is(err, errClientGrantNotFound) {
				return store.ErrNotFound
			}
			return err
		}
		exists, err := tx.OrganizationsII().HasClientGrant(r.Context(), resolved(r).ID, id, grantID)
		if err != nil {
			return err
		}
		if !exists {
			return store.ErrNotFound
		}
		return tx.OrganizationsII().DeleteClientGrant(r.Context(), resolved(r).ID, id, grantID)
	})
	if err != nil {
		h.orgIIError(w, r, err)
		return
	}
	h.audit(r, "remove organization client grant", "id", id, "grant_id", grantID)
	w.WriteHeader(204)
}
func (h *Handlers) ListClientGrantOrganizations(w http.ResponseWriter, r *http.Request, grantID string) {
	if !organizationGrantNoBody(w, r) {
		return
	}
	if !h.orgIIAvailable(w, r) {
		return
	}
	if !clientGrantID.MatchString(grantID) {
		Fail(w, errBadGrantID)
		return
	}
	p, checkpoint, err := orgQuery(r, "page", "per_page", "include_totals", "from", "take")
	if err != nil {
		Fail(w, err)
		return
	}
	if _, err := findClientGrant(r, h.Store, resolved(r).ID, grantID); err != nil {
		if errors.Is(err, errClientGrantNotFound) {
			err = store.ErrNotFound
		}
		h.orgIIError(w, r, err)
		return
	}
	result, err := h.Store.OrganizationsII().GrantOrganizations(r.Context(), resolved(r).ID, grantID, p)
	if errors.Is(err, store.ErrInvalid) {
		Fail(w, &Error{Status: 400, Code: "invalid_paging", Message: "Invalid checkpoint"})
		return
	}
	if err != nil {
		h.orgIIError(w, r, err)
		return
	}
	items := make([]map[string]any, 0, len(result.Items))
	for _, org := range result.Items {
		items = append(items, orgView(org))
	}
	writeOrgList(w, "organizations", items, result.Total, result.Next, p, checkpoint, false)
}

func organizationGrantNoBody(w http.ResponseWriter, r *http.Request) bool {
	if r.Body != nil && r.ContentLength != 0 {
		Fail(w, badBody("this operation accepts no body"))
		return false
	}
	return true
}
