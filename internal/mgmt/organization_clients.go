package mgmt

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// organizationClientSummary deliberately excludes credentials and arbitrary
// client configuration. Keep this dedicated projection separate from clientView.
type organizationClientSummary struct {
	Name              string        `json:"name"`
	AppType           store.AppType `json:"app_type"`
	IsFirstParty      bool          `json:"is_first_party"`
	GrantTypes        []string      `json:"grant_types"`
	OrganizationUsage string        `json:"organization_usage,omitempty"`
}
type organizationClientView struct {
	ClientID           string                    `json:"client_id"`
	UseForMemberAccess bool                      `json:"use_for_member_access"`
	Client             organizationClientSummary `json:"client"`
}

func clientAssociationView(link store.OrganizationClient, c *store.Client) organizationClientView {
	grants := c.GrantTypes
	if grants == nil {
		grants = []string{}
	}
	return organizationClientView{link.ClientID, link.UseForMemberAccess, organizationClientSummary{c.Name, c.AppType, c.IsFirstParty, grants, c.OrganizationUsage}}
}
func (h *Handlers) organizationClientParent(w http.ResponseWriter, r *http.Request, id string) bool {
	if !h.orgIIAvailable(w, r) {
		return false
	}
	if _, err := invitationOrg(r, h.Store, id); err != nil {
		h.orgIIError(w, r, err)
		return false
	}
	return true
}
func noClientQuery(r *http.Request) error {
	if len(r.URL.Query()) != 0 {
		return badQuery("unsupported query parameter")
	}
	return nil
}
func (h *Handlers) ListOrganizationClients(w http.ResponseWriter, r *http.Request, id string) {
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
	res, err := h.Store.OrganizationsII().ListClients(r.Context(), resolved(r).ID, id, p)
	if errors.Is(err, store.ErrInvalid) {
		Fail(w, &Error{Status: 400, Code: "invalid_paging", Message: "Invalid checkpoint"})
		return
	}
	if err != nil {
		h.orgIIError(w, r, err)
		return
	}
	items := make([]organizationClientView, 0, len(res.Items))
	for _, link := range res.Items {
		c, err := h.Store.Clients().Get(r.Context(), resolved(r).ID, link.ClientID)
		if err != nil {
			h.orgIIError(w, r, err)
			return
		}
		items = append(items, clientAssociationView(link, c))
	}
	out := map[string]any{"clients": items}
	if res.Next != "" {
		out["next"] = res.Next
	}
	writeJSON(w, 200, out)
}
func readOrganizationClients(r *http.Request, remove bool) ([]store.OrganizationClient, error) {
	if err := noClientQuery(r); err != nil {
		return nil, err
	}
	body, err := decodeObject(r)
	if err != nil {
		return nil, err
	}
	raw, ok := body["clients"]
	if !ok || len(body) != 1 || isNull(raw) {
		return nil, badBody("clients is required")
	}
	var entries []json.RawMessage
	if decodeStrict(raw, &entries) != nil || len(entries) < 1 || len(entries) > 10 {
		return nil, badBody("clients must contain from 1 to 10 entries")
	}
	out := make([]store.OrganizationClient, 0, len(entries))
	seen := map[string]bool{}
	for _, entry := range entries {
		var link store.OrganizationClient
		if remove {
			if decodeString(entry, &link.ClientID) != nil {
				return nil, badBody("client IDs must be strings")
			}
		} else {
			var item map[string]json.RawMessage
			if decodeStrict(entry, &item) != nil || len(item) != 2 {
				return nil, badBody("each client requires client_id and use_for_member_access")
			}
			if decodeString(item["client_id"], &link.ClientID) != nil || isNull(item["use_for_member_access"]) || decodeStrict(item["use_for_member_access"], &link.UseForMemberAccess) != nil {
				return nil, badBody("invalid client association")
			}
		}
		if link.ClientID == "" {
			return nil, badBody("client_id is required")
		}
		if seen[link.ClientID] {
			return nil, store.ErrConflict
		}
		seen[link.ClientID] = true
		out = append(out, link)
	}
	return out, nil
}
func (h *Handlers) AssociateOrganizationClients(w http.ResponseWriter, r *http.Request, id string) {
	if !h.organizationClientParent(w, r, id) {
		return
	}
	links, err := readOrganizationClients(r, false)
	if err != nil {
		h.orgIIError(w, r, err)
		return
	}
	items := make([]organizationClientView, 0, len(links))
	tid := resolved(r).ID
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		if _, err := invitationOrg(r, tx, id); err != nil {
			return err
		}
		for i := range links {
			links[i].TenantID, links[i].OrganizationID = tid, id
			c, err := tx.Clients().Get(r.Context(), tid, links[i].ClientID)
			if err != nil {
				return err
			}
			if _, err := tx.OrganizationsII().GetClient(r.Context(), tid, id, links[i].ClientID); err == nil {
				return store.ErrConflict
			} else if !errors.Is(err, store.ErrNotFound) {
				return err
			}
			items = append(items, clientAssociationView(links[i], c))
		}
		return tx.OrganizationsII().PutClients(r.Context(), tid, id, links)
	})
	if err != nil {
		h.orgIIError(w, r, err)
		return
	}
	h.audit(r, "associate organization clients", "id", id)
	writeJSON(w, 201, items)
}
func (h *Handlers) DeleteOrganizationClients(w http.ResponseWriter, r *http.Request, id string) {
	if !h.organizationClientParent(w, r, id) {
		return
	}
	links, err := readOrganizationClients(r, true)
	if err != nil {
		h.orgIIError(w, r, err)
		return
	}
	tid := resolved(r).ID
	ids := make([]string, len(links))
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		if _, err := invitationOrg(r, tx, id); err != nil {
			return err
		}
		for i, link := range links {
			ids[i] = link.ClientID
			if _, err := tx.Clients().Get(r.Context(), tid, link.ClientID); err != nil {
				return err
			}
		}
		return tx.OrganizationsII().DeleteClients(r.Context(), tid, id, ids)
	})
	if err != nil {
		h.orgIIError(w, r, err)
		return
	}
	h.audit(r, "remove organization clients", "id", id)
	w.WriteHeader(204)
}
func (h *Handlers) GetOrganizationClient(w http.ResponseWriter, r *http.Request, id, clientID string) {
	if !h.organizationClientParent(w, r, id) {
		return
	}
	if err := noClientQuery(r); err != nil {
		Fail(w, err)
		return
	}
	link, err := h.Store.OrganizationsII().GetClient(r.Context(), resolved(r).ID, id, clientID)
	if err != nil {
		h.orgIIError(w, r, err)
		return
	}
	c, err := h.Store.Clients().Get(r.Context(), resolved(r).ID, clientID)
	if err != nil {
		h.orgIIError(w, r, err)
		return
	}
	writeJSON(w, 200, clientAssociationView(*link, c))
}
func (h *Handlers) UpdateOrganizationClient(w http.ResponseWriter, r *http.Request, id, clientID string) {
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
	for k, v := range body {
		if k != "use_for_member_access" || isNull(v) {
			Fail(w, badBody("unsupported or null property %s", k))
			return
		}
	}
	var out organizationClientView
	tid := resolved(r).ID
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		if _, err := invitationOrg(r, tx, id); err != nil {
			return err
		}
		link, err := tx.OrganizationsII().GetClient(r.Context(), tid, id, clientID)
		if err != nil {
			return err
		}
		if raw, ok := body["use_for_member_access"]; ok {
			if decodeStrict(raw, &link.UseForMemberAccess) != nil {
				return badBody("use_for_member_access must be boolean")
			}
		}
		c, err := tx.Clients().Get(r.Context(), tid, clientID)
		if err != nil {
			return err
		}
		if err := tx.OrganizationsII().PutClients(r.Context(), tid, id, []store.OrganizationClient{*link}); err != nil {
			return err
		}
		out = clientAssociationView(*link, c)
		return nil
	})
	if err != nil {
		h.orgIIError(w, r, err)
		return
	}
	h.audit(r, "update organization client", "id", id, "client", clientID)
	writeJSON(w, 200, out)
}
