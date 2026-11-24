package mgmt

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Connection profiles (Plan 37c Phase B): templates for the connections SSO
// tickets create. The Auth0 members other than name are kept as validated
// JSON; cross_app_access_resource_app (Early Access) and the
// universal_logout and directory_sync features are stored only.

var (
	errConnectionProfileNotFound = &Error{Status: http.StatusNotFound, Code: "inexistent_connection_profile", Message: "The connection profile does not exist"}
	errConnectionProfileConflict = &Error{Status: http.StatusConflict, Code: "connection_profile_conflict", Message: "A connection profile with this name already exists"}
)

// connectionProfileTemplates are zeroauthy's built-in templates. Auth0's
// catalogue is not documented (Q10); these cover SSO alone and SSO with
// SCIM provisioning.
var connectionProfileTemplates = []map[string]any{
	{"id": "cpt_sso", "display_name": "Single sign-on", "template": map[string]any{
		"name": "Single sign-on", "connection_name_prefix_template": "con-{org_name}", "enabled_features": []string{},
		"organization": map[string]any{"show_as_button": "optional", "assign_membership_on_login": "optional"}}},
	{"id": "cpt_scim", "display_name": "Single sign-on with SCIM provisioning", "template": map[string]any{
		"name": "Single sign-on with SCIM provisioning", "connection_name_prefix_template": "con-{org_name}", "enabled_features": []string{"scim"},
		"organization": map[string]any{"show_as_button": "optional", "assign_membership_on_login": "optional"},
		"provisioning": map[string]any{"scim": map[string]any{"tokens": map[string]any{"scopes": []string{"get:users", "post:users", "put:users", "patch:users", "delete:users"}}}}}},
}

func connectionProfileView(p *store.ConnectionProfile) map[string]any {
	out := map[string]any{}
	_ = json.Unmarshal(p.Doc, &out)
	out["id"], out["name"] = p.ID, p.Name
	return out
}

func (h *Handlers) connectionProfileError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		Fail(w, errConnectionProfileNotFound)
	case errors.Is(err, store.ErrConflict):
		Fail(w, errConnectionProfileConflict)
	default:
		h.selfServiceError(w, r, err)
	}
}

// connectionProfileBody validates a create or update body and splits off
// the name.
func connectionProfileBody(r *http.Request, schema string) (string, map[string]json.RawMessage, error) {
	raw, err := readBodyRaw(r)
	if err == nil {
		err = checkSchema(schema, raw)
	}
	var body map[string]json.RawMessage
	if err == nil {
		err = json.Unmarshal(raw, &body)
	}
	if err != nil {
		return "", nil, err
	}
	var name string
	if v, ok := body["name"]; ok {
		_ = json.Unmarshal(v, &name)
		delete(body, "name")
	}
	return name, body, nil
}

// ListConnectionProfiles serves GET /connection-profiles (checkpoint).
func (h *Handlers) ListConnectionProfiles(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.selfService(w)
	if !ok {
		return
	}
	p, err := readGroupPage(r, false)
	if err != nil {
		Fail(w, err)
		return
	}
	list, total, err := ss.ListConnectionProfiles(r.Context(), resolved(r).ID, store.Page{Offset: p.offset, Limit: p.limit})
	if err != nil {
		h.connectionProfileError(w, r, err)
		return
	}
	items := make([]map[string]any, len(list))
	for i, v := range list {
		items[i] = connectionProfileView(v)
	}
	writeGroupList(w, "connection_profiles", items, total, p)
}

// CreateConnectionProfile serves POST /connection-profiles.
func (h *Handlers) CreateConnectionProfile(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.selfService(w)
	if !ok {
		return
	}
	name, body, err := connectionProfileBody(r, "CreateConnectionProfileRequestContent")
	if err != nil {
		Fail(w, err)
		return
	}
	doc, _ := json.Marshal(body)
	now := h.now()
	p := &store.ConnectionProfile{TenantID: resolved(r).ID, ID: "cop_" + secrets.RandomString(22), Name: name, Doc: doc, CreatedAt: now, UpdatedAt: now}
	if err := ss.CreateConnectionProfile(r.Context(), p); err != nil {
		h.connectionProfileError(w, r, err)
		return
	}
	logDetails(r, "create connection profile", "id", p.ID)
	writeJSON(w, http.StatusCreated, connectionProfileView(p))
}

// GetConnectionProfile serves GET /connection-profiles/{id}.
func (h *Handlers) GetConnectionProfile(w http.ResponseWriter, r *http.Request, id string) {
	ss, ok := h.selfService(w)
	if !ok {
		return
	}
	p, err := ss.GetConnectionProfile(r.Context(), resolved(r).ID, id)
	if err != nil {
		h.connectionProfileError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, connectionProfileView(p))
}

// UpdateConnectionProfile serves PATCH /connection-profiles/{id}: given
// members replace.
func (h *Handlers) UpdateConnectionProfile(w http.ResponseWriter, r *http.Request, id string) {
	if _, ok := h.selfService(w); !ok {
		return
	}
	name, body, err := connectionProfileBody(r, "UpdateConnectionProfileRequestContent")
	if err != nil {
		Fail(w, err)
		return
	}
	var out *store.ConnectionProfile
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		p, err := tx.SelfService().GetConnectionProfile(r.Context(), resolved(r).ID, id)
		if err != nil {
			return err
		}
		cur := map[string]json.RawMessage{}
		_ = json.Unmarshal(p.Doc, &cur)
		for k, v := range body {
			cur[k] = v
		}
		if name != "" {
			p.Name = name
		}
		p.Doc, _ = json.Marshal(cur)
		p.UpdatedAt = h.now()
		out = p
		return tx.SelfService().UpdateConnectionProfile(r.Context(), p)
	})
	if err != nil {
		h.connectionProfileError(w, r, err)
		return
	}
	logDetails(r, "update connection profile", "id", id)
	writeJSON(w, http.StatusOK, connectionProfileView(out))
}

// DeleteConnectionProfile serves DELETE /connection-profiles/{id};
// deleting a missing profile succeeds (the contract lists no 404).
func (h *Handlers) DeleteConnectionProfile(w http.ResponseWriter, r *http.Request, id string) {
	ss, ok := h.selfService(w)
	if !ok {
		return
	}
	if err := ss.DeleteConnectionProfile(r.Context(), resolved(r).ID, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		h.connectionProfileError(w, r, err)
		return
	}
	logDetails(r, "delete connection profile", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

// ListConnectionProfileTemplates serves GET /connection-profiles/templates.
func (h *Handlers) ListConnectionProfileTemplates(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"connection_profile_templates": connectionProfileTemplates})
}

// GetConnectionProfileTemplate serves GET
// /connection-profiles/templates/{id}.
func (h *Handlers) GetConnectionProfileTemplate(w http.ResponseWriter, _ *http.Request, id string) {
	for _, t := range connectionProfileTemplates {
		if t["id"] == id {
			writeJSON(w, http.StatusOK, t)
			return
		}
	}
	Fail(w, &Error{Status: http.StatusNotFound, Code: "inexistent_connection_profile_template", Message: "The connection profile template does not exist"})
}
