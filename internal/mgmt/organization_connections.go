package mgmt

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// An organization's connections are served by two resources over the same
// links: the GA /enabled_connections and the Early Access /connections
// that the Deploy CLI uses (D-0055). /connections adds is_enabled and the
// two access levels, which zeroauthy does not store: responses carry the
// observed defaults and writes of any other value are 400.

const (
	orgAccessLevelDefault       = "none"
	orgMemberAccessLevelDefault = "limited"
)

var (
	errOrgConnectionConflict = &Error{Status: http.StatusConflict, Message: "The connection is already enabled for this organization"}
	// Observed: a well-formed connection that is not enabled is 404 without
	// errorCode on GET.
	errOrgConnectionNotEnabled = &Error{Status: http.StatusNotFound, Message: "The connection is not enabled for this organization"}
	errOrgConnectionURI        = &Error{Status: http.StatusBadRequest, Code: "invalid_uri", Message: "Path validation error: the connection id is invalid"}
)

// connectionBody selects which properties a connection body accepts.
type connectionBody int

const (
	connectionCreate    connectionBody = iota // enabled_connections POST and organization create
	connectionUpdate                          // enabled_connections PATCH
	allConnectionCreate                       // /connections POST
	allConnectionUpdate                       // /connections PATCH
)

// readConnectionFlags applies a connection body to c. Unknown properties are
// 400 (observed: strict snake_case).
func readConnectionFlags(raw json.RawMessage, c *store.OrganizationConnection, kind connectionBody) error {
	var body map[string]json.RawMessage
	if decodeStrict(raw, &body) != nil {
		return badBody("a connection must be an object")
	}
	create := kind == connectionCreate || kind == allConnectionCreate
	all := kind == allConnectionCreate || kind == allConnectionUpdate
	if create {
		if _, ok := body["connection_id"]; !ok {
			return badBody("connection_id is required")
		}
	}
	for k, v := range body {
		var err error
		switch k {
		case "connection_id":
			if !create {
				return badBody("unknown property %q", k)
			}
			if decodeString(v, &c.ConnectionID) != nil || !connectionID.MatchString(c.ConnectionID) {
				return badBody("connection_id must be a connection ID")
			}
		case "assign_membership_on_login":
			err = decodeStrict(v, &c.AssignMembershipOnLogin)
		case "is_signup_enabled":
			err = decodeStrict(v, &c.IsSignupEnabled)
		case "show_as_button":
			err = decodeStrict(v, &c.ShowAsButton)
		case "is_enabled":
			if !all {
				return badBody("unknown property %q", k)
			}
			var on bool
			if decodeStrict(v, &on) != nil || !on {
				return badBody("is_enabled can only be true: disabled organization connections are not supported (D-0055)")
			}
		case "organization_connection_name":
			if !all {
				return badBody("unknown property %q", k)
			}
			if !isNull(v) {
				return badBody("organization_connection_name is not supported (D-0055)")
			}
		case "organization_access_level", "organization_member_access_level":
			if !all {
				return badBody("unknown property %q", k)
			}
			want := orgAccessLevelDefault
			if k == "organization_member_access_level" {
				want = orgMemberAccessLevelDefault
			}
			var level string
			if !isNull(v) && (decodeString(v, &level) != nil || level != want) {
				return badBody("%s can only be %q (D-0055)", k, want)
			}
		default:
			return badBody("unknown property %q", k)
		}
		if err != nil {
			return badBody("%s must be a boolean", k)
		}
	}
	return nil
}

func orgConnectionView(c store.OrganizationConnection, conn *store.Connection, all bool) map[string]any {
	out := map[string]any{
		"connection_id":              c.ConnectionID,
		"assign_membership_on_login": c.AssignMembershipOnLogin,
		"is_signup_enabled":          c.IsSignupEnabled,
		"show_as_button":             c.ShowAsButton,
		"connection":                 map[string]any{"name": conn.Name, "strategy": conn.Strategy},
	}
	if all {
		out["is_enabled"] = true
		out["organization_access_level"] = orgAccessLevelDefault
		out["organization_member_access_level"] = orgMemberAccessLevelDefault
	}
	return out
}

// orgConnectionTarget loads the connection c enables (404
// inexistent_connection) and checks c's flags against its strategy.
// st is the store or transaction to read the connection from.
func orgConnectionTarget(r *http.Request, st store.Store, c store.OrganizationConnection) (*store.Connection, error) {
	conn, err := st.Connections().Get(r.Context(), c.TenantID, c.ConnectionID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errConnectionNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := orgrules.ValidateConnection(conn.Strategy, c); err != nil {
		return nil, badBody("%v", err)
	}
	return conn, nil
}

// orgConnectionPath checks the organization and the connection ID of a
// connection path. The organization must exist; the connection ID must be
// well formed.
func (h *Handlers) orgConnectionPath(w http.ResponseWriter, r *http.Request, id, connID string) (store.Organizations, bool) {
	orgs, ok := h.orgs(w)
	if !ok {
		return nil, false
	}
	if _, err := loadOrg(r, orgs, id); err != nil {
		h.orgError(w, r, err)
		return nil, false
	}
	if connID != "" && !connectionID.MatchString(connID) {
		Fail(w, errOrgConnectionURI)
		return nil, false
	}
	return orgs, true
}

func (h *Handlers) listOrgConnections(w http.ResponseWriter, r *http.Request, id string, all bool) {
	if _, ok := h.orgs(w); !ok {
		return
	}
	allowed := []string{"page", "per_page", "include_totals"}
	if all {
		allowed = append(allowed, "is_enabled")
	}
	p, _, err := orgQuery(r, allowed...)
	if err != nil {
		Fail(w, err)
		return
	}
	enabledOnly, err := boolParam(r, "is_enabled", true)
	if err != nil {
		Fail(w, err)
		return
	}
	orgs, ok := h.orgConnectionPath(w, r, id, "")
	if !ok {
		return
	}
	tid := resolved(r).ID
	res, err := orgs.Connections(r.Context(), tid, id, p)
	if err != nil {
		h.orgError(w, r, err)
		return
	}
	items := make([]map[string]any, 0, len(res.Items))
	total := res.Total
	if !enabledOnly {
		// Every stored link is enabled.
		res.Items, total = nil, 0
	}
	for _, c := range res.Items {
		conn, err := h.Store.Connections().Get(r.Context(), tid, c.ConnectionID)
		if err != nil {
			h.orgError(w, r, err)
			return
		}
		items = append(items, orgConnectionView(c, conn, all))
	}
	name := "enabled_connections"
	if all {
		name = "connections"
	}
	writeOrgList(w, name, items, total, "", p, false, true)
}

func (h *Handlers) createOrgConnection(w http.ResponseWriter, r *http.Request, id string, all bool) {
	orgs, ok := h.orgs(w)
	if !ok {
		return
	}
	data, err := decodeObject(r)
	if err != nil {
		Fail(w, err)
		return
	}
	raw, _ := json.Marshal(data)
	c := store.OrganizationConnection{ShowAsButton: true}
	kind := connectionCreate
	if all {
		kind = allConnectionCreate
	}
	if err := readConnectionFlags(raw, &c, kind); err != nil {
		Fail(w, err)
		return
	}
	if _, err := loadOrg(r, orgs, id); err != nil {
		h.orgError(w, r, err)
		return
	}
	c.TenantID, c.OrganizationID = resolved(r).ID, id
	conn, err := orgConnectionTarget(r, h.Store, c)
	if err != nil {
		h.orgError(w, r, err)
		return
	}
	if err := orgs.PutConnection(r.Context(), c, true); err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			Fail(w, errOrgConnectionConflict)
		case errors.Is(err, store.ErrPrecondition):
			Fail(w, badBody("an organization can enable at most %d connections (D-0055)", orgrules.Limit("enabled_connections_per_organization_max")))
		default:
			h.orgError(w, r, err)
		}
		return
	}
	h.audit(r, "enable organization connection", "id", id, "connection", c.ConnectionID)
	writeJSON(w, http.StatusCreated, orgConnectionView(c, conn, all))
}

func (h *Handlers) getOrgConnection(w http.ResponseWriter, r *http.Request, id, connID string, all bool) {
	orgs, ok := h.orgConnectionPath(w, r, id, connID)
	if !ok {
		return
	}
	tid := resolved(r).ID
	c, err := orgs.GetConnection(r.Context(), tid, id, connID)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errOrgConnectionNotEnabled)
		return
	}
	if err != nil {
		h.orgError(w, r, err)
		return
	}
	conn, err := h.Store.Connections().Get(r.Context(), tid, connID)
	if err != nil {
		h.orgError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, orgConnectionView(*c, conn, all))
}

func (h *Handlers) updateOrgConnection(w http.ResponseWriter, r *http.Request, id, connID string, all bool) {
	if _, ok := h.orgConnectionPath(w, r, id, connID); !ok {
		return
	}
	tid := resolved(r).ID
	var out store.OrganizationConnection
	var conn *store.Connection
	err := h.Store.WithTx(r.Context(), func(tx store.Store) error {
		c, err := tx.Organizations().GetConnection(r.Context(), tid, id, connID)
		if errors.Is(err, store.ErrNotFound) {
			// Observed: PATCH of a connection that is not enabled is 404
			// inexistent_connection.
			return errConnectionNotFound
		}
		if err != nil {
			return err
		}
		data, err := decodeObject(r)
		if err != nil {
			return err
		}
		raw, _ := json.Marshal(data)
		kind := connectionUpdate
		if all {
			kind = allConnectionUpdate
		}
		if err := readConnectionFlags(raw, c, kind); err != nil {
			return err
		}
		if conn, err = orgConnectionTarget(r, tx, *c); err != nil {
			return err
		}
		if err := tx.Organizations().PutConnection(r.Context(), *c, false); err != nil {
			return err
		}
		out = *c
		return nil
	})
	if err != nil {
		h.orgError(w, r, err)
		return
	}
	h.audit(r, "update organization connection", "id", id, "connection", connID)
	writeJSON(w, http.StatusOK, orgConnectionView(out, conn, all))
}

func (h *Handlers) deleteOrgConnection(w http.ResponseWriter, r *http.Request, id, connID string) {
	orgs, ok := h.orgConnectionPath(w, r, id, connID)
	if !ok {
		return
	}
	tid := resolved(r).ID
	// Observed: an unknown connection is 404 inexistent_connection; a known
	// one that is not enabled is 204.
	if _, err := h.Store.Connections().Get(r.Context(), tid, connID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			err = errConnectionNotFound
		}
		h.orgError(w, r, err)
		return
	}
	if err := orgs.DeleteConnection(r.Context(), tid, id, connID); err != nil {
		h.orgError(w, r, err)
		return
	}
	h.audit(r, "disable organization connection", "id", id, "connection", connID)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) ListOrganizationConnections(w http.ResponseWriter, r *http.Request, id string) {
	h.listOrgConnections(w, r, id, false)
}
func (h *Handlers) CreateOrganizationConnection(w http.ResponseWriter, r *http.Request, id string) {
	h.createOrgConnection(w, r, id, false)
}
func (h *Handlers) GetOrganizationConnection(w http.ResponseWriter, r *http.Request, id, connID string) {
	h.getOrgConnection(w, r, id, connID, false)
}
func (h *Handlers) UpdateOrganizationConnection(w http.ResponseWriter, r *http.Request, id, connID string) {
	h.updateOrgConnection(w, r, id, connID, false)
}
func (h *Handlers) DeleteOrganizationConnection(w http.ResponseWriter, r *http.Request, id, connID string) {
	h.deleteOrgConnection(w, r, id, connID)
}

// The Early Access /organizations/{id}/connections resource (D-0055).

func (h *Handlers) ListOrganizationAllConnections(w http.ResponseWriter, r *http.Request, id string) {
	h.listOrgConnections(w, r, id, true)
}
func (h *Handlers) CreateOrganizationAllConnection(w http.ResponseWriter, r *http.Request, id string) {
	h.createOrgConnection(w, r, id, true)
}
func (h *Handlers) GetOrganizationAllConnection(w http.ResponseWriter, r *http.Request, id, connID string) {
	h.getOrgConnection(w, r, id, connID, true)
}
func (h *Handlers) UpdateOrganizationAllConnection(w http.ResponseWriter, r *http.Request, id, connID string) {
	h.updateOrgConnection(w, r, id, connID, true)
}
func (h *Handlers) DeleteOrganizationAllConnection(w http.ResponseWriter, r *http.Request, id, connID string) {
	h.deleteOrgConnection(w, r, id, connID)
}
