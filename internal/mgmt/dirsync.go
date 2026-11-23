package mgmt

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/dirsync"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/scim"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// Directory provisioning of google-apps connections (Plan 37c Phase C,
// D-0150 LR37c-14…16).

var (
	errDirSyncUnavailable  = &Error{Status: http.StatusNotImplemented, Code: "not_implemented", Message: "The storage backend does not support directory provisioning"}
	errDirProvNotFound     = &Error{Status: http.StatusNotFound, Code: "inexistent_directory_provisioning", Message: "The connection has no directory provisioning configuration"}
	errDirProvExists       = &Error{Status: http.StatusConflict, Code: "directory_provisioning_exists", Message: "A directory provisioning configuration already exists for this connection"}
	errDirSyncInProgress   = &Error{Status: http.StatusConflict, Code: "synchronization_in_progress", Message: "A synchronization is already pending or running"}
	errDirSyncNoGrant      = &Error{Status: http.StatusBadRequest, Code: "operation_not_supported", Message: "A Google Workspace administrator has not authorized directory access"}
	errSynchronizedGroups  = &Error{Status: http.StatusBadRequest, Code: "invalid_body", Message: "At most 1000 groups can be selected"}
	errDirProvGroupsAccess = &Error{Status: http.StatusBadRequest, Code: "invalid_body", Message: "Group synchronization needs options.api_enable_groups on the connection"}
)

const maxSynchronizedGroups = 1000

func (h *Handlers) dirSync(w http.ResponseWriter) (store.DirectorySync, bool) {
	if !store.DirectorySyncAvailable(h.Store) {
		Fail(w, errDirSyncUnavailable)
		return nil, false
	}
	return h.Store.DirectorySync(), true
}

// dirConnection loads the tenant's google-apps connection.
func (h *Handlers) dirConnection(r *http.Request, id string) (*store.Connection, federation.Config, error) {
	if !connectionID.MatchString(id) {
		return nil, federation.Config{}, errBadConnectionID
	}
	c, err := h.Store.Connections().Get(r.Context(), resolved(r).ID, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, federation.Config{}, errConnectionNotFound
	}
	if err != nil {
		return nil, federation.Config{}, err
	}
	if c.Strategy != rules.GoogleApps {
		return nil, federation.Config{}, badBody("directory provisioning is available only for google-apps connections")
	}
	cfg, err := federation.ParseConfig(*connrules.FromConnection(c))
	if err != nil || cfg.GoogleApps == nil {
		return nil, federation.Config{}, badBody("the connection's options are invalid")
	}
	return c, cfg, nil
}

func (h *Handlers) dirSyncError(w http.ResponseWriter, r *http.Request, err error) {
	var typed *Error
	switch {
	case errors.As(err, &typed):
		Fail(w, typed)
	case errors.Is(err, store.ErrDirectorySyncUnavailable):
		Fail(w, errDirSyncUnavailable)
	case errors.Is(err, store.ErrNotFound):
		Fail(w, errDirProvNotFound)
	case errors.Is(err, store.ErrConflict):
		Fail(w, errDirProvExists)
	default:
		Fail(w, internalError(h, r, "directory provisioning", err))
	}
}

func dirProvView(c *store.Connection, p *store.DirectoryProvisioning) map[string]any {
	var d dirsync.Doc
	_ = json.Unmarshal(p.Doc, &d)
	if d.Mapping == nil {
		d.Mapping = dirsync.DefaultMapping()
	}
	out := map[string]any{"connection_id": c.ID, "connection_name": c.Name, "strategy": c.Strategy, "mapping": d.Mapping,
		"synchronize_automatically": d.SynchronizeAutomatically,
		"created_at": p.CreatedAt.UTC().Format(time.RFC3339Nano), "updated_at": p.UpdatedAt.UTC().Format(time.RFC3339Nano)}
	if d.SynchronizeGroups != "" {
		out["synchronize_groups"] = d.SynchronizeGroups
	}
	if p.LastSyncAt != nil {
		out["last_synchronization_at"] = p.LastSyncAt.UTC().Format(time.RFC3339Nano)
		out["last_synchronization_status"] = p.LastSyncStatus
		if p.LastSyncError != "" {
			out["last_synchronization_error"] = p.LastSyncError
		}
	}
	return out
}

// readDirDoc applies a create or update body to d.
func readDirDoc(r *http.Request, schema string, cfg federation.Config, d *dirsync.Doc) error {
	raw, err := readLimited(r)
	if err != nil {
		return err
	}
	if t := strings.TrimSpace(string(raw)); t == "" || t == "null" {
		raw = json.RawMessage(`{}`)
	}
	if err := checkSchema(schema, raw); err != nil {
		return err
	}
	var body struct {
		Mapping                  []store.SCIMMapping `json:"mapping"`
		SynchronizeAutomatically *bool               `json:"synchronize_automatically"`
		SynchronizeGroups        *string             `json:"synchronize_groups"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return badBody("the body must be a JSON object")
	}
	// The contract names the IdP attribute "idp".
	var named struct {
		Mapping []struct {
			Auth0 string `json:"auth0"`
			IdP   string `json:"idp"`
		} `json:"mapping"`
	}
	_ = json.Unmarshal(raw, &named)
	if named.Mapping != nil {
		body.Mapping = make([]store.SCIMMapping, len(named.Mapping))
		for i, m := range named.Mapping {
			body.Mapping[i] = store.SCIMMapping{Auth0: m.Auth0, SCIM: m.IdP}
		}
		if _, err := scim.ParseMapping(body.Mapping); err != nil {
			return badBody("mapping: %s", err.Error())
		}
		d.Mapping = body.Mapping
	}
	if body.SynchronizeAutomatically != nil {
		d.SynchronizeAutomatically = *body.SynchronizeAutomatically
	}
	if body.SynchronizeGroups != nil {
		d.SynchronizeGroups = *body.SynchronizeGroups
	}
	if d.SynchronizeGroups != "" && d.SynchronizeGroups != "off" && !cfg.GoogleApps.APIEnableGroups {
		return errDirProvGroupsAccess
	}
	return nil
}

// dirDocJSON stores the mapping under the SCIM mapping's field names.
func dirDocJSON(d dirsync.Doc) json.RawMessage {
	b, _ := json.Marshal(d)
	return b
}

// mappingView renders the mapping with the contract's "idp" field.
func mappingView(m []store.SCIMMapping) []map[string]string {
	out := make([]map[string]string, len(m))
	for i, e := range m {
		out[i] = map[string]string{"auth0": e.Auth0, "idp": e.SCIM}
	}
	return out
}

func writeDirProv(w http.ResponseWriter, status int, c *store.Connection, p *store.DirectoryProvisioning) {
	v := dirProvView(c, p)
	v["mapping"] = mappingView(v["mapping"].([]store.SCIMMapping))
	writeJSON(w, status, v)
}

// ListDirectoryProvisionings serves GET /connections-directory-provisionings.
func (h *Handlers) ListDirectoryProvisionings(w http.ResponseWriter, r *http.Request) {
	ds, ok := h.dirSync(w)
	if !ok {
		return
	}
	p, err := readGroupPage(r, false)
	if err != nil {
		Fail(w, err)
		return
	}
	tn := resolved(r)
	list, total, err := ds.ListProvisionings(r.Context(), tn.ID, store.Page{Offset: p.offset, Limit: p.limit})
	if err != nil {
		h.dirSyncError(w, r, err)
		return
	}
	items := []map[string]any{}
	for _, v := range list {
		c, err := h.Store.Connections().Get(r.Context(), tn.ID, v.ConnectionID)
		if err != nil {
			h.dirSyncError(w, r, err)
			return
		}
		view := dirProvView(c, v)
		view["mapping"] = mappingView(view["mapping"].([]store.SCIMMapping))
		items = append(items, view)
	}
	writeGroupList(w, "directory_provisionings", items, total, p)
}

// GetDirectoryProvisioning serves GET /connections/{id}/directory-provisioning.
func (h *Handlers) GetDirectoryProvisioning(w http.ResponseWriter, r *http.Request, id string) {
	ds, ok := h.dirSync(w)
	if !ok {
		return
	}
	c, _, err := h.dirConnection(r, id)
	if err != nil {
		h.dirSyncError(w, r, err)
		return
	}
	p, err := ds.GetProvisioning(r.Context(), c.TenantID, c.ID)
	if err != nil {
		h.dirSyncError(w, r, err)
		return
	}
	writeDirProv(w, http.StatusOK, c, p)
}

// CreateDirectoryProvisioning serves POST /connections/{id}/directory-provisioning.
func (h *Handlers) CreateDirectoryProvisioning(w http.ResponseWriter, r *http.Request, id string) {
	ds, ok := h.dirSync(w)
	if !ok {
		return
	}
	c, cfg, err := h.dirConnection(r, id)
	if err == nil && !cfg.GoogleApps.APIEnableUsers {
		err = badBody("directory provisioning needs options.api_enable_users on the connection")
	}
	d := dirsync.Doc{Mapping: dirsync.DefaultMapping(), SynchronizeGroups: "off"}
	if err == nil {
		err = readDirDoc(r, "CreateDirectoryProvisioningRequestContent", cfg, &d)
	}
	if err != nil {
		h.dirSyncError(w, r, err)
		return
	}
	now := h.now()
	p := &store.DirectoryProvisioning{TenantID: c.TenantID, ConnectionID: c.ID, Doc: dirDocJSON(d), CreatedAt: now, UpdatedAt: now}
	if err := ds.CreateProvisioning(r.Context(), p); err != nil {
		h.dirSyncError(w, r, err)
		return
	}
	writeDirProv(w, http.StatusCreated, c, p)
}

// UpdateDirectoryProvisioning serves PATCH /connections/{id}/directory-provisioning.
func (h *Handlers) UpdateDirectoryProvisioning(w http.ResponseWriter, r *http.Request, id string) {
	if _, ok := h.dirSync(w); !ok {
		return
	}
	c, cfg, err := h.dirConnection(r, id)
	if err != nil {
		h.dirSyncError(w, r, err)
		return
	}
	var out *store.DirectoryProvisioning
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		p, err := tx.DirectorySync().GetProvisioning(r.Context(), c.TenantID, c.ID)
		if err != nil {
			return err
		}
		var d dirsync.Doc
		_ = json.Unmarshal(p.Doc, &d)
		if err := readDirDoc(r, "UpdateDirectoryProvisioningRequestContent", cfg, &d); err != nil {
			return err
		}
		p.Doc, p.UpdatedAt = dirDocJSON(d), h.now()
		if !d.SynchronizeAutomatically && p.LeaseUntil == nil && p.NextSyncAt != nil && p.NextSyncAt.After(h.now()) {
			// Turning automatic runs off cancels the scheduled one.
			p.NextSyncAt, p.SyncID = nil, ""
		}
		out = p
		return tx.DirectorySync().UpdateProvisioning(r.Context(), p)
	})
	if err != nil {
		h.dirSyncError(w, r, err)
		return
	}
	writeDirProv(w, http.StatusOK, c, out)
}

// DeleteDirectoryProvisioning serves DELETE /connections/{id}/directory-provisioning.
// Users and groups already synchronized stay.
func (h *Handlers) DeleteDirectoryProvisioning(w http.ResponseWriter, r *http.Request, id string) {
	ds, ok := h.dirSync(w)
	if !ok {
		return
	}
	c, _, err := h.dirConnection(r, id)
	if err == nil {
		err = ds.DeleteProvisioning(r.Context(), c.TenantID, c.ID)
	}
	if err != nil {
		h.dirSyncError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetDirectoryProvisioningDefaultMapping serves GET .../directory-provisioning/default-mapping.
func (h *Handlers) GetDirectoryProvisioningDefaultMapping(w http.ResponseWriter, r *http.Request, id string) {
	if _, ok := h.dirSync(w); !ok {
		return
	}
	if _, _, err := h.dirConnection(r, id); err != nil {
		h.dirSyncError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mapping": mappingView(dirsync.DefaultMapping())})
}

// CreateDirectorySynchronization serves POST .../directory-provisioning/synchronizations.
func (h *Handlers) CreateDirectorySynchronization(w http.ResponseWriter, r *http.Request, id string) {
	if _, ok := h.dirSync(w); !ok {
		return
	}
	c, _, err := h.dirConnection(r, id)
	if err != nil {
		h.dirSyncError(w, r, err)
		return
	}
	now := h.now()
	var syncID string
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		p, err := tx.DirectorySync().GetProvisioning(r.Context(), c.TenantID, c.ID)
		if err != nil {
			return err
		}
		if len(p.AdminGrant) == 0 {
			return errDirSyncNoGrant
		}
		if (p.LeaseUntil != nil && p.LeaseUntil.After(now)) || (p.NextSyncAt != nil && !p.NextSyncAt.After(now)) {
			return errDirSyncInProgress
		}
		syncID = dirsync.Schedule(p, now)
		return tx.DirectorySync().UpdateProvisioning(r.Context(), p)
	})
	if err != nil {
		h.dirSyncError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"connection_id": c.ID, "synchronization_id": syncID, "status": "pending"})
}

type syncGroup struct {
	ID                 string `json:"id"`
	Name               string `json:"name,omitempty"`
	Email              string `json:"email,omitempty"`
	DirectMembersCount *int   `json:"direct_members_count,omitempty"`
}

func readGroupsBody(r *http.Request, schema string) ([]syncGroup, error) {
	raw, err := readBodyRaw(r)
	if err == nil {
		err = checkSchema(schema, raw)
	}
	var body struct {
		Groups []syncGroup `json:"groups"`
	}
	if err == nil {
		err = json.Unmarshal(raw, &body)
	}
	if err != nil {
		return nil, err
	}
	return body.Groups, nil
}

func toStored(gs []syncGroup) []store.SynchronizedGroup {
	out := make([]store.SynchronizedGroup, len(gs))
	for i, g := range gs {
		doc, _ := json.Marshal(g)
		out[i] = store.SynchronizedGroup{GroupID: g.ID, Doc: doc}
	}
	return out
}

// changeGroups applies change to the selection in one transaction.
func (h *Handlers) changeGroups(w http.ResponseWriter, r *http.Request, id string, change func([]store.SynchronizedGroup) []store.SynchronizedGroup) {
	if _, ok := h.dirSync(w); !ok {
		return
	}
	c, _, err := h.dirConnection(r, id)
	if err != nil {
		h.dirSyncError(w, r, err)
		return
	}
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		cur, err := tx.DirectorySync().ListGroups(r.Context(), c.TenantID, c.ID)
		if err != nil {
			return err
		}
		next := change(cur)
		seen := map[string]bool{}
		for _, g := range next {
			seen[g.GroupID] = true
		}
		if len(seen) > maxSynchronizedGroups {
			return errSynchronizedGroups
		}
		return tx.DirectorySync().ReplaceGroups(r.Context(), c.TenantID, c.ID, next)
	})
	if err != nil {
		h.dirSyncError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// AddSynchronizedGroups serves POST .../synchronized-groups: added entries
// replace ones with the same ID.
func (h *Handlers) AddSynchronizedGroups(w http.ResponseWriter, r *http.Request, id string) {
	gs, err := readGroupsBody(r, "AddSynchronizedGroupsRequestContent")
	if err != nil {
		Fail(w, err)
		return
	}
	add := toStored(gs)
	h.changeGroups(w, r, id, func(cur []store.SynchronizedGroup) []store.SynchronizedGroup {
		// The new entries first: ReplaceGroups keeps the first of an ID.
		return append(add, cur...)
	})
}

// ReplaceSynchronizedGroups serves PUT .../synchronized-groups.
func (h *Handlers) ReplaceSynchronizedGroups(w http.ResponseWriter, r *http.Request, id string) {
	gs, err := readGroupsBody(r, "ReplaceSynchronizedGroupsRequestContent")
	if err != nil {
		Fail(w, err)
		return
	}
	next := toStored(gs)
	h.changeGroups(w, r, id, func([]store.SynchronizedGroup) []store.SynchronizedGroup { return next })
}

// DeleteSynchronizedGroups serves DELETE .../synchronized-groups.
func (h *Handlers) DeleteSynchronizedGroups(w http.ResponseWriter, r *http.Request, id string) {
	gs, err := readGroupsBody(r, "DeleteSynchronizedGroupsRequestContent")
	if err != nil {
		Fail(w, err)
		return
	}
	drop := map[string]bool{}
	for _, g := range gs {
		drop[g.ID] = true
	}
	h.changeGroups(w, r, id, func(cur []store.SynchronizedGroup) []store.SynchronizedGroup {
		var out []store.SynchronizedGroup
		for _, g := range cur {
			if !drop[g.GroupID] {
				out = append(out, g)
			}
		}
		return out
	})
}

// ListSynchronizedGroups serves GET .../synchronized-groups; q is a prefix
// search on name or email ("name:eng*").
func (h *Handlers) ListSynchronizedGroups(w http.ResponseWriter, r *http.Request, id string) {
	ds, ok := h.dirSync(w)
	if !ok {
		return
	}
	p, err := readGroupPage(r, false)
	var field, prefix string
	if err == nil {
		field, prefix, err = groupQuery(r.URL.Query().Get("q"))
	}
	var c *store.Connection
	if err == nil {
		c, _, err = h.dirConnection(r, id)
	}
	if err != nil {
		h.dirSyncError(w, r, err)
		return
	}
	all, err := ds.ListGroups(r.Context(), c.TenantID, c.ID)
	if err != nil {
		h.dirSyncError(w, r, err)
		return
	}
	var items []map[string]any
	for _, g := range all {
		var v map[string]any
		if json.Unmarshal(g.Doc, &v) != nil || v == nil {
			v = map[string]any{}
		}
		v["id"] = g.GroupID
		if field != "" {
			s, _ := v[field].(string)
			if !strings.HasPrefix(strings.ToLower(s), prefix) {
				continue
			}
		}
		items = append(items, v)
	}
	writeGroupList(w, "groups", window(items, p), len(items), p)
}

// groupQuery parses "name:prefix*" or "email:prefix*" (or an exact value).
func groupQuery(q string) (string, string, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return "", "", nil
	}
	field, value, ok := strings.Cut(q, ":")
	value = strings.TrimSuffix(value, "*")
	if !ok || (field != "name" && field != "email") || value == "" || strings.ContainsAny(value, "*?\"() ") || len(value) > 254 {
		return "", "", badBody(`q must be a prefix search on name or email, e.g. "name:engineering*"`)
	}
	return field, strings.ToLower(value), nil
}

// CreateDirectoryProvisioningConsent serves the system API's consent link
// (zeroauthy extension, LR37c-15): a 15-minute link on the tenant's
// canonical host that starts the Google Workspace administrator consent.
func (h *Handlers) CreateDirectoryProvisioningConsent(w http.ResponseWriter, r *http.Request, tenantName, id string) {
	base, ok := tenant.FromContext(r.Context())
	if !ok || h.SystemHost == "" || base.Host != tenant.NormalizeHost(h.SystemHost) {
		WriteError(w, http.StatusNotFound, "", "Not Found")
		return
	}
	caller, ok := CallerFrom(r.Context())
	if !ok || caller.Kind != Operator || !manages(caller.Tenants, tenantName) {
		WriteError(w, http.StatusForbidden, "insufficient_scope", "The operator does not manage this tenant")
		return
	}
	if !store.DirectorySyncAvailable(h.Store) {
		Fail(w, errDirSyncUnavailable)
		return
	}
	if !connectionID.MatchString(id) {
		Fail(w, errBadConnectionID)
		return
	}
	ctx := r.Context()
	t, err := h.Store.Tenants().GetByName(ctx, tenantName)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errTenantNotFound)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "directory consent", err))
		return
	}
	c, err := h.Store.Connections().Get(ctx, t.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		Fail(w, errConnectionNotFound)
		return
	}
	if err != nil {
		Fail(w, internalError(h, r, "directory consent", err))
		return
	}
	if c.Strategy != rules.GoogleApps || len(c.FederationSecretsSealed) == 0 {
		Fail(w, badBody("the connection must be a google-apps connection with a client secret"))
		return
	}
	if _, err := h.Store.DirectorySync().GetProvisioning(ctx, t.ID, c.ID); err != nil {
		h.dirSyncError(w, r, err)
		return
	}
	host := t.CanonicalHost
	if host == "" && len(t.Domains) > 0 {
		host = t.Domains[0]
	}
	if host == "" {
		host = strings.TrimSuffix(strings.TrimPrefix(tenant.ManagementAPIIdentifier(t, h.BaseDomain), "https://"), "/api/v2/")
	}
	ticket, err := dirsync.NewTicket(h.Wrapper, t.ID, c.ID, h.now())
	if err != nil {
		Fail(w, internalError(h, r, "directory consent", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"url":          "https://" + host + dirsync.ConsentPath + "?ticket=" + url.QueryEscape(ticket),
		"redirect_uri": "https://" + host + dirsync.CallbackPath,
		"expires_at":   h.now().Add(dirsync.TicketTTL).UTC().Format(time.RFC3339),
	})
}
