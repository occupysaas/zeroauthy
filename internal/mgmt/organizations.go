package mgmt

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Organizations (Plan 29, D-0055). Shapes and rules follow
// internal/orgrules/inventory.json.

var (
	errOrganizationsUnavailable = &Error{Status: http.StatusNotImplemented, Code: "organizations_unavailable", Message: "The storage plugin does not support Organizations; upgrade the storage plugin"}
	// Observed: the organization 404 and 409 carry no errorCode.
	errOrganizationNotFound = &Error{Status: http.StatusNotFound, Message: "No organization found by that id or name"}
	errOrganizationConflict = &Error{Status: http.StatusConflict, Message: "An organization with this name already exists"}
	errOrganizationURI      = &Error{Status: http.StatusBadRequest, Code: "invalid_uri", Message: "Path validation error: the organization id is invalid"}
)

// plainBadRequest is a 400 without errorCode, for the validation failures
// that were observed without one.
func plainBadRequest(format string, args ...any) *Error {
	return &Error{Status: http.StatusBadRequest, Message: "Payload validation error: " + fmt.Sprintf(format, args...)}
}

// orgs returns the store's organizations, or writes 501 when a storage
// plugin lacks the capability.
func (h *Handlers) orgs(w http.ResponseWriter) (store.Organizations, bool) {
	if !store.OrganizationsSupported(h.Store) {
		Fail(w, errOrganizationsUnavailable)
		return nil, false
	}
	return h.Store.Organizations(), true
}

// orgError maps store errors of organization routes.
func (h *Handlers) orgError(w http.ResponseWriter, r *http.Request, err error) {
	var typed *Error
	switch {
	case errors.As(err, &typed):
		Fail(w, typed)
	case errors.Is(err, store.ErrOrganizationsIIUnavailable):
		Fail(w, errOrganizationsIIUnavailable)
	case errors.Is(err, store.ErrOrganizationsUnavailable):
		Fail(w, errOrganizationsUnavailable)
	case errors.Is(err, store.ErrNotFound):
		Fail(w, errOrganizationNotFound)
	case errors.Is(err, store.ErrConflict):
		Fail(w, errOrganizationConflict)
	case errors.Is(err, store.ErrPrecondition):
		Fail(w, badBody("the organization limit (D-0055) is reached"))
	case errors.Is(err, store.ErrInvalid):
		Fail(w, badBody("invalid organization"))
	default:
		Fail(w, internalError(h, r, "organizations", err))
	}
}

// loadOrg checks the path ID shape (400 invalid_uri) and loads the
// organization (404 without errorCode).
func loadOrg(r *http.Request, orgs store.Organizations, id string) (*store.Organization, error) {
	if !orgrules.ValidID(id) {
		return nil, errOrganizationURI
	}
	o, err := orgs.Get(r.Context(), resolved(r).ID, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errOrganizationNotFound
	}
	return o, err
}

func orgView(o store.Organization) map[string]any {
	out := map[string]any{
		"id": o.ID, "name": o.Name, "display_name": o.DisplayName,
		"third_party_client_access": o.ThirdPartyClientAccess,
		"is_app_entitlement_active": o.IsAppEntitlementActive,
	}
	if b := o.Branding; b != nil {
		branding := map[string]any{}
		if b.LogoURL != nil {
			branding["logo_url"] = *b.LogoURL
		}
		if b.Colors != nil {
			branding["colors"] = map[string]any{"primary": b.Colors.Primary, "page_background": b.Colors.PageBackground}
		}
		out["branding"] = branding
	}
	if len(o.Metadata) > 0 {
		out["metadata"] = o.Metadata
	}
	return out
}

// orgQuery reads the pagination of an organization list. allowed names the
// accepted parameters; another one is 400. It returns the page and whether
// checkpoint mode applies.
func orgQuery(r *http.Request, allowed ...string) (store.OrgPage, bool, error) {
	var p store.OrgPage
	q := r.URL.Query()
	for k, vs := range q {
		if !slices.Contains(allowed, k) || len(vs) != 1 && k != "grant_ids" {
			return p, false, badQuery("Query validation error: unsupported or repeated parameter %q", k)
		}
	}
	num := func(name string, lo, hi int) (int, error) {
		if !q.Has(name) {
			return 0, nil
		}
		n, err := strconv.Atoi(q.Get(name))
		if err != nil || n < lo || n > hi {
			return 0, badQuery("Query validation error: %s must be an integer from %d to %d", name, lo, hi)
		}
		return n, nil
	}
	var err error
	if p.Page, err = num("page", 0, MaxPage); err != nil {
		return p, false, err
	}
	if p.PerPage, err = num("per_page", 1, orgrules.Limit("per_page_max")); err != nil {
		return p, false, err
	}
	if p.Take, err = num("take", 1, orgrules.Limit("take_max")); err != nil {
		return p, false, err
	}
	if q.Has("from") || q.Has("take") {
		// Checkpoint mode ignores page (observed).
		p.Page = 0
	} else if p.Page > orgrules.Limit("page_max") {
		return p, false, &Error{Status: http.StatusBadRequest, Code: "invalid_paging", Message: "Requesting page exceeds the allowed maximum of 1000 records"}
	}
	if p.IncludeTotals, err = boolParam(r, "include_totals", false); err != nil {
		return p, false, err
	}
	p.From = q.Get("from")
	p.Sort = q.Get("sort")
	if _, _, err := orgrules.ParseSort(p.Sort); err != nil {
		return p, false, badQuery("Query validation error: sort must be name, display_name or created_at with :1 or :-1")
	}
	norm := p
	mode, err := orgrules.NormalizePage(&norm)
	if err != nil {
		return p, false, badQuery("Query validation error: invalid pagination")
	}
	return norm, mode == orgrules.Checkpoint, nil
}

// writeOrgList writes a list as a bare array, the totals object or the
// checkpoint object. countLimit reports the number of returned entries as
// limit (observed for connection lists, D-0055) instead of per_page.
func writeOrgList(w http.ResponseWriter, name string, items []map[string]any, total int, next string, p store.OrgPage, checkpoint, countLimit bool) {
	switch {
	case checkpoint:
		out := map[string]any{name: items}
		if next != "" {
			out["next"] = next
		}
		writeJSON(w, http.StatusOK, out)
	case p.IncludeTotals:
		limit := p.PerPage
		if countLimit {
			limit = len(items)
		}
		writeJSON(w, http.StatusOK, map[string]any{name: items, "start": p.Page * p.PerPage, "limit": limit, "total": total})
	default:
		writeJSON(w, http.StatusOK, items)
	}
}

func (h *Handlers) ListOrganizations(w http.ResponseWriter, r *http.Request) {
	orgs, ok := h.orgs(w)
	if !ok {
		return
	}
	p, checkpoint, err := orgQuery(r, "page", "per_page", "include_totals", "from", "take", "sort", "include_client_association_for")
	if err != nil {
		Fail(w, err)
		return
	}
	if r.URL.Query().Has("include_client_association_for") {
		if r.URL.Query().Get("include_client_association_for") == "" {
			Fail(w, badQuery("include_client_association_for must be non-empty"))
			return
		}
		if !h.orgIIAvailable(w, r) {
			return
		}
	}
	res, err := orgs.List(r.Context(), resolved(r).ID, p)
	if errors.Is(err, store.ErrInvalid) {
		Fail(w, &Error{Status: http.StatusBadRequest, Message: "The from parameter is not a valid checkpoint"})
		return
	}
	if err != nil {
		h.orgError(w, r, err)
		return
	}
	items := make([]map[string]any, 0, len(res.Items))
	for _, o := range res.Items {
		view := orgView(o)
		if clientID := r.URL.Query().Get("include_client_association_for"); clientID != "" {
			link, err := h.Store.OrganizationsII().GetClient(r.Context(), resolved(r).ID, o.ID, clientID)
			if err == nil {
				view["client"] = map[string]any{"use_for_member_access": link.UseForMemberAccess}
			} else if !errors.Is(err, store.ErrNotFound) {
				h.orgIIError(w, r, err)
				return
			}
		}
		items = append(items, view)
	}
	writeOrgList(w, "organizations", items, res.Total, res.Next, p, checkpoint, false)
}

// readOrgBody applies a create or PATCH body to o. It returns the enabled
// connections of a create body (nil when absent) and whether the body
// carried them.
func readOrgBody(r *http.Request, o *store.Organization, create bool) ([]store.OrganizationConnection, bool, error) {
	body, err := decodeObject(r)
	if err != nil {
		return nil, false, err
	}
	if create {
		if _, ok := body["name"]; !ok {
			return nil, false, badBody("name is required")
		}
	} else if len(body) == 0 {
		// Observed: an empty PATCH is 400 without errorCode.
		return nil, false, plainBadRequest("at least one property is required")
	}
	var conns []store.OrganizationConnection
	hasConns := false
	for k, raw := range body {
		switch k {
		case "name":
			if decodeString(raw, &o.Name) != nil {
				return nil, false, badBody("name must be a string")
			}
		case "display_name":
			if decodeString(raw, &o.DisplayName) != nil || o.DisplayName == "" {
				return nil, false, badBody("display_name must be a non-empty string")
			}
		case "third_party_client_access":
			if decodeString(raw, &o.ThirdPartyClientAccess) != nil {
				return nil, false, badBody("third_party_client_access must be block or allow")
			}
		case "is_app_entitlement_active":
			if isNull(raw) || decodeStrict(raw, &o.IsAppEntitlementActive) != nil {
				return nil, false, badBody("is_app_entitlement_active must be a boolean")
			}
		case "branding":
			b, err := decodeOrgBranding(raw)
			if err != nil {
				return nil, false, err
			}
			o.Branding = b
		case "metadata":
			m, err := decodeOrgMetadata(raw)
			if err != nil {
				return nil, false, err
			}
			o.Metadata = m
		case "enabled_connections":
			if !create {
				return nil, false, badBody("unknown property %q", k)
			}
			var items []json.RawMessage
			if decodeStrict(raw, &items) != nil {
				return nil, false, badBody("enabled_connections must be an array")
			}
			if len(items) > orgrules.Limit("enabled_connections_create_max") {
				return nil, false, badBody("enabled_connections can have at most %d entries", orgrules.Limit("enabled_connections_create_max"))
			}
			hasConns = true
			for _, item := range items {
				c := store.OrganizationConnection{ShowAsButton: true}
				if err := readConnectionFlags(item, &c, connectionCreate); err != nil {
					return nil, false, err
				}
				conns = append(conns, c)
			}
		default:
			return nil, false, badBody("unknown property %q", k)
		}
	}
	if _, err := orgrules.NormalizeOrganization(*o); err != nil {
		return nil, false, badBody("%v", err)
	}
	return conns, hasConns, nil
}

// decodeOrgBranding reads branding; null and {} unset it.
func decodeOrgBranding(raw json.RawMessage) (*store.OrgBranding, error) {
	if isNull(raw) {
		return nil, nil
	}
	var v struct {
		LogoURL *string `json:"logo_url"`
		Colors  *struct {
			Primary        *string `json:"primary"`
			PageBackground *string `json:"page_background"`
		} `json:"colors"`
	}
	if err := decodeStrict(raw, &v); err != nil {
		return nil, badBody("branding %v", err)
	}
	b := &store.OrgBranding{LogoURL: v.LogoURL}
	if v.Colors != nil {
		if v.Colors.Primary == nil || v.Colors.PageBackground == nil {
			return nil, badBody("branding.colors needs both primary and page_background")
		}
		b.Colors = &store.OrgColors{Primary: *v.Colors.Primary, PageBackground: *v.Colors.PageBackground}
	}
	if b.LogoURL == nil && b.Colors == nil {
		return nil, nil
	}
	return b, nil
}

// decodeOrgMetadata reads metadata; null and {} unset it. Values must be
// strings (observed: null is refused).
func decodeOrgMetadata(raw json.RawMessage) (map[string]string, error) {
	if isNull(raw) {
		return nil, nil
	}
	var m map[string]json.RawMessage
	if decodeStrict(raw, &m) != nil {
		return nil, badBody("metadata must be an object")
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		// Observed: a null or empty value and an over-long key are 400
		// without errorCode; a non-string value is invalid_body.
		if isNull(v) {
			return nil, plainBadRequest("metadata value for %q must not be null", k)
		}
		var s string
		if decodeString(v, &s) != nil {
			return nil, badBody("metadata value for %q must be a string", k)
		}
		if s == "" {
			return nil, plainBadRequest("metadata value for %q must not be empty", k)
		}
		if utf8.RuneCountInString(k) > orgrules.Limit("metadata_key_chars_max") {
			return nil, plainBadRequest("metadata keys must have at most %d characters", orgrules.Limit("metadata_key_chars_max"))
		}
		out[k] = s
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func (h *Handlers) CreateOrganization(w http.ResponseWriter, r *http.Request) {
	orgs, ok := h.orgs(w)
	if !ok {
		return
	}
	tid := resolved(r).ID
	o := &store.Organization{TenantID: tid, ID: orgrules.NewID()}
	conns, hasConns, err := readOrgBody(r, o, true)
	if err != nil {
		Fail(w, err)
		return
	}
	if o.IsAppEntitlementActive && !h.orgIIAvailable(w, r) {
		return
	}
	if hasConns {
		if c, _ := CallerFrom(r.Context()); !c.Has("create:organization_connections") {
			WriteError(w, http.StatusForbidden, "insufficient_scope", "Insufficient scope, expected all of: create:organizations,create:organization_connections")
			return
		}
	}
	summaries := make([]*store.Connection, len(conns))
	seen := map[string]bool{}
	for i := range conns {
		if seen[conns[i].ConnectionID] {
			Fail(w, errOrgConnectionConflict)
			return
		}
		seen[conns[i].ConnectionID] = true
		conns[i].TenantID, conns[i].OrganizationID = tid, o.ID
		conn, err := orgConnectionTarget(r, h.Store, conns[i], false)
		if err != nil {
			h.orgError(w, r, err)
			return
		}
		summaries[i] = conn
	}
	if err := orgs.Create(r.Context(), o, conns); err != nil {
		h.orgError(w, r, err)
		return
	}
	h.audit(r, "create organization", "id", o.ID)
	out := orgView(*o)
	if hasConns {
		list := make([]map[string]any, len(conns))
		for i, c := range conns {
			list[i] = orgConnectionView(c, summaries[i], false)
		}
		out["enabled_connections"] = list
	}
	writeJSON(w, http.StatusCreated, out)
}

func (h *Handlers) GetOrganization(w http.ResponseWriter, r *http.Request, id string) {
	orgs, ok := h.orgs(w)
	if !ok {
		return
	}
	o, err := loadOrg(r, orgs, id)
	if err != nil {
		h.orgError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, orgView(*o))
}

func (h *Handlers) GetOrganizationByName(w http.ResponseWriter, r *http.Request, name string) {
	orgs, ok := h.orgs(w)
	if !ok {
		return
	}
	// The name format is validated before the lookup (observed).
	if _, err := orgrules.NormalizeOrganization(store.Organization{Name: name}); err != nil {
		Fail(w, &Error{Status: http.StatusBadRequest, Code: "invalid_uri", Message: "Path validation error: the organization name is invalid"})
		return
	}
	o, err := orgs.GetByName(r.Context(), resolved(r).ID, name)
	if err != nil {
		h.orgError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, orgView(*o))
}

func (h *Handlers) UpdateOrganization(w http.ResponseWriter, r *http.Request, id string) {
	if _, ok := h.orgs(w); !ok {
		return
	}
	var out *store.Organization
	err := h.Store.WithTx(r.Context(), func(tx store.Store) error {
		o, err := loadOrg(r, tx.Organizations(), id)
		if err != nil {
			return err
		}
		if _, _, err := readOrgBody(r, o, false); err != nil {
			return err
		}
		if o.IsAppEntitlementActive {
			if c, ok := h.Store.(store.OrganizationsIISupporter); ok {
				if err := c.CheckOrganizationsIISupport(r.Context()); err != nil {
					return err
				}
			}
			if !store.OrganizationsIISupported(h.Store) {
				return store.ErrOrganizationsIIUnavailable
			}
		}
		if err := tx.Organizations().Update(r.Context(), o); err != nil {
			return err
		}
		out = o
		return nil
	})
	if err != nil {
		h.orgError(w, r, err)
		return
	}
	h.audit(r, "update organization", "id", id)
	writeJSON(w, http.StatusOK, orgView(*out))
}

func (h *Handlers) DeleteOrganization(w http.ResponseWriter, r *http.Request, id string) {
	orgs, ok := h.orgs(w)
	if !ok {
		return
	}
	if !orgrules.ValidID(id) {
		Fail(w, errOrganizationURI)
		return
	}
	if err := orgs.Delete(r.Context(), resolved(r).ID, id); err != nil {
		h.orgError(w, r, err)
		return
	}
	h.audit(r, "delete organization", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

// ListOrganizationClientGrants answers the read-only organization client
// grant list. Associating grants with organizations is Plan 30, so the list
// is always empty (D-0055); the organization must exist.
func (h *Handlers) ListOrganizationClientGrants(w http.ResponseWriter, r *http.Request, id string) {
	orgs, ok := h.orgs(w)
	if !ok {
		return
	}
	p, _, err := orgQuery(r, "page", "per_page", "include_totals", "audience", "client_id", "grant_ids")
	if err == nil && len(r.URL.Query()["grant_ids"]) > orgrules.Limit("batch_ids_max") {
		err = badQuery("Query validation error: grant_ids can be given at most %d times", orgrules.Limit("batch_ids_max"))
	}
	if err != nil {
		Fail(w, err)
		return
	}
	if _, err := loadOrg(r, orgs, id); err != nil {
		h.orgError(w, r, err)
		return
	}
	writeOrgList(w, "client_grants", []map[string]any{}, 0, "", p, false, true)
}
