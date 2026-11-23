package mgmt

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/scim"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Self-service SSO (Plan 37c Phase B, D-0150): profiles, their custom text
// and SSO tickets. Bodies are validated against the Auth0 schemas of the
// Management contract (checkSchema).

var (
	errSelfServiceUnavailable = &Error{Status: http.StatusNotImplemented, Code: "not_implemented", Message: "The storage backend does not support self-service SSO"}
	errSSProfileNotFound      = &Error{Status: http.StatusNotFound, Code: "inexistent_self_service_profile", Message: "The self-service profile does not exist"}
	errSSProfileConflict      = &Error{Status: http.StatusConflict, Code: "self_service_profile_conflict", Message: "A self-service profile with this name already exists"}
)

// selfServiceStrategies are the allowed_strategies zeroauthy can create
// (Q7); Auth0's other values (google-apps and the SAML variants) answer 400.
var selfServiceStrategies = []string{"oidc", "samlp", "waad", "adfs", "okta"}

// Ticket lifetime: the OpenAPI default and maximum (Q8).
const (
	defaultTicketTTL = 432000
	ticketTokenChars = 43
)

// profileFields are the Auth0 members of a profile kept in Doc.
var profileFields = []string{"description", "branding", "allowed_strategies", "user_attributes", "user_attribute_profile_id"}

func (h *Handlers) selfService(w http.ResponseWriter) (store.SelfService, bool) {
	if !store.SelfServiceAvailable(h.Store) {
		Fail(w, errSelfServiceUnavailable)
		return nil, false
	}
	return h.Store.SelfService(), true
}

func (h *Handlers) selfServiceError(w http.ResponseWriter, r *http.Request, err error) {
	var typed *Error
	switch {
	case errors.As(err, &typed):
		Fail(w, typed)
	case errors.Is(err, store.ErrSelfServiceUnavailable):
		Fail(w, errSelfServiceUnavailable)
	case errors.Is(err, store.ErrNotFound):
		Fail(w, errSSProfileNotFound)
	default:
		Fail(w, internalError(h, r, "self-service SSO", err))
	}
}

// readBodyRaw reads a JSON body (empty means {}).
func readBodyRaw(r *http.Request) (json.RawMessage, error) {
	raw, err := readLimited(r)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return json.RawMessage(`{}`), nil
	}
	return raw, nil
}

// checkStrategies refuses allowed_strategies zeroauthy cannot configure.
func checkStrategies(doc map[string]json.RawMessage) error {
	raw, ok := doc["allowed_strategies"]
	if !ok || string(raw) == "null" {
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		return badBody("allowed_strategies must be a list of strategies")
	}
	for _, s := range list {
		if !slices.Contains(selfServiceStrategies, s) {
			return badBody("allowed_strategies: %q is not available; use %s", s, strings.Join(selfServiceStrategies, ", "))
		}
	}
	return nil
}

func ssProfileView(p *store.SelfServiceProfile) map[string]any {
	out := map[string]any{}
	_ = json.Unmarshal(p.Doc, &out)
	out["id"], out["name"] = p.ID, p.Name
	out["created_at"], out["updated_at"] = p.CreatedAt.UTC().Format(time.RFC3339Nano), p.UpdatedAt.UTC().Format(time.RFC3339Nano)
	return out
}

// profileDoc keeps the profile members of a validated body.
func profileDoc(body map[string]json.RawMessage) (json.RawMessage, error) {
	doc := map[string]json.RawMessage{}
	for _, k := range profileFields {
		if v, ok := body[k]; ok && string(v) != "null" {
			doc[k] = v
		}
	}
	return json.Marshal(doc)
}

// ListSelfServiceProfiles serves GET /self-service-profiles.
func (h *Handlers) ListSelfServiceProfiles(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.selfService(w)
	if !ok {
		return
	}
	page, perPage, totals, err := Page(r)
	if err != nil {
		Fail(w, err)
		return
	}
	list, total, err := ss.ListProfiles(r.Context(), resolved(r).ID, store.Page{Offset: page * perPage, Limit: perPage})
	if err != nil {
		h.selfServiceError(w, r, err)
		return
	}
	items := make([]map[string]any, len(list))
	for i, p := range list {
		items[i] = ssProfileView(p)
	}
	if totals {
		writeJSON(w, http.StatusOK, map[string]any{"self_service_profiles": items, "start": page * perPage, "limit": perPage, "total": total})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

// CreateSelfServiceProfile serves POST /self-service-profiles.
func (h *Handlers) CreateSelfServiceProfile(w http.ResponseWriter, r *http.Request) {
	ss, ok := h.selfService(w)
	if !ok {
		return
	}
	raw, err := readBodyRaw(r)
	if err == nil {
		err = checkSchema("CreateSelfServiceProfileRequestContent", raw)
	}
	var body map[string]json.RawMessage
	if err == nil {
		err = json.Unmarshal(raw, &body)
	}
	if err == nil {
		err = checkStrategies(body)
	}
	if err != nil {
		Fail(w, err)
		return
	}
	var name string
	_ = json.Unmarshal(body["name"], &name)
	doc, err := profileDoc(body)
	if err != nil {
		Fail(w, err)
		return
	}
	now := h.now()
	p := &store.SelfServiceProfile{TenantID: resolved(r).ID, ID: "ssp_" + secrets.RandomString(22), Name: name, Doc: doc, CreatedAt: now, UpdatedAt: now}
	if err := ss.CreateProfile(r.Context(), p); errors.Is(err, store.ErrConflict) {
		Fail(w, errSSProfileConflict)
		return
	} else if err != nil {
		h.selfServiceError(w, r, err)
		return
	}
	logDetails(r, "create self-service profile", "id", p.ID)
	writeJSON(w, http.StatusCreated, ssProfileView(p))
}

// GetSelfServiceProfile serves GET /self-service-profiles/{id}.
func (h *Handlers) GetSelfServiceProfile(w http.ResponseWriter, r *http.Request, id string) {
	ss, ok := h.selfService(w)
	if !ok {
		return
	}
	p, err := ss.GetProfile(r.Context(), resolved(r).ID, id)
	if err != nil {
		h.selfServiceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, ssProfileView(p))
}

// UpdateSelfServiceProfile serves PATCH /self-service-profiles/{id}: given
// members replace, null clears description, branding, user_attributes and
// user_attribute_profile_id.
func (h *Handlers) UpdateSelfServiceProfile(w http.ResponseWriter, r *http.Request, id string) {
	if _, ok := h.selfService(w); !ok {
		return
	}
	raw, err := readBodyRaw(r)
	if err == nil {
		err = checkSchema("UpdateSelfServiceProfileRequestContent", raw)
	}
	var body map[string]json.RawMessage
	if err == nil {
		err = json.Unmarshal(raw, &body)
	}
	if err == nil {
		err = checkStrategies(body)
	}
	if err != nil {
		Fail(w, err)
		return
	}
	var out *store.SelfServiceProfile
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		p, err := tx.SelfService().GetProfile(r.Context(), resolved(r).ID, id)
		if err != nil {
			return err
		}
		cur := map[string]json.RawMessage{}
		_ = json.Unmarshal(p.Doc, &cur)
		for k, v := range body {
			if k == "name" {
				if err := json.Unmarshal(v, &p.Name); err != nil {
					return badBody("name must be a string")
				}
				continue
			}
			cur[k] = v
		}
		if p.Doc, err = profileDoc(cur); err != nil {
			return err
		}
		p.UpdatedAt = h.now()
		if err := tx.SelfService().UpdateProfile(r.Context(), p); errors.Is(err, store.ErrConflict) {
			return errSSProfileConflict
		} else if err != nil {
			return err
		}
		out = p
		return nil
	})
	if err != nil {
		h.selfServiceError(w, r, err)
		return
	}
	logDetails(r, "update self-service profile", "id", id)
	writeJSON(w, http.StatusOK, ssProfileView(out))
}

// DeleteSelfServiceProfile serves DELETE /self-service-profiles/{id}; its
// custom text and tickets go too. Deleting a missing profile succeeds (the
// contract lists no 404).
func (h *Handlers) DeleteSelfServiceProfile(w http.ResponseWriter, r *http.Request, id string) {
	ss, ok := h.selfService(w)
	if !ok {
		return
	}
	if err := ss.DeleteProfile(r.Context(), resolved(r).ID, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		h.selfServiceError(w, r, err)
		return
	}
	logDetails(r, "delete self-service profile", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

// customTextPage checks the language and page path values.
func customTextPage(language, page string) error {
	if language != "en" || page != "get-started" {
		return &Error{Status: http.StatusNotFound, Code: "inexistent_custom_text", Message: "Custom text is available for language en and page get-started"}
	}
	return nil
}

// GetSelfServiceProfileCustomText serves GET
// /self-service-profiles/{id}/custom-text/{language}/{page}.
func (h *Handlers) GetSelfServiceProfileCustomText(w http.ResponseWriter, r *http.Request, id, language, page string) {
	ss, ok := h.selfService(w)
	if !ok {
		return
	}
	if err := customTextPage(language, page); err != nil {
		Fail(w, err)
		return
	}
	text, err := ss.GetCustomText(r.Context(), resolved(r).ID, id, language, page)
	if err != nil {
		h.selfServiceError(w, r, err)
		return
	}
	if text == nil {
		text = json.RawMessage(`{}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(text)
}

// SetSelfServiceProfileCustomText serves PUT
// /self-service-profiles/{id}/custom-text/{language}/{page}: the body
// replaces the page's text.
func (h *Handlers) SetSelfServiceProfileCustomText(w http.ResponseWriter, r *http.Request, id, language, page string) {
	ss, ok := h.selfService(w)
	if !ok {
		return
	}
	if err := customTextPage(language, page); err != nil {
		Fail(w, err)
		return
	}
	raw, err := readBodyRaw(r)
	if err == nil {
		err = checkSchema("SetSelfServiceProfileCustomTextRequestContent", raw)
	}
	var text map[string]string
	if err == nil && json.Unmarshal(raw, &text) != nil {
		err = badBody("custom text must map keys to strings")
	}
	if err == nil && len(text) > 50 {
		err = badBody("custom text has at most 50 keys")
	}
	if err != nil {
		Fail(w, err)
		return
	}
	norm, _ := json.Marshal(text)
	if err := ss.SetCustomText(r.Context(), resolved(r).ID, id, language, page, norm); err != nil {
		h.selfServiceError(w, r, err)
		return
	}
	logDetails(r, "set self-service custom text", "id", id)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(norm)
}

// ticketRequest is the part of a ticket request the handler checks against
// the tenant.
type ticketRequest struct {
	ConnectionID     string `json:"connection_id"`
	ConnectionConfig *struct {
		Name string `json:"name"`
	} `json:"connection_config"`
	EnabledClients       []string `json:"enabled_clients"`
	EnabledOrganizations []struct {
		OrganizationID string `json:"organization_id"`
	} `json:"enabled_organizations"`
	TTL int `json:"ttl_sec"`
}

// ticketHost is the host of the ticket URL: the auth0-custom-domain header
// when it names one of the tenant's domains, else the canonical host.
func ticketHost(r *http.Request) (string, error) {
	tn := resolved(r)
	if d := strings.ToLower(strings.TrimSpace(r.Header.Get("auth0-custom-domain"))); d != "" {
		if !slices.Contains(tn.Domains, d) {
			return "", badBody("auth0-custom-domain is not a domain of this tenant")
		}
		return d, nil
	}
	if tn.CanonicalHost != "" {
		return tn.CanonicalHost, nil
	}
	if len(tn.Domains) > 0 {
		return tn.Domains[0], nil
	}
	return "", badBody("the tenant has no host for the ticket")
}

// CreateSsoTicket serves POST /self-service-profiles/{id}/sso-ticket. The
// ticket edits connection_id or creates the connection named in
// connection_config (exactly one); clients and organizations must exist.
// The token is returned once, in the ticket URL, and stored as its hash.
func (h *Handlers) CreateSsoTicket(w http.ResponseWriter, r *http.Request, id string) {
	ss, ok := h.selfService(w)
	if !ok {
		return
	}
	raw, err := readBodyRaw(r)
	if err == nil {
		err = checkSchema("CreateSelfServiceProfileSsoTicketRequestContent", raw)
	}
	var req ticketRequest
	if err == nil && json.Unmarshal(raw, &req) != nil {
		err = badBody("invalid ticket request")
	}
	if err == nil && (req.ConnectionID == "") == (req.ConnectionConfig == nil) {
		err = badBody("exactly one of connection_id and connection_config is required")
	}
	var host string
	if err == nil {
		host, err = ticketHost(r)
	}
	if err != nil {
		Fail(w, err)
		return
	}
	tid := resolved(r).ID
	ctx := r.Context()
	profile, err := ss.GetProfile(ctx, tid, id)
	if err != nil {
		h.selfServiceError(w, r, err)
		return
	}
	if req.ConnectionID != "" {
		c, err := h.Store.Connections().Get(ctx, tid, req.ConnectionID)
		if errors.Is(err, store.ErrNotFound) {
			Fail(w, errConnectionNotFound)
			return
		} else if err != nil {
			h.selfServiceError(w, r, err)
			return
		}
		if !profileAllows(profile, c.Strategy) {
			Fail(w, badBody("the connection's strategy %q is not allowed by the profile", c.Strategy))
			return
		}
	} else if _, err := h.Store.Connections().GetByName(ctx, tid, req.ConnectionConfig.Name); err == nil {
		Fail(w, &Error{Status: http.StatusConflict, Code: "connection_conflict", Message: "A connection with the same name already exists"})
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		h.selfServiceError(w, r, err)
		return
	}
	for _, cid := range req.EnabledClients {
		if _, err := h.Store.Clients().Get(ctx, tid, cid); err != nil {
			Fail(w, badBody("enabled_clients: unknown client %q", cid))
			return
		}
	}
	for _, o := range req.EnabledOrganizations {
		if !store.OrganizationsSupported(h.Store) {
			Fail(w, errOrganizationsUnavailable)
			return
		}
		if _, err := h.Store.Organizations().Get(ctx, tid, o.OrganizationID); err != nil {
			Fail(w, badBody("enabled_organizations: unknown organization %q", o.OrganizationID))
			return
		}
	}
	ttl := req.TTL
	if ttl == 0 {
		ttl = defaultTicketTTL
	}
	now := h.now()
	token := secrets.RandomString(ticketTokenChars)
	t := &store.SSOTicket{TenantID: tid, ID: "tkt_" + secrets.RandomString(22), ProfileID: id, Hash: scim.HashToken(token), ConnectionID: req.ConnectionID, Doc: raw,
		CreatedAt: now, ExpiresAt: now.Add(time.Duration(ttl) * time.Second)}
	if err := ss.CreateTicket(ctx, t); err != nil {
		h.selfServiceError(w, r, err)
		return
	}
	logDetails(r, "create sso ticket", "profile", id, "id", t.ID)
	writeJSON(w, http.StatusCreated, map[string]any{"ticket": "https://" + host + "/self-service/connections-flow?ticket=" + token})
}

// profileAllows reports whether the profile allows strategy (no list
// allows every strategy zeroauthy can configure).
func profileAllows(p *store.SelfServiceProfile, strategy string) bool {
	var doc struct {
		Allowed []string `json:"allowed_strategies"`
	}
	_ = json.Unmarshal(p.Doc, &doc)
	if len(doc.Allowed) == 0 {
		return slices.Contains(selfServiceStrategies, strategy)
	}
	return slices.Contains(doc.Allowed, strategy)
}

// RevokeSsoTicket serves POST
// /self-service-profiles/{profileId}/sso-ticket/{id}/revoke; id is the
// ticket value of the URL. Revoking twice, or an unknown ticket, still
// answers 202 (the contract lists no 404).
func (h *Handlers) RevokeSsoTicket(w http.ResponseWriter, r *http.Request, profileID, id string) {
	ss, ok := h.selfService(w)
	if !ok {
		return
	}
	tid := resolved(r).ID
	if len(id) <= 256 {
		t, err := ss.GetTicketByHash(r.Context(), tid, scim.HashToken(id))
		if err == nil && t.ProfileID == profileID {
			err = ss.RevokeTicket(r.Context(), tid, profileID, t.ID, h.now())
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			h.selfServiceError(w, r, err)
			return
		}
		if err == nil {
			logDetails(r, "revoke sso ticket", "profile", profileID, "id", t.ID)
		}
	}
	w.WriteHeader(http.StatusAccepted)
}
