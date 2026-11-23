package mgmt

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/scim"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// SCIM configurations and tokens of enterprise connections (Plan 37c,
// D-0150). Tokens are returned once by POST and stored as a SHA-256 hash.

var (
	errSCIMConfigNotFound = &Error{Status: http.StatusNotFound, Code: "inexistent_scim_configuration", Message: "The connection has no SCIM configuration"}
	errSCIMConfigExists   = &Error{Status: http.StatusBadRequest, Code: "scim_configuration_exists", Message: "A SCIM configuration already exists for this connection"}
	errSCIMTokenNotFound  = &Error{Status: http.StatusNotFound, Code: "inexistent_scim_token", Message: "The SCIM token does not exist"}
	errSCIMTokenLimit     = &Error{Status: http.StatusConflict, Code: "scim_token_limit", Message: "Maximum of 2 tokens already issued for this connection"}
)

// scimScopes are the scopes a SCIM token can hold; a token request without
// scopes gets all of them.
var scimScopes = []string{"get:users", "post:users", "put:users", "patch:users", "delete:users", "get:groups", "post:groups", "put:groups", "patch:groups", "delete:groups"}

// minSCIMTokenLifetime is the documented exclusive lower bound (seconds).
const minSCIMTokenLifetime = 900

// scimConnection checks the ID and loads the tenant's connection; with
// scimOnly the strategy must accept SCIM.
func (h *Handlers) scimConnection(r *http.Request, id string, scimOnly bool) (*store.Connection, error) {
	if !connectionID.MatchString(id) {
		return nil, errBadConnectionID
	}
	c, err := h.Store.Connections().Get(r.Context(), resolved(r).ID, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errConnectionNotFound
	}
	if err != nil {
		return nil, err
	}
	if scimOnly && !slices.Contains(scim.Strategies, c.Strategy) {
		return nil, badBody("SCIM is available only for %s connections", strings.Join(scim.Strategies, ", "))
	}
	return c, nil
}

func scimConfigView(tn *store.Tenant, c *store.Connection, cfg *store.SCIMConfig) map[string]any {
	mapping := cfg.Mapping
	if mapping == nil {
		mapping = []store.SCIMMapping{}
	}
	uid := cfg.UserIDAttribute
	if uid == "" {
		uid = scim.DefaultUserIDAttribute
	}
	return map[string]any{"tenant_name": tn.Name, "connection_id": c.ID, "connection_name": c.Name, "strategy": c.Strategy,
		"user_id_attribute": uid, "mapping": mapping,
		"created_at": cfg.CreatedAt.UTC().Format(time.RFC3339Nano), "updated_on": cfg.UpdatedAt.UTC().Format(time.RFC3339Nano)}
}

// readSCIMConfig reads and validates user_id_attribute and mapping.
// required demands both (PATCH); absent ones take the defaults.
func readSCIMConfig(r *http.Request, required bool) (string, []store.SCIMMapping, error) {
	body := map[string]json.RawMessage{}
	if r.ContentLength != 0 {
		raw, err := readLimited(r)
		if err != nil {
			return "", nil, err
		}
		if t := strings.TrimSpace(string(raw)); t != "" && t != "null" {
			if err := json.Unmarshal(raw, &body); err != nil || body == nil {
				return "", nil, badBody("the body must be a JSON object")
			}
		}
	}
	for k := range body {
		if k != "user_id_attribute" && k != "mapping" {
			return "", nil, badBody("unknown property %q", k)
		}
	}
	if required && (body["user_id_attribute"] == nil || body["mapping"] == nil) {
		return "", nil, badBody("user_id_attribute and mapping are required")
	}
	uid := scim.DefaultUserIDAttribute
	if raw := body["user_id_attribute"]; raw != nil {
		if err := decodeStrict(raw, &uid); err != nil || uid == "" || len(uid) > 256 {
			return "", nil, badBody("user_id_attribute must be a SCIM attribute path")
		}
		p, err := scim.ParsePath(uid)
		if err != nil || p.Filter != nil && p.Sub == "" {
			return "", nil, badBody("user_id_attribute must be a SCIM attribute path")
		}
	}
	mapping := scim.DefaultMapping()
	if raw := body["mapping"]; raw != nil {
		mapping = nil
		if err := decodeStrict(raw, &mapping); err != nil {
			return "", nil, badBody("mapping must be a list of {auth0, scim} entries")
		}
		for _, m := range mapping {
			if m.Auth0 == "" || m.SCIM == "" || len(m.Auth0) > 256 || len(m.SCIM) > 256 {
				return "", nil, badBody("mapping entries need auth0 and scim of 1 to 256 characters")
			}
		}
		if _, err := scim.ParseMapping(mapping); err != nil {
			return "", nil, badBody("%s", err.Error())
		}
		if mapping == nil {
			mapping = []store.SCIMMapping{}
		}
	}
	return uid, mapping, nil
}

// readLimited reads a Management request body (bounded by the API's body
// limit middleware).
func readLimited(r *http.Request) ([]byte, error) {
	var raw json.RawMessage
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	if err := dec.Decode(&raw); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, badBody("the body is not valid JSON")
	}
	if dec.More() {
		return nil, badBody("the body is not valid JSON")
	}
	return raw, nil
}

func (h *Handlers) scimError(w http.ResponseWriter, r *http.Request, err error) {
	var typed *Error
	switch {
	case errors.As(err, &typed):
		Fail(w, typed)
	case errors.Is(err, store.ErrDirectoryUnavailable):
		Fail(w, errDirectoryUnavailable)
	case errors.Is(err, store.ErrSCIMTokenLimit):
		Fail(w, errSCIMTokenLimit)
	default:
		Fail(w, internalError(h, r, "SCIM configuration", err))
	}
}

// GetScimConfiguration serves GET /connections/{id}/scim-configuration.
func (h *Handlers) GetScimConfiguration(w http.ResponseWriter, r *http.Request, id string) {
	d, ok := h.directory(w)
	if !ok {
		return
	}
	c, err := h.scimConnection(r, id, false)
	if err != nil {
		h.scimError(w, r, err)
		return
	}
	cfg, err := d.GetSCIMConfig(r.Context(), resolved(r).ID, c.ID)
	if errors.Is(err, store.ErrNotFound) {
		err = errSCIMConfigNotFound
	}
	if err != nil {
		h.scimError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, scimConfigView(resolved(r), c, cfg))
}

// CreateScimConfiguration serves POST /connections/{id}/scim-configuration.
func (h *Handlers) CreateScimConfiguration(w http.ResponseWriter, r *http.Request, id string) {
	d, ok := h.directory(w)
	if !ok {
		return
	}
	c, err := h.scimConnection(r, id, true)
	if err != nil {
		h.scimError(w, r, err)
		return
	}
	uid, mapping, err := readSCIMConfig(r, false)
	if err != nil {
		Fail(w, err)
		return
	}
	now := h.now()
	cfg := &store.SCIMConfig{TenantID: resolved(r).ID, ConnectionID: c.ID, UserIDAttribute: uid, Mapping: mapping, CreatedAt: now, UpdatedAt: now}
	err = d.CreateSCIMConfig(r.Context(), cfg)
	if errors.Is(err, store.ErrConflict) {
		err = errSCIMConfigExists
	}
	if err != nil {
		h.scimError(w, r, err)
		return
	}
	logDetails(r, "create scim configuration", "connection", c.ID)
	writeJSON(w, http.StatusCreated, scimConfigView(resolved(r), c, cfg))
}

// UpdateScimConfiguration serves PATCH /connections/{id}/scim-configuration.
func (h *Handlers) UpdateScimConfiguration(w http.ResponseWriter, r *http.Request, id string) {
	if _, ok := h.directory(w); !ok {
		return
	}
	c, err := h.scimConnection(r, id, false)
	if err != nil {
		h.scimError(w, r, err)
		return
	}
	uid, mapping, err := readSCIMConfig(r, true)
	if err != nil {
		Fail(w, err)
		return
	}
	var cfg *store.SCIMConfig
	err = h.Store.WithTx(r.Context(), func(tx store.Store) error {
		cur, err := tx.Directory().GetSCIMConfig(r.Context(), resolved(r).ID, c.ID)
		if errors.Is(err, store.ErrNotFound) {
			return errSCIMConfigNotFound
		}
		if err != nil {
			return err
		}
		cur.UserIDAttribute, cur.Mapping, cur.UpdatedAt = uid, mapping, h.now()
		cfg = cur
		return tx.Directory().UpdateSCIMConfig(r.Context(), cur)
	})
	if err != nil {
		h.scimError(w, r, err)
		return
	}
	logDetails(r, "update scim configuration", "connection", c.ID)
	writeJSON(w, http.StatusOK, scimConfigView(resolved(r), c, cfg))
}

// DeleteScimConfiguration serves DELETE /connections/{id}/scim-configuration:
// the configuration and the connection's tokens go; provisioned users and
// groups stay. Deleting a missing configuration succeeds.
func (h *Handlers) DeleteScimConfiguration(w http.ResponseWriter, r *http.Request, id string) {
	d, ok := h.directory(w)
	if !ok {
		return
	}
	c, err := h.scimConnection(r, id, false)
	if err != nil {
		h.scimError(w, r, err)
		return
	}
	if err := d.DeleteSCIMConfig(r.Context(), resolved(r).ID, c.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		h.scimError(w, r, err)
		return
	}
	logDetails(r, "delete scim configuration", "connection", c.ID)
	w.WriteHeader(http.StatusNoContent)
}

// GetScimDefaultMapping serves GET
// /connections/{id}/scim-configuration/default-mapping.
func (h *Handlers) GetScimDefaultMapping(w http.ResponseWriter, r *http.Request, id string) {
	if _, ok := h.directory(w); !ok {
		return
	}
	if _, err := h.scimConnection(r, id, true); err != nil {
		h.scimError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mapping": scim.DefaultMapping()})
}

func scimTokenView(t *store.SCIMToken) map[string]any {
	out := map[string]any{"token_id": t.ID, "scopes": t.Scopes, "created_at": t.CreatedAt.UTC().Format(time.RFC3339Nano)}
	if t.ExpiresAt != nil {
		out["valid_until"] = t.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	if t.LastUsedAt != nil {
		out["last_used_at"] = t.LastUsedAt.UTC().Format(time.RFC3339Nano)
	}
	return out
}

// ListScimTokens serves GET /connections/{id}/scim-configuration/tokens.
func (h *Handlers) ListScimTokens(w http.ResponseWriter, r *http.Request, id string) {
	d, ok := h.directory(w)
	if !ok {
		return
	}
	c, err := h.scimConnection(r, id, false)
	if err != nil {
		h.scimError(w, r, err)
		return
	}
	toks, err := d.ListSCIMTokens(r.Context(), resolved(r).ID, c.ID)
	if err != nil {
		h.scimError(w, r, err)
		return
	}
	out := make([]map[string]any, len(toks))
	for i, t := range toks {
		out[i] = scimTokenView(t)
	}
	writeJSON(w, http.StatusOK, out)
}

// CreateScimToken serves POST /connections/{id}/scim-configuration/tokens.
func (h *Handlers) CreateScimToken(w http.ResponseWriter, r *http.Request, id string) {
	d, ok := h.directory(w)
	if !ok {
		return
	}
	c, err := h.scimConnection(r, id, false)
	if err != nil {
		h.scimError(w, r, err)
		return
	}
	body := map[string]json.RawMessage{}
	if r.ContentLength != 0 {
		if body, err = decodeObject(r); err != nil {
			Fail(w, err)
			return
		}
	}
	scopes := slices.Clone(scimScopes)
	var lifetime *int64
	for k, raw := range body {
		switch k {
		case "scopes":
			scopes = nil
			if err := decodeStrict(raw, &scopes); err != nil || len(scopes) == 0 {
				Fail(w, badBody("scopes must be a nonempty list"))
				return
			}
			for i, s := range scopes {
				if !slices.Contains(scimScopes, s) || slices.Contains(scopes[:i], s) {
					Fail(w, badBody("invalid or repeated scope %q", s))
					return
				}
			}
		case "token_lifetime":
			if string(raw) == "null" {
				continue
			}
			var n int64
			if err := decodeStrict(raw, &n); err != nil || n <= minSCIMTokenLifetime || n > 10*365*24*3600 {
				Fail(w, badBody("token_lifetime must be an integer number of seconds greater than %d", minSCIMTokenLifetime))
				return
			}
			lifetime = &n
		default:
			Fail(w, badBody("unknown property %q", k))
			return
		}
	}
	if _, err := d.GetSCIMConfig(r.Context(), resolved(r).ID, c.ID); errors.Is(err, store.ErrNotFound) {
		Fail(w, errSCIMConfigNotFound)
		return
	} else if err != nil {
		h.scimError(w, r, err)
		return
	}
	now := h.now()
	raw := secrets.RandomString(48)
	t := &store.SCIMToken{TenantID: resolved(r).ID, ConnectionID: c.ID, ID: "tok_" + secrets.RandomString(16), Hash: scim.HashToken(raw), Scopes: scopes, CreatedAt: now}
	if lifetime != nil {
		exp := now.Add(time.Duration(*lifetime) * time.Second)
		t.ExpiresAt = &exp
	}
	if err := d.CreateSCIMToken(r.Context(), t); err != nil {
		h.scimError(w, r, err)
		return
	}
	logDetails(r, "create scim token", "connection", c.ID, "id", t.ID)
	out := scimTokenView(t)
	out["token"] = raw
	writeJSON(w, http.StatusCreated, out)
}

// DeleteScimToken serves DELETE
// /connections/{id}/scim-configuration/tokens/{token_id}.
func (h *Handlers) DeleteScimToken(w http.ResponseWriter, r *http.Request, id, tokenID string) {
	d, ok := h.directory(w)
	if !ok {
		return
	}
	c, err := h.scimConnection(r, id, false)
	if err != nil {
		h.scimError(w, r, err)
		return
	}
	if tokenID == "" || len(tokenID) > 64 {
		Fail(w, errSCIMTokenNotFound)
		return
	}
	err = d.DeleteSCIMToken(r.Context(), resolved(r).ID, c.ID, tokenID)
	if errors.Is(err, store.ErrNotFound) {
		err = errSCIMTokenNotFound
	}
	if err != nil {
		h.scimError(w, r, err)
		return
	}
	logDetails(r, "delete scim token", "connection", c.ID, "id", tokenID)
	w.WriteHeader(http.StatusNoContent)
}

// ListScimConfigurations serves GET /connections-scim-configurations
// (checkpoint), oldest first.
func (h *Handlers) ListScimConfigurations(w http.ResponseWriter, r *http.Request) {
	d, ok := h.directory(w)
	if !ok {
		return
	}
	p, err := readGroupPage(r, false)
	if err != nil {
		Fail(w, err)
		return
	}
	tn := resolved(r)
	cfgs, err := d.ListSCIMConfigs(r.Context(), tn.ID)
	if err != nil {
		h.scimError(w, r, err)
		return
	}
	slices.SortFunc(cfgs, func(a, b *store.SCIMConfig) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.ConnectionID, b.ConnectionID)
	})
	var items []map[string]any
	for _, cfg := range window(cfgs, p) {
		c, err := h.Store.Connections().Get(r.Context(), tn.ID, cfg.ConnectionID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			h.scimError(w, r, err)
			return
		}
		items = append(items, scimConfigView(tn, c, cfg))
	}
	writeGroupList(w, "scim_configurations", items, len(cfgs), p)
}
