package myorg

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"github.com/go-chi/chi/v5"
	"github.com/zeroauthy/zeroauthy/internal/scim"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Provisioning (Phase B, LR42b-20, LR42b-21): an identity provider's SCIM
// configuration and tokens, written through the Management API so the Plan
// 37c limits and hashing apply. Writes need access level full.

const minTokenLifetime = 900

func provisioningView(conn *store.Connection, cfg *store.SCIMConfig) map[string]any {
	attrs := []any{}
	for _, m := range cfg.Mapping {
		attrs = append(attrs, map[string]any{"user_attribute": m.Auth0, "provisioning_field": m.SCIM, "is_required": false, "is_extra": false, "is_missing": false})
	}
	uid := cfg.UserIDAttribute
	if uid == "" {
		uid = scim.DefaultUserIDAttribute
	}
	return map[string]any{"identity_provider_id": conn.ID, "identity_provider_name": conn.Name, "strategy": conn.Strategy, "method": "scim", "attributes": attrs, "user_id_attribute": uid}
}

func provisioningNotFound() *Problem {
	return notFound("The identity provider has no provisioning configuration.")
}

// scimConfig is the provider's SCIM configuration, 404 when it has none.
func (h *Handlers) scimConfig(r *http.Request, c *Caller, conn *store.Connection) (*store.SCIMConfig, error) {
	if !store.DirectoryAvailable(h.Store) {
		return nil, provisioningNotFound()
	}
	cfg, err := h.Store.Directory().GetSCIMConfig(r.Context(), c.TenantID, conn.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, provisioningNotFound()
	}
	return cfg, err
}

// provisioned is the provider and its SCIM configuration; write also
// requires access level full.
func (h *Handlers) provisioned(r *http.Request, c *Caller, write bool) (*store.Connection, *store.SCIMConfig, error) {
	conn, oc, err := h.idp(r, c, chi.URLParam(r, "idp_id"))
	if err != nil {
		return nil, nil, err
	}
	if write {
		if p := needAccess(oc, "Changing provisioning", "full"); p != nil {
			return nil, nil, p
		}
		if err := h.notShared(r.Context(), c, conn.ID); err != nil {
			return nil, nil, err
		}
	}
	cfg, err := h.scimConfig(r, c, conn)
	return conn, cfg, err
}

func (h *Handlers) getProvisioning(w http.ResponseWriter, r *http.Request, c *Caller) {
	conn, cfg, err := h.provisioned(r, c, false)
	if err != nil {
		h.idpFail(w, r, c, "get provisioning", err)
		return
	}
	h.event(r, c, idpEventOK)
	writeJSON(w, r, http.StatusOK, provisioningView(conn, cfg))
}

func (h *Handlers) refreshProvisioningAttributes(w http.ResponseWriter, r *http.Request, c *Caller) {
	conn, cfg, err := h.provisioned(r, c, false)
	if err == nil && r.ContentLength != 0 {
		var empty struct{}
		if p := decode(r, &empty); p != nil {
			err = p
		}
	}
	if err != nil {
		h.idpFail(w, r, c, "refresh provisioning attributes", err)
		return
	}
	// No User Attribute Profiles: nothing to refresh (LR42b-20).
	h.event(r, c, idpEventOK)
	writeJSON(w, r, http.StatusOK, provisioningView(conn, cfg))
}

func (h *Handlers) createProvisioning(w http.ResponseWriter, r *http.Request, c *Caller) {
	conn, oc, err := h.idp(r, c, chi.URLParam(r, "idp_id"))
	if err == nil {
		if p := needAccess(oc, "Changing provisioning", "full"); p != nil {
			err = p
		}
	}
	ctx := r.Context()
	if err == nil {
		err = h.notShared(ctx, c, conn.ID)
	}
	if err == nil {
		var prof *profileDoc
		if prof, err = h.profile(ctx, c); err == nil {
			allowed := slices.Contains(scim.Strategies, conn.Strategy)
			if prof.present {
				allowed = allowed && prof.provisions(conn.Strategy)
			}
			if !allowed {
				err = badRequest("provisioning_not_allowed", "Provisioning is not available for this identity provider.")
			}
		}
	}
	if err == nil {
		if _, cerr := h.scimConfig(r, c, conn); cerr == nil {
			err = badRequest("provisioning_exists", "The identity provider already has a provisioning configuration.")
		} else if !errors.Is(cerr, store.ErrNotFound) && !isProblem(cerr, http.StatusNotFound) {
			err = cerr
		}
	}
	if err == nil {
		var wr = h.Writes
		if wr, err = h.writes(); err == nil {
			res, cerr := wr.MyOrgCreateSCIM(ctx, c.Tenant, c.Host, conn.ID)
			if err = cerr; err == nil && !res.OK() {
				err = mgmtProblem(res)
			}
		}
	}
	var cfg *store.SCIMConfig
	if err == nil {
		cfg, err = h.scimConfig(r, c, conn)
	}
	if err != nil {
		h.idpFail(w, r, c, "create provisioning", err)
		return
	}
	h.event(r, c, idpEventOK)
	writeJSON(w, r, http.StatusCreated, provisioningView(conn, cfg))
}

func isProblem(err error, status int) bool {
	var p *Problem
	return errors.As(err, &p) && p.Status == status
}

func (h *Handlers) deleteProvisioning(w http.ResponseWriter, r *http.Request, c *Caller) {
	conn, _, err := h.provisioned(r, c, true)
	ctx := r.Context()
	if err == nil {
		// Revoke the tokens first: the configuration goes with them.
		var toks []*store.SCIMToken
		if toks, err = h.Store.Directory().ListSCIMTokens(ctx, c.TenantID, conn.ID); err == nil {
			for _, t := range toks {
				if err = h.deleteToken(r, c, conn.ID, t.ID); err != nil {
					break
				}
			}
		}
	}
	if err == nil {
		var wr = h.Writes
		if wr, err = h.writes(); err == nil {
			res, derr := wr.MyOrgDeleteSCIM(ctx, c.Tenant, c.Host, conn.ID)
			if err = derr; err == nil && !res.OK() {
				err = mgmtProblem(res)
			}
		}
	}
	if err != nil {
		h.idpFail(w, r, c, "delete provisioning", err)
		return
	}
	h.event(r, c, idpEventOK)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) deleteToken(r *http.Request, c *Caller, connID, tokenID string) error {
	wr, err := h.writes()
	if err != nil {
		return err
	}
	res, err := wr.MyOrgDeleteSCIMToken(r.Context(), c.Tenant, c.Host, connID, tokenID)
	if err == nil && !res.OK() {
		err = mgmtProblem(res)
	}
	return err
}

// tokenView is the OpenAPI's SCIM token (IdpScimTokenRead).
func tokenView(m map[string]any) map[string]any {
	out := map[string]any{}
	for _, k := range []string{"token_id", "scopes", "created_at", "valid_until"} {
		if v, ok := m[k]; ok && v != nil {
			out[k] = v
		}
	}
	return out
}

func storedTokenView(t *store.SCIMToken) map[string]any {
	out := map[string]any{"token_id": t.ID, "scopes": t.Scopes, "created_at": timeString(t.CreatedAt)}
	if t.ExpiresAt != nil {
		out["valid_until"] = timeString(*t.ExpiresAt)
	}
	return out
}

func (h *Handlers) listSCIMTokens(w http.ResponseWriter, r *http.Request, c *Caller) {
	conn, _, err := h.provisioned(r, c, false)
	var toks []*store.SCIMToken
	if err == nil {
		toks, err = h.Store.Directory().ListSCIMTokens(r.Context(), c.TenantID, conn.ID)
	}
	if err != nil {
		h.idpFail(w, r, c, "list SCIM tokens", err)
		return
	}
	out := []any{}
	for _, t := range toks {
		out = append(out, storedTokenView(t))
	}
	h.event(r, c, idpEventOK)
	writeJSON(w, r, http.StatusOK, map[string]any{"scim_tokens": out})
}

// token is the provider's SCIM token idp_scim_token_id, 404 otherwise.
func (h *Handlers) token(r *http.Request, c *Caller, write bool) (*store.Connection, *store.SCIMToken, error) {
	conn, _, err := h.provisioned(r, c, write)
	if err != nil {
		return nil, nil, err
	}
	toks, err := h.Store.Directory().ListSCIMTokens(r.Context(), c.TenantID, conn.ID)
	if err != nil {
		return nil, nil, err
	}
	id := chi.URLParam(r, "idp_scim_token_id")
	for _, t := range toks {
		if t.ID == id {
			return conn, t, nil
		}
	}
	return nil, nil, notFound("The SCIM token does not exist.")
}

func (h *Handlers) getSCIMToken(w http.ResponseWriter, r *http.Request, c *Caller) {
	_, t, err := h.token(r, c, false)
	if err != nil {
		h.idpFail(w, r, c, "get SCIM token", err)
		return
	}
	h.event(r, c, idpEventOK)
	writeJSON(w, r, http.StatusOK, storedTokenView(t))
}

func (h *Handlers) deleteSCIMToken(w http.ResponseWriter, r *http.Request, c *Caller) {
	conn, t, err := h.token(r, c, true)
	if err == nil {
		err = h.deleteToken(r, c, conn.ID, t.ID)
	}
	if err != nil {
		h.idpFail(w, r, c, "delete SCIM token", err)
		return
	}
	h.event(r, c, idpEventOK)
	w.WriteHeader(http.StatusNoContent)
}

// createSCIMToken applies the connection profile's token settings
// (LR42b-21) and creates the token through the Management API; its value
// is returned only here.
func (h *Handlers) createSCIMToken(w http.ResponseWriter, r *http.Request, c *Caller) {
	conn, _, err := h.provisioned(r, c, true)
	var raw map[string]json.RawMessage
	if err == nil {
		if p := decode(r, &raw); p != nil {
			err = p
		}
	}
	ctx := r.Context()
	var prof *profileDoc
	if err == nil {
		prof, err = h.profile(ctx, c)
	}
	body := map[string]any{}
	if err == nil {
		err = tokenRequest(raw, prof.tokens(conn.Strategy), body)
	}
	if err == nil {
		var wr = h.Writes
		if wr, err = h.writes(); err == nil {
			res, cerr := wr.MyOrgCreateSCIMToken(ctx, c.Tenant, c.Host, conn.ID, body)
			switch {
			case cerr != nil:
				err = cerr
			case res.Status == http.StatusConflict || res.Status == http.StatusTooManyRequests:
				err = badRequest("token_limit", res.Message())
			case !res.OK():
				err = mgmtProblem(res)
			default:
				var m map[string]any
				if err = json.Unmarshal(res.Body, &m); err == nil {
					out := tokenView(m)
					out["token"] = m["token"]
					h.event(r, c, idpEventOK)
					writeJSON(w, r, http.StatusCreated, out)
					return
				}
			}
		}
	}
	h.idpFail(w, r, c, "create SCIM token", err)
}

// tokenRequest checks a token request against the profile's settings and
// fills the Management API body (scopes, token_lifetime).
func tokenRequest(raw map[string]json.RawMessage, t *tokensDoc, body map[string]any) error {
	allowedScopes := scimScopes
	if t != nil && t.Scopes != nil {
		allowedScopes = t.Scopes
	}
	scopes := slices.Clone(allowedScopes)
	var lifetime *int
	explicitNull := false
	for k, v := range raw {
		switch k {
		case "scopes":
			scopes = nil
			if err := json.Unmarshal(v, &scopes); err != nil || len(scopes) == 0 {
				return badRequest("invalid_body", "scopes must be a non-empty list of SCIM scopes.")
			}
			for i, s := range scopes {
				if !slices.Contains(allowedScopes, s) || slices.Contains(scopes[:i], s) {
					return badRequest("invalid_body", "scope "+s+" is not allowed or repeated.")
				}
			}
		case "token_lifetime":
			if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
				explicitNull = true
				continue
			}
			var n int
			if err := json.Unmarshal(v, &n); err != nil || n <= minTokenLifetime {
				return badRequest("invalid_body", "token_lifetime must be more than 900 seconds, or null.")
			}
			lifetime = &n
		default:
			return badRequest("invalid_body", "unknown member "+k+".")
		}
	}
	var max *int
	if t != nil {
		max = t.MaxAllowedExpiry
	}
	switch {
	case explicitNull && max != nil:
		return badRequest("invalid_body", "A non-expiring token is not allowed; token_lifetime must be at most the profile's maximum.")
	case lifetime == nil && !explicitNull && t != nil:
		if t.DefaultExpiry != nil {
			lifetime = t.DefaultExpiry
		} else {
			lifetime = max
		}
	}
	if lifetime != nil && max != nil && *lifetime > *max {
		return badRequest("invalid_body", "token_lifetime is beyond the profile's maximum.")
	}
	body["scopes"] = scopes
	if lifetime != nil {
		body["token_lifetime"] = *lifetime
	}
	return nil
}
