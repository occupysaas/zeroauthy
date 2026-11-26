package myorg

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/zeroauthy/zeroauthy/internal/orgidp"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Identity provider updates (LR42b-18), deletion and detachment
// (LR42b-23), and domain links (LR42b-19).

func insufficientAccess(detail string) *Problem {
	return problem(http.StatusForbidden, "insufficient_access", "Forbidden", detail)
}

// needAccess refuses unless oc's access level is one of levels.
func needAccess(oc *store.OrganizationConnection, what string, levels ...string) *Problem {
	if !slices.Contains(levels, accessLevel(oc)) {
		return insufficientAccess(what + " needs the identity provider's access level to be " + joinOr(levels) + ".")
	}
	return nil
}

func joinOr(v []string) string {
	if len(v) == 1 {
		return v[0]
	}
	return v[0] + " or " + v[1]
}

type idpUpdate struct {
	DisplayName             *string        `json:"display_name"`
	ShowAsButton            *bool          `json:"show_as_button"`
	AssignMembershipOnLogin *bool          `json:"assign_membership_on_login"`
	IsEnabled               *bool          `json:"is_enabled"`
	UseForThirdParty        *bool          `json:"use_for_third_party_client_access"`
	Options                 map[string]any `json:"options"`
}

func (h *Handlers) updateIdP(w http.ResponseWriter, r *http.Request, c *Caller) {
	conn, oc, err := h.idp(r, c, chi.URLParam(r, "idp_id"))
	if err != nil {
		h.idpFail(w, r, c, "update identity provider", err)
		return
	}
	var in idpUpdate
	if p := decode(r, &in); p != nil {
		h.idpFail(w, r, c, "update identity provider", p)
		return
	}
	full, flags := in.DisplayName != nil || in.Options != nil || in.UseForThirdParty != nil, in.ShowAsButton != nil || in.AssignMembershipOnLogin != nil || in.IsEnabled != nil
	if full {
		if p := needAccess(oc, "Updating display_name, options or use_for_third_party_client_access", "full"); p != nil {
			h.idpFail(w, r, c, "update identity provider", p)
			return
		}
	}
	if flags {
		if p := needAccess(oc, "Updating show_as_button, assign_membership_on_login or is_enabled", "full", "limited"); p != nil {
			h.idpFail(w, r, c, "update identity provider", p)
			return
		}
	}
	if p := thirdPartyRefused(in.UseForThirdParty); p != nil {
		h.idpFail(w, r, c, "update identity provider", p)
		return
	}
	if in.DisplayName != nil {
		if n := utf8.RuneCountInString(*in.DisplayName); n < 1 || n > 128 {
			h.idpFail(w, r, c, "update identity provider", badRequest("invalid_body", "display_name must be 1 to 128 characters."))
			return
		}
	}
	ctx := r.Context()
	prof, err := h.profile(ctx, c)
	if err != nil {
		h.idpFail(w, r, c, "update identity provider", err)
		return
	}
	if p := prof.checkFlags(in.ShowAsButton, in.AssignMembershipOnLogin); p != nil {
		h.idpFail(w, r, c, "update identity provider", p)
		return
	}
	wr, err := h.writes()
	if err != nil {
		h.idpFail(w, r, c, "update identity provider", err)
		return
	}
	if in.DisplayName != nil || in.Options != nil {
		body := map[string]any{}
		if in.DisplayName != nil {
			body["display_name"] = *in.DisplayName
		}
		if in.Options != nil {
			opts, err := orgidp.ForUpdate(conn.Strategy, in.Options)
			if err != nil {
				h.idpFail(w, r, c, "update identity provider", badRequest("invalid_body", err.Error()))
				return
			}
			// The options replace the connection's; its domains stay.
			cur, err := h.connectionView(ctx, c, conn.ID)
			if err != nil {
				h.idpFail(w, r, c, "update identity provider", err)
				return
			}
			if o, _ := cur["options"].(map[string]any); o["domain_aliases"] != nil {
				opts["domain_aliases"] = o["domain_aliases"]
			}
			body["options"] = opts
		}
		if err := h.patchConnection(ctx, c, conn.ID, body); err != nil {
			h.idpFail(w, r, c, "update identity provider", err)
			return
		}
	}
	if flags {
		link := map[string]any{}
		if in.ShowAsButton != nil {
			link["show_as_button"] = *in.ShowAsButton
		}
		if in.AssignMembershipOnLogin != nil {
			link["assign_membership_on_login"] = *in.AssignMembershipOnLogin
		}
		if in.IsEnabled != nil {
			link["is_enabled"] = *in.IsEnabled
		}
		res, err := wr.MyOrgUpdateOrganizationConnection(ctx, c.Tenant, c.Host, c.Org.ID, conn.ID, link)
		if err == nil && !res.OK() {
			err = mgmtProblem(res)
		}
		if err != nil {
			h.idpFail(w, r, c, "update identity provider", err)
			return
		}
	}
	h.respondIdP(w, r, c, conn.ID, http.StatusOK)
}

// patchConnection is PATCH /api/v2/connections/{id} with body.
func (h *Handlers) patchConnection(ctx context.Context, c *Caller, id string, body map[string]any) error {
	wr, err := h.writes()
	if err != nil {
		return err
	}
	res, err := wr.MyOrgUpdateConnection(ctx, c.Tenant, c.Host, id, body)
	if err == nil && !res.OK() {
		err = mgmtProblem(res)
	}
	return err
}

// respondIdP answers the identity provider id as it now is.
func (h *Handlers) respondIdP(w http.ResponseWriter, r *http.Request, c *Caller, id string, status int) {
	conn, oc, err := h.idp(r, c, id)
	var v map[string]any
	if err == nil {
		v, err = h.idpView(r.Context(), c, conn, oc)
	}
	if err != nil {
		h.idpFail(w, r, c, "identity provider", err)
		return
	}
	h.event(r, c, idpEventOK)
	writeJSON(w, r, status, v)
}

func (h *Handlers) refreshIdPAttributes(w http.ResponseWriter, r *http.Request, c *Caller) {
	conn, _, err := h.idp(r, c, chi.URLParam(r, "idp_id"))
	if err == nil && r.ContentLength != 0 {
		var empty struct{}
		if p := decode(r, &empty); p != nil {
			err = p
		}
	}
	if err != nil {
		h.idpFail(w, r, c, "refresh identity provider attributes", err)
		return
	}
	// No User Attribute Profiles: nothing to refresh (LR42b-20).
	h.respondIdP(w, r, c, conn.ID, http.StatusOK)
}

func (h *Handlers) deleteIdP(w http.ResponseWriter, r *http.Request, c *Caller) {
	conn, oc, err := h.idp(r, c, chi.URLParam(r, "idp_id"))
	if err == nil {
		if p := needAccess(oc, "Deleting an identity provider", "full"); p != nil {
			err = p
		}
	}
	ctx := r.Context()
	if err == nil && c.Config.ConnectionDeletionBehavior == "allow_if_empty" {
		q := &store.UserQuery{Op: store.QueryTerm, Field: "identities.connection", Kind: store.KindString, Value: conn.Name}
		_, n, lerr := h.Store.Users().List(ctx, c.TenantID, q, store.UserSort{}, store.Page{Limit: 1})
		switch {
		case lerr != nil:
			err = lerr
		case n > 0:
			err = badRequest("connection_not_empty", "The identity provider still has users; the application allows deleting only empty ones.")
		}
	}
	var wr = h.Writes
	if err == nil {
		wr, err = h.writes()
	}
	if err == nil {
		res, derr := wr.MyOrgDeleteConnection(ctx, c.Tenant, c.Host, conn.ID)
		if err = derr; err == nil && !res.OK() {
			err = mgmtProblem(res)
		}
	}
	if err != nil {
		h.idpFail(w, r, c, "delete identity provider", err)
		return
	}
	h.event(r, c, idpEventOK)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) detachIdP(w http.ResponseWriter, r *http.Request, c *Caller) {
	conn, _, err := h.idp(r, c, chi.URLParam(r, "idp_id"))
	var wr = h.Writes
	if err == nil {
		wr, err = h.writes()
	}
	if err == nil {
		res, derr := wr.MyOrgDisableOrganization(r.Context(), c.Tenant, c.Host, c.Org.ID, conn.ID)
		if err = derr; err == nil && !res.OK() {
			err = mgmtProblem(res)
		}
	}
	if err != nil {
		h.idpFail(w, r, c, "detach identity provider", err)
		return
	}
	h.event(r, c, idpEventOK)
	w.WriteHeader(http.StatusNoContent)
}

// setDomains replaces the connection's domain_aliases, keeping its other
// options (the secret stays: the view omits it and updates keep it).
func (h *Handlers) setDomains(ctx context.Context, c *Caller, id string, domains []string) error {
	cur, err := h.connectionView(ctx, c, id)
	if err != nil {
		return err
	}
	opts, _ := cur["options"].(map[string]any)
	if opts == nil {
		opts = map[string]any{}
	}
	if len(domains) == 0 {
		delete(opts, "domain_aliases")
	} else {
		opts["domain_aliases"] = domains
	}
	return h.patchConnection(ctx, c, id, map[string]any{"options": opts})
}

// domainsOf is the connection's domain_aliases.
func (h *Handlers) domainsOf(ctx context.Context, c *Caller, id string) ([]string, error) {
	cur, err := h.connectionView(ctx, c, id)
	if err != nil {
		return nil, err
	}
	opts, _ := cur["options"].(map[string]any)
	raw, _ := json.Marshal(opts["domain_aliases"])
	var out []string
	_ = json.Unmarshal(raw, &out)
	return out, nil
}

func (h *Handlers) addIdPDomain(w http.ResponseWriter, r *http.Request, c *Caller) {
	conn, oc, err := h.idp(r, c, chi.URLParam(r, "idp_id"))
	if err == nil {
		if p := needAccess(oc, "Changing an identity provider's domains", "full"); p != nil {
			err = p
		}
	}
	var in struct {
		Domain string `json:"domain"`
	}
	if err == nil {
		if p := decode(r, &in); p != nil {
			err = p
		}
	}
	ctx := r.Context()
	var current, add []string
	if err == nil {
		current, err = h.domainsOf(ctx, c, conn.ID)
	}
	if err == nil {
		add, err = h.linkable(ctx, c, conn.ID, []string{in.Domain})
	}
	if err == nil && slices.Contains(current, add[0]) {
		err = conflict("domain_associated", "The domain is already associated with this identity provider.")
	}
	if err == nil {
		err = h.setDomains(ctx, c, conn.ID, append(current, add[0]))
	}
	if err != nil {
		h.idpFail(w, r, c, "add identity provider domain", err)
		return
	}
	h.event(r, c, idpEventOK)
	writeJSON(w, r, http.StatusCreated, map[string]any{"domain": add[0]})
}

func (h *Handlers) removeIdPDomain(w http.ResponseWriter, r *http.Request, c *Caller) {
	conn, oc, err := h.idp(r, c, chi.URLParam(r, "idp_id"))
	if err == nil {
		if p := needAccess(oc, "Changing an identity provider's domains", "full"); p != nil {
			err = p
		}
	}
	ctx := r.Context()
	var current []string
	var name string
	if err == nil {
		var p *Problem
		if name, p = normalizeDomain("domain", chi.URLParam(r, "domain")); p != nil {
			err = p
		}
	}
	if err == nil {
		current, err = h.domainsOf(ctx, c, conn.ID)
	}
	if err == nil && !slices.Contains(current, name) {
		err = notFound("The identity provider does not have this domain.")
	}
	if err == nil {
		err = h.setDomains(ctx, c, conn.ID, slices.DeleteFunc(current, func(d string) bool { return d == name }))
	}
	if err != nil {
		h.idpFail(w, r, c, "remove identity provider domain", err)
		return
	}
	h.event(r, c, idpEventOK)
	w.WriteHeader(http.StatusNoContent)
}

// unlinkDomain removes the domain name from every identity provider of the
// organization that has it (an organization domain was deleted).
func (h *Handlers) unlinkDomain(ctx context.Context, c *Caller, name string) error {
	held, err := h.linkedDomains(ctx, c)
	if err != nil {
		return err
	}
	id, ok := held[name]
	if !ok {
		return nil
	}
	current, err := h.domainsOf(ctx, c, id)
	if err != nil {
		return err
	}
	return h.setDomains(ctx, c, id, slices.DeleteFunc(current, func(d string) bool { return d == name }))
}

func (h *Handlers) domainIdPs(w http.ResponseWriter, r *http.Request, c *Caller) {
	d, err := h.domain(r, c)
	ctx := r.Context()
	var held map[string]string
	if err == nil {
		held, err = h.linkedDomains(ctx, c)
	}
	out := []any{}
	if id, ok := held[d.Domain]; err == nil && ok {
		var conn *store.Connection
		conn, err = h.Store.Connections().Get(ctx, c.TenantID, id)
		if errors.Is(err, store.ErrNotFound) {
			err = nil
		} else if err == nil {
			var v map[string]any
			if v, err = h.connectionView(ctx, c, id); err == nil {
				display, _ := v["display_name"].(string)
				if display == "" {
					display = conn.Name
				}
				out = append(out, map[string]any{"id": conn.ID, "name": conn.Name, "display_name": display})
			}
		}
	}
	if err != nil {
		h.domainFail(w, r, c, "domain identity providers", err)
		return
	}
	h.event(r, c, domainEventOK)
	writeJSON(w, r, http.StatusOK, map[string]any{"identity_providers": out})
}
