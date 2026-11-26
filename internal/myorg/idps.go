package myorg

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/orgidp"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Identity providers (Phase B, D-0221): enterprise connections of the
// OpenAPI's strategies enabled on the organization at an access level other
// than none (LR42b-18). Writes go through the Management API (h.Writes).

const (
	idpEventOK   = "my_organization_api_idp_succeeded"
	idpEventFail = "my_organization_api_idp_failed"
	cfgEventFail = "my_organization_api_config_failed"
)

var accessLevels = []string{"none", "readonly", "limited", "full"}

func (h *Handlers) idpFail(w http.ResponseWriter, r *http.Request, c *Caller, what string, err error) {
	h.event(r, c, idpEventFail)
	h.fail(w, r, what, err)
}

// accessLevel is oc's organization access level, none when unset.
func accessLevel(oc *store.OrganizationConnection) string {
	if oc.OrganizationAccessLevel == "" {
		return "none"
	}
	return oc.OrganizationAccessLevel
}

func memberAccessLevel(oc *store.OrganizationConnection) string {
	if oc.OrganizationMemberAccessLevel == "" {
		return "limited"
	}
	return oc.OrganizationMemberAccessLevel
}

func idpNotFound() *Problem { return notFound("The identity provider does not exist.") }

// idp is the organization's identity provider id: its connection and
// organization connection; 404 for any other ID (LR42b-18).
func (h *Handlers) idp(r *http.Request, c *Caller, id string) (*store.Connection, *store.OrganizationConnection, error) {
	ctx := r.Context()
	if len(id) > 64 {
		return nil, nil, idpNotFound()
	}
	oc, err := h.Store.Organizations().GetConnection(ctx, c.TenantID, c.Org.ID, id)
	if errors.Is(err, store.ErrNotFound) || err == nil && accessLevel(oc) == "none" {
		return nil, nil, idpNotFound()
	}
	if err != nil {
		return nil, nil, err
	}
	conn, err := h.Store.Connections().Get(ctx, c.TenantID, id)
	if errors.Is(err, store.ErrNotFound) || err == nil && !slices.Contains(orgidp.Strategies, conn.Strategy) {
		return nil, nil, idpNotFound()
	}
	return conn, oc, err
}

// writes is the Management API, or a server error when it is not wired.
func (h *Handlers) writes() (*mgmt.Handlers, error) {
	if h.Writes == nil {
		return nil, errors.New("my org: no Management API for identity provider writes")
	}
	return h.Writes, nil
}

// mgmtProblem maps a failed Management API response to a problem.
func mgmtProblem(res mgmt.AssistantResult) *Problem {
	msg := res.Message()
	if msg == "" {
		msg = "The request was refused."
	}
	switch res.Status {
	case http.StatusBadRequest:
		return badRequest("invalid_body", msg)
	case http.StatusConflict:
		return conflict("conflict", msg)
	case http.StatusNotFound:
		return idpNotFound()
	case http.StatusForbidden:
		return problem(http.StatusForbidden, "forbidden", "Forbidden", msg)
	}
	return serverError()
}

// connectionView is the Management API's view of connection id (no
// secrets).
func (h *Handlers) connectionView(ctx context.Context, c *Caller, id string) (map[string]any, error) {
	wr, err := h.writes()
	if err != nil {
		return nil, err
	}
	res, err := wr.MyOrgGetConnection(ctx, c.Tenant, c.Host, id)
	if err != nil {
		return nil, err
	}
	if !res.OK() {
		return nil, mgmtProblem(res)
	}
	var v map[string]any
	if err := json.Unmarshal(res.Body, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// idpView is the OpenAPI's identity provider.
func (h *Handlers) idpView(ctx context.Context, c *Caller, conn *store.Connection, oc *store.OrganizationConnection) (map[string]any, error) {
	v, err := h.connectionView(ctx, c, conn.ID)
	if err != nil {
		return nil, err
	}
	opts, _ := v["options"].(map[string]any)
	domains := []any{}
	if d, ok := opts["domain_aliases"].([]any); ok {
		domains = d
	}
	display, _ := v["display_name"].(string)
	if display == "" {
		display = conn.Name
	}
	return map[string]any{
		"id": conn.ID, "name": conn.Name, "strategy": conn.Strategy, "domains": domains, "display_name": display,
		"show_as_button": oc.ShowAsButton, "assign_membership_on_login": oc.AssignMembershipOnLogin,
		"is_enabled": !oc.IsEnabledSet || oc.IsEnabled, "access_level": accessLevel(oc), "member_access_level": memberAccessLevel(oc),
		"use_for_third_party_client_access": false, "options": orgidp.FromConnection(conn.Strategy, opts), "attributes": []any{},
	}, nil
}

// thirdPartyRefused refuses use_for_third_party_client_access true: zeroauthy
// has no connection-level third-party control (D-0221), so providers are
// for first-party applications only, the OpenAPI's default.
func thirdPartyRefused(v *bool) *Problem {
	if v != nil && *v {
		return badRequest("invalid_body", "use_for_third_party_client_access true is not supported by this server.")
	}
	return nil
}

// orgConnections lists every organization connection that is an identity
// provider in scope.
func (h *Handlers) orgConnections(ctx context.Context, c *Caller) ([]store.OrganizationConnection, error) {
	var out []store.OrganizationConnection
	from := ""
	for {
		res, err := h.Store.Organizations().Connections(ctx, c.TenantID, c.Org.ID, store.OrgPage{From: from, Take: 100})
		if err != nil {
			return nil, err
		}
		for _, oc := range res.Items {
			if accessLevel(&oc) != "none" {
				out = append(out, oc)
			}
		}
		if res.Next == "" {
			return out, nil
		}
		from = res.Next
	}
}

func (h *Handlers) listIdPs(w http.ResponseWriter, r *http.Request, c *Caller) {
	q := r.URL.Query()
	levels := q["member_access_level"]
	for _, l := range levels {
		if !slices.Contains(accessLevels, l) {
			h.idpFail(w, r, c, "list identity providers", invalidQuery("member_access_level", "member_access_level must be none, readonly, limited or full."))
			return
		}
	}
	var enabled *bool
	if v, ok := q["is_enabled"]; ok {
		b, err := strconv.ParseBool(v[0])
		if err != nil || len(v) != 1 {
			h.idpFail(w, r, c, "list identity providers", invalidQuery("is_enabled", "is_enabled must be true or false."))
			return
		}
		enabled = &b
	}
	ctx := r.Context()
	ocs, err := h.orgConnections(ctx, c)
	if err != nil {
		h.idpFail(w, r, c, "list identity providers", err)
		return
	}
	out := []any{}
	for i := range ocs {
		oc := &ocs[i]
		if enabled != nil && (!oc.IsEnabledSet || oc.IsEnabled) != *enabled || len(levels) > 0 && !slices.Contains(levels, memberAccessLevel(oc)) {
			continue
		}
		conn, err := h.Store.Connections().Get(ctx, c.TenantID, oc.ConnectionID)
		if errors.Is(err, store.ErrNotFound) || err == nil && !slices.Contains(orgidp.Strategies, conn.Strategy) {
			continue
		}
		var v map[string]any
		if err == nil {
			v, err = h.idpView(ctx, c, conn, oc)
		}
		if err != nil {
			h.idpFail(w, r, c, "list identity providers", err)
			return
		}
		out = append(out, v)
	}
	h.event(r, c, idpEventOK)
	writeJSON(w, r, http.StatusOK, map[string]any{"identity_providers": out})
}

func (h *Handlers) getIdP(w http.ResponseWriter, r *http.Request, c *Caller) {
	conn, oc, err := h.idp(r, c, chi.URLParam(r, "idp_id"))
	var v map[string]any
	if err == nil {
		v, err = h.idpView(r.Context(), c, conn, oc)
	}
	if err != nil {
		h.idpFail(w, r, c, "get identity provider", err)
		return
	}
	h.event(r, c, idpEventOK)
	writeJSON(w, r, http.StatusOK, v)
}

type idpCreate struct {
	Name                    string         `json:"name"`
	Strategy                string         `json:"strategy"`
	Domains                 []string       `json:"domains"`
	DisplayName             *string        `json:"display_name"`
	ShowAsButton            *bool          `json:"show_as_button"`
	AssignMembershipOnLogin *bool          `json:"assign_membership_on_login"`
	IsEnabled               *bool          `json:"is_enabled"`
	UseForThirdParty        *bool          `json:"use_for_third_party_client_access"`
	Options                 map[string]any `json:"options"`
}

func (h *Handlers) createIdP(w http.ResponseWriter, r *http.Request, c *Caller) {
	var in idpCreate
	if p := decode(r, &in); p != nil {
		h.idpFail(w, r, c, "create identity provider", p)
		return
	}
	if n := utf8.RuneCountInString(in.Name); n < 1 || n > 128 {
		h.idpFail(w, r, c, "create identity provider", badRequest("invalid_body", "name must be 1 to 128 characters.", ValidationError{Detail: "name must be 1 to 128 characters.", Field: "name", Pointer: "/name", Source: "body"}))
		return
	}
	if in.DisplayName != nil {
		if n := utf8.RuneCountInString(*in.DisplayName); n < 1 || n > 128 {
			h.idpFail(w, r, c, "create identity provider", badRequest("invalid_body", "display_name must be 1 to 128 characters."))
			return
		}
	}
	if p := thirdPartyRefused(in.UseForThirdParty); p != nil {
		h.idpFail(w, r, c, "create identity provider", p)
		return
	}
	if !slices.Contains(orgidp.Strategies, in.Strategy) || !slices.Contains(c.Config.AllowedStrategies, in.Strategy) {
		h.idpFail(w, r, c, "create identity provider", badRequest("invalid_body", "The strategy is not allowed for this application."))
		return
	}
	opts, err := orgidp.ToConnection(in.Strategy, in.Options)
	if err != nil {
		h.idpFail(w, r, c, "create identity provider", badRequest("invalid_body", err.Error()))
		return
	}
	ctx := r.Context()
	prof, err := h.profile(ctx, c)
	if err != nil {
		h.idpFail(w, r, c, "create identity provider", err)
		return
	}
	if p := prof.checkFlags(in.ShowAsButton, in.AssignMembershipOnLogin); p != nil {
		h.idpFail(w, r, c, "create identity provider", p)
		return
	}
	if len(in.Domains) > 0 {
		domains, err := h.linkable(ctx, c, "", in.Domains)
		if err != nil {
			h.idpFail(w, r, c, "create identity provider", err)
			return
		}
		opts["domain_aliases"] = domains
	}
	wr, err := h.writes()
	if err != nil {
		h.idpFail(w, r, c, "create identity provider", err)
		return
	}
	clients := []string{c.ClientID}
	if l := c.Config.InvitationLandingClientID; l != "" && l != c.ClientID {
		clients = append(clients, l)
	}
	body := map[string]any{"name": in.Name, "strategy": in.Strategy, "options": opts, "enabled_clients": clients}
	if in.DisplayName != nil {
		body["display_name"] = *in.DisplayName
	}
	res, err := wr.MyOrgCreateConnection(ctx, c.Tenant, c.Host, body)
	if err == nil && !res.OK() {
		err = mgmtProblem(res)
	}
	if err != nil {
		h.idpFail(w, r, c, "create identity provider", err)
		return
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(res.Body, &created); err != nil || created.ID == "" {
		h.idpFail(w, r, c, "create identity provider", errors.New("my org: connection create returned no id"))
		return
	}
	link := map[string]any{"connection_id": created.ID, "organization_access_level": "full", "is_enabled": in.IsEnabled == nil || *in.IsEnabled,
		"show_as_button": prof.flag(prof.Organization.ShowAsButton, in.ShowAsButton), "assign_membership_on_login": prof.flag(prof.Organization.AssignMembershipOnLogin, in.AssignMembershipOnLogin)}
	res, err = wr.MyOrgEnableOrganization(ctx, c.Tenant, c.Host, c.Org.ID, link)
	if err == nil && !res.OK() {
		err = mgmtProblem(res)
	}
	if err != nil {
		// No orphan connection (LR42b-18).
		if del, derr := wr.MyOrgDeleteConnection(ctx, c.Tenant, c.Host, created.ID); derr != nil || !del.OK() {
			h.log().ErrorContext(ctx, "my org: remove connection after a failed organization link", "connection_id", created.ID, "status", del.Status, "err", derr)
		}
		h.idpFail(w, r, c, "create identity provider", err)
		return
	}
	conn, oc, err := h.idp(r, c, created.ID)
	var v map[string]any
	if err == nil {
		v, err = h.idpView(ctx, c, conn, oc)
	}
	if err != nil {
		h.idpFail(w, r, c, "create identity provider", err)
		return
	}
	h.event(r, c, idpEventOK)
	writeJSON(w, r, http.StatusCreated, v)
}

// linkable checks that each domain is a verified domain of the organization
// not held by another of its identity providers than except (LR42b-19),
// and returns them normalized.
func (h *Handlers) linkable(ctx context.Context, c *Caller, except string, domains []string) ([]string, error) {
	held, err := h.linkedDomains(ctx, c)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, raw := range domains {
		d, p := normalizeDomain("domain", raw)
		if p != nil {
			return nil, p
		}
		od, err := h.Store.OrganizationsII().GetDiscoveryDomainByName(ctx, c.TenantID, c.Org.ID, d)
		if errors.Is(err, store.ErrNotFound) || err == nil && od.Status != "verified" {
			return nil, badRequest("invalid_body", "The domain "+d+" is not a verified domain of the organization.")
		}
		if err != nil {
			return nil, err
		}
		if owner, ok := held[d]; ok && owner != except {
			return nil, conflict("domain_associated", "The domain "+d+" is already associated with another identity provider of the organization.")
		}
		if !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out, nil
}

// linkedDomains maps each domain held by one of the organization's
// identity providers to that provider's ID.
func (h *Handlers) linkedDomains(ctx context.Context, c *Caller) (map[string]string, error) {
	ocs, err := h.orgConnections(ctx, c)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, oc := range ocs {
		conn, err := h.Store.Connections().Get(ctx, c.TenantID, oc.ConnectionID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !slices.Contains(orgidp.Strategies, conn.Strategy) {
			continue
		}
		v, err := h.connectionView(ctx, c, conn.ID)
		if err != nil {
			return nil, err
		}
		opts, _ := v["options"].(map[string]any)
		aliases, _ := opts["domain_aliases"].([]any)
		for _, a := range aliases {
			if s, ok := a.(string); ok {
				out[s] = conn.ID
			}
		}
	}
	return out, nil
}
