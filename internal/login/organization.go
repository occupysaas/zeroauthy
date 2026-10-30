package login

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

// OrgContext is reloaded from the bound transaction on every hosted step.
type OrgContext = orglogin.Context

var ErrNotMember = orglogin.ErrNotMember

func EligibleConnections(clientConns []*store.Connection, oc OrgContext) []*store.Connection {
	return orglogin.EligibleConnections(clientConns, oc)
}
func EnsureMembership(ctx context.Context, tx store.Store, oc OrgContext, userID, connectionID string) error {
	return orglogin.EnsureMembership(ctx, tx, oc, userID, connectionID)
}
func PickerChoices(ctx context.Context, st store.Store, tid, userID, connectionID string) ([]store.Organization, *store.Organization, error) {
	return orglogin.PickerChoices(ctx, st, tid, userID, connectionID)
}

func (h *Handlers) renderOrganization(w http.ResponseWriter, r *http.Request, f *flow, orgs []store.Organization, message string, status int) {
	screen := "organization-selection"
	if f.txn.Params[store.TxnParamOrgMode] == string(authz.OrgPickAfter) || len(orgs) > 0 {
		screen = "organization-picker"
	}
	if !h.prepareHostedForm(w, r, f, "organizations", screen) {
		return
	}
	client, err := h.Store.Clients().Get(r.Context(), f.res.Tenant.ID, f.txn.ClientID)
	if err != nil {
		h.fail(w, r, err, f)
		return
	}
	email, name := discoveryMethods(client)
	ui.RenderOrganization(w, status, f.view, ui.OrganizationData{Email: email, Name: name, Personal: email && client.OrganizationUsage == store.OrgUsageAllow && f.txn.HostedState.Step == "organization-discovery" && len(orgs) == 0, RedirectURI: f.txn.Params["redirect_uri"], State: f.txn.ID, CSRF: f.txn.CSRFToken, Revision: f.txn.HostedState.Revision, Orgs: orgs, Error: message}, screen)
}

// bindOrg replaces only a still-pending transaction in a single store tx. The
// browser cookie and CSRF binding survive; a replay cannot replace the choice.
func (h *Handlers) bindOrg(r *http.Request, f *flow, org *store.Organization) error {
	return h.Store.WithTx(r.Context(), func(tx store.Store) error {
		cur, err := tx.AuthTransactions().Get(r.Context(), f.res.Tenant.ID, f.txn.ID)
		if err != nil {
			return err
		}
		if cur.Params[store.TxnParamOrgID] != "" || cur.Params[orglogin.InvitationIDParam] != "" || cur.ClientID != f.txn.ClientID || cur.Params[store.TxnParamOrgMode] != f.txn.Params[store.TxnParamOrgMode] || cur.HostedState.Revision != f.txn.HostedState.Revision {
			return errTxn
		}
		// WithTx alone does not serialize SQL readers. Claim the pending
		// revision before checking policy or replacing the row: a concurrent
		// loser must not delete a choice another request has committed.
		if err := tx.AuthTransactions().CompareAndSwapHosted(r.Context(), cur.TenantID, cur.ID, cur.HostedState.Revision, cur.HostedState, h.now()); err != nil {
			return err
		}
		client, err := tx.Clients().Get(r.Context(), f.res.Tenant.ID, cur.ClientID)
		if err != nil {
			return err
		}
		if e := authz.CheckOrganizationBinding(r.Context(), tx, f.res.Tenant, client, cur.Params); e != nil {
			return errTxn
		}
		if cur.Params[store.TxnParamOrgMode] == string(authz.OrgPromptBefore) {
			email, name := discoveryMethods(client)
			if cur.HostedState.Step == "organization-discovery" {
				if !email {
					return errTxn
				}
				choices, e := orglogin.Discover(r.Context(), tx, cur.TenantID, cur.ClientID, cur.HostedState.Identifier)
				if e != nil {
					return e
				}
				choices = discoveryChoices(choices)
				if org == nil {
					if client.OrganizationUsage != store.OrgUsageAllow || len(choices) != 0 {
						return errTxn
					}
				} else if !slices.ContainsFunc(choices, func(o store.Organization) bool { return o.ID == org.ID }) {
					return errTxn
				}
			} else if !name || org == nil {
				return errTxn
			}
		}
		raw := ""
		if org != nil {
			raw = org.ID
		}
		if _, e := authz.ResolveOrganization(r.Context(), tx, f.res, client, raw); e != nil {
			return errTxn
		}
		if cur.Params[store.TxnParamOrgMode] == string(authz.OrgPickAfter) {
			sess, e := tx.Sessions().Get(r.Context(), cur.TenantID, cur.Params["za_org_session"])
			if e != nil {
				return errTxn
			}
			conn, e := tx.Connections().GetByName(r.Context(), cur.TenantID, sess.Connection)
			if e != nil || !access.ConnectionUsable(client, conn) {
				return errTxn
			}
			choices, auto, e := orglogin.PickerChoicesForClient(r.Context(), tx, cur.TenantID, sess.UserID, conn.ID, client)
			if e != nil {
				return e
			}
			eligible := auto != nil && auto.ID == org.ID
			for _, o := range choices {
				if o.ID == org.ID {
					eligible = true
				}
			}
			if !eligible {
				return errTxn
			}
			if e = EnsureMembership(r.Context(), tx, OrgContext{Org: org}, sess.UserID, conn.ID); e != nil {
				return e
			}
		}
		if org != nil {
			cur.Params[store.TxnParamOrgID] = org.ID
			cur.Params[store.TxnParamOrgMode] = string(authz.OrgFixed)
		} else {
			delete(cur.Params, store.TxnParamOrgID)
			cur.Params[store.TxnParamOrgMode] = string(authz.OrgPersonal)
		}
		cur.HostedState.Step, cur.HostedState.Identifier = "", ""
		cur.HostedState.Revision++
		if err = tx.AuthTransactions().Delete(r.Context(), cur.TenantID, cur.ID); err != nil {
			return err
		}
		if err = tx.AuthTransactions().Create(r.Context(), cur); err != nil {
			return err
		}
		f.txn = cur
		return nil
	})
}
func (h *Handlers) organizationStep(w http.ResponseWriter, r *http.Request, f *flow) bool {
	mode := authz.OrgMode(f.txn.Params[store.TxnParamOrgMode])
	if mode != authz.OrgPromptBefore && mode != authz.OrgPickAfter {
		return false
	}
	if r.Method == http.MethodPost && !postedHostedRevision(r, f) {
		h.fail(w, r, errTxn, f)
		return true
	}
	if mode == authz.OrgPromptBefore {
		return h.organizationDiscoveryStep(w, r, f)
	}

	sess, err := h.Authz.ActiveSession(r.Context(), r, f.res)
	if err != nil {
		h.fail(w, r, err, f)
		return true
	}
	if sess == nil || sess.ID != f.txn.Params["za_org_session"] {
		return false
	}
	conn, err := h.Store.Connections().GetByName(r.Context(), f.res.Tenant.ID, sess.Connection)
	if err != nil {
		h.fail(w, r, err, f)
		return true
	}
	client, err := h.Store.Clients().Get(r.Context(), f.res.Tenant.ID, f.txn.ClientID)
	if err != nil {
		h.fail(w, r, err, f)
		return true
	}
	choices, auto, err := orglogin.PickerChoicesForClient(r.Context(), h.Store, f.res.Tenant.ID, sess.UserID, conn.ID, client)
	if err != nil {
		h.fail(w, r, err, f)
		return true
	}
	if r.Method == http.MethodPost {
		auto = nil
		for i := range choices {
			if choices[i].ID == r.PostForm.Get("organization") {
				auto = &choices[i]
				break
			}
		}
		if auto == nil {
			h.renderOrganization(w, r, f, choices, f.view.L.T(i18n.KeyOrganizationChoiceInvalid), http.StatusBadRequest)
			return true
		}
	}
	if auto != nil {
		if err = h.bindOrg(r, f, auto); err != nil {
			h.fail(w, r, errTxn, f)
			return true
		}
		h.Authz.Resume(w, r, f.res, f.txn, sess)
		return true
	}
	if len(choices) == 0 {
		h.Authz.Resume(w, r, f.res, f.txn, sess)
		return true
	}
	h.renderOrganization(w, r, f, choices, "", http.StatusOK)
	return true
}

func organizationSignupAllowed(f *flow) bool {
	if f.conn == nil || f.conn.DisableSignup {
		return false
	}
	if f.org.Org == nil {
		return f.txn.Params[store.TxnParamOrgMode] != string(authz.OrgPromptBefore)
	}
	link, ok := f.org.Connections[f.conn.ID]
	return ok && (!link.IsEnabledSet || link.IsEnabled) && link.IsSignupEnabled && (link.AssignMembershipOnLogin || f.txn.Params[orglogin.InvitationIDParam] != "")
}

// Empty methods preserve the original name prompt for existing clients.
func discoveryMethods(c *store.Client) (email, name bool) {
	return slices.Contains(c.OrganizationDiscoveryMethods, store.OrgDiscoveryEmail), len(c.OrganizationDiscoveryMethods) == 0 || slices.Contains(c.OrganizationDiscoveryMethods, store.OrgDiscoveryName)
}
func discoveryChoices(orgs []store.Organization) []store.Organization {
	slices.SortFunc(orgs, func(a, b store.Organization) int {
		if n := strings.Compare(a.DisplayName, b.DisplayName); n != 0 {
			return n
		}
		return strings.Compare(a.ID, b.ID)
	})
	return orgs[:min(20, len(orgs))]
}
func (h *Handlers) organizationNext(w http.ResponseWriter, r *http.Request, f *flow) {
	page := "/u/login"
	if f.txn.Params["screen_hint"] == "signup" {
		page = "/u/signup"
	}
	http.Redirect(w, r, page+"?"+url.Values{"state": {f.txn.ID}}.Encode(), http.StatusSeeOther)
}
func (h *Handlers) organizationDiscoveryStep(w http.ResponseWriter, r *http.Request, f *flow) bool {
	client, err := h.Store.Clients().Get(r.Context(), f.res.Tenant.ID, f.txn.ClientID)
	if err != nil {
		h.fail(w, r, err, f)
		return true
	}
	email, name := discoveryMethods(client)
	pending := f.txn.HostedState.Step == "organization-discovery"
	var choices []store.Organization
	if pending && email {
		choices, err = orglogin.Discover(r.Context(), h.Store, f.txn.TenantID, f.txn.ClientID, f.txn.HostedState.Identifier)
		if err != nil {
			h.fail(w, r, err, f)
			return true
		}
		choices = discoveryChoices(choices)
	}
	if r.Method != http.MethodPost {
		h.renderOrganization(w, r, f, choices, "", http.StatusOK)
		return true
	}
	// Discovery uses the shared suspicious-IP budget without user lookup or
	// password brute-force accounting, since no account is being authenticated.
	decision, e := h.protectionService().Begin(r.Context(), protection.Attempt{Tenant: f.res.Tenant, Flow: "organization-discovery", IP: httpx.ClientIP(r, h.TrustProxyHeaders)})
	if e != nil {
		h.fail(w, r, e, f)
		return true
	}
	if !decision.Allowed {
		h.renderOrganization(w, r, f, choices, f.view.L.T(i18n.KeyTooManyAttempts), http.StatusTooManyRequests)
		return true
	}
	// Discovery has no authenticated success to refund the request budget.
	if e = h.protectionService().Finish(r.Context(), decision.Receipt, "failure"); e != nil {
		h.fail(w, r, e, f)
		return true
	}
	screen := "organization-selection"
	if f.txn.HostedState.FormScreen == "organization-picker" {
		screen = "organization-picker"
	}
	if !h.guardHostedForm(w, r, f, "organizations", screen, func(status int, message string) { h.renderOrganization(w, r, f, choices, message, status) }) {
		return true
	}
	invalid := func() {
		h.renderOrganization(w, r, f, choices, f.view.L.T(i18n.KeyOrganizationInvalid), http.StatusBadRequest)
	}
	if pending && r.PostForm.Get("email") == "" && r.PostForm.Get("action") != "name" {
		if !email {
			invalid()
			return true
		}
		var chosen *store.Organization
		for i := range choices {
			if choices[i].ID == r.PostForm.Get("organization") {
				chosen = &choices[i]
				break
			}
		}
		personal := r.PostForm.Get("action") == "personal" && client.OrganizationUsage == store.OrgUsageAllow && len(choices) == 0
		if chosen == nil && !personal {
			invalid()
			return true
		}
		if err = h.bindOrg(r, f, chosen); err != nil {
			h.fail(w, r, errTxn, f)
			return true
		}
		h.organizationNext(w, r, f)
		return true
	}
	if r.PostForm.Get("email") != "" {
		if !email || len(r.PostForm.Get("email")) > 320 {
			invalid()
			return true
		}
		identifier := strings.TrimSpace(r.PostForm.Get("email"))
		choices, err = orglogin.Discover(r.Context(), h.Store, f.txn.TenantID, f.txn.ClientID, identifier)
		if errors.Is(err, store.ErrInvalid) {
			invalid()
			return true
		}
		if err != nil {
			h.fail(w, r, err, f)
			return true
		}
		next := f.txn.HostedState.Clone()
		next.Step = "organization-discovery"
		next.Identifier = identifier
		if err = h.transitionHosted(r, f, next); err != nil {
			h.fail(w, r, errTxn, f)
			return true
		}
		choices = discoveryChoices(choices)
		if len(choices) == 1 {
			if err = h.bindOrg(r, f, &choices[0]); err != nil {
				h.fail(w, r, errTxn, f)
				return true
			}
			h.organizationNext(w, r, f)
			return true
		}
		if len(choices) == 0 {
			invalid()
		} else {
			h.renderOrganization(w, r, f, choices, "", http.StatusOK)
		}
		return true
	}
	if !name {
		invalid()
		return true
	}
	// Name entry is a hosted prompt exception to the Authentication API name flag.
	org, err := h.Store.Organizations().GetByName(r.Context(), f.res.Tenant.ID, r.PostForm.Get("organization"))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		h.fail(w, r, err, f)
		return true
	}
	if err == nil {
		// Return from discovery to the configured name flow through a revision CAS.
		if pending {
			next := f.txn.HostedState.Clone()
			next.Step = ""
			next.Identifier = ""
			if err = h.transitionHosted(r, f, next); err != nil {
				h.fail(w, r, errTxn, f)
				return true
			}
		}
		if _, denied := authz.ResolveOrganization(r.Context(), h.Store, f.res, client, org.ID); denied == nil {
			if err = h.bindOrg(r, f, org); err != nil {
				h.fail(w, r, errTxn, f)
				return true
			}
			h.organizationNext(w, r, f)
			return true
		}
	}
	invalid()
	return true
}
