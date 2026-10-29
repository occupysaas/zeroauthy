package login

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
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
	if f.txn.Params[store.TxnParamOrgMode] == string(authz.OrgPickAfter) {
		screen = "organization-picker"
	}
	if !h.prepareHostedForm(w, r, f, "organizations", screen) {
		return
	}
	ui.RenderOrganization(w, status, f.view, ui.OrganizationData{State: f.txn.ID, CSRF: f.txn.CSRFToken, Revision: f.txn.HostedState.Revision, Orgs: orgs, Error: message}, screen)
}

// bindOrg replaces only a still-pending transaction in a single store tx. The
// browser cookie and CSRF binding survive; a replay cannot replace the choice.
func (h *Handlers) bindOrg(r *http.Request, f *flow, org *store.Organization) error {
	return h.Store.WithTx(r.Context(), func(tx store.Store) error {
		cur, err := tx.AuthTransactions().Get(r.Context(), f.res.Tenant.ID, f.txn.ID)
		if err != nil {
			return err
		}
		if cur.Params[store.TxnParamOrgMode] != f.txn.Params[store.TxnParamOrgMode] || cur.HostedState.Revision != f.txn.HostedState.Revision {
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
		if _, e := authz.ResolveOrganization(r.Context(), tx, f.res, client, org.ID); e != nil {
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
			choices, auto, e := PickerChoices(r.Context(), tx, cur.TenantID, sess.UserID, conn.ID)
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
		cur.Params[store.TxnParamOrgID] = org.ID
		cur.Params[store.TxnParamOrgMode] = string(authz.OrgFixed)
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
		if r.Method == http.MethodPost {
			org, err := h.Store.Organizations().GetByName(r.Context(), f.res.Tenant.ID, r.PostForm.Get("organization"))
			if err == nil {
				client, e := h.Store.Clients().Get(r.Context(), f.res.Tenant.ID, f.txn.ClientID)
				if e != nil {
					h.fail(w, r, e, f)
					return true
				}
				_, denied := authz.ResolveOrganization(r.Context(), h.Store, f.res, client, org.ID)
				if denied == nil {
					if err = h.bindOrg(r, f, org); err != nil {
						h.fail(w, r, errTxn, f)
						return true
					}
					page := "/u/login"
					if f.txn.Params["screen_hint"] == "signup" {
						page = "/u/signup"
					}
					http.Redirect(w, r, page+"?"+url.Values{"state": {f.txn.ID}}.Encode(), http.StatusSeeOther)
					return true
				}
			} else if !errors.Is(err, store.ErrNotFound) {
				h.fail(w, r, err, f)
				return true
			}
			h.renderOrganization(w, r, f, nil, f.view.L.T(i18n.KeyOrganizationInvalid), http.StatusBadRequest)
			return true
		}
		h.renderOrganization(w, r, f, nil, "", http.StatusOK)
		return true
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
	choices, auto, err := PickerChoices(r.Context(), h.Store, f.res.Tenant.ID, sess.UserID, conn.ID)
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
	return ok && link.IsSignupEnabled && link.AssignMembershipOnLogin
}
